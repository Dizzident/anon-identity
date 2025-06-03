/**
 * Function Executor for MCP
 * 
 * Secure function execution framework with validation, sandboxing, and monitoring
 */

import { EventEmitter } from 'events';
import {
  FunctionCall,
  FunctionResult,
  FunctionDefinition,
  FunctionSecurity,
  FunctionRiskLevel,
  MCPError,
  MCPErrorCode
} from '../types';
import { FunctionRegistry, FunctionExecutionContext, FunctionExecutionResult } from './function-registry';
import { AuthManager } from '../security/auth-manager';
import { AuditLogger } from '../security/audit-logger';

/**
 * Execution environment
 */
export interface ExecutionEnvironment {
  sandboxed: boolean;
  timeoutMs: number;
  memoryLimitMB: number;
  networkAccess: boolean;
  fileSystemAccess: boolean;
  allowedModules: string[];
  environmentVariables: Record<string, string>;
}

/**
 * Execution options
 */
export interface ExecutionOptions {
  environment?: Partial<ExecutionEnvironment>;
  priority: 'low' | 'normal' | 'high' | 'critical';
  retryOnFailure: boolean;
  maxRetries: number;
  validateResult: boolean;
  auditExecution: boolean;
}

/**
 * Result validation schema
 */
export interface ResultValidationSchema {
  type: string;
  properties?: Record<string, any>;
  required?: string[];
  maxLength?: number;
  maxItems?: number;
  pattern?: string;
}

/**
 * Execution metrics
 */
export interface ExecutionMetrics {
  functionName: string;
  executionTime: number;
  memoryUsed: number;
  cpuTime: number;
  networkCalls: number;
  errors: string[];
  warnings: string[];
  securityViolations: string[];
}

/**
 * Sandbox violation
 */
export interface SandboxViolation {
  type: 'network' | 'filesystem' | 'memory' | 'cpu' | 'module' | 'timeout';
  message: string;
  timestamp: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Function execution queue item
 */
interface QueueItem {
  id: string;
  functionCall: FunctionCall;
  context: FunctionExecutionContext;
  options: ExecutionOptions;
  resolve: (result: FunctionExecutionResult) => void;
  reject: (error: MCPError) => void;
  queuedAt: Date;
  priority: number;
}

/**
 * Function Executor
 */
export class FunctionExecutor extends EventEmitter {
  private executionQueue: QueueItem[] = [];
  private activeExecutions: Map<string, NodeJS.Timeout> = new Map();
  private resultValidators: Map<string, ResultValidationSchema> = new Map();
  private securityPolicies: Map<string, FunctionSecurity> = new Map();
  private isProcessing = false;
  private processInterval?: NodeJS.Timeout;

  constructor(
    private functionRegistry: FunctionRegistry,
    private authManager: AuthManager,
    private auditLogger: AuditLogger,
    private defaultEnvironment: ExecutionEnvironment = {
      sandboxed: true,
      timeoutMs: 30000,
      memoryLimitMB: 100,
      networkAccess: false,
      fileSystemAccess: false,
      allowedModules: ['crypto', 'util', 'querystring'],
      environmentVariables: {}
    }
  ) {
    super();
    this.startQueueProcessor();
  }

  /**
   * Execute function with full security and validation
   */
  async executeFunction(
    functionCall: FunctionCall,
    context: FunctionExecutionContext,
    options: ExecutionOptions = {
      priority: 'normal',
      retryOnFailure: true,
      maxRetries: 3,
      validateResult: true,
      auditExecution: true
    }
  ): Promise<FunctionExecutionResult> {
    // Pre-execution security checks
    await this.performSecurityChecks(functionCall, context);

    // For critical priority, execute immediately
    if (options.priority === 'critical') {
      return this.executeImmediate(functionCall, context, options);
    }

    // Otherwise, queue for execution
    return this.queueExecution(functionCall, context, options);
  }

  /**
   * Register result validator for function
   */
  registerResultValidator(functionName: string, schema: ResultValidationSchema): void {
    this.resultValidators.set(functionName, schema);
  }

  /**
   * Set security policy for function
   */
  setSecurityPolicy(functionName: string, policy: FunctionSecurity): void {
    this.securityPolicies.set(functionName, policy);
  }

  /**
   * Get execution statistics
   */
  getExecutionStatistics(): {
    queueSize: number;
    activeExecutions: number;
    totalExecuted: number;
    averageExecutionTime: number;
    errorRate: number;
    securityViolations: number;
  } {
    // This would be tracked in a real implementation
    return {
      queueSize: this.executionQueue.length,
      activeExecutions: this.activeExecutions.size,
      totalExecuted: 0,
      averageExecutionTime: 0,
      errorRate: 0,
      securityViolations: 0
    };
  }

  /**
   * Perform security checks before execution
   */
  private async performSecurityChecks(
    functionCall: FunctionCall,
    context: FunctionExecutionContext
  ): Promise<void> {
    // Check if function exists and is enabled
    const definition = this.functionRegistry.getFunctionDefinition(functionCall.name);
    if (!definition) {
      throw new MCPError({
        code: MCPErrorCode.FUNCTION_NOT_FOUND,
        message: `Function ${functionCall.name} not found`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Get security policy
    const security = this.securityPolicies.get(functionCall.name) || {
      requiredScopes: [],
      riskLevel: FunctionRiskLevel.LOW,
      auditRequired: true,
      approvalRequired: false
    };

    // Check required scopes
    if (security.requiredScopes.length > 0) {
      const authResult = await this.authManager.authorize(
        context.agentDID,
        `function:${functionCall.name}`,
        'execute'
      );

      if (!authResult.authorized) {
        throw new MCPError({
          code: MCPErrorCode.FORBIDDEN,
          message: `Insufficient permissions for function ${functionCall.name}`,
          timestamp: new Date(),
          retryable: false
        });
      }
    }

    // Check approval requirement for high-risk functions
    if (security.approvalRequired && security.riskLevel === FunctionRiskLevel.HIGH) {
      // In a real implementation, this would check for approval
      this.emit('approval_required', {
        functionCall,
        context,
        security
      });
    }

    // Audit function call if required
    if (security.auditRequired) {
      await this.auditLogger.logRequest(
        {
          id: context.requestId,
          type: 'function_call' as any,
          prompt: `Function call: ${functionCall.name}`,
          agentDID: context.agentDID,
          sessionId: context.sessionId,
          metadata: {
            agentDID: context.agentDID,
            sessionId: context.sessionId,
            requestId: context.requestId,
            timestamp: new Date(),
            source: 'function-executor',
            priority: 'medium' as any,
            functionName: functionCall.name
          }
        },
        context.agentDID,
        context.sessionId
      );
    }
  }

  /**
   * Execute function immediately
   */
  private async executeImmediate(
    functionCall: FunctionCall,
    context: FunctionExecutionContext,
    options: ExecutionOptions
  ): Promise<FunctionExecutionResult> {
    const executionId = `exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    try {
      // Create execution environment
      const environment = this.createExecutionEnvironment(functionCall.name, options.environment);
      
      // Start execution with monitoring
      const result = await this.executeWithMonitoring(
        executionId,
        functionCall,
        context,
        environment,
        options
      );

      // Validate result if required
      if (options.validateResult) {
        await this.validateExecutionResult(functionCall.name, result);
      }

      return result;

    } catch (error) {
      // Handle retry logic
      if (options.retryOnFailure && options.maxRetries > 0) {
        const retryOptions = { ...options, maxRetries: options.maxRetries - 1 };
        return this.executeImmediate(functionCall, context, retryOptions);
      }

      throw error;
    }
  }

  /**
   * Queue execution for later processing
   */
  private async queueExecution(
    functionCall: FunctionCall,
    context: FunctionExecutionContext,
    options: ExecutionOptions
  ): Promise<FunctionExecutionResult> {
    return new Promise((resolve, reject) => {
      const queueItem: QueueItem = {
        id: `queue-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        functionCall,
        context,
        options,
        resolve,
        reject,
        queuedAt: new Date(),
        priority: this.getPriorityValue(options.priority)
      };

      // Insert in priority order
      const insertIndex = this.executionQueue.findIndex(item => item.priority < queueItem.priority);
      if (insertIndex === -1) {
        this.executionQueue.push(queueItem);
      } else {
        this.executionQueue.splice(insertIndex, 0, queueItem);
      }

      this.emit('function_queued', {
        functionName: functionCall.name,
        queuePosition: insertIndex === -1 ? this.executionQueue.length : insertIndex + 1,
        queueSize: this.executionQueue.length
      });
    });
  }

  /**
   * Execute function with comprehensive monitoring
   */
  private async executeWithMonitoring(
    executionId: string,
    functionCall: FunctionCall,
    context: FunctionExecutionContext,
    environment: ExecutionEnvironment,
    options: ExecutionOptions
  ): Promise<FunctionExecutionResult> {
    const startTime = Date.now();
    const metrics: ExecutionMetrics = {
      functionName: functionCall.name,
      executionTime: 0,
      memoryUsed: 0,
      cpuTime: 0,
      networkCalls: 0,
      errors: [],
      warnings: [],
      securityViolations: []
    };

    try {
      // Set up timeout
      const timeout = setTimeout(() => {
        this.activeExecutions.delete(executionId);
        throw new MCPError({
          code: MCPErrorCode.FUNCTION_TIMEOUT,
          message: `Function ${functionCall.name} timed out after ${environment.timeoutMs}ms`,
          timestamp: new Date(),
          retryable: true
        });
      }, environment.timeoutMs);

      this.activeExecutions.set(executionId, timeout);

      // Create sandboxed execution context if required
      let executionResult: FunctionExecutionResult;
      
      if (environment.sandboxed) {
        executionResult = await this.executeSandboxed(
          functionCall,
          context,
          environment,
          metrics
        );
      } else {
        executionResult = await this.functionRegistry.executeFunction(functionCall, context);
      }

      // Clear timeout
      clearTimeout(timeout);
      this.activeExecutions.delete(executionId);

      // Update metrics
      metrics.executionTime = Date.now() - startTime;

      // Emit monitoring events
      this.emit('function_executed', {
        executionId,
        functionCall,
        result: executionResult,
        metrics
      });

      return executionResult;

    } catch (error) {
      // Clear timeout
      const timeout = this.activeExecutions.get(executionId);
      if (timeout) {
        clearTimeout(timeout);
        this.activeExecutions.delete(executionId);
      }

      metrics.executionTime = Date.now() - startTime;
      metrics.errors.push((error as Error).message);

      this.emit('function_error', {
        executionId,
        functionCall,
        error,
        metrics
      });

      throw error;
    }
  }

  /**
   * Execute function in sandbox
   */
  private async executeSandboxed(
    functionCall: FunctionCall,
    context: FunctionExecutionContext,
    environment: ExecutionEnvironment,
    metrics: ExecutionMetrics
  ): Promise<FunctionExecutionResult> {
    // In a real implementation, this would use actual sandboxing
    // For now, we'll simulate sandbox constraints and monitoring

    const violations: SandboxViolation[] = [];

    // Monitor memory usage (simulated)
    const initialMemory = process.memoryUsage();
    
    try {
      // Execute with constraints
      const result = await this.functionRegistry.executeFunction(functionCall, context);

      // Check memory usage
      const finalMemory = process.memoryUsage();
      const memoryUsed = (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024; // MB
      
      if (memoryUsed > environment.memoryLimitMB) {
        violations.push({
          type: 'memory',
          message: `Function exceeded memory limit: ${memoryUsed}MB > ${environment.memoryLimitMB}MB`,
          timestamp: new Date(),
          severity: 'high'
        });
      }

      metrics.memoryUsed = memoryUsed;

      // Report violations
      if (violations.length > 0) {
        violations.forEach(violation => {
          metrics.securityViolations.push(violation.message);
        });

        this.emit('sandbox_violation', {
          functionName: functionCall.name,
          violations
        });
      }

      return result;

    } catch (error) {
      // Handle sandbox-specific errors
      if ((error as Error).message.includes('MODULE_NOT_FOUND')) {
        violations.push({
          type: 'module',
          message: 'Attempted to access unauthorized module',
          timestamp: new Date(),
          severity: 'critical'
        });
      }

      throw error;
    }
  }

  /**
   * Validate execution result
   */
  private async validateExecutionResult(
    functionName: string,
    result: FunctionExecutionResult
  ): Promise<void> {
    const schema = this.resultValidators.get(functionName);
    if (!schema) {
      return; // No validation schema defined
    }

    const validation = this.validateResultAgainstSchema(result.result, schema);
    if (!validation.valid) {
      throw new MCPError({
        code: MCPErrorCode.FUNCTION_ERROR,
        message: `Function result validation failed: ${validation.errors.join(', ')}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Add validation warnings to result metadata
    if (validation.warnings.length > 0) {
      result.metadata.warnings = (result.metadata.warnings || []).concat(validation.warnings);
    }
  }

  /**
   * Validate result against schema
   */
  private validateResultAgainstSchema(
    result: any,
    schema: ResultValidationSchema
  ): { valid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Type validation
    if (schema.type && typeof result !== schema.type) {
      if (schema.type === 'array' && !Array.isArray(result)) {
        errors.push(`Expected array, got ${typeof result}`);
      } else if (schema.type === 'object' && (typeof result !== 'object' || result === null || Array.isArray(result))) {
        errors.push(`Expected object, got ${typeof result}`);
      }
    }

    // String validation
    if (schema.type === 'string' && typeof result === 'string') {
      if (schema.maxLength && result.length > schema.maxLength) {
        errors.push(`String length ${result.length} exceeds maximum ${schema.maxLength}`);
      }
      if (schema.pattern && !new RegExp(schema.pattern).test(result)) {
        errors.push(`String does not match pattern ${schema.pattern}`);
      }
    }

    // Array validation
    if (schema.type === 'array' && Array.isArray(result)) {
      if (schema.maxItems && result.length > schema.maxItems) {
        errors.push(`Array length ${result.length} exceeds maximum ${schema.maxItems}`);
      }
    }

    // Object validation
    if (schema.type === 'object' && typeof result === 'object' && result !== null) {
      if (schema.required) {
        for (const requiredProp of schema.required) {
          if (!(requiredProp in result)) {
            errors.push(`Missing required property: ${requiredProp}`);
          }
        }
      }

      if (schema.properties) {
        for (const [prop, value] of Object.entries(result)) {
          if (!schema.properties[prop]) {
            warnings.push(`Unexpected property: ${prop}`);
          }
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Create execution environment
   */
  private createExecutionEnvironment(
    functionName: string,
    overrides?: Partial<ExecutionEnvironment>
  ): ExecutionEnvironment {
    // Get function-specific security settings
    const security = this.securityPolicies.get(functionName);
    
    let environment = { ...this.defaultEnvironment };

    // Apply security-based environment settings
    if (security) {
      switch (security.riskLevel) {
        case FunctionRiskLevel.HIGH:
        case FunctionRiskLevel.CRITICAL:
          environment.networkAccess = false;
          environment.fileSystemAccess = false;
          environment.timeoutMs = Math.min(environment.timeoutMs, 10000); // 10 seconds max
          environment.memoryLimitMB = Math.min(environment.memoryLimitMB, 50); // 50MB max
          break;
        case FunctionRiskLevel.MEDIUM:
          environment.networkAccess = false;
          environment.timeoutMs = Math.min(environment.timeoutMs, 20000); // 20 seconds max
          break;
        case FunctionRiskLevel.LOW:
          // Use defaults
          break;
      }
    }

    // Apply overrides
    if (overrides) {
      environment = { ...environment, ...overrides };
    }

    return environment;
  }

  /**
   * Get priority value for sorting
   */
  private getPriorityValue(priority: string): number {
    switch (priority) {
      case 'critical': return 4;
      case 'high': return 3;
      case 'normal': return 2;
      case 'low': return 1;
      default: return 2;
    }
  }

  /**
   * Start queue processor
   */
  private startQueueProcessor(): void {
    this.processInterval = setInterval(() => {
      this.processQueue();
    }, 100); // Process every 100ms
  }

  /**
   * Process execution queue
   */
  private async processQueue(): Promise<void> {
    if (this.isProcessing || this.executionQueue.length === 0) {
      return;
    }

    // Limit concurrent executions
    const maxConcurrent = 10;
    if (this.activeExecutions.size >= maxConcurrent) {
      return;
    }

    this.isProcessing = true;

    try {
      const item = this.executionQueue.shift();
      if (item) {
        // Execute the queued function
        this.executeImmediate(item.functionCall, item.context, item.options)
          .then(result => item.resolve(result))
          .catch(error => item.reject(error));
      }
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Clear execution queue
   */
  clearQueue(): void {
    for (const item of this.executionQueue) {
      item.reject(new MCPError({
        code: MCPErrorCode.FUNCTION_ERROR,
        message: 'Execution queue cleared',
        timestamp: new Date(),
        retryable: false
      }));
    }
    this.executionQueue = [];
  }

  /**
   * Shutdown executor
   */
  shutdown(): void {
    // Clear timers
    if (this.processInterval) {
      clearInterval(this.processInterval);
    }

    // Cancel active executions
    for (const [id, timeout] of this.activeExecutions) {
      clearTimeout(timeout);
    }
    this.activeExecutions.clear();

    // Clear queue
    this.clearQueue();

    this.removeAllListeners();
  }
}

export default FunctionExecutor;