/**
 * Function Registry for MCP
 * 
 * Central registry for managing function definitions and execution across providers
 */

import { EventEmitter } from 'events';
import {
  FunctionDefinition,
  FunctionCall,
  FunctionResult,
  FunctionSecurity,
  FunctionRiskLevel,
  MCPError,
  MCPErrorCode,
  ParameterDefinition
} from '../types';

/**
 * Function execution context
 */
export interface FunctionExecutionContext {
  agentDID: string;
  sessionId: string;
  requestId: string;
  provider: string;
  model: string;
  timestamp: Date;
  metadata?: Record<string, any>;
}

/**
 * Function handler
 */
export type FunctionHandler = (
  args: Record<string, any>,
  context: FunctionExecutionContext
) => Promise<any>;

/**
 * Function metadata
 */
export interface FunctionMetadata {
  id: string;
  name: string;
  version: string;
  author: string;
  description: string;
  category: string;
  tags: string[];
  deprecated: boolean;
  createdAt: Date;
  updatedAt: Date;
  usageCount: number;
  averageExecutionTime: number;
  successRate: number;
}

/**
 * Function validation result
 */
export interface FunctionValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  sanitizedArgs?: Record<string, any>;
}

/**
 * Registered function
 */
export interface RegisteredFunction {
  definition: FunctionDefinition;
  handler: FunctionHandler;
  metadata: FunctionMetadata;
  security: FunctionSecurity;
  enabled: boolean;
}

/**
 * Function execution result
 */
export interface FunctionExecutionResult {
  functionCallId: string;
  result: any;
  error?: string;
  executionTime: number;
  timestamp: Date;
  metadata: {
    provider: string;
    model: string;
    agentDID: string;
    sessionId: string;
    memoryUsage?: number;
    warnings?: string[];
  };
}

/**
 * Function registry configuration
 */
export interface FunctionRegistryConfig {
  maxExecutionTime: number;
  maxMemoryUsage: number;
  enableSandboxing: boolean;
  allowDynamicRegistration: boolean;
  securityLevel: 'strict' | 'moderate' | 'permissive';
  auditAllCalls: boolean;
  cacheResults: boolean;
  cacheTimeout: number;
}

/**
 * Function Registry
 */
export class FunctionRegistry extends EventEmitter {
  private functions: Map<string, RegisteredFunction> = new Map();
  private categories: Map<string, Set<string>> = new Map();
  private executionCache: Map<string, { result: any; timestamp: Date }> = new Map();
  private executionMetrics: Map<string, { calls: number; totalTime: number; errors: number }> = new Map();

  constructor(
    private config: FunctionRegistryConfig = {
      maxExecutionTime: 30000, // 30 seconds
      maxMemoryUsage: 100 * 1024 * 1024, // 100MB
      enableSandboxing: true,
      allowDynamicRegistration: true,
      securityLevel: 'moderate',
      auditAllCalls: true,
      cacheResults: true,
      cacheTimeout: 300000 // 5 minutes
    }
  ) {
    super();
    this.initializeBuiltinFunctions();
  }

  /**
   * Register a function
   */
  async registerFunction(
    definition: FunctionDefinition,
    handler: FunctionHandler,
    options: {
      security?: Partial<FunctionSecurity>;
      metadata?: Partial<FunctionMetadata>;
      enabled?: boolean;
    } = {}
  ): Promise<string> {
    // Validate function definition
    const validation = this.validateFunctionDefinition(definition);
    if (!validation.valid) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_FUNCTION_CALL,
        message: `Invalid function definition: ${validation.errors.join(', ')}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Check if function already exists
    if (this.functions.has(definition.name)) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_FUNCTION_CALL,
        message: `Function ${definition.name} already registered`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Create function metadata
    const metadata: FunctionMetadata = {
      id: `func-${definition.name}-${Date.now()}`,
      name: definition.name,
      version: '1.0.0',
      author: 'system',
      description: definition.description,
      category: 'general',
      tags: [],
      deprecated: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      usageCount: 0,
      averageExecutionTime: 0,
      successRate: 1.0,
      ...options.metadata
    };

    // Create security configuration
    const security: FunctionSecurity = {
      requiredScopes: [],
      riskLevel: FunctionRiskLevel.LOW,
      auditRequired: this.config.auditAllCalls,
      approvalRequired: false,
      ...options.security
    };

    // Create registered function
    const registeredFunction: RegisteredFunction = {
      definition,
      handler,
      metadata,
      security,
      enabled: options.enabled !== false
    };

    this.functions.set(definition.name, registeredFunction);

    // Update category index
    const category = metadata.category;
    if (!this.categories.has(category)) {
      this.categories.set(category, new Set());
    }
    this.categories.get(category)!.add(definition.name);

    // Initialize metrics
    this.executionMetrics.set(definition.name, {
      calls: 0,
      totalTime: 0,
      errors: 0
    });

    this.emit('function_registered', {
      name: definition.name,
      metadata,
      security
    });

    return metadata.id;
  }

  /**
   * Execute a function
   */
  async executeFunction(
    functionCall: FunctionCall,
    context: FunctionExecutionContext
  ): Promise<FunctionExecutionResult> {
    const startTime = Date.now();
    const functionName = functionCall.name;

    try {
      // Get registered function
      const registeredFunction = this.functions.get(functionName);
      if (!registeredFunction) {
        throw new MCPError({
          code: MCPErrorCode.FUNCTION_NOT_FOUND,
          message: `Function ${functionName} not found`,
          timestamp: new Date(),
          retryable: false
        });
      }

      // Check if function is enabled
      if (!registeredFunction.enabled) {
        throw new MCPError({
          code: MCPErrorCode.FUNCTION_ERROR,
          message: `Function ${functionName} is disabled`,
          timestamp: new Date(),
          retryable: false
        });
      }

      // Validate arguments
      const validation = this.validateFunctionArguments(
        registeredFunction.definition,
        functionCall.arguments
      );

      if (!validation.valid) {
        throw new MCPError({
          code: MCPErrorCode.INVALID_FUNCTION_CALL,
          message: `Invalid arguments: ${validation.errors.join(', ')}`,
          timestamp: new Date(),
          retryable: false
        });
      }

      // Check cache if enabled
      if (this.config.cacheResults) {
        const cacheKey = this.generateCacheKey(functionCall);
        const cached = this.executionCache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp.getTime() < this.config.cacheTimeout) {
          return {
            functionCallId: functionCall.id || `exec-${Date.now()}`,
            result: cached.result,
            executionTime: 0,
            timestamp: new Date(),
            metadata: {
              provider: context.provider,
              model: context.model,
              agentDID: context.agentDID,
              sessionId: context.sessionId,
              warnings: ['Result returned from cache']
            }
          };
        }
      }

      // Execute function with timeout
      const sanitizedArgs = validation.sanitizedArgs || functionCall.arguments;
      const result = await this.executeWithTimeout(
        registeredFunction.handler,
        sanitizedArgs,
        context,
        this.config.maxExecutionTime
      );

      const executionTime = Date.now() - startTime;

      // Update metrics
      this.updateExecutionMetrics(functionName, executionTime, true);

      // Update function metadata
      registeredFunction.metadata.usageCount++;
      registeredFunction.metadata.updatedAt = new Date();
      this.updateAverageExecutionTime(registeredFunction.metadata, executionTime);
      this.updateSuccessRate(registeredFunction.metadata, true);

      // Cache result if enabled
      if (this.config.cacheResults) {
        const cacheKey = this.generateCacheKey(functionCall);
        this.executionCache.set(cacheKey, {
          result,
          timestamp: new Date()
        });
      }

      const executionResult: FunctionExecutionResult = {
        functionCallId: functionCall.id || `exec-${Date.now()}`,
        result,
        executionTime,
        timestamp: new Date(),
        metadata: {
          provider: context.provider,
          model: context.model,
          agentDID: context.agentDID,
          sessionId: context.sessionId,
          warnings: validation.warnings
        }
      };

      this.emit('function_executed', {
        functionName,
        context,
        result: executionResult
      });

      return executionResult;

    } catch (error) {
      const executionTime = Date.now() - startTime;
      
      // Update metrics
      this.updateExecutionMetrics(functionName, executionTime, false);

      // Update function metadata if function exists
      const registeredFunction = this.functions.get(functionName);
      if (registeredFunction) {
        this.updateSuccessRate(registeredFunction.metadata, false);
      }

      const mcpError = error instanceof MCPError ? error : new MCPError({
        code: MCPErrorCode.FUNCTION_ERROR,
        message: (error as Error).message,
        timestamp: new Date(),
        retryable: false
      });

      this.emit('function_error', {
        functionName,
        context,
        error: mcpError
      });

      return {
        functionCallId: functionCall.id || `exec-${Date.now()}`,
        result: null,
        error: mcpError.message,
        executionTime,
        timestamp: new Date(),
        metadata: {
          provider: context.provider,
          model: context.model,
          agentDID: context.agentDID,
          sessionId: context.sessionId
        }
      };
    }
  }

  /**
   * Get function definition by name
   */
  getFunctionDefinition(name: string): FunctionDefinition | null {
    const func = this.functions.get(name);
    return func ? func.definition : null;
  }

  /**
   * Get all function definitions
   */
  getAllFunctionDefinitions(): FunctionDefinition[] {
    return Array.from(this.functions.values())
      .filter(func => func.enabled)
      .map(func => func.definition);
  }

  /**
   * Get functions by category
   */
  getFunctionsByCategory(category: string): FunctionDefinition[] {
    const functionNames = this.categories.get(category) || new Set();
    return Array.from(functionNames)
      .map(name => this.functions.get(name))
      .filter(func => func && func.enabled)
      .map(func => func!.definition);
  }

  /**
   * Search functions
   */
  searchFunctions(query: string): FunctionDefinition[] {
    const lowerQuery = query.toLowerCase();
    return Array.from(this.functions.values())
      .filter(func => 
        func.enabled && (
          func.definition.name.toLowerCase().includes(lowerQuery) ||
          func.definition.description.toLowerCase().includes(lowerQuery) ||
          func.metadata.tags.some(tag => tag.toLowerCase().includes(lowerQuery))
        )
      )
      .map(func => func.definition);
  }

  /**
   * Enable/disable function
   */
  setFunctionEnabled(name: string, enabled: boolean): void {
    const func = this.functions.get(name);
    if (func) {
      func.enabled = enabled;
      this.emit('function_status_changed', { name, enabled });
    }
  }

  /**
   * Unregister function
   */
  unregisterFunction(name: string): boolean {
    const func = this.functions.get(name);
    if (func) {
      this.functions.delete(name);
      
      // Remove from category
      const category = func.metadata.category;
      this.categories.get(category)?.delete(name);
      
      // Clear metrics
      this.executionMetrics.delete(name);
      
      // Clear cache entries
      for (const [key] of this.executionCache) {
        if (key.includes(name)) {
          this.executionCache.delete(key);
        }
      }

      this.emit('function_unregistered', { name });
      return true;
    }
    return false;
  }

  /**
   * Get function statistics
   */
  getFunctionStatistics(): {
    totalFunctions: number;
    enabledFunctions: number;
    functionsByCategory: Record<string, number>;
    topFunctions: Array<{ name: string; calls: number; avgTime: number }>;
    errorRate: number;
  } {
    const totalFunctions = this.functions.size;
    const enabledFunctions = Array.from(this.functions.values())
      .filter(func => func.enabled).length;

    const functionsByCategory: Record<string, number> = {};
    for (const [category, names] of this.categories) {
      functionsByCategory[category] = names.size;
    }

    const metrics = Array.from(this.executionMetrics.entries())
      .map(([name, stats]) => ({
        name,
        calls: stats.calls,
        avgTime: stats.calls > 0 ? stats.totalTime / stats.calls : 0
      }))
      .sort((a, b) => b.calls - a.calls)
      .slice(0, 10);

    const totalCalls = Array.from(this.executionMetrics.values())
      .reduce((sum, stats) => sum + stats.calls, 0);
    const totalErrors = Array.from(this.executionMetrics.values())
      .reduce((sum, stats) => sum + stats.errors, 0);
    const errorRate = totalCalls > 0 ? totalErrors / totalCalls : 0;

    return {
      totalFunctions,
      enabledFunctions,
      functionsByCategory,
      topFunctions: metrics,
      errorRate
    };
  }

  /**
   * Validate function definition
   */
  private validateFunctionDefinition(definition: FunctionDefinition): FunctionValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check required fields
    if (!definition.name || typeof definition.name !== 'string') {
      errors.push('Function name is required and must be a string');
    }

    if (!definition.description || typeof definition.description !== 'string') {
      errors.push('Function description is required and must be a string');
    }

    if (!definition.parameters || typeof definition.parameters !== 'object') {
      errors.push('Function parameters are required');
    }

    // Validate name format
    if (definition.name && !/^[a-zA-Z][a-zA-Z0-9_]*$/.test(definition.name)) {
      errors.push('Function name must start with a letter and contain only letters, numbers, and underscores');
    }

    // Validate parameters
    if (definition.parameters) {
      if (definition.parameters.type !== 'object') {
        errors.push('Parameters type must be "object"');
      }

      if (!definition.parameters.properties || typeof definition.parameters.properties !== 'object') {
        errors.push('Parameters must have properties');
      }

      if (!Array.isArray(definition.parameters.required)) {
        warnings.push('Parameters should specify required fields');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate function arguments
   */
  private validateFunctionArguments(
    definition: FunctionDefinition,
    args: Record<string, any>
  ): FunctionValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const sanitizedArgs: Record<string, any> = { ...args };

    const { parameters } = definition;

    // Check required parameters
    if (parameters.required) {
      for (const required of parameters.required) {
        if (!(required in args)) {
          errors.push(`Missing required parameter: ${required}`);
        }
      }
    }

    // Validate parameter types
    for (const [name, value] of Object.entries(args)) {
      const paramDef = parameters.properties[name];
      if (!paramDef) {
        warnings.push(`Unknown parameter: ${name}`);
        continue;
      }

      const validation = this.validateParameterValue(value, paramDef);
      if (!validation.valid) {
        errors.push(`Invalid parameter ${name}: ${validation.error}`);
      } else if (validation.sanitized !== undefined) {
        sanitizedArgs[name] = validation.sanitized;
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      sanitizedArgs: errors.length === 0 ? sanitizedArgs : undefined
    };
  }

  /**
   * Validate parameter value
   */
  private validateParameterValue(
    value: any,
    paramDef: ParameterDefinition
  ): { valid: boolean; error?: string; sanitized?: any } {
    // Type validation
    switch (paramDef.type) {
      case 'string':
        if (typeof value !== 'string') {
          return { valid: false, error: 'Expected string' };
        }
        break;
      case 'number':
        if (typeof value !== 'number' || isNaN(value)) {
          return { valid: false, error: 'Expected number' };
        }
        break;
      case 'boolean':
        if (typeof value !== 'boolean') {
          return { valid: false, error: 'Expected boolean' };
        }
        break;
      case 'array':
        if (!Array.isArray(value)) {
          return { valid: false, error: 'Expected array' };
        }
        break;
      case 'object':
        if (typeof value !== 'object' || value === null || Array.isArray(value)) {
          return { valid: false, error: 'Expected object' };
        }
        break;
    }

    // Enum validation
    if (paramDef.enum && !paramDef.enum.includes(value)) {
      return { valid: false, error: `Value must be one of: ${paramDef.enum.join(', ')}` };
    }

    // Range validation for numbers
    if (paramDef.type === 'number') {
      if (paramDef.minimum !== undefined && value < paramDef.minimum) {
        return { valid: false, error: `Value must be >= ${paramDef.minimum}` };
      }
      if (paramDef.maximum !== undefined && value > paramDef.maximum) {
        return { valid: false, error: `Value must be <= ${paramDef.maximum}` };
      }
    }

    // Pattern validation for strings
    if (paramDef.type === 'string' && paramDef.pattern) {
      const regex = new RegExp(paramDef.pattern);
      if (!regex.test(value)) {
        return { valid: false, error: `Value must match pattern: ${paramDef.pattern}` };
      }
    }

    return { valid: true };
  }

  /**
   * Execute function with timeout
   */
  private async executeWithTimeout<T>(
    handler: FunctionHandler,
    args: Record<string, any>,
    context: FunctionExecutionContext,
    timeout: number
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new MCPError({
          code: MCPErrorCode.FUNCTION_TIMEOUT,
          message: `Function execution timed out after ${timeout}ms`,
          timestamp: new Date(),
          retryable: false
        }));
      }, timeout);

      handler(args, context)
        .then(result => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timer);
          reject(error);
        });
    });
  }

  /**
   * Generate cache key for function call
   */
  private generateCacheKey(functionCall: FunctionCall): string {
    const argsString = JSON.stringify(functionCall.arguments, Object.keys(functionCall.arguments).sort());
    return `${functionCall.name}:${argsString}`;
  }

  /**
   * Update execution metrics
   */
  private updateExecutionMetrics(name: string, executionTime: number, success: boolean): void {
    const metrics = this.executionMetrics.get(name);
    if (metrics) {
      metrics.calls++;
      metrics.totalTime += executionTime;
      if (!success) {
        metrics.errors++;
      }
    }
  }

  /**
   * Update average execution time
   */
  private updateAverageExecutionTime(metadata: FunctionMetadata, executionTime: number): void {
    const totalTime = metadata.averageExecutionTime * (metadata.usageCount - 1) + executionTime;
    metadata.averageExecutionTime = totalTime / metadata.usageCount;
  }

  /**
   * Update success rate
   */
  private updateSuccessRate(metadata: FunctionMetadata, success: boolean): void {
    const previousSuccesses = metadata.successRate * (metadata.usageCount - 1);
    const newSuccesses = success ? previousSuccesses + 1 : previousSuccesses;
    metadata.successRate = newSuccesses / metadata.usageCount;
  }

  /**
   * Initialize built-in functions
   */
  private initializeBuiltinFunctions(): void {
    // Register basic utility functions
    this.registerFunction(
      {
        name: 'get_current_time',
        description: 'Get the current date and time',
        parameters: {
          type: 'object',
          properties: {
            format: {
              type: 'string',
              description: 'Time format (iso, unix, readable)',
              enum: ['iso', 'unix', 'readable']
            }
          },
          required: []
        }
      },
      async (args) => {
        const now = new Date();
        switch (args.format) {
          case 'unix':
            return Math.floor(now.getTime() / 1000);
          case 'readable':
            return now.toLocaleString();
          default:
            return now.toISOString();
        }
      },
      {
        metadata: {
          category: 'utility',
          tags: ['time', 'date', 'utility']
        },
        security: {
          requiredScopes: [],
          riskLevel: FunctionRiskLevel.LOW,
          auditRequired: false,
          approvalRequired: false
        }
      }
    );

    this.registerFunction(
      {
        name: 'generate_uuid',
        description: 'Generate a random UUID',
        parameters: {
          type: 'object',
          properties: {
            version: {
              type: 'number',
              description: 'UUID version (4 only supported)',
              enum: [4]
            }
          },
          required: []
        }
      },
      async (args) => {
        // Simple UUID v4 generation
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
          const r = Math.random() * 16 | 0;
          const v = c === 'x' ? r : (r & 0x3 | 0x8);
          return v.toString(16);
        });
      },
      {
        metadata: {
          category: 'utility',
          tags: ['uuid', 'random', 'identifier']
        },
        security: {
          requiredScopes: [],
          riskLevel: FunctionRiskLevel.LOW,
          auditRequired: false,
          approvalRequired: false
        }
      }
    );
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.executionCache.clear();
    this.emit('cache_cleared');
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    this.executionCache.clear();
    this.executionMetrics.clear();
    this.functions.clear();
    this.categories.clear();
    this.removeAllListeners();
  }
}

export default FunctionRegistry;