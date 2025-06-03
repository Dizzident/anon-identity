/**
 * MCP Security Integration
 * 
 * Integrates MCP with existing security framework and implements LLM-based threat detection
 */

import { EventEmitter } from 'events';
import {
  LLMRequest,
  LLMResponse,
  LLMRequestType,
  RequestPriority,
  FunctionDefinition,
  MCPError,
  MCPErrorCode
} from '../types';
import { MessageRouter } from '../routing/message-router';
import { AuthManager } from '../security/auth-manager';
import { AuditLogger, AuditEventType } from '../security/audit-logger';
import { RateLimiterManager } from '../security/rate-limiter';
import { CredentialManager } from '../security/credential-manager';
import { FunctionRegistry } from '../functions/function-registry';
import { FunctionExecutor } from '../functions/function-executor';

/**
 * Security threat types
 */
export enum ThreatType {
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  DATA_EXFILTRATION = 'data_exfiltration',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  INJECTION_ATTACK = 'injection_attack',
  DENIAL_OF_SERVICE = 'denial_of_service',
  ANOMALOUS_BEHAVIOR = 'anomalous_behavior',
  POLICY_VIOLATION = 'policy_violation',
  SUSPICIOUS_PATTERN = 'suspicious_pattern'
}

/**
 * Threat severity levels
 */
export enum ThreatSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Security threat
 */
export interface SecurityThreat {
  id: string;
  type: ThreatType;
  severity: ThreatSeverity;
  confidence: number;
  timestamp: Date;
  source: string;
  targetAgent?: string;
  description: string;
  evidence: Record<string, any>;
  recommendations: string[];
  automatedResponse?: SecurityResponse;
}

/**
 * Security response
 */
export interface SecurityResponse {
  action: 'block' | 'throttle' | 'alert' | 'investigate' | 'quarantine';
  duration?: number;
  reason: string;
  metadata?: Record<string, any>;
}

/**
 * Security analysis request
 */
export interface SecurityAnalysisRequest {
  type: 'request' | 'response' | 'behavior' | 'pattern';
  data: any;
  context: {
    agentDID: string;
    sessionId?: string;
    requestType?: LLMRequestType;
    historicalData?: any[];
  };
}

/**
 * Security policy
 */
export interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  rules: SecurityRule[];
  enabled: boolean;
  priority: number;
}

/**
 * Security rule
 */
export interface SecurityRule {
  condition: string;
  action: SecurityResponse;
  exceptions?: string[];
}

/**
 * MCP Security Integration
 */
export class MCPSecurityIntegration extends EventEmitter {
  private activeThreats: Map<string, SecurityThreat> = new Map();
  private securityPolicies: Map<string, SecurityPolicy> = new Map();
  private threatHistory: SecurityThreat[] = [];
  private functionRegistry: FunctionRegistry;
  private functionExecutor: FunctionExecutor;
  private analysisInProgress: Set<string> = new Set();

  constructor(
    private messageRouter: MessageRouter,
    private authManager: AuthManager,
    private auditLogger: AuditLogger,
    private rateLimiter: RateLimiterManager,
    private credentialManager: CredentialManager,
    private config: {
      enableThreatDetection: boolean;
      enableAutomatedResponse: boolean;
      threatRetentionPeriod: number;
      analysisTimeout: number;
      maxConcurrentAnalysis: number;
      llmProvider?: string;
      llmModel?: string;
    } = {
      enableThreatDetection: true,
      enableAutomatedResponse: false,
      threatRetentionPeriod: 86400000 * 30, // 30 days
      analysisTimeout: 30000, // 30 seconds
      maxConcurrentAnalysis: 10,
      llmProvider: 'openai',
      llmModel: 'gpt-4'
    }
  ) {
    super();
    this.functionRegistry = new FunctionRegistry();
    this.functionExecutor = new FunctionExecutor(
      this.functionRegistry,
      authManager,
      auditLogger
    );
    this.initializeSecurityFunctions();
    this.loadDefaultPolicies();
    this.setupEventHandlers();
  }

  /**
   * Initialize security analysis functions
   */
  private initializeSecurityFunctions(): void {
    // Register threat detection function
    this.functionRegistry.registerFunction(
      {
        name: 'detect_security_threats',
        description: 'Analyze data for potential security threats',
        parameters: {
          type: 'object',
          properties: {
            threatType: {
              type: 'string',
              description: 'Type of threat detected',
              enum: Object.values(ThreatType)
            },
            severity: {
              type: 'string',
              description: 'Severity of the threat',
              enum: Object.values(ThreatSeverity)
            },
            confidence: {
              type: 'number',
              description: 'Confidence level (0-1)',
              minimum: 0,
              maximum: 1
            },
            description: {
              type: 'string',
              description: 'Detailed description of the threat'
            },
            evidence: {
              type: 'object',
              description: 'Evidence supporting the threat detection'
            },
            recommendations: {
              type: 'array',
              description: 'Recommended actions',
              items: { type: 'string' }
            }
          },
          required: ['threatType', 'severity', 'confidence', 'description']
        }
      },
      async (args, context) => {
        return {
          detected: true,
          threat: args
        };
      },
      {
        security: {
          requiredScopes: ['security:analyze'],
          riskLevel: 'low' as any,
          auditRequired: true,
          approvalRequired: false
        }
      }
    );

    // Register behavior analysis function
    this.functionRegistry.registerFunction(
      {
        name: 'analyze_agent_behavior',
        description: 'Analyze agent behavior for anomalies',
        parameters: {
          type: 'object',
          properties: {
            normalBehavior: {
              type: 'object',
              description: 'Expected normal behavior patterns'
            },
            observedBehavior: {
              type: 'object',
              description: 'Actual observed behavior'
            },
            anomalies: {
              type: 'array',
              description: 'Detected anomalies',
              items: {
                type: 'object',
                properties: {
                  type: { type: 'string', description: 'Threat type' },
                  severity: { type: 'string', description: 'Threat severity' },
                  description: { type: 'string', description: 'Threat description' }
                }
              }
            },
            riskScore: {
              type: 'number',
              description: 'Overall risk score (0-1)',
              minimum: 0,
              maximum: 1
            }
          },
          required: ['anomalies', 'riskScore']
        }
      },
      async (args, context) => {
        return {
          analyzed: true,
          result: args
        };
      }
    );

    // Register policy evaluation function
    this.functionRegistry.registerFunction(
      {
        name: 'evaluate_security_policy',
        description: 'Evaluate request against security policies',
        parameters: {
          type: 'object',
          properties: {
            violations: {
              type: 'array',
              description: 'Policy violations detected',
              items: {
                type: 'object',
                properties: {
                  policyId: { type: 'string', description: 'Policy ID' },
                  ruleBroken: { type: 'string', description: 'Rule that was broken' },
                  severity: { type: 'string', description: 'Violation severity' },
                  recommendation: { type: 'string', description: 'Recommended action' }
                }
              }
            },
            compliant: {
              type: 'boolean',
              description: 'Whether the request is compliant'
            },
            riskLevel: {
              type: 'string',
              description: 'Overall risk level',
              enum: ['low', 'medium', 'high', 'critical']
            }
          },
          required: ['violations', 'compliant', 'riskLevel']
        }
      },
      async (args, context) => {
        return args;
      }
    );
  }

  /**
   * Analyze request for threats
   */
  async analyzeRequest(request: LLMRequest): Promise<SecurityThreat[]> {
    if (!this.config.enableThreatDetection) {
      return [];
    }

    const analysisId = `analysis-${request.id}`;
    
    // Check concurrent analysis limit
    if (this.analysisInProgress.size >= this.config.maxConcurrentAnalysis) {
      console.warn('Max concurrent security analysis reached, skipping');
      return [];
    }

    this.analysisInProgress.add(analysisId);

    try {
      // Build analysis prompt
      const prompt = this.buildRequestAnalysisPrompt(request);

      // Create LLM request for threat detection
      const analysisRequest: LLMRequest = {
        id: analysisId,
        type: LLMRequestType.FUNCTION_CALL,
        prompt,
        agentDID: 'security-analyzer',
        sessionId: `security-${Date.now()}`,
        functions: [
          this.functionRegistry.getFunctionDefinition('detect_security_threats')!
        ],
        parameters: {
          temperature: 0.2, // Low temperature for consistent security analysis
          maxTokens: 1000
        },
        metadata: {
          agentDID: 'security-analyzer',
          sessionId: `security-${Date.now()}`,
          requestId: analysisId,
          timestamp: new Date(),
          source: 'security-integration',
          priority: RequestPriority.HIGH
        }
      };

      // Route to LLM with timeout
      const response = await Promise.race([
        this.messageRouter.routeMessage(analysisRequest),
        new Promise<LLMResponse>((_, reject) => 
          setTimeout(() => reject(new Error('Analysis timeout')), this.config.analysisTimeout)
        )
      ]);

      // Process threat detection results
      const threats = this.processThreatsFromResponse(response, request);

      // Apply automated responses if enabled
      if (this.config.enableAutomatedResponse && threats.length > 0) {
        await this.applyAutomatedResponses(threats, request);
      }

      // Store threats
      for (const threat of threats) {
        this.activeThreats.set(threat.id, threat);
        this.threatHistory.push(threat);
        this.emit('threat_detected', threat);
      }

      // Clean old threats
      this.cleanOldThreats();

      return threats;

    } catch (error) {
      console.error('Security analysis failed:', error);
      return [];
    } finally {
      this.analysisInProgress.delete(analysisId);
    }
  }

  /**
   * Analyze response for threats
   */
  async analyzeResponse(response: LLMResponse, originalRequest: LLMRequest): Promise<SecurityThreat[]> {
    if (!this.config.enableThreatDetection) {
      return [];
    }

    try {
      // Check for data exfiltration patterns
      const dataExfiltrationThreats = await this.checkDataExfiltration(response, originalRequest);
      
      // Check for injection attacks in responses
      const injectionThreats = await this.checkResponseInjection(response);

      // Combine threats
      const threats = [...dataExfiltrationThreats, ...injectionThreats];

      // Store and emit threats
      for (const threat of threats) {
        this.activeThreats.set(threat.id, threat);
        this.threatHistory.push(threat);
        this.emit('threat_detected', threat);
      }

      return threats;

    } catch (error) {
      console.error('Response security analysis failed:', error);
      return [];
    }
  }

  /**
   * Analyze agent behavior
   */
  async analyzeAgentBehavior(
    agentDID: string,
    recentActivity: any[],
    historicalPatterns?: any
  ): Promise<SecurityThreat[]> {
    if (!this.config.enableThreatDetection) {
      return [];
    }

    try {
      // Build behavior analysis prompt
      const prompt = this.buildBehaviorAnalysisPrompt(agentDID, recentActivity, historicalPatterns);

      // Create analysis request
      const analysisRequest: LLMRequest = {
        id: `behavior-analysis-${Date.now()}`,
        type: LLMRequestType.FUNCTION_CALL,
        prompt,
        agentDID: 'security-analyzer',
        sessionId: `behavior-${Date.now()}`,
        functions: [
          this.functionRegistry.getFunctionDefinition('analyze_agent_behavior')!
        ],
        parameters: {
          temperature: 0.3,
          maxTokens: 1500
        },
        metadata: {
          agentDID: 'security-analyzer',
          sessionId: `behavior-${Date.now()}`,
          requestId: `behavior-analysis-${Date.now()}`,
          timestamp: new Date(),
          source: 'security-integration',
          priority: RequestPriority.MEDIUM
        }
      };

      const response = await this.messageRouter.routeMessage(analysisRequest);
      
      // Process behavior analysis results
      const threats = this.processBehaviorAnalysis(response, agentDID);

      // Store threats
      for (const threat of threats) {
        this.activeThreats.set(threat.id, threat);
        this.threatHistory.push(threat);
        this.emit('threat_detected', threat);
      }

      return threats;

    } catch (error) {
      console.error('Behavior analysis failed:', error);
      return [];
    }
  }

  /**
   * Evaluate request against policies
   */
  async evaluatePolicies(request: LLMRequest): Promise<{
    compliant: boolean;
    violations: Array<{ policy: SecurityPolicy; rule: SecurityRule }>;
    recommendations: string[];
  }> {
    const violations: Array<{ policy: SecurityPolicy; rule: SecurityRule }> = [];
    const recommendations: string[] = [];

    // Check each active policy
    for (const [, policy] of this.securityPolicies) {
      if (!policy.enabled) continue;

      for (const rule of policy.rules) {
        if (this.evaluateRule(rule, request)) {
          violations.push({ policy, rule });
          
          // Add recommendation based on action
          switch (rule.action.action) {
            case 'block':
              recommendations.push(`Block request due to ${policy.name} violation`);
              break;
            case 'throttle':
              recommendations.push(`Throttle agent ${request.agentDID} for ${rule.action.duration}ms`);
              break;
            case 'alert':
              recommendations.push(`Alert security team about ${policy.name} violation`);
              break;
            case 'investigate':
              recommendations.push(`Investigate agent ${request.agentDID} for suspicious activity`);
              break;
            case 'quarantine':
              recommendations.push(`Quarantine agent ${request.agentDID} pending investigation`);
              break;
          }
        }
      }
    }

    // Use LLM for complex policy evaluation if needed
    if (violations.length > 0 || this.requiresLLMEvaluation(request)) {
      const llmEvaluation = await this.evaluatePoliciesWithLLM(request, violations);
      recommendations.push(...llmEvaluation.recommendations);
    }

    return {
      compliant: violations.length === 0,
      violations,
      recommendations
    };
  }

  /**
   * Get active threats
   */
  getActiveThreats(filters?: {
    agentDID?: string;
    severity?: ThreatSeverity;
    type?: ThreatType;
  }): SecurityThreat[] {
    let threats = Array.from(this.activeThreats.values());

    if (filters?.agentDID) {
      threats = threats.filter(t => t.targetAgent === filters.agentDID);
    }
    if (filters?.severity) {
      threats = threats.filter(t => t.severity === filters.severity);
    }
    if (filters?.type) {
      threats = threats.filter(t => t.type === filters.type);
    }

    return threats;
  }

  /**
   * Clear threat
   */
  clearThreat(threatId: string): void {
    const threat = this.activeThreats.get(threatId);
    if (threat) {
      this.activeThreats.delete(threatId);
      this.emit('threat_cleared', threat);
    }
  }

  /**
   * Add security policy
   */
  addSecurityPolicy(policy: SecurityPolicy): void {
    this.securityPolicies.set(policy.id, policy);
    this.emit('policy_added', policy);
  }

  /**
   * Remove security policy
   */
  removeSecurityPolicy(policyId: string): void {
    const policy = this.securityPolicies.get(policyId);
    if (policy) {
      this.securityPolicies.delete(policyId);
      this.emit('policy_removed', policy);
    }
  }

  /**
   * Build request analysis prompt
   */
  private buildRequestAnalysisPrompt(request: LLMRequest): string {
    return `
Analyze the following LLM request for security threats:

REQUEST DETAILS:
- Agent DID: ${request.agentDID}
- Request Type: ${request.type}
- Priority: ${request.metadata?.priority}
- Session ID: ${request.sessionId}
- Timestamp: ${request.metadata?.timestamp}

PROMPT CONTENT:
${request.prompt}

${request.functions ? `
FUNCTIONS REQUESTED:
${request.functions.map(f => `- ${f.name}: ${f.description}`).join('\n')}
` : ''}

ANALYSIS REQUIREMENTS:
1. Check for unauthorized access attempts
2. Identify potential injection attacks (prompt injection, etc.)
3. Detect data exfiltration attempts
4. Look for privilege escalation
5. Identify anomalous patterns
6. Check for policy violations

Consider the context and provide a detailed threat assessment.
    `.trim();
  }

  /**
   * Build behavior analysis prompt
   */
  private buildBehaviorAnalysisPrompt(
    agentDID: string,
    recentActivity: any[],
    historicalPatterns?: any
  ): string {
    return `
Analyze the behavior of agent ${agentDID} for security anomalies:

RECENT ACTIVITY (Last ${recentActivity.length} actions):
${JSON.stringify(recentActivity.slice(-10), null, 2)}

${historicalPatterns ? `
HISTORICAL PATTERNS:
${JSON.stringify(historicalPatterns, null, 2)}
` : ''}

ANALYSIS REQUIREMENTS:
1. Compare recent activity to historical patterns
2. Identify unusual request patterns or frequencies
3. Detect potential compromise indicators
4. Look for data access anomalies
5. Check for privilege abuse
6. Identify coordinated attack patterns

Provide a risk assessment with specific anomalies identified.
    `.trim();
  }

  /**
   * Process threats from LLM response
   */
  private processThreatsFromResponse(response: LLMResponse, request: LLMRequest): SecurityThreat[] {
    const threats: SecurityThreat[] = [];

    if (response.functionCall && response.functionCall.name === 'detect_security_threats') {
      const args = response.functionCall.arguments;
      
      if (args.detected) {
        const threat: SecurityThreat = {
          id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          type: args.threat.threatType,
          severity: args.threat.severity,
          confidence: args.threat.confidence,
          timestamp: new Date(),
          source: 'llm-analysis',
          targetAgent: request.agentDID,
          description: args.threat.description,
          evidence: args.threat.evidence || {},
          recommendations: args.threat.recommendations || []
        };

        // Add automated response based on severity
        if (this.config.enableAutomatedResponse) {
          threat.automatedResponse = this.determineAutomatedResponse(threat);
        }

        threats.push(threat);
      }
    }

    return threats;
  }

  /**
   * Process behavior analysis results
   */
  private processBehaviorAnalysis(response: LLMResponse, agentDID: string): SecurityThreat[] {
    const threats: SecurityThreat[] = [];

    if (response.functionCall && response.functionCall.name === 'analyze_agent_behavior') {
      const args = response.functionCall.arguments;
      
      if (args.analyzed && args.result.riskScore > 0.5) {
        for (const anomaly of args.result.anomalies) {
          const threat: SecurityThreat = {
            id: `anomaly-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            type: ThreatType.ANOMALOUS_BEHAVIOR,
            severity: this.mapAnomalySeverity(anomaly.severity),
            confidence: args.result.riskScore,
            timestamp: new Date(),
            source: 'behavior-analysis',
            targetAgent: agentDID,
            description: anomaly.description,
            evidence: {
              anomalyType: anomaly.type,
              riskScore: args.result.riskScore,
              observedBehavior: args.result.observedBehavior
            },
            recommendations: [`Investigate ${anomaly.type} anomaly`]
          };

          threats.push(threat);
        }
      }
    }

    return threats;
  }

  /**
   * Check for data exfiltration
   */
  private async checkDataExfiltration(
    response: LLMResponse,
    request: LLMRequest
  ): Promise<SecurityThreat[]> {
    const threats: SecurityThreat[] = [];

    // Simple heuristics - in production this would be more sophisticated
    const sensitivePatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
      /\b(?:\d{4}[-\s]?){3}\d{4}\b/, // Credit card
      /\bBEARER\s+[A-Za-z0-9\-._~+\/]+=*\b/i, // Bearer token
    ];

    const content = response.content || '';
    let hasSensitiveData = false;

    for (const pattern of sensitivePatterns) {
      if (pattern.test(content)) {
        hasSensitiveData = true;
        break;
      }
    }

    if (hasSensitiveData) {
      threats.push({
        id: `exfil-${Date.now()}`,
        type: ThreatType.DATA_EXFILTRATION,
        severity: ThreatSeverity.HIGH,
        confidence: 0.8,
        timestamp: new Date(),
        source: 'response-analysis',
        targetAgent: request.agentDID,
        description: 'Potential sensitive data in LLM response',
        evidence: {
          responseLength: content.length,
          patterns: 'sensitive-data-patterns'
        },
        recommendations: [
          'Review response for sensitive data',
          'Apply data masking if necessary',
          'Alert data protection team'
        ]
      });
    }

    return threats;
  }

  /**
   * Check for injection in response
   */
  private async checkResponseInjection(response: LLMResponse): Promise<SecurityThreat[]> {
    const threats: SecurityThreat[] = [];
    const content = response.content || '';

    // Check for potential code injection
    const codePatterns = [
      /<script[\s\S]*?<\/script>/gi,
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
      /\b__proto__\b/gi,
      /\bconstructor\s*\[/gi
    ];

    for (const pattern of codePatterns) {
      if (pattern.test(content)) {
        threats.push({
          id: `injection-${Date.now()}`,
          type: ThreatType.INJECTION_ATTACK,
          severity: ThreatSeverity.CRITICAL,
          confidence: 0.9,
          timestamp: new Date(),
          source: 'response-analysis',
          description: 'Potential code injection in LLM response',
          evidence: {
            pattern: pattern.toString(),
            content: content.substring(0, 200)
          },
          recommendations: [
            'Sanitize response before use',
            'Block execution of response content',
            'Investigate LLM compromise'
          ]
        });
        break;
      }
    }

    return threats;
  }

  /**
   * Determine automated response
   */
  private determineAutomatedResponse(threat: SecurityThreat): SecurityResponse {
    switch (threat.severity) {
      case ThreatSeverity.CRITICAL:
        return {
          action: 'block',
          reason: `Critical threat detected: ${threat.type}`,
          metadata: { threatId: threat.id }
        };
      
      case ThreatSeverity.HIGH:
        return {
          action: 'throttle',
          duration: 300000, // 5 minutes
          reason: `High severity threat: ${threat.type}`,
          metadata: { threatId: threat.id }
        };
      
      case ThreatSeverity.MEDIUM:
        return {
          action: 'alert',
          reason: `Medium severity threat requires investigation`,
          metadata: { threatId: threat.id }
        };
      
      default:
        return {
          action: 'investigate',
          reason: `Low severity threat logged for review`,
          metadata: { threatId: threat.id }
        };
    }
  }

  /**
   * Apply automated responses
   */
  private async applyAutomatedResponses(threats: SecurityThreat[], request: LLMRequest): Promise<void> {
    for (const threat of threats) {
      if (!threat.automatedResponse) continue;

      const response = threat.automatedResponse;

      switch (response.action) {
        case 'block':
          // Block the agent
          // TODO: Implement revokeAccess on AuthManager
          // await this.authManager.revokeAccess(request.agentDID, response.reason);
          await this.auditLogger.logSecurityAlert(
            request.agentDID,
            'access_blocked',
            { threat, response }
          );
          break;

        case 'throttle':
          // Apply rate limiting
          // TODO: Implement applyPenalty on RateLimiterManager
          // await this.rateLimiter.applyPenalty(request.agentDID, response.duration || 60000, response.reason);
          break;

        case 'alert':
          // Emit alert event
          this.emit('security_alert', {
            threat,
            request,
            response
          });
          break;

        case 'investigate':
          // Log for investigation
          await this.auditLogger.logSecurityAlert(
            request.agentDID,
            'investigation_required',
            { threat, response }
          );
          break;

        case 'quarantine':
          // Quarantine agent
          // TODO: Implement quarantineAgent on AuthManager
          // await this.authManager.quarantineAgent(request.agentDID, response.reason);
          break;
      }

      this.emit('automated_response_applied', {
        threat,
        response,
        agentDID: request.agentDID
      });
    }
  }

  /**
   * Evaluate rule against request
   */
  private evaluateRule(rule: SecurityRule, request: LLMRequest): boolean {
    // Simple rule evaluation - in production this would be more sophisticated
    try {
      // Parse condition (simplified)
      if (rule.condition.includes('priority:high') && 
          request.metadata?.priority !== RequestPriority.HIGH) {
        return false;
      }

      if (rule.condition.includes('type:function_call') && 
          request.type !== LLMRequestType.FUNCTION_CALL) {
        return false;
      }

      // Check exceptions
      if (rule.exceptions?.includes(request.agentDID)) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if request requires LLM evaluation
   */
  private requiresLLMEvaluation(request: LLMRequest): boolean {
    // Complex requests that benefit from LLM analysis
    return request.type === LLMRequestType.FUNCTION_CALL ||
           (request.functions?.length || 0) > 0 ||
           request.prompt.length > 1000;
  }

  /**
   * Evaluate policies with LLM
   */
  private async evaluatePoliciesWithLLM(
    request: LLMRequest,
    violations: Array<{ policy: SecurityPolicy; rule: SecurityRule }>
  ): Promise<{ recommendations: string[] }> {
    try {
      const prompt = `
Evaluate the security policy violations and provide recommendations:

REQUEST: ${JSON.stringify(request, null, 2)}

VIOLATIONS:
${violations.map(v => `- ${v.policy.name}: ${v.rule.condition}`).join('\n')}

Provide specific security recommendations.
      `;

      const llmRequest: LLMRequest = {
        id: `policy-eval-${Date.now()}`,
        type: LLMRequestType.FUNCTION_CALL,
        prompt,
        agentDID: 'security-analyzer',
        sessionId: `policy-${Date.now()}`,
        functions: [
          this.functionRegistry.getFunctionDefinition('evaluate_security_policy')!
        ],
        parameters: {
          temperature: 0.2,
          maxTokens: 500
        },
        metadata: {
          agentDID: 'security-analyzer',
          sessionId: `policy-${Date.now()}`,
          requestId: `policy-eval-${Date.now()}`,
          timestamp: new Date(),
          source: 'security-integration',
          priority: RequestPriority.HIGH
        }
      };

      const response = await this.messageRouter.routeMessage(llmRequest);
      
      if (response.functionCall) {
        const args = response.functionCall.arguments;
        return {
          recommendations: args.violations.map((v: any) => v.recommendation)
        };
      }

      return { recommendations: [] };

    } catch (error) {
      console.error('LLM policy evaluation failed:', error);
      return { recommendations: [] };
    }
  }

  /**
   * Map anomaly severity
   */
  private mapAnomalySeverity(severity: string): ThreatSeverity {
    switch (severity?.toLowerCase()) {
      case 'critical': return ThreatSeverity.CRITICAL;
      case 'high': return ThreatSeverity.HIGH;
      case 'medium': return ThreatSeverity.MEDIUM;
      default: return ThreatSeverity.LOW;
    }
  }

  /**
   * Load default security policies
   */
  private loadDefaultPolicies(): void {
    // High-risk function call policy
    this.addSecurityPolicy({
      id: 'high-risk-functions',
      name: 'High Risk Function Calls',
      description: 'Restrict access to high-risk functions',
      enabled: true,
      priority: 1,
      rules: [
        {
          condition: 'type:function_call AND functions:delete,drop,truncate',
          action: {
            action: 'block',
            reason: 'High-risk function call detected'
          }
        }
      ]
    });

    // Rate limiting policy
    this.addSecurityPolicy({
      id: 'rate-limiting',
      name: 'Excessive Request Rate',
      description: 'Prevent DoS attacks through rate limiting',
      enabled: true,
      priority: 2,
      rules: [
        {
          condition: 'rate:>100/minute',
          action: {
            action: 'throttle',
            duration: 60000,
            reason: 'Excessive request rate'
          }
        }
      ]
    });

    // Data access policy
    this.addSecurityPolicy({
      id: 'data-access',
      name: 'Sensitive Data Access',
      description: 'Monitor access to sensitive data',
      enabled: true,
      priority: 3,
      rules: [
        {
          condition: 'prompt:contains(password,secret,key,token)',
          action: {
            action: 'alert',
            reason: 'Potential sensitive data access'
          }
        }
      ]
    });
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    // Monitor auth events
    this.authManager.on('authentication_failed', (event) => {
      this.handleAuthenticationFailure(event);
    });

    this.authManager.on('authorization_denied', (event) => {
      this.handleAuthorizationDenial(event);
    });

    // Monitor rate limiter events
    this.rateLimiter.on('rate_limit_exceeded', (event) => {
      this.handleRateLimitExceeded(event);
    });

    // Monitor audit events
    this.auditLogger.on('suspicious_activity', (event) => {
      this.handleSuspiciousActivity(event);
    });
  }

  /**
   * Handle authentication failure
   */
  private async handleAuthenticationFailure(event: any): Promise<void> {
    const threat: SecurityThreat = {
      id: `auth-fail-${Date.now()}`,
      type: ThreatType.UNAUTHORIZED_ACCESS,
      severity: ThreatSeverity.MEDIUM,
      confidence: 0.9,
      timestamp: new Date(),
      source: 'auth-monitor',
      targetAgent: event.agentDID,
      description: 'Authentication failure detected',
      evidence: {
        attempts: event.attempts,
        method: event.method
      },
      recommendations: [
        'Monitor for brute force attempts',
        'Consider temporary account lock'
      ]
    };

    this.activeThreats.set(threat.id, threat);
    this.threatHistory.push(threat);
    this.emit('threat_detected', threat);
  }

  /**
   * Handle authorization denial
   */
  private async handleAuthorizationDenial(event: any): Promise<void> {
    // Check for privilege escalation attempts
    if (event.resource?.includes('admin') || event.action?.includes('delete')) {
      const threat: SecurityThreat = {
        id: `priv-esc-${Date.now()}`,
        type: ThreatType.PRIVILEGE_ESCALATION,
        severity: ThreatSeverity.HIGH,
        confidence: 0.8,
        timestamp: new Date(),
        source: 'auth-monitor',
        targetAgent: event.agentDID,
        description: 'Potential privilege escalation attempt',
        evidence: {
          resource: event.resource,
          action: event.action,
          denied: true
        },
        recommendations: [
          'Review agent permissions',
          'Check for compromised credentials'
        ]
      };

      this.activeThreats.set(threat.id, threat);
      this.threatHistory.push(threat);
      this.emit('threat_detected', threat);
    }
  }

  /**
   * Handle rate limit exceeded
   */
  private async handleRateLimitExceeded(event: any): Promise<void> {
    const threat: SecurityThreat = {
      id: `dos-${Date.now()}`,
      type: ThreatType.DENIAL_OF_SERVICE,
      severity: ThreatSeverity.HIGH,
      confidence: 0.9,
      timestamp: new Date(),
      source: 'rate-limiter',
      targetAgent: event.agentDID,
      description: 'Potential DoS attack - rate limit exceeded',
      evidence: {
        requests: event.requestCount,
        period: event.period,
        limit: event.limit
      },
      recommendations: [
        'Apply stricter rate limiting',
        'Investigate request patterns',
        'Consider blocking if pattern continues'
      ],
      automatedResponse: {
        action: 'throttle',
        duration: 300000, // 5 minutes
        reason: 'Rate limit exceeded - potential DoS'
      }
    };

    this.activeThreats.set(threat.id, threat);
    this.threatHistory.push(threat);
    this.emit('threat_detected', threat);

    // Apply automated response
    if (this.config.enableAutomatedResponse && threat.automatedResponse) {
      await this.applyAutomatedResponses([threat], {} as any);
    }
  }

  /**
   * Handle suspicious activity
   */
  private async handleSuspiciousActivity(event: any): Promise<void> {
    // Analyze the suspicious activity with LLM
    await this.analyzeAgentBehavior(
      event.agentDID,
      event.activities,
      event.baseline
    );
  }

  /**
   * Clean old threats
   */
  private cleanOldThreats(): void {
    const cutoff = Date.now() - this.config.threatRetentionPeriod;
    
    // Clean active threats
    for (const [id, threat] of this.activeThreats) {
      if (threat.timestamp.getTime() < cutoff) {
        this.activeThreats.delete(id);
      }
    }

    // Clean threat history
    this.threatHistory = this.threatHistory.filter(
      t => t.timestamp.getTime() > cutoff
    );
  }

  /**
   * Get threat statistics
   */
  getStatistics(): {
    totalThreats: number;
    activeThreats: number;
    threatsBySeverity: Record<ThreatSeverity, number>;
    threatsByType: Record<ThreatType, number>;
    automatedResponses: number;
    averageConfidence: number;
  } {
    const stats = {
      totalThreats: this.threatHistory.length,
      activeThreats: this.activeThreats.size,
      threatsBySeverity: {
        [ThreatSeverity.LOW]: 0,
        [ThreatSeverity.MEDIUM]: 0,
        [ThreatSeverity.HIGH]: 0,
        [ThreatSeverity.CRITICAL]: 0
      },
      threatsByType: {
        [ThreatType.UNAUTHORIZED_ACCESS]: 0,
        [ThreatType.DATA_EXFILTRATION]: 0,
        [ThreatType.PRIVILEGE_ESCALATION]: 0,
        [ThreatType.INJECTION_ATTACK]: 0,
        [ThreatType.DENIAL_OF_SERVICE]: 0,
        [ThreatType.ANOMALOUS_BEHAVIOR]: 0,
        [ThreatType.POLICY_VIOLATION]: 0,
        [ThreatType.SUSPICIOUS_PATTERN]: 0
      },
      automatedResponses: 0,
      averageConfidence: 0
    };

    let totalConfidence = 0;

    for (const threat of this.threatHistory) {
      stats.threatsBySeverity[threat.severity]++;
      stats.threatsByType[threat.type]++;
      totalConfidence += threat.confidence;
      
      if (threat.automatedResponse) {
        stats.automatedResponses++;
      }
    }

    stats.averageConfidence = this.threatHistory.length > 0 
      ? totalConfidence / this.threatHistory.length 
      : 0;

    return stats;
  }

  /**
   * Export threat report
   */
  exportThreatReport(format: 'json' | 'csv' = 'json'): string {
    const threats = Array.from(this.activeThreats.values());
    
    if (format === 'json') {
      return JSON.stringify({
        generated: new Date(),
        activeThreats: threats,
        statistics: this.getStatistics(),
        policies: Array.from(this.securityPolicies.values())
      }, null, 2);
    } else {
      // CSV format
      const headers = ['ID', 'Type', 'Severity', 'Confidence', 'Timestamp', 'Agent', 'Description'];
      const rows = [headers.join(',')];
      
      for (const threat of threats) {
        rows.push([
          threat.id,
          threat.type,
          threat.severity,
          threat.confidence.toFixed(2),
          threat.timestamp.toISOString(),
          threat.targetAgent || 'N/A',
          `"${threat.description.replace(/"/g, '""')}"`
        ].join(','));
      }
      
      return rows.join('\n');
    }
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    this.analysisInProgress.clear();
    this.activeThreats.clear();
    this.securityPolicies.clear();
    this.threatHistory = [];
    this.removeAllListeners();
  }
}

export default MCPSecurityIntegration;