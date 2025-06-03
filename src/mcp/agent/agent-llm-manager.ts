/**
 * Agent-LLM Communication Manager
 * 
 * Manages all LLM interactions for agents with security, context management, and routing
 */

import { EventEmitter } from 'events';
import {
  LLMRequest,
  LLMResponse,
  LLMRequestType,
  ConversationContext,
  FunctionDefinition,
  FunctionCall,
  RequestPriority,
  MCPError,
  MCPErrorCode
} from '../types';
import { MCPClient } from '../client';
import { UnifiedLLMInterface } from '../interface';
import { AuthManager } from '../security/auth-manager';
import { AuditLogger } from '../security/audit-logger';
import { RateLimiterManager } from '../security/rate-limiter';
import { AgentIdentity } from '../../agent/types';
import { DelegationManager } from '../../agent/delegation-manager';
import { DelegationPolicyEngine } from '../../agent/delegation-policy-engine';

/**
 * Agent context for LLM interactions
 */
export interface AgentLLMContext {
  agentDID: string;
  agentName: string;
  agentDescription?: string;
  parentDID?: string;
  scopes: string[];
  delegationDepth: number;
  maxDelegationDepth: number;
  activeServices: string[];
  metadata?: Record<string, any>;
}

/**
 * LLM interaction options
 */
export interface LLMInteractionOptions {
  priority?: RequestPriority;
  timeout?: number;
  maxRetries?: number;
  includeContext?: boolean;
  providerId?: string;
  temperature?: number;
  maxTokens?: number;
  systemPrompt?: string;
}

/**
 * Delegation decision result
 */
export interface DelegationDecision {
  decision: 'approve' | 'deny' | 'request_more_info';
  reason: string;
  suggestedScopes?: string[];
  suggestedConstraints?: any;
  confidence: number;
  warnings?: string[];
}

/**
 * Policy interpretation result
 */
export interface PolicyInterpretation {
  summary: string;
  requirements: string[];
  restrictions: string[];
  recommendations: string[];
  riskLevel: 'low' | 'medium' | 'high';
}

/**
 * Agent LLM Manager
 */
export class AgentLLMManager extends EventEmitter {
  private llmInterface: UnifiedLLMInterface;
  private sessionMap: Map<string, string> = new Map(); // agentDID -> sessionId
  private contextCache: Map<string, AgentLLMContext> = new Map();
  private functionHandlers: Map<string, (args: any) => Promise<any>> = new Map();

  constructor(
    private mcpClient: MCPClient,
    private authManager: AuthManager,
    private auditLogger: AuditLogger,
    private rateLimiter: RateLimiterManager,
    private delegationManager?: DelegationManager,
    private policyEngine?: DelegationPolicyEngine
  ) {
    super();
    this.llmInterface = new UnifiedLLMInterface(mcpClient);
    this.initializeDefaultFunctions();
    this.setupEventHandlers();
  }

  /**
   * Process natural language request from agent
   */
  async processNaturalLanguageRequest(
    agentDID: string,
    request: string,
    options: LLMInteractionOptions = {}
  ): Promise<LLMResponse> {
    try {
      // Get or create session
      const sessionId = await this.getOrCreateSession(agentDID);
      
      // Check authentication
      const authResult = await this.authManager.authorize(
        agentDID,
        'llm:request',
        'completion'
      );
      
      if (!authResult.authorized) {
        throw new MCPError({
          code: MCPErrorCode.FORBIDDEN,
          message: `Authorization denied: ${authResult.deniedReasons?.join(', ')}`,
          timestamp: new Date(),
          retryable: false
        });
      }

      // Build context-aware prompt
      const prompt = await this.buildContextAwarePrompt(agentDID, request, options);
      
      // Check rate limits
      const rateLimitResult = await this.rateLimiter.checkRateLimit({
        id: `${agentDID}-${Date.now()}`,
        type: LLMRequestType.COMPLETION,
        prompt,
        agentDID,
        sessionId,
        metadata: {
          agentDID,
          sessionId,
          requestId: `req-${Date.now()}`,
          timestamp: new Date(),
          source: 'agent-llm-manager',
          priority: options.priority || RequestPriority.MEDIUM
        }
      } as LLMRequest);

      if (!rateLimitResult.allowed) {
        throw new MCPError({
          code: MCPErrorCode.RATE_LIMITED,
          message: rateLimitResult.reason || 'Rate limit exceeded',
          timestamp: new Date(),
          retryable: true,
          details: {
            retryAfter: rateLimitResult.retryAfter,
            resetAt: rateLimitResult.resetAt
          }
        });
      }

      // Log request
      const auditId = await this.auditLogger.logRequest(
        {
          id: `req-${Date.now()}`,
          type: LLMRequestType.COMPLETION,
          prompt,
          agentDID,
          sessionId,
          metadata: {
            agentDID,
            sessionId,
            requestId: `req-${Date.now()}`,
            timestamp: new Date(),
            source: 'agent-llm-manager',
            priority: options.priority || RequestPriority.MEDIUM
          }
        } as LLMRequest,
        agentDID,
        sessionId
      );

      // Send request to LLM
      const startTime = Date.now();
      const response = await this.llmInterface.completion(
        agentDID,
        sessionId,
        prompt,
        {
          parameters: {
            temperature: options.temperature,
            maxTokens: options.maxTokens
          },
          providerId: options.providerId,
          priority: options.priority
        }
      );

      // Log response
      await this.auditLogger.logResponse(
        response,
        {
          id: auditId,
          type: LLMRequestType.COMPLETION,
          prompt,
          agentDID,
          sessionId,
          metadata: {
            agentDID,
            sessionId,
            requestId: auditId,
            timestamp: new Date(),
            source: 'agent-llm-manager'
          }
        } as LLMRequest,
        Date.now() - startTime
      );

      // Record usage for quotas
      if (response.usage) {
        await this.rateLimiter.recordUsage(
          agentDID,
          response.usage,
          response.provider,
          response.model
        );
      }

      this.emit('request_completed', {
        agentDID,
        request,
        response,
        duration: Date.now() - startTime
      });

      return response;

    } catch (error) {
      this.emit('request_error', {
        agentDID,
        request,
        error
      });
      throw error;
    }
  }

  /**
   * Process delegation decision request
   */
  async processDelegationDecision(
    parentAgentDID: string,
    delegationRequest: {
      targetAgentDID: string;
      requestedScopes: string[];
      purpose: string;
      duration?: number;
      constraints?: any;
    },
    options: LLMInteractionOptions = {}
  ): Promise<DelegationDecision> {
    const context = await this.getAgentContext(parentAgentDID);
    
    // Build delegation analysis prompt
    const prompt = this.buildDelegationPrompt(context, delegationRequest);
    
    // Define function for structured decision
    const decisionFunction: FunctionDefinition = {
      name: 'make_delegation_decision',
      description: 'Make a decision about the delegation request',
      parameters: {
        type: 'object',
        properties: {
          decision: {
            type: 'string',
            enum: ['approve', 'deny', 'request_more_info'],
            description: 'The delegation decision'
          },
          reason: {
            type: 'string',
            description: 'Detailed reason for the decision'
          },
          suggestedScopes: {
            type: 'array',
            items: { type: 'string' },
            description: 'Suggested scopes if different from requested'
          },
          suggestedConstraints: {
            type: 'object',
            description: 'Additional constraints to apply'
          },
          confidence: {
            type: 'number',
            minimum: 0,
            maximum: 1,
            description: 'Confidence level in the decision'
          },
          warnings: {
            type: 'array',
            items: { type: 'string' },
            description: 'Any warnings or concerns'
          }
        },
        required: ['decision', 'reason', 'confidence']
      }
    };

    const sessionId = await this.getOrCreateSession(parentAgentDID);
    
    try {
      const { response, functionCalls } = await this.llmInterface.functionCall(
        parentAgentDID,
        sessionId,
        prompt,
        [decisionFunction],
        {
          parameters: {
            temperature: 0.3, // Lower temperature for more consistent decisions
            maxTokens: options.maxTokens || 500
          },
          providerId: options.providerId,
          priority: options.priority || RequestPriority.HIGH
        }
      );

      if (functionCalls.length > 0) {
        const decision = functionCalls[0].arguments as DelegationDecision;
        
        // Log the delegation decision
        await this.auditLogger.logAuthorization(
          parentAgentDID,
          `delegation:${delegationRequest.targetAgentDID}`,
          'delegate',
          decision.decision === 'approve',
          decision.warnings
        );

        return decision;
      }

      // Fallback if no function call
      return {
        decision: 'deny',
        reason: 'Unable to process delegation request',
        confidence: 0,
        warnings: ['LLM did not provide structured decision']
      };

    } catch (error) {
      this.emit('delegation_error', {
        parentAgentDID,
        delegationRequest,
        error
      });
      
      // Conservative fallback
      return {
        decision: 'deny',
        reason: `Error processing delegation: ${(error as Error).message}`,
        confidence: 0,
        warnings: ['Error occurred during decision making']
      };
    }
  }

  /**
   * Interpret policy using LLM
   */
  async interpretPolicy(
    agentDID: string,
    policy: any,
    context: string,
    options: LLMInteractionOptions = {}
  ): Promise<PolicyInterpretation> {
    const prompt = `
Analyze the following policy and provide an interpretation in the context of: ${context}

Policy:
${JSON.stringify(policy, null, 2)}

Provide a clear interpretation including:
1. A summary of what the policy allows and restricts
2. Specific requirements that must be met
3. Key restrictions to be aware of
4. Recommendations for compliance
5. Risk level assessment
    `;

    const sessionId = await this.getOrCreateSession(agentDID);
    
    const interpretFunction: FunctionDefinition = {
      name: 'interpret_policy',
      description: 'Provide structured policy interpretation',
      parameters: {
        type: 'object',
        properties: {
          summary: {
            type: 'string',
            description: 'Brief summary of the policy'
          },
          requirements: {
            type: 'array',
            items: { type: 'string' },
            description: 'List of requirements'
          },
          restrictions: {
            type: 'array',
            items: { type: 'string' },
            description: 'List of restrictions'
          },
          recommendations: {
            type: 'array',
            items: { type: 'string' },
            description: 'Compliance recommendations'
          },
          riskLevel: {
            type: 'string',
            enum: ['low', 'medium', 'high'],
            description: 'Overall risk level'
          }
        },
        required: ['summary', 'requirements', 'restrictions', 'recommendations', 'riskLevel']
      }
    };

    try {
      const { response, functionCalls } = await this.llmInterface.functionCall(
        agentDID,
        sessionId,
        prompt,
        [interpretFunction],
        {
          parameters: {
            temperature: 0.3,
            maxTokens: options.maxTokens || 800
          },
          providerId: options.providerId
        }
      );

      if (functionCalls.length > 0) {
        return functionCalls[0].arguments as PolicyInterpretation;
      }

      // Parse from text response if no function call
      return this.parseUnstructuredPolicyInterpretation(response.content || '');

    } catch (error) {
      this.emit('policy_interpretation_error', {
        agentDID,
        policy,
        error
      });
      
      throw error;
    }
  }

  /**
   * Get scope recommendations based on request
   */
  async getScopeRecommendations(
    agentDID: string,
    purpose: string,
    currentScopes: string[],
    availableScopes: string[],
    options: LLMInteractionOptions = {}
  ): Promise<{
    recommendedScopes: string[];
    reasoning: string;
    alternatives?: string[][];
  }> {
    const prompt = `
Given the following context:
- Purpose: ${purpose}
- Current scopes: ${currentScopes.join(', ') || 'none'}
- Available scopes: ${availableScopes.join(', ')}

Recommend the minimal set of scopes needed to accomplish the purpose while maintaining security.
Consider the principle of least privilege.
    `;

    const sessionId = await this.getOrCreateSession(agentDID);
    
    const recommendFunction: FunctionDefinition = {
      name: 'recommend_scopes',
      description: 'Recommend optimal scopes for the purpose',
      parameters: {
        type: 'object',
        properties: {
          recommendedScopes: {
            type: 'array',
            items: { type: 'string' },
            description: 'Recommended minimal scopes'
          },
          reasoning: {
            type: 'string',
            description: 'Explanation for the recommendations'
          },
          alternatives: {
            type: 'array',
            items: {
              type: 'array',
              items: { type: 'string' }
            },
            description: 'Alternative scope combinations if any'
          }
        },
        required: ['recommendedScopes', 'reasoning']
      }
    };

    try {
      const { response, functionCalls } = await this.llmInterface.functionCall(
        agentDID,
        sessionId,
        prompt,
        [recommendFunction],
        {
          parameters: {
            temperature: 0.4,
            maxTokens: options.maxTokens || 600
          },
          providerId: options.providerId
        }
      );

      if (functionCalls.length > 0) {
        const args = functionCalls[0].arguments;
        return {
          recommendedScopes: args.recommendedScopes || currentScopes,
          reasoning: args.reasoning || 'LLM provided recommendation',
          alternatives: args.alternatives
        };
      }

      // Fallback to current scopes
      return {
        recommendedScopes: currentScopes,
        reasoning: 'Unable to generate recommendations, maintaining current scopes'
      };

    } catch (error) {
      this.emit('scope_recommendation_error', {
        agentDID,
        purpose,
        error
      });
      
      throw error;
    }
  }

  /**
   * Register function handler for LLM function calls
   */
  registerFunctionHandler(
    name: string,
    handler: (args: any) => Promise<any>,
    definition: FunctionDefinition
  ): void {
    this.functionHandlers.set(name, handler);
    
    // Store definition for future use
    (this as any)[`${name}_definition`] = definition;
  }

  /**
   * Execute function call from LLM
   */
  async executeFunctionCall(functionCall: FunctionCall): Promise<any> {
    const handler = this.functionHandlers.get(functionCall.name);
    
    if (!handler) {
      throw new MCPError({
        code: MCPErrorCode.FUNCTION_NOT_FOUND,
        message: `No handler registered for function: ${functionCall.name}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    try {
      const result = await handler(functionCall.arguments);
      
      this.emit('function_executed', {
        functionName: functionCall.name,
        arguments: functionCall.arguments,
        result
      });

      return result;
    } catch (error) {
      this.emit('function_error', {
        functionName: functionCall.name,
        arguments: functionCall.arguments,
        error
      });
      
      throw error;
    }
  }

  /**
   * Get or create agent context
   */
  private async getAgentContext(agentDID: string): Promise<AgentLLMContext> {
    // Check cache first
    const cached = this.contextCache.get(agentDID);
    if (cached) {
      return cached;
    }

    // Build context from agent identity
    // This would integrate with the actual agent identity system
    const context: AgentLLMContext = {
      agentDID,
      agentName: agentDID.split(':').pop() || 'Unknown Agent',
      scopes: [],
      delegationDepth: 0,
      maxDelegationDepth: 3,
      activeServices: []
    };

    this.contextCache.set(agentDID, context);
    return context;
  }

  /**
   * Build context-aware prompt
   */
  private async buildContextAwarePrompt(
    agentDID: string,
    request: string,
    options: LLMInteractionOptions
  ): Promise<string> {
    const context = await this.getAgentContext(agentDID);
    
    let prompt = '';
    
    // Add system prompt if provided
    if (options.systemPrompt) {
      prompt += `System: ${options.systemPrompt}\n\n`;
    }
    
    // Add context if requested
    if (options.includeContext !== false) {
      prompt += `Context:\n`;
      prompt += `- Agent: ${context.agentName} (${context.agentDID})\n`;
      prompt += `- Scopes: ${context.scopes.join(', ') || 'none'}\n`;
      prompt += `- Delegation Level: ${context.delegationDepth}/${context.maxDelegationDepth}\n`;
      if (context.parentDID) {
        prompt += `- Parent Agent: ${context.parentDID}\n`;
      }
      prompt += `\n`;
    }
    
    // Add the actual request
    prompt += `Request: ${request}`;
    
    return prompt;
  }

  /**
   * Build delegation analysis prompt
   */
  private buildDelegationPrompt(
    parentContext: AgentLLMContext,
    delegationRequest: any
  ): string {
    return `
As an AI governance system, analyze the following delegation request:

Parent Agent Context:
- DID: ${parentContext.agentDID}
- Name: ${parentContext.agentName}
- Current Scopes: ${parentContext.scopes.join(', ')}
- Delegation Depth: ${parentContext.delegationDepth}/${parentContext.maxDelegationDepth}

Delegation Request:
- Target Agent: ${delegationRequest.targetAgentDID}
- Purpose: ${delegationRequest.purpose}
- Requested Scopes: ${delegationRequest.requestedScopes.join(', ')}
- Duration: ${delegationRequest.duration ? `${delegationRequest.duration}ms` : 'indefinite'}
- Constraints: ${JSON.stringify(delegationRequest.constraints || {}, null, 2)}

Consider:
1. Is the parent agent authorized to delegate these scopes?
2. Are the requested scopes appropriate for the stated purpose?
3. Would this delegation create security risks?
4. Is the delegation depth limit respected?
5. Are there any scope reductions that should be applied?

Make a decision and provide detailed reasoning.
    `;
  }

  /**
   * Parse unstructured policy interpretation
   */
  private parseUnstructuredPolicyInterpretation(text: string): PolicyInterpretation {
    // Simple parsing logic - in production would use more sophisticated NLP
    const lines = text.split('\n').filter(line => line.trim());
    
    return {
      summary: lines[0] || 'Unable to parse policy interpretation',
      requirements: lines.filter(line => line.includes('require') || line.includes('must')),
      restrictions: lines.filter(line => line.includes('restrict') || line.includes('cannot')),
      recommendations: lines.filter(line => line.includes('recommend') || line.includes('should')),
      riskLevel: text.toLowerCase().includes('high risk') ? 'high' : 
                 text.toLowerCase().includes('medium risk') ? 'medium' : 'low'
    };
  }

  /**
   * Get or create session for agent
   */
  private async getOrCreateSession(agentDID: string): Promise<string> {
    let sessionId = this.sessionMap.get(agentDID);
    
    if (!sessionId) {
      sessionId = `session-${agentDID}-${Date.now()}`;
      this.sessionMap.set(agentDID, sessionId);
      
      // Get authentication token for the agent
      const authResult = await this.authManager.authenticate(
        agentDID,
        { apiKey: 'agent-internal-key' }, // In production, use proper credentials
        'api_key' as any
      );
      
      if (authResult.authenticated && authResult.token) {
        await this.authManager.createSession(authResult.token);
      }
    }
    
    return sessionId;
  }

  /**
   * Initialize default function handlers
   */
  private initializeDefaultFunctions(): void {
    // Register delegation evaluation function
    this.registerFunctionHandler(
      'evaluate_delegation',
      async (args: any) => {
        if (this.delegationManager && this.policyEngine) {
          const policy = await this.policyEngine.evaluatePolicy(args);
          return {
            allowed: policy.allowed,
            violations: policy.violations,
            warnings: policy.warnings
          };
        }
        return { allowed: true, violations: [], warnings: [] };
      },
      {
        name: 'evaluate_delegation',
        description: 'Evaluate a delegation request against policies',
        parameters: {
          type: 'object',
          properties: {
            parentDID: { type: 'string', description: 'Parent agent DID for delegation' },
            targetDID: { type: 'string', description: 'Target agent DID to delegate to' },
            scopes: {
              type: 'array',
              description: 'Array of scopes to delegate',
              items: { type: 'string' }
            }
          },
          required: ['parentDID', 'targetDID', 'scopes']
        }
      }
    );

    // Register scope validation function
    this.registerFunctionHandler(
      'validate_scopes',
      async (args: any) => {
        const { scopes, availableScopes } = args;
        const validScopes = scopes.filter((scope: string) => 
          availableScopes.includes(scope)
        );
        return {
          valid: validScopes.length === scopes.length,
          validScopes,
          invalidScopes: scopes.filter((scope: string) => 
            !availableScopes.includes(scope)
          )
        };
      },
      {
        name: 'validate_scopes',
        description: 'Validate requested scopes against available scopes',
        parameters: {
          type: 'object',
          properties: {
            scopes: {
              type: 'array',
              description: 'Requested scopes to validate',
              items: { type: 'string' }
            },
            availableScopes: {
              type: 'array',
              description: 'Available scopes for validation',
              items: { type: 'string' }
            }
          },
          required: ['scopes', 'availableScopes']
        }
      }
    );
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    // Forward LLM interface events
    this.llmInterface.on('completion', (event) => {
      this.emit('llm_completion', event);
    });

    this.llmInterface.on('function_call', (event) => {
      this.emit('llm_function_call', event);
    });

    this.llmInterface.on('error', (event) => {
      this.emit('llm_error', event);
    });

    // Handle provider events
    this.llmInterface.on('provider_connected', (providerId) => {
      this.emit('provider_connected', providerId);
    });

    this.llmInterface.on('provider_disconnected', (providerId) => {
      this.emit('provider_disconnected', providerId);
    });
  }

  /**
   * Clear agent session
   */
  clearAgentSession(agentDID: string): void {
    const sessionId = this.sessionMap.get(agentDID);
    if (sessionId) {
      this.llmInterface.clearContext(agentDID, sessionId);
      this.sessionMap.delete(agentDID);
    }
    this.contextCache.delete(agentDID);
  }

  /**
   * Get usage statistics for agent
   */
  async getAgentUsageStats(agentDID: string): Promise<any> {
    const sessionId = this.sessionMap.get(agentDID);
    if (!sessionId) {
      return { error: 'No active session for agent' };
    }

    const context = this.llmInterface.getContext(agentDID, sessionId);
    const quotaStatuses = await this.rateLimiter.getAgentQuotaStatuses(agentDID);
    
    return {
      sessionId,
      conversationLength: context.history.length,
      totalTokens: context.tokens,
      quotas: quotaStatuses,
      lastActivity: context.lastUpdated
    };
  }

  /**
   * Shutdown manager
   */
  shutdown(): void {
    // Clear all sessions
    for (const [agentDID, sessionId] of this.sessionMap.entries()) {
      this.llmInterface.clearContext(agentDID, sessionId);
    }
    
    this.sessionMap.clear();
    this.contextCache.clear();
    this.functionHandlers.clear();
    
    this.removeAllListeners();
  }
}

export default AgentLLMManager;