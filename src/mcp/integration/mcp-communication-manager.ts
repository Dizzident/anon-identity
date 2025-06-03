/**
 * MCP-Enabled Communication Manager
 * 
 * Extends the existing CommunicationManager to leverage MCP for all LLM interactions
 */

import {
  CommunicationManager,
  CommunicationManagerOptions
} from '../../agent/communication/communication-manager';
import {
  AgentMessage,
  AgentMessageType,
  MessageEnvelope,
  MessageHandlerContext
} from '../../agent/communication/types';
import { AgentIdentity } from '../../agent/types';
import { AgentIdentityManager } from '../../agent/agent-identity';
import { DelegationManager } from '../../agent/delegation-manager';
import { DelegationPolicyEngine } from '../../agent/delegation-policy-engine';
import { ActivityLogger } from '../../agent/activity/activity-logger';

// MCP imports
import { MCPClient } from '../client';
import { AgentLLMManager } from '../agent/agent-llm-manager';
import { LLMDelegationEngine } from '../delegation/llm-delegation-engine';
import { DelegationIntegration } from '../delegation/delegation-integration';
import { AgentMatcher } from '../matching/agent-matcher';
import { ProviderSelector } from '../providers/provider-selector';
import { StreamManager } from '../streaming/stream-manager';
import { ContextManager } from '../context/context-manager';
import { MessageRouter } from '../routing/message-router';
import { AuthManager } from '../security/auth-manager';
import { AuditLogger } from '../security/audit-logger';
import { RateLimiterManager } from '../security/rate-limiter';
import { CredentialManager } from '../security/credential-manager';

// Types
import {
  LLMRequest,
  LLMResponse,
  LLMRequestType,
  RequestPriority,
  ConversationContext,
  ContextPriority,
  SelectionStrategy,
  StreamSession,
  AgentCapabilityProfile,
  TaskDescription,
  MCPError,
  MCPErrorCode,
  AuditExportFormat
} from '../types';

/**
 * MCP-enabled communication manager options
 */
export interface MCPCommunicationManagerOptions extends CommunicationManagerOptions {
  mcpClient: MCPClient;
  llmIntegration?: {
    enableNaturalLanguage?: boolean;
    enablePolicyEvaluation?: boolean;
    enableAgentMatching?: boolean;
    enableStreaming?: boolean;
    defaultProvider?: string;
    defaultModel?: string;
  };
  contextSettings?: {
    maxTokensPerContext?: number;
    compressionStrategy?: 'summary' | 'sliding-window' | 'importance';
    shareContextBetweenAgents?: boolean;
  };
}

/**
 * MCP-Enabled Communication Manager
 */
export class MCPEnabledCommunicationManager extends CommunicationManager {
  private llmManager: AgentLLMManager;
  private delegationEngine: LLMDelegationEngine;
  private delegationIntegration: DelegationIntegration;
  private agentMatcher: AgentMatcher;
  private providerSelector?: ProviderSelector;
  private streamManager: StreamManager;
  private contextManager: ContextManager;
  private messageRouter: MessageRouter;
  private mcpAuditLogger: AuditLogger;
  private conversationContexts: Map<string, ConversationContext> = new Map();
  protected mcpAgentIdentity: AgentIdentity;

  constructor(
    agentIdentity: AgentIdentity,
    agentManager: AgentIdentityManager,
    delegationManager: DelegationManager,
    policyEngine: DelegationPolicyEngine,
    activityLogger: ActivityLogger,
    private mcpOptions: MCPCommunicationManagerOptions,
    authManager: AuthManager,
    rateLimiter: RateLimiterManager,
    credentialManager: CredentialManager
  ) {
    super(
      agentIdentity,
      agentManager,
      delegationManager,
      policyEngine,
      activityLogger,
      mcpOptions
    );

    // Store agent identity for MCP operations
    this.mcpAgentIdentity = agentIdentity;

    // Initialize MCP components
    this.mcpAuditLogger = new AuditLogger({
      enabled: true,
      logAllRequests: true,
      logResponses: true,
      logSensitiveData: false,
      retentionPeriod: 86400000 * 30,
      exportFormat: [AuditExportFormat.JSON]
    });

    this.messageRouter = new MessageRouter(
      mcpOptions.mcpClient,
      authManager,
      this.mcpAuditLogger,
      rateLimiter,
      credentialManager
    );

    this.contextManager = new ContextManager({
      maxTokensPerContext: mcpOptions.contextSettings?.maxTokensPerContext || 4000,
      compressionThreshold: 0.8,
      compressionStrategy: mcpOptions.contextSettings?.compressionStrategy || 'importance',
      retentionCheckInterval: 3600000,
      sharing: {
        allowSharing: mcpOptions.contextSettings?.shareContextBetweenAgents ?? true,
        requireConsent: true,
        maxShareDepth: 2,
        shareableFields: ['domain', 'purpose', 'summary']
      },
      archiveAfterDays: 30
    });

    this.llmManager = new AgentLLMManager(
      mcpOptions.mcpClient,
      authManager,
      this.mcpAuditLogger,
      rateLimiter
    );

    this.delegationEngine = new LLMDelegationEngine(
      this.messageRouter,
      authManager,
      this.mcpAuditLogger
    );

    this.delegationIntegration = new DelegationIntegration(
      this.delegationEngine,
      this.messageRouter,
      null as any, // Will be initialized separately
      authManager,
      this.mcpAuditLogger
    );

    this.agentMatcher = new AgentMatcher(
      this.messageRouter,
      authManager,
      this.mcpAuditLogger
    );

    // Initialize provider selector if providers are configured
    const availableProviders = mcpOptions.mcpClient.getAvailableProviders();
    if (availableProviders.length > 0) {
      // Convert provider IDs to provider objects
      const providers = new Map<string, any>();
      availableProviders.forEach(id => {
        const provider = mcpOptions.mcpClient.getProvider(id);
        if (provider) {
          providers.set(id, provider);
        }
      });
      this.providerSelector = new ProviderSelector(providers);
    }

    this.streamManager = new StreamManager(
      this.messageRouter,
      authManager,
      this.mcpAuditLogger
    );
  }

  /**
   * Process a natural language message
   */
  async processNaturalLanguageMessage(
    message: string,
    targetAgent?: string,
    options?: {
      streaming?: boolean;
      priority?: RequestPriority;
      onChunk?: (chunk: string) => void;
    }
  ): Promise<MessageEnvelope> {
    if (!this.mcpOptions.llmIntegration?.enableNaturalLanguage) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Natural language processing is not enabled',
        timestamp: new Date(),
        retryable: false
      });
    }

    try {
      // Get or create conversation context
      const context = await this.getOrCreateContext(this.mcpAgentIdentity.did);

      // Build LLM request
      const request: LLMRequest = {
        id: `nl-msg-${Date.now()}`,
        type: LLMRequestType.COMPLETION,
        prompt: this.buildNaturalLanguagePrompt(message, targetAgent),
        agentDID: this.mcpAgentIdentity.did,
        sessionId: context.sessionId,
        streaming: options?.streaming,
        metadata: {
          agentDID: this.mcpAgentIdentity.did,
          sessionId: context.sessionId,
          requestId: `nl-msg-${Date.now()}`,
          timestamp: new Date(),
          source: 'mcp-communication-manager',
          priority: options?.priority || RequestPriority.MEDIUM,
          purpose: 'natural-language-message'
        }
      };

      let response: LLMResponse;

      if (options?.streaming && this.mcpOptions.llmIntegration?.enableStreaming) {
        // Use streaming for real-time interaction
        const streamSession = await this.streamManager.startStream(request, {
          priority: options.priority === RequestPriority.HIGH ? 'high' : 'medium',
          onChunk: (chunk) => {
            if (options.onChunk && chunk.delta) {
              options.onChunk(chunk.delta);
            }
          },
          onComplete: (resp) => {
            response = resp;
          }
        });

        // Wait for streaming to complete
        await new Promise<void>((resolve) => {
          const checkInterval = setInterval(() => {
            if (response || streamSession.status !== 'active') {
              clearInterval(checkInterval);
              resolve();
            }
          }, 100);
        });
      } else {
        // Standard request-response
        response = await this.messageRouter.routeMessage(request);
      }

      // Parse LLM response into agent message
      const agentMessage = this.parseNaturalLanguageResponse(response!, targetAgent);

      // Update context
      await this.contextManager.addMessage(context.conversationId, {
        role: 'user' as any,
        content: message
      });

      await this.contextManager.addMessage(context.conversationId, {
        role: 'assistant' as any,
        content: response!.content || ''
      });

      // Log activity
      await this.logLLMActivity('natural-language-message', request, response!);

      // Create message envelope for return
      const envelope: MessageEnvelope = {
        message: agentMessage,
        routingInfo: {
          path: [this.mcpAgentIdentity.did, targetAgent || 'broadcast'],
          ttl: 300000
        }
      };

      return envelope;

    } catch (error) {
      console.error('Failed to process natural language message:', error);
      throw error;
    }
  }

  /**
   * Evaluate delegation request using LLM
   */
  async evaluateDelegationWithLLM(
    requestingAgent: string,
    targetAgent: string,
    requestedScopes: string[],
    purpose: string,
    duration?: number
  ): Promise<{
    decision: 'approve' | 'deny' | 'approve_with_modifications' | 'request_more_info';
    confidence: number;
    reasoning: string;
    suggestedScopes?: string[];
    warnings: string[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  }> {
    if (!this.mcpOptions.llmIntegration?.enablePolicyEvaluation) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'LLM policy evaluation is not enabled',
        timestamp: new Date(),
        retryable: false
      });
    }

    try {
      // Build delegation request
      const delegationRequest = {
        requestId: `del-eval-${Date.now()}`,
        parentAgentDID: this.mcpAgentIdentity.did,
        targetAgentDID: targetAgent,
        requestedScopes,
        purpose,
        context: `Agent ${requestingAgent} is requesting delegation to ${targetAgent}`,
        duration: duration || 24 * 60 * 60 * 1000, // Default 24 hours
        urgency: 'medium' as const,
        requestedAt: new Date()
      };

      // Build decision context
      const decisionContext = await this.buildDecisionContext(requestingAgent, targetAgent);

      // Use delegation engine for decision
      const decision = await this.delegationEngine.makeDelegationDecision(
        delegationRequest,
        decisionContext
      );

      // Log the decision
      await this.logLLMActivity('delegation-evaluation', delegationRequest as any, decision as any);

      return {
        decision: decision.decision,
        confidence: decision.confidence,
        reasoning: decision.reasoning,
        suggestedScopes: decision.suggestedScopes,
        warnings: decision.warnings,
        riskLevel: decision.riskAssessment.level
      };

    } catch (error) {
      console.error('Failed to evaluate delegation with LLM:', error);
      throw error;
    }
  }

  /**
   * Find matching agents for a task
   */
  async findAgentsForTask(
    taskDescription: string,
    requiredCapabilities: string[],
    options?: {
      maxResults?: number;
      minTrustLevel?: number;
      urgency?: 'low' | 'medium' | 'high' | 'critical';
    }
  ): Promise<Array<{
    agent: AgentCapabilityProfile;
    score: number;
    confidence: number;
    reasoning: string;
  }>> {
    if (!this.mcpOptions.llmIntegration?.enableAgentMatching) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Agent matching is not enabled',
        timestamp: new Date(),
        retryable: false
      });
    }

    try {
      // Create task description
      const task: TaskDescription = {
        id: `task-${Date.now()}`,
        title: taskDescription.substring(0, 100),
        description: taskDescription,
        requiredCapabilities,
        priority: options?.urgency || 'medium',
        constraints: {
          minTrustLevel: options?.minTrustLevel
        },
        context: {
          domain: 'general',
          urgency: options?.urgency === 'high' || options?.urgency === 'critical',
          complexity: 'moderate',
          estimatedDuration: 3600000 // 1 hour default
        }
      };

      // Find matches
      const matches = await this.agentMatcher.findMatches(task);

      // Log activity
      await this.logLLMActivity('agent-matching', task as any, { matches } as any);

      // Return top results
      return matches.slice(0, options?.maxResults || 5).map(match => ({
        agent: match.agent,
        score: match.score,
        confidence: match.confidence,
        reasoning: match.reasoning
      }));

    } catch (error) {
      console.error('Failed to find agents for task:', error);
      throw error;
    }
  }

  /**
   * Send message with intelligent routing
   */
  async sendMessageWithRouting(
    message: AgentMessage,
    targetAgent: string,
    options?: {
      priority?: RequestPriority;
      preferredProvider?: string;
      requireConfirmation?: boolean;
    }
  ): Promise<MessageEnvelope> {
    try {
      // Select optimal provider if available
      if (this.providerSelector && !options?.preferredProvider) {
        const criteria = {
          requestType: LLMRequestType.COMPLETION,
          priority: options?.priority || RequestPriority.MEDIUM,
          requirements: {
            maxLatency: 5000,
            minReliability: 0.9
          },
          context: {
            agentDID: this.mcpAgentIdentity.did,
            domain: 'messaging',
            sensitiveData: false
          }
        };

        const selection = await this.providerSelector.selectProvider(
          {} as any, // Mock request
          criteria,
          SelectionStrategy.RELIABILITY
        );

        options = {
          ...options,
          preferredProvider: selection.primaryProvider.id
        };
      }

      // Use parent class method with provider hint
      await this.sendMessage(message, targetAgent);

      // Create a message envelope for return and logging
      const envelope: MessageEnvelope = {
        message: message,
        routingInfo: {
          path: [this.mcpAgentIdentity.did, targetAgent || ''],
          ttl: 300000
        }
      };

      // Log with MCP audit logger
      await this.mcpAuditLogger.logRequest(
        {
          id: message.id,
          type: LLMRequestType.COMPLETION,
          prompt: `Send message to ${targetAgent}`,
          agentDID: this.mcpAgentIdentity.did,
          sessionId: `msg-${Date.now()}`,
          metadata: {
            agentDID: this.mcpAgentIdentity.did,
            sessionId: `msg-${Date.now()}`,
            requestId: message.id,
            timestamp: new Date(),
            source: 'mcp-communication-manager',
            priority: options?.priority || RequestPriority.MEDIUM
          }
        },
        this.mcpAgentIdentity.did,
        `msg-${Date.now()}`
      );

      return envelope;

    } catch (error) {
      console.error('Failed to send message with routing:', error);
      throw error;
    }
  }

  /**
   * Get or create conversation context
   */
  private async getOrCreateContext(agentDID: string): Promise<ConversationContext> {
    const existing = this.conversationContexts.get(agentDID);
    if (existing) {
      return existing;
    }

    const context = await this.contextManager.createContext(
      agentDID,
      `session-${Date.now()}`,
      {
        domain: 'agent-communication',
        purpose: 'Agent-to-agent messaging with LLM assistance',
        priority: ContextPriority.MEDIUM,
        agentName: this.mcpAgentIdentity.name,
        sharedWith: [],
        retention: {
          duration: 86400000 * 7, // 7 days
          autoCompress: true,
          autoDelete: false,
          archiveAfter: 86400000 * 30
        }
      }
    );

    this.conversationContexts.set(agentDID, context);
    return context;
  }

  /**
   * Build natural language prompt
   */
  private buildNaturalLanguagePrompt(message: string, targetAgent?: string): string {
    const context = targetAgent 
      ? `The user wants to communicate with agent ${targetAgent}.`
      : 'The user wants to send a message.';

    return `
You are an intelligent agent communication assistant. ${context}

User message: "${message}"

Please help process this message and determine:
1. The intent of the message
2. The appropriate message type (request, command, query, notification)
3. Any specific actions or data required
4. The urgency level

Respond in a structured format that can be parsed into an agent message.
    `.trim();
  }

  /**
   * Parse natural language response
   */
  private parseNaturalLanguageResponse(response: LLMResponse, targetAgent?: string): AgentMessage {
    // Parse LLM response into structured agent message
    const content = response.content || '';
    
    // Simple parsing - in production this would be more sophisticated
    const messageType = content.toLowerCase().includes('request') ? AgentMessageType.DELEGATION_REQUEST :
                       content.toLowerCase().includes('query') ? AgentMessageType.QUERY_STATUS :
                       content.toLowerCase().includes('capability') ? AgentMessageType.QUERY_CAPABILITIES :
                       AgentMessageType.NOTIFY_POLICY_CHANGE;

    return {
      id: `msg-${Date.now()}`,
      type: messageType,
      from: this.mcpAgentIdentity.did,
      to: targetAgent || 'broadcast',
      timestamp: new Date(),
      version: '1.0.0',
      payload: {
        action: 'process',
        data: {
          originalMessage: content,
          processedBy: 'mcp-llm',
          model: response.model,
          confidence: 0.8
        }
      },
      metadata: {
        llmProcessed: true,
        providerId: response.provider,
        modelUsed: response.model
      }
    };
  }

  /**
   * Build decision context for delegation
   */
  private async buildDecisionContext(
    requestingAgent: string,
    targetAgent: string
  ): Promise<any> {
    // In a real implementation, this would gather comprehensive context
    return {
      parentAgent: {
        did: this.mcpAgentIdentity.did,
        name: this.mcpAgentIdentity.name,
        type: 'user',
        trustLevel: 0.8,
        capabilities: [], // TODO: Get capabilities from delegation credential
        permissions: [], // TODO: Get permissions from delegation credential
        history: {
          totalDelegations: 10,
          successfulDelegations: 9,
          revokedDelegations: 1,
          averageDelegationDuration: 86400000,
          lastActivity: new Date()
        },
        riskFactors: []
      },
      targetAgent: {
        did: targetAgent,
        name: targetAgent.split(':').pop() || 'Unknown',
        type: 'service',
        trustLevel: 0.7
      },
      organizationalPolicies: [],
      systemPolicies: [],
      currentDelegations: [],
      systemLoad: {
        cpu: 45,
        memory: 60,
        activeAgents: 15
      },
      securityLevel: 'normal',
      timeOfDay: new Date().toLocaleTimeString(),
      workingHours: true
    };
  }

  /**
   * Log LLM activity
   */
  private async logLLMActivity(
    activityType: string,
    request: any,
    response: any
  ): Promise<void> {
    const activity = {
      id: `llm-activity-${Date.now()}`,
      agentDID: this.mcpAgentIdentity.did,
      timestamp: new Date(),
      type: 'llm-interaction',
      category: activityType,
      action: activityType,
      result: response.status || 'success',
      details: {
        request: {
          type: request.type,
          priority: request.metadata?.priority
        },
        response: {
          provider: response.provider,
          model: response.model,
          tokensUsed: response.usage?.totalTokens
        }
      },
      metadata: {
        duration: Date.now() - request.timestamp?.getTime() || 0,
        cost: response.usage?.cost
      }
    };

    // Log to both MCP audit logger and activity logger
    await this.mcpAuditLogger.logRequest(
      request,
      request.agentDID,
      request.sessionId
    );
  }

  /**
   * Get LLM usage statistics
   */
  async getLLMUsageStatistics(): Promise<{
    totalRequests: number;
    totalTokens: number;
    totalCost: number;
    averageLatency: number;
    providerBreakdown: Record<string, {
      requests: number;
      tokens: number;
      cost: number;
    }>;
  }> {
    // This would aggregate statistics from various MCP components
    const routerStats = this.messageRouter.getStatistics();
    const contextStats = this.contextManager.getStatistics();

    return {
      totalRequests: routerStats.activeRequests,
      totalTokens: contextStats.totalTokens,
      totalCost: 0, // Would calculate from audit logs
      averageLatency: routerStats.averageLatency,
      providerBreakdown: {} // Would aggregate from provider health data
    };
  }

  /**
   * Share context between agents
   */
  async shareContextWithAgent(
    targetAgentDID: string,
    options?: {
      shareHistory?: boolean;
      shareSummary?: boolean;
    }
  ): Promise<void> {
    if (!this.mcpOptions.contextSettings?.shareContextBetweenAgents) {
      throw new MCPError({
        code: MCPErrorCode.FORBIDDEN,
        message: 'Context sharing is not enabled',
        timestamp: new Date(),
        retryable: false
      });
    }

    const context = await this.getOrCreateContext(this.mcpAgentIdentity.did);
    
    await this.contextManager.shareContext(
      context.conversationId,
      targetAgentDID,
      {
        shareHistory: options?.shareHistory ?? true,
        shareSummary: options?.shareSummary ?? true,
        shareMetadata: true
      }
    );
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    // Cleanup MCP resources
    this.streamManager.shutdown();
    this.contextManager.shutdown();
    this.messageRouter.shutdown();
    this.providerSelector?.shutdown();
    this.agentMatcher.shutdown();
    this.delegationEngine.shutdown();
    this.delegationIntegration.shutdown();
    
    // Clear contexts
    this.conversationContexts.clear();
  }
}

export default MCPEnabledCommunicationManager;