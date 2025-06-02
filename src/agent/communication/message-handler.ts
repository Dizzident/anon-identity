import {
  AgentMessage,
  AgentMessageType,
  MessageHandler,
  MessageHandlerContext,
  DelegationRequestMessage,
  DelegationGrantMessage,
  DelegationDenyMessage,
  StatusQueryMessage,
  StatusResponseMessage,
  CommunicationStats
} from './types';
import { AgentIdentity, DelegationCredential } from '../types';
import { AgentIdentityManager } from '../agent-identity';
import { DelegationManager, DelegationMetadata } from '../delegation-manager';
import { DelegationPolicyEngine } from '../delegation-policy-engine';
import { MessageProtocol } from './message-protocol';
import { ActivityLogger, createActivity } from '../activity/activity-logger';
import { ActivityType, ActivityStatus } from '../activity/types';

export class MessageHandlerRegistry {
  private handlers: Map<AgentMessageType, MessageHandler[]> = new Map();
  private defaultHandlers: Map<AgentMessageType, MessageHandler> = new Map();
  
  constructor(
    private agentManager: AgentIdentityManager,
    private delegationManager: DelegationManager,
    private policyEngine: DelegationPolicyEngine,
    private activityLogger: ActivityLogger
  ) {
    this.registerDefaultHandlers();
  }

  /**
   * Registers a message handler for a specific message type
   */
  registerHandler(type: AgentMessageType, handler: MessageHandler): void {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, []);
    }
    this.handlers.get(type)!.push(handler);
  }

  /**
   * Removes a message handler
   */
  unregisterHandler(type: AgentMessageType, handler: MessageHandler): void {
    const handlers = this.handlers.get(type);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }

  /**
   * Processes an incoming message
   */
  async processMessage(
    message: AgentMessage,
    agentIdentity: AgentIdentity,
    sendMessage: (message: AgentMessage) => Promise<void>
  ): Promise<AgentMessage | void> {
    const context: MessageHandlerContext = {
      agentIdentity,
      sendMessage,
      getAgent: (did: string) => this.agentManager.getAgent(did),
      validateCredential: async (credential: DelegationCredential) => 
        this.delegationManager.validateDelegation(credential)
    };

    // Log incoming message
    await this.activityLogger.logActivity(createActivity(
      ActivityType.COMMUNICATION,
      {
        agentDID: agentIdentity.did,
        parentDID: agentIdentity.parentDID,
        serviceDID: 'internal',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {
          messageType: message.type,
          messageId: message.id,
          from: message.from,
          direction: 'incoming'
        }
      }
    ));

    // Try default handler first
    const defaultHandler = this.defaultHandlers.get(message.type);
    if (defaultHandler) {
      try {
        const response = await defaultHandler(message, context);
        if (response) {
          return response;
        }
      } catch (error) {
        console.error(`Default handler error for ${message.type}:`, error);
        return MessageProtocol.createErrorResponse(
          message,
          `Handler error: ${error instanceof Error ? error.message : 'Unknown error'}`,
          agentIdentity.did
        );
      }
    }

    // Try custom handlers
    const handlers = this.handlers.get(message.type) || [];
    for (const handler of handlers) {
      try {
        const response = await handler(message, context);
        if (response) {
          return response;
        }
      } catch (error) {
        console.error(`Custom handler error for ${message.type}:`, error);
      }
    }

    // No handler found
    return MessageProtocol.createErrorResponse(
      message,
      `No handler found for message type: ${message.type}`,
      agentIdentity.did
    );
  }

  /**
   * Registers default handlers for standard message types
   */
  private registerDefaultHandlers(): void {
    this.defaultHandlers.set(AgentMessageType.DELEGATION_REQUEST, this.handleDelegationRequest.bind(this) as MessageHandler);
    this.defaultHandlers.set(AgentMessageType.QUERY_STATUS, this.handleStatusQuery.bind(this) as MessageHandler);
    this.defaultHandlers.set(AgentMessageType.PING, this.handlePing.bind(this));
    this.defaultHandlers.set(AgentMessageType.ACK, this.handleAck.bind(this));
    this.defaultHandlers.set(AgentMessageType.ERROR, this.handleError.bind(this));
  }

  /**
   * Handles delegation requests
   */
  private async handleDelegationRequest(
    message: DelegationRequestMessage,
    context: MessageHandlerContext
  ): Promise<AgentMessage> {
    const { agentIdentity, sendMessage } = context;
    const { requestedScopes, serviceDID, duration, purpose } = message.payload;

    try {
      // Check if this agent can delegate
      if (!agentIdentity.canDelegate) {
        return MessageProtocol.createResponse(
          message,
          AgentMessageType.DELEGATION_DENY,
          {
            reason: 'Agent is not authorized to delegate',
            violations: ['delegation_not_allowed']
          },
          agentIdentity.did
        );
      }

      // Evaluate delegation policy
      const policyResult = await this.policyEngine.evaluatePolicy({
        parentAgent: agentIdentity,
        requestedScopes,
        serviceDID,
        metadata: { purpose, requestedDuration: duration }
      });

      if (!policyResult.allowed) {
        return MessageProtocol.createResponse(
          message,
          AgentMessageType.DELEGATION_DENY,
          {
            reason: 'Policy evaluation failed',
            violations: policyResult.violations,
            suggestedScopes: this.getSuggestedScopes(requestedScopes, agentIdentity)
          },
          agentIdentity.did
        );
      }

      // Create sub-agent
      const subAgent = await this.agentManager.createSubAgent(agentIdentity.did, {
        name: `Sub-agent for ${message.from}`,
        description: `Delegated agent with purpose: ${purpose || 'Not specified'}`,
        parentAgentDID: agentIdentity.did,
        requestedScopes
      });

      // Create delegation credential
      const expiresAt = duration 
        ? new Date(Date.now() + duration)
        : this.policyEngine.calculateExpiration(policyResult.policy!, new Date(Date.now() + 24 * 60 * 60 * 1000));

      const grant = {
        serviceDID: serviceDID || 'default',
        scopes: this.agentManager.reduceScopesForDelegation(
          await this.getAgentScopes(agentIdentity),
          requestedScopes,
          policyResult.policy?.scopeReduction
        ),
        expiresAt
      };

      const metadata: DelegationMetadata = {
        delegationDepth: agentIdentity.delegationDepth + 1,
        maxDelegationDepth: agentIdentity.maxDelegationDepth,
        canDelegate: grant.scopes.length > 0 && agentIdentity.canDelegate
      };

      const credential = await this.delegationManager.createDelegationCredential(
        agentIdentity.did,
        agentIdentity.keyPair,
        subAgent.did,
        subAgent.name,
        grant,
        metadata
      );

      this.agentManager.addDelegationCredential(subAgent.did, credential);

      // Log successful delegation
      await this.activityLogger.logActivity(createActivity(
        ActivityType.DELEGATION,
        {
          agentDID: agentIdentity.did,
          parentDID: agentIdentity.parentDID,
          serviceDID: serviceDID || 'default',
          status: ActivityStatus.SUCCESS,
          scopes: grant.scopes,
          details: {
            subAgentDID: subAgent.did,
            requestingAgent: message.from,
            purpose,
            grantedScopes: grant.scopes,
            expiresAt: expiresAt.toISOString()
          }
        }
      ));

      return MessageProtocol.createResponse(
        message,
        AgentMessageType.DELEGATION_GRANT,
        {
          credential,
          grantedScopes: grant.scopes,
          expiresAt,
          limitations: policyResult.appliedConstraints
        },
        agentIdentity.did
      );

    } catch (error) {
      // Log failed delegation
      await this.activityLogger.logActivity(createActivity(
        ActivityType.DELEGATION,
        {
          agentDID: agentIdentity.did,
          parentDID: agentIdentity.parentDID,
          serviceDID: serviceDID || 'default',
          status: ActivityStatus.FAILED,
          scopes: requestedScopes,
          details: {
            requestingAgent: message.from,
            error: error instanceof Error ? error.message : 'Unknown error',
            purpose
          }
        }
      ));

      return MessageProtocol.createResponse(
        message,
        AgentMessageType.DELEGATION_DENY,
        {
          reason: 'Internal error processing delegation request',
          violations: ['internal_error']
        },
        agentIdentity.did
      );
    }
  }

  /**
   * Handles status queries
   */
  private async handleStatusQuery(
    message: StatusQueryMessage,
    context: MessageHandlerContext
  ): Promise<AgentMessage> {
    const { agentIdentity } = context;
    const { includeChain, includeScopes, includeMetrics } = message.payload;

    const payload: any = {
      status: 'active' as const,
      delegationDepth: agentIdentity.delegationDepth,
      remainingDepth: this.agentManager.validateDelegationDepth(agentIdentity.did) 
        ? (agentIdentity.maxDelegationDepth || 3) - agentIdentity.delegationDepth 
        : 0
    };

    if (includeScopes) {
      payload.scopes = await this.getAgentScopes(agentIdentity);
    }

    if (includeMetrics) {
      payload.metrics = await this.getAgentMetrics(agentIdentity);
    }

    return MessageProtocol.createResponse(
      message,
      AgentMessageType.RESPONSE_STATUS,
      payload,
      agentIdentity.did
    );
  }

  /**
   * Handles ping messages
   */
  private async handlePing(
    message: AgentMessage,
    context: MessageHandlerContext
  ): Promise<AgentMessage> {
    return MessageProtocol.createResponse(
      message,
      AgentMessageType.PONG,
      {
        timestamp: new Date(),
        agentStatus: 'active'
      },
      context.agentIdentity.did
    );
  }

  /**
   * Handles acknowledgment messages
   */
  private async handleAck(
    message: AgentMessage,
    context: MessageHandlerContext
  ): Promise<void> {
    // Log acknowledgment received
    await this.activityLogger.logActivity(createActivity(
      ActivityType.COMMUNICATION,
      {
        agentDID: context.agentIdentity.did,
        parentDID: context.agentIdentity.parentDID,
        serviceDID: 'internal',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {
          messageType: 'ack_received',
          originalMessageId: message.payload.originalMessageId,
          from: message.from
        }
      }
    ));
  }

  /**
   * Handles error messages
   */
  private async handleError(
    message: AgentMessage,
    context: MessageHandlerContext
  ): Promise<void> {
    // Log error received
    await this.activityLogger.logActivity(createActivity(
      ActivityType.COMMUNICATION,
      {
        agentDID: context.agentIdentity.did,
        parentDID: context.agentIdentity.parentDID,
        serviceDID: 'internal',
        status: ActivityStatus.FAILED,
        scopes: [],
        details: {
          messageType: 'error_received',
          error: message.payload.error,
          originalMessageId: message.payload.originalMessageId,
          from: message.from
        }
      }
    ));
  }

  // Helper methods

  private async getAgentScopes(agent: AgentIdentity): Promise<string[]> {
    const credentials = this.agentManager.getDelegationCredentials(agent.did);
    const allScopes = new Set<string>();
    
    credentials.forEach(cred => {
      cred.credentialSubject.scopes.forEach(scope => allScopes.add(scope));
    });
    
    return Array.from(allScopes);
  }

  private async getAgentMetrics(agent: AgentIdentity): Promise<any> {
    // This would typically query actual metrics from storage
    // For now, return mock data
    return {
      subAgentsCreated: 0,
      delegationsGranted: 0,
      delegationsDenied: 0,
      lastActivity: new Date()
    };
  }

  private getSuggestedScopes(requestedScopes: string[], agent: AgentIdentity): string[] {
    // This would implement logic to suggest alternative scopes
    // For now, return empty array
    return [];
  }
}