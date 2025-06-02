import {
  AgentMessage,
  AgentMessageType,
  DelegationRequestMessage,
  DelegationGrantMessage,
  DelegationDenyMessage,
  StatusQueryMessage,
  StatusResponseMessage
} from './types';
import { DelegationCredential } from '../types';
import { MessageProtocol } from './message-protocol';

/**
 * Factory class for creating common message types
 */
export class MessageFactory {
  /**
   * Creates a delegation request message
   */
  static createDelegationRequest(
    from: string,
    to: string,
    requestedScopes: string[],
    options: {
      serviceDID?: string;
      duration?: number;
      purpose?: string;
      constraints?: Record<string, any>;
      replyTo?: string;
    } = {}
  ): DelegationRequestMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.DELEGATION_REQUEST,
      from,
      to,
      {
        requestedScopes,
        serviceDID: options.serviceDID,
        duration: options.duration,
        purpose: options.purpose,
        constraints: options.constraints
      },
      { replyTo: options.replyTo }
    );
  }

  /**
   * Creates a delegation grant message
   */
  static createDelegationGrant(
    from: string,
    to: string,
    credential: DelegationCredential,
    grantedScopes: string[],
    expiresAt: Date,
    options: {
      limitations?: string[];
      replyTo?: string;
    } = {}
  ): DelegationGrantMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.DELEGATION_GRANT,
      from,
      to,
      {
        credential,
        grantedScopes,
        expiresAt,
        limitations: options.limitations
      },
      { replyTo: options.replyTo }
    );
  }

  /**
   * Creates a delegation deny message
   */
  static createDelegationDeny(
    from: string,
    to: string,
    reason: string,
    options: {
      violations?: string[];
      suggestedScopes?: string[];
      retryAfter?: Date;
      replyTo?: string;
    } = {}
  ): DelegationDenyMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.DELEGATION_DENY,
      from,
      to,
      {
        reason,
        violations: options.violations,
        suggestedScopes: options.suggestedScopes,
        retryAfter: options.retryAfter
      },
      { replyTo: options.replyTo }
    );
  }

  /**
   * Creates a status query message
   */
  static createStatusQuery(
    from: string,
    to: string,
    options: {
      includeChain?: boolean;
      includeScopes?: boolean;
      includeMetrics?: boolean;
      replyTo?: string;
    } = {}
  ): StatusQueryMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.QUERY_STATUS,
      from,
      to,
      {
        includeChain: options.includeChain,
        includeScopes: options.includeScopes,
        includeMetrics: options.includeMetrics
      },
      { replyTo: options.replyTo }
    );
  }

  /**
   * Creates a status response message
   */
  static createStatusResponse(
    from: string,
    to: string,
    status: 'active' | 'suspended' | 'revoked',
    delegationDepth: number,
    remainingDepth: number,
    options: {
      scopes?: string[];
      metrics?: {
        subAgentsCreated: number;
        delegationsGranted: number;
        delegationsDenied: number;
        lastActivity: Date;
      };
      replyTo?: string;
    } = {}
  ): StatusResponseMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.RESPONSE_STATUS,
      from,
      to,
      {
        status,
        delegationDepth,
        remainingDepth,
        scopes: options.scopes,
        metrics: options.metrics
      },
      { replyTo: options.replyTo }
    );
  }

  /**
   * Creates a ping message
   */
  static createPing(
    from: string,
    to: string,
    options: {
      timestamp?: Date;
      metadata?: Record<string, any>;
      replyTo?: string;
    } = {}
  ): AgentMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.PING,
      from,
      to,
      {
        timestamp: options.timestamp || new Date()
      },
      { 
        replyTo: options.replyTo,
        metadata: options.metadata
      }
    );
  }

  /**
   * Creates a pong message (response to ping)
   */
  static createPong(
    from: string,
    to: string,
    originalPingId: string,
    options: {
      agentStatus?: string;
      responseTime?: number;
      metadata?: Record<string, any>;
    } = {}
  ): AgentMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.PONG,
      from,
      to,
      {
        timestamp: new Date(),
        agentStatus: options.agentStatus || 'active',
        responseTime: options.responseTime
      },
      { 
        replyTo: originalPingId,
        metadata: options.metadata
      }
    );
  }

  /**
   * Creates an error message
   */
  static createError(
    from: string,
    to: string,
    error: string,
    originalMessageId?: string,
    options: {
      errorCode?: string;
      details?: Record<string, any>;
      replyTo?: string;
    } = {}
  ): AgentMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.ERROR,
      from,
      to,
      {
        error,
        errorCode: options.errorCode,
        originalMessageId,
        details: options.details,
        timestamp: new Date()
      },
      { replyTo: options.replyTo || originalMessageId }
    );
  }

  /**
   * Creates an acknowledgment message
   */
  static createAck(
    from: string,
    to: string,
    originalMessageId: string,
    status: 'received' | 'processing' | 'completed' = 'received',
    options: {
      details?: Record<string, any>;
      metadata?: Record<string, any>;
    } = {}
  ): AgentMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.ACK,
      from,
      to,
      {
        status,
        originalMessageId,
        timestamp: new Date(),
        details: options.details
      },
      { 
        replyTo: originalMessageId,
        metadata: options.metadata
      }
    );
  }

  /**
   * Creates a revocation notification message
   */
  static createRevocationNotification(
    from: string,
    to: string,
    revokedAgentDID: string,
    reason: string,
    options: {
      effectiveDate?: Date;
      cascading?: boolean;
      metadata?: Record<string, any>;
    } = {}
  ): AgentMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.NOTIFY_REVOCATION,
      from,
      to,
      {
        revokedAgentDID,
        reason,
        effectiveDate: options.effectiveDate || new Date(),
        cascading: options.cascading || false
      },
      { metadata: options.metadata }
    );
  }

  /**
   * Creates an expiration notification message
   */
  static createExpirationNotification(
    from: string,
    to: string,
    agentDID: string,
    expirationDate: Date,
    options: {
      gracePeriod?: number;
      autoRenew?: boolean;
      metadata?: Record<string, any>;
    } = {}
  ): AgentMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.NOTIFY_EXPIRATION,
      from,
      to,
      {
        agentDID,
        expirationDate,
        gracePeriod: options.gracePeriod,
        autoRenew: options.autoRenew || false,
        notificationTime: new Date()
      },
      { metadata: options.metadata }
    );
  }

  /**
   * Creates a policy change notification message
   */
  static createPolicyChangeNotification(
    from: string,
    to: string,
    policyId: string,
    changeType: 'created' | 'updated' | 'deleted' | 'enabled' | 'disabled',
    options: {
      effectiveDate?: Date;
      affectedAgents?: string[];
      description?: string;
      metadata?: Record<string, any>;
    } = {}
  ): AgentMessage {
    return MessageProtocol.createMessage(
      AgentMessageType.NOTIFY_POLICY_CHANGE,
      from,
      to,
      {
        policyId,
        changeType,
        effectiveDate: options.effectiveDate || new Date(),
        affectedAgents: options.affectedAgents,
        description: options.description,
        notificationTime: new Date()
      },
      { metadata: options.metadata }
    );
  }

  /**
   * Creates a batch of messages with common properties
   */
  static createBatch(
    from: string,
    recipients: string[],
    messageType: AgentMessageType,
    payload: any,
    options: {
      batchId?: string;
      metadata?: Record<string, any>;
    } = {}
  ): AgentMessage[] {
    const batchId = options.batchId || `batch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    return recipients.map(to => {
      return MessageProtocol.createMessage(
        messageType,
        from,
        to,
        payload,
        {
          metadata: {
            ...options.metadata,
            batchId,
            batchSize: recipients.length
          }
        }
      );
    });
  }

  /**
   * Utility to check if a message is of a specific type with type safety
   */
  static isMessageType<T extends AgentMessage>(
    message: AgentMessage,
    type: AgentMessageType
  ): message is T {
    return message.type === type;
  }

  /**
   * Extracts common message metadata
   */
  static extractMessageInfo(message: AgentMessage): {
    id: string;
    type: AgentMessageType;
    from: string;
    to: string;
    timestamp: Date;
    isExpired: boolean;
    age: number; // milliseconds
  } {
    const now = new Date();
    const age = now.getTime() - message.timestamp.getTime();
    const isExpired = message.expiresAt ? now > message.expiresAt : false;

    return {
      id: message.id,
      type: message.type,
      from: message.from,
      to: message.to,
      timestamp: message.timestamp,
      isExpired,
      age
    };
  }
}