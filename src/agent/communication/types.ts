import { AgentIdentity, DelegationCredential } from '../types';

/**
 * Message types for inter-agent communication
 */
export enum AgentMessageType {
  // Delegation requests
  DELEGATION_REQUEST = 'delegation.request',
  DELEGATION_GRANT = 'delegation.grant',
  DELEGATION_DENY = 'delegation.deny',
  DELEGATION_REVOKE = 'delegation.revoke',
  
  // Queries
  QUERY_STATUS = 'query.status',
  QUERY_CAPABILITIES = 'query.capabilities',
  QUERY_CHAIN = 'query.chain',
  
  // Responses
  RESPONSE_STATUS = 'response.status',
  RESPONSE_CAPABILITIES = 'response.capabilities',
  RESPONSE_CHAIN = 'response.chain',
  
  // Notifications
  NOTIFY_REVOCATION = 'notify.revocation',
  NOTIFY_EXPIRATION = 'notify.expiration',
  NOTIFY_POLICY_CHANGE = 'notify.policy_change',
  
  // System
  PING = 'system.ping',
  PONG = 'system.pong',
  ERROR = 'system.error',
  ACK = 'system.ack'
}

/**
 * Base message structure for all inter-agent communications
 */
export interface AgentMessage {
  id: string;
  type: AgentMessageType;
  from: string; // Agent DID
  to: string; // Agent DID
  timestamp: Date;
  version: string;
  signature?: string;
  replyTo?: string; // Message ID this is replying to
  expiresAt?: Date;
  metadata?: Record<string, any>;
  payload: any;
}

/**
 * Delegation request message
 */
export interface DelegationRequestMessage extends AgentMessage {
  type: AgentMessageType.DELEGATION_REQUEST;
  payload: {
    requestedScopes: string[];
    serviceDID?: string;
    duration?: number; // milliseconds
    purpose?: string;
    constraints?: Record<string, any>;
  };
}

/**
 * Delegation grant message
 */
export interface DelegationGrantMessage extends AgentMessage {
  type: AgentMessageType.DELEGATION_GRANT;
  payload: {
    credential: DelegationCredential;
    grantedScopes: string[];
    expiresAt: Date;
    limitations?: string[];
  };
}

/**
 * Delegation deny message
 */
export interface DelegationDenyMessage extends AgentMessage {
  type: AgentMessageType.DELEGATION_DENY;
  payload: {
    reason: string;
    violations?: string[];
    suggestedScopes?: string[];
    retryAfter?: Date;
  };
}

/**
 * Status query message
 */
export interface StatusQueryMessage extends AgentMessage {
  type: AgentMessageType.QUERY_STATUS;
  payload: {
    includeChain?: boolean;
    includeScopes?: boolean;
    includeMetrics?: boolean;
  };
}

/**
 * Status response message
 */
export interface StatusResponseMessage extends AgentMessage {
  type: AgentMessageType.RESPONSE_STATUS;
  payload: {
    status: 'active' | 'suspended' | 'revoked';
    delegationDepth: number;
    remainingDepth: number;
    scopes?: string[];
    metrics?: {
      subAgentsCreated: number;
      delegationsGranted: number;
      delegationsDenied: number;
      lastActivity: Date;
    };
  };
}

/**
 * Message envelope for transport
 */
export interface MessageEnvelope {
  message: AgentMessage;
  routingInfo?: {
    path: string[];
    ttl: number;
  };
  encryption?: {
    algorithm: string;
    recipientKey: string;
    encryptedContent?: string;
  };
}

/**
 * Message handler function type
 */
export type MessageHandler<T extends AgentMessage = AgentMessage> = (
  message: T,
  context: MessageHandlerContext
) => Promise<AgentMessage | void>;

/**
 * Context provided to message handlers
 */
export interface MessageHandlerContext {
  agentIdentity: AgentIdentity;
  sendMessage: (message: AgentMessage) => Promise<void>;
  getAgent: (did: string) => AgentIdentity | undefined;
  validateCredential: (credential: DelegationCredential) => Promise<boolean>;
}

/**
 * Communication channel interface
 */
export interface CommunicationChannel {
  id: string;
  type: 'direct' | 'queue' | 'websocket' | 'http';
  isConnected: boolean;
  
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  send(envelope: MessageEnvelope): Promise<void>;
  onMessage(handler: (envelope: MessageEnvelope) => void): void;
}

/**
 * Message validation result
 */
export interface MessageValidationResult {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
}

/**
 * Communication statistics
 */
export interface CommunicationStats {
  messagesSent: number;
  messagesReceived: number;
  messagesDropped: number;
  averageResponseTime: number;
  lastMessageTime?: Date;
  errorRate: number;
}