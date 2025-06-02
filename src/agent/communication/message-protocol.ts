import { 
  AgentMessage, 
  AgentMessageType, 
  MessageEnvelope, 
  MessageValidationResult,
  MessageHandler,
  MessageHandlerContext
} from './types';
import { AgentIdentity } from '../types';
import { signData, verifyData } from '../../core/crypto';
import { DIDService } from '../../core/did';

export class MessageProtocol {
  private static readonly VERSION = '1.0.0';
  private static readonly MESSAGE_TTL = 5 * 60 * 1000; // 5 minutes
  
  /**
   * Creates a new message with proper formatting and metadata
   */
  static createMessage<T extends AgentMessage>(
    type: AgentMessageType,
    from: string,
    to: string,
    payload: any,
    options?: {
      replyTo?: string;
      expiresAt?: Date;
      metadata?: Record<string, any>;
    }
  ): T {
    const now = new Date();
    const expiresAt = options?.expiresAt || new Date(now.getTime() + this.MESSAGE_TTL);
    
    return {
      id: this.generateMessageId(),
      type,
      from,
      to,
      timestamp: now,
      version: this.VERSION,
      replyTo: options?.replyTo,
      expiresAt,
      metadata: options?.metadata,
      payload
    } as T;
  }

  /**
   * Signs a message with the sender's private key
   */
  static async signMessage(
    message: AgentMessage,
    senderKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array }
  ): Promise<AgentMessage> {
    // Create canonical representation for signing
    const { signature, ...messageWithoutSignature } = message;
    const canonical = this.canonicalizeMessage(messageWithoutSignature);
    
    // Sign the message
    const messageSignature = signData(canonical, senderKeyPair.privateKey);
    
    return {
      ...message,
      signature: messageSignature
    };
  }

  /**
   * Verifies a message signature
   */
  static async verifyMessage(message: AgentMessage): Promise<boolean> {
    if (!message.signature) {
      return false;
    }

    try {
      // Extract sender's public key from DID
      const senderPublicKey = DIDService.getPublicKeyFromDID(message.from);
      
      // Create canonical representation
      const { signature, ...messageWithoutSignature } = message;
      const canonical = this.canonicalizeMessage(messageWithoutSignature);
      
      // Verify signature
      return verifyData(canonical, message.signature, senderPublicKey);
    } catch (error) {
      return false;
    }
  }

  /**
   * Validates message structure and content
   */
  static validateMessage(message: AgentMessage): MessageValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check required fields
    if (!message.id) errors.push('Message ID is required');
    if (!message.type) errors.push('Message type is required');
    if (!message.from) errors.push('Sender DID is required');
    if (!message.to) errors.push('Recipient DID is required');
    if (!message.timestamp) errors.push('Timestamp is required');
    if (!message.version) errors.push('Version is required');

    // Validate DID format
    if (message.from && !this.isValidDID(message.from)) {
      errors.push('Invalid sender DID format');
    }
    if (message.to && !this.isValidDID(message.to)) {
      errors.push('Invalid recipient DID format');
    }

    // Check message expiration
    if (message.expiresAt && new Date() > message.expiresAt) {
      errors.push('Message has expired');
    }

    // Check version compatibility
    if (message.version !== this.VERSION) {
      warnings.push(`Version mismatch: expected ${this.VERSION}, got ${message.version}`);
    }

    // Validate message type
    if (!Object.values(AgentMessageType).includes(message.type)) {
      errors.push(`Unknown message type: ${message.type}`);
    }

    // Type-specific validation
    const typeValidation = this.validateMessagePayload(message);
    errors.push(...typeValidation.errors);
    warnings.push(...typeValidation.warnings);

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
      warnings: warnings.length > 0 ? warnings : undefined
    };
  }

  /**
   * Creates a message envelope for transport
   */
  static createEnvelope(
    message: AgentMessage,
    options?: {
      routingPath?: string[];
      ttl?: number;
      encryption?: {
        algorithm: string;
        recipientKey: string;
      };
    }
  ): MessageEnvelope {
    const envelope: MessageEnvelope = {
      message
    };

    if (options?.routingPath || options?.ttl) {
      envelope.routingInfo = {
        path: options.routingPath || [],
        ttl: options.ttl || 10
      };
    }

    if (options?.encryption) {
      envelope.encryption = {
        algorithm: options.encryption.algorithm,
        recipientKey: options.encryption.recipientKey
      };
    }

    return envelope;
  }

  /**
   * Extracts message from envelope and validates
   */
  static async processEnvelope(
    envelope: MessageEnvelope,
    agentKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array }
  ): Promise<{ message: AgentMessage; errors?: string[] }> {
    const errors: string[] = [];

    // Decrypt if necessary
    let message = envelope.message;
    if (envelope.encryption && envelope.encryption.encryptedContent) {
      if (!agentKeyPair) {
        errors.push('Encrypted message received but no keys provided for decryption');
        return { message, errors };
      }
      
      try {
        // In a real implementation, decrypt the content here
        // For now, we'll skip actual decryption
        message = JSON.parse(envelope.encryption.encryptedContent);
      } catch (error) {
        errors.push('Failed to decrypt message');
        return { message, errors };
      }
    }

    // Validate message
    const validation = this.validateMessage(message);
    if (!validation.valid) {
      errors.push(...(validation.errors || []));
    }

    // Verify signature
    const signatureValid = await this.verifyMessage(message);
    if (!signatureValid) {
      errors.push('Invalid message signature');
    }

    return { message, errors: errors.length > 0 ? errors : undefined };
  }

  /**
   * Creates standard response messages
   */
  static createResponse(
    originalMessage: AgentMessage,
    responseType: AgentMessageType,
    payload: any,
    from: string
  ): AgentMessage {
    return this.createMessage(
      responseType,
      from,
      originalMessage.from,
      payload,
      {
        replyTo: originalMessage.id,
        metadata: {
          originalType: originalMessage.type,
          responseTo: originalMessage.id
        }
      }
    );
  }

  /**
   * Creates error response
   */
  static createErrorResponse(
    originalMessage: AgentMessage,
    error: string,
    from: string
  ): AgentMessage {
    return this.createResponse(
      originalMessage,
      AgentMessageType.ERROR,
      {
        error,
        originalMessageId: originalMessage.id,
        originalMessageType: originalMessage.type
      },
      from
    );
  }

  /**
   * Creates acknowledgment response
   */
  static createAckResponse(
    originalMessage: AgentMessage,
    from: string,
    status: 'received' | 'processing' | 'completed' = 'received'
  ): AgentMessage {
    return this.createResponse(
      originalMessage,
      AgentMessageType.ACK,
      {
        status,
        originalMessageId: originalMessage.id,
        timestamp: new Date()
      },
      from
    );
  }

  // Private helper methods

  private static generateMessageId(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2);
    return `msg_${timestamp}_${random}`;
  }

  private static canonicalizeMessage(message: Partial<AgentMessage>): string {
    // Create a canonical string representation for signing
    const keys = Object.keys(message).sort();
    const canonical: Record<string, any> = {};
    
    keys.forEach(key => {
      const value = (message as any)[key];
      if (value !== undefined) {
        canonical[key] = value;
      }
    });
    
    return JSON.stringify(canonical);
  }

  private static isValidDID(did: string): boolean {
    return did.startsWith('did:') && did.includes(':') && did.length > 10;
  }

  private static validateMessagePayload(message: AgentMessage): {
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!message.payload) {
      errors.push('Message payload is required');
      return { errors, warnings };
    }

    switch (message.type) {
      case AgentMessageType.DELEGATION_REQUEST:
        if (!message.payload.requestedScopes || !Array.isArray(message.payload.requestedScopes)) {
          errors.push('Delegation request must include requestedScopes array');
        }
        if (message.payload.requestedScopes?.length === 0) {
          warnings.push('Delegation request has empty scopes array');
        }
        break;

      case AgentMessageType.DELEGATION_GRANT:
        if (!message.payload.credential) {
          errors.push('Delegation grant must include credential');
        }
        if (!message.payload.grantedScopes || !Array.isArray(message.payload.grantedScopes)) {
          errors.push('Delegation grant must include grantedScopes array');
        }
        break;

      case AgentMessageType.DELEGATION_DENY:
        if (!message.payload.reason) {
          errors.push('Delegation deny must include reason');
        }
        break;

      case AgentMessageType.QUERY_STATUS:
        // Status queries can have empty payloads
        break;

      case AgentMessageType.RESPONSE_STATUS:
        if (!message.payload.status) {
          errors.push('Status response must include status');
        }
        if (typeof message.payload.delegationDepth !== 'number') {
          errors.push('Status response must include delegationDepth number');
        }
        break;

      case AgentMessageType.PING:
        // Ping can have empty payload
        break;

      case AgentMessageType.PONG:
        // Pong can have empty payload
        break;

      case AgentMessageType.ERROR:
        if (!message.payload.error) {
          errors.push('Error message must include error description');
        }
        break;

      default:
        warnings.push(`Unknown message type validation: ${message.type}`);
    }

    return { errors, warnings };
  }

  /**
   * Serializes a message for transport
   */
  static serialize(message: AgentMessage): string {
    return JSON.stringify(message, (key, value) => {
      // Handle Date objects
      if (value instanceof Date) {
        return value.toISOString();
      }
      return value;
    });
  }

  /**
   * Deserializes a message from transport
   */
  static deserialize(data: string): AgentMessage {
    return JSON.parse(data, (key, value) => {
      // Handle Date objects
      if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) {
        return new Date(value);
      }
      return value;
    });
  }
}