import {
  AgentMessage,
  AgentMessageType,
  MessageEnvelope,
  CommunicationChannel,
  CommunicationStats,
  MessageHandlerContext
} from './types';
import { AgentIdentity } from '../types';
import { MessageProtocol } from './message-protocol';
import { MessageHandlerRegistry } from './message-handler';
import { AgentIdentityManager } from '../agent-identity';
import { DelegationManager } from '../delegation-manager';
import { DelegationPolicyEngine } from '../delegation-policy-engine';
import { ActivityLogger } from '../activity/activity-logger';

export interface CommunicationManagerOptions {
  enableEncryption?: boolean;
  defaultMessageTTL?: number;
  maxRetries?: number;
  retryDelay?: number;
  enableStats?: boolean;
}

export class CommunicationManager {
  private channels: Map<string, CommunicationChannel> = new Map();
  private messageHandlers: MessageHandlerRegistry;
  private stats: Map<string, CommunicationStats> = new Map();
  private options: Required<CommunicationManagerOptions>;
  private pendingMessages: Map<string, {
    envelope: MessageEnvelope;
    retries: number;
    lastAttempt: Date;
  }> = new Map();

  constructor(
    private agentIdentity: AgentIdentity,
    agentManager: AgentIdentityManager,
    delegationManager: DelegationManager,
    policyEngine: DelegationPolicyEngine,
    activityLogger: ActivityLogger,
    options: CommunicationManagerOptions = {}
  ) {
    this.options = {
      enableEncryption: options.enableEncryption || false,
      defaultMessageTTL: options.defaultMessageTTL || 300000, // 5 minutes
      maxRetries: options.maxRetries || 3,
      retryDelay: options.retryDelay || 5000,
      enableStats: options.enableStats || true
    };

    this.messageHandlers = new MessageHandlerRegistry(
      agentManager,
      delegationManager,
      policyEngine,
      activityLogger
    );

    this.initializeStats();
  }

  /**
   * Adds a communication channel
   */
  addChannel(channel: CommunicationChannel): void {
    this.channels.set(channel.id, channel);
    
    // Set up message handling for this channel
    channel.onMessage(async (envelope) => {
      await this.handleIncomingMessage(envelope, channel.id);
    });

    // Initialize stats for this channel
    if (this.options.enableStats) {
      this.stats.set(channel.id, {
        messagesSent: 0,
        messagesReceived: 0,
        messagesDropped: 0,
        averageResponseTime: 0,
        errorRate: 0
      });
    }
  }

  /**
   * Removes a communication channel
   */
  async removeChannel(channelId: string): Promise<void> {
    const channel = this.channels.get(channelId);
    if (channel) {
      await channel.disconnect();
      this.channels.delete(channelId);
      this.stats.delete(channelId);
    }
  }

  /**
   * Connects all channels
   */
  async connectAll(): Promise<void> {
    const connections = Array.from(this.channels.values()).map(channel => 
      channel.connect().catch(error => {
        console.error(`Failed to connect channel ${channel.id}:`, error);
        return error;
      })
    );

    await Promise.allSettled(connections);
  }

  /**
   * Disconnects all channels
   */
  async disconnectAll(): Promise<void> {
    const disconnections = Array.from(this.channels.values()).map(channel => 
      channel.disconnect().catch(error => {
        console.error(`Failed to disconnect channel ${channel.id}:`, error);
        return error;
      })
    );

    await Promise.allSettled(disconnections);
  }

  /**
   * Sends a message through the best available channel
   */
  async sendMessage(
    message: AgentMessage,
    preferredChannelId?: string
  ): Promise<void> {
    // Sign the message
    const signedMessage = await MessageProtocol.signMessage(message, this.agentIdentity.keyPair);
    
    // Create envelope
    const envelope = MessageProtocol.createEnvelope(signedMessage, {
      ttl: this.options.defaultMessageTTL
    });

    // Choose channel
    const channel = this.selectChannel(message.to, preferredChannelId);
    if (!channel) {
      throw new Error(`No available channel for recipient: ${message.to}`);
    }

    try {
      await this.sendThroughChannel(envelope, channel);
      this.updateStats(channel.id, 'sent');
    } catch (error) {
      this.updateStats(channel.id, 'error');
      
      // Add to retry queue if retries are enabled
      if (this.options.maxRetries > 0) {
        this.pendingMessages.set(message.id, {
          envelope,
          retries: 0,
          lastAttempt: new Date()
        });
      }
      
      throw error;
    }
  }

  /**
   * Sends a delegation request to another agent
   */
  async requestDelegation(
    targetAgentDID: string,
    requestedScopes: string[],
    options: {
      serviceDID?: string;
      duration?: number;
      purpose?: string;
      channelId?: string;
    } = {}
  ): Promise<void> {
    const message = MessageProtocol.createMessage(
      AgentMessageType.DELEGATION_REQUEST,
      this.agentIdentity.did,
      targetAgentDID,
      {
        requestedScopes,
        serviceDID: options.serviceDID,
        duration: options.duration,
        purpose: options.purpose
      }
    );

    await this.sendMessage(message, options.channelId);
  }

  /**
   * Queries another agent's status
   */
  async queryAgentStatus(
    targetAgentDID: string,
    options: {
      includeChain?: boolean;
      includeScopes?: boolean;
      includeMetrics?: boolean;
      channelId?: string;
    } = {}
  ): Promise<void> {
    const message = MessageProtocol.createMessage(
      AgentMessageType.QUERY_STATUS,
      this.agentIdentity.did,
      targetAgentDID,
      {
        includeChain: options.includeChain,
        includeScopes: options.includeScopes,
        includeMetrics: options.includeMetrics
      }
    );

    await this.sendMessage(message, options.channelId);
  }

  /**
   * Pings another agent
   */
  async pingAgent(targetAgentDID: string, channelId?: string): Promise<void> {
    const message = MessageProtocol.createMessage(
      AgentMessageType.PING,
      this.agentIdentity.did,
      targetAgentDID,
      {}
    );

    await this.sendMessage(message, channelId);
  }

  /**
   * Registers a custom message handler
   */
  registerMessageHandler(type: AgentMessageType, handler: (message: AgentMessage, context: MessageHandlerContext) => Promise<AgentMessage | void>): void {
    this.messageHandlers.registerHandler(type, handler);
  }

  /**
   * Gets communication statistics
   */
  getStats(channelId?: string): CommunicationStats | Map<string, CommunicationStats> {
    if (channelId) {
      return this.stats.get(channelId) || {
        messagesSent: 0,
        messagesReceived: 0,
        messagesDropped: 0,
        averageResponseTime: 0,
        errorRate: 0
      };
    }
    return this.stats;
  }

  /**
   * Gets list of connected channels
   */
  getConnectedChannels(): string[] {
    return Array.from(this.channels.values())
      .filter(channel => channel.isConnected)
      .map(channel => channel.id);
  }

  /**
   * Retries failed messages
   */
  async retryFailedMessages(): Promise<number> {
    let retriedCount = 0;
    const now = new Date();
    
    for (const [messageId, pending] of this.pendingMessages.entries()) {
      // Check if enough time has passed for retry
      if (now.getTime() - pending.lastAttempt.getTime() >= this.options.retryDelay) {
        if (pending.retries < this.options.maxRetries) {
          try {
            const channel = this.selectChannel(pending.envelope.message.to);
            if (channel) {
              await this.sendThroughChannel(pending.envelope, channel);
              this.pendingMessages.delete(messageId);
              retriedCount++;
            } else {
              pending.retries++;
              pending.lastAttempt = now;
            }
          } catch (error) {
            pending.retries++;
            pending.lastAttempt = now;
            
            if (pending.retries >= this.options.maxRetries) {
              this.pendingMessages.delete(messageId);
            }
          }
        } else {
          // Max retries reached, remove from queue
          this.pendingMessages.delete(messageId);
        }
      }
    }
    
    return retriedCount;
  }

  // Private methods

  private async handleIncomingMessage(envelope: MessageEnvelope, channelId: string): Promise<void> {
    try {
      // Validate and process envelope
      const { message, errors } = await MessageProtocol.processEnvelope(
        envelope,
        this.agentIdentity.keyPair
      );

      if (errors && errors.length > 0) {
        console.error('Message processing errors:', errors);
        this.updateStats(channelId, 'dropped');
        return;
      }

      // Update stats
      this.updateStats(channelId, 'received');

      // Process message through handlers
      const response = await this.messageHandlers.processMessage(
        message,
        this.agentIdentity,
        (responseMessage) => this.sendMessage(responseMessage, channelId)
      );

      // Send response if one was generated
      if (response) {
        await this.sendMessage(response, channelId);
      }

    } catch (error) {
      console.error('Error handling incoming message:', error);
      this.updateStats(channelId, 'error');
    }
  }

  private selectChannel(recipientDID: string, preferredChannelId?: string): CommunicationChannel | null {
    // Try preferred channel first
    if (preferredChannelId) {
      const preferred = this.channels.get(preferredChannelId);
      if (preferred && preferred.isConnected) {
        return preferred;
      }
    }

    // Find best available channel
    const connectedChannels = Array.from(this.channels.values())
      .filter(channel => channel.isConnected);

    if (connectedChannels.length === 0) {
      return null;
    }

    // Simple selection: prefer direct channels, then websockets
    const direct = connectedChannels.find(ch => ch.type === 'direct');
    if (direct) return direct;

    const websocket = connectedChannels.find(ch => ch.type === 'websocket');
    if (websocket) return websocket;

    // Return first available
    return connectedChannels[0];
  }

  private async sendThroughChannel(envelope: MessageEnvelope, channel: CommunicationChannel): Promise<void> {
    if (!channel.isConnected) {
      throw new Error(`Channel ${channel.id} is not connected`);
    }

    await channel.send(envelope);
  }

  private updateStats(channelId: string, type: 'sent' | 'received' | 'dropped' | 'error'): void {
    if (!this.options.enableStats) return;

    const stats = this.stats.get(channelId);
    if (!stats) return;

    switch (type) {
      case 'sent':
        stats.messagesSent++;
        break;
      case 'received':
        stats.messagesReceived++;
        stats.lastMessageTime = new Date();
        break;
      case 'dropped':
        stats.messagesDropped++;
        break;
      case 'error':
        const totalMessages = stats.messagesSent + stats.messagesReceived;
        if (totalMessages > 0) {
          stats.errorRate = (stats.messagesDropped + 1) / totalMessages;
        }
        break;
    }
  }

  private initializeStats(): void {
    if (!this.options.enableStats) return;

    // Set up periodic retry of failed messages
    setInterval(() => {
      this.retryFailedMessages().catch(error => {
        console.error('Error retrying failed messages:', error);
      });
    }, this.options.retryDelay);
  }
}