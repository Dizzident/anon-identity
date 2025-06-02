import { CommunicationChannel, MessageEnvelope } from '../types';

export interface DirectChannelOptions {
  deliveryDelay?: number; // Simulate network delay
  reliability?: number; // 0-1, chance of successful delivery
  enableLogging?: boolean;
}

/**
 * Direct communication channel for same-process agent communication
 * Useful for testing and same-application agent interactions
 */
export class DirectChannel implements CommunicationChannel {
  id: string;
  type: 'direct' = 'direct';
  isConnected: boolean = false;

  private static channels: Map<string, DirectChannel> = new Map();
  private messageHandlers: Set<(envelope: MessageEnvelope) => void> = new Set();
  private options: Required<DirectChannelOptions>;

  constructor(id: string, options: DirectChannelOptions = {}) {
    this.id = id;
    this.options = {
      deliveryDelay: options.deliveryDelay || 0,
      reliability: options.reliability || 1.0,
      enableLogging: options.enableLogging || false
    };
    
    // Register this channel
    DirectChannel.channels.set(id, this);
  }

  async connect(): Promise<void> {
    this.isConnected = true;
    if (this.options.enableLogging) {
      console.log(`Direct channel ${this.id} connected`);
    }
  }

  async disconnect(): Promise<void> {
    this.isConnected = false;
    DirectChannel.channels.delete(this.id);
    if (this.options.enableLogging) {
      console.log(`Direct channel ${this.id} disconnected`);
    }
  }

  async send(envelope: MessageEnvelope): Promise<void> {
    if (!this.isConnected) {
      throw new Error('Channel not connected');
    }

    // Simulate network reliability
    if (Math.random() > this.options.reliability) {
      throw new Error('Message delivery failed (simulated network issue)');
    }

    // Extract recipient from message
    const recipientDID = envelope.message.to;
    const recipientChannel = this.findChannelForAgent(recipientDID);

    if (!recipientChannel) {
      throw new Error(`No direct channel found for recipient: ${recipientDID}`);
    }

    // Simulate network delay
    const deliverMessage = () => {
      if (recipientChannel.isConnected) {
        recipientChannel.deliverMessage(envelope);
      } else {
        if (this.options.enableLogging) {
          console.warn(`Recipient channel ${recipientChannel.id} not connected, dropping message`);
        }
      }
    };

    if (this.options.deliveryDelay > 0) {
      setTimeout(deliverMessage, this.options.deliveryDelay);
    } else {
      deliverMessage();
    }
  }

  onMessage(handler: (envelope: MessageEnvelope) => void): void {
    this.messageHandlers.add(handler);
  }

  removeMessageHandler(handler: (envelope: MessageEnvelope) => void): void {
    this.messageHandlers.delete(handler);
  }

  private deliverMessage(envelope: MessageEnvelope): void {
    if (this.options.enableLogging) {
      console.log(`Direct channel ${this.id} received message:`, envelope.message.type);
    }

    // Deliver to all handlers
    this.messageHandlers.forEach(handler => {
      try {
        handler(envelope);
      } catch (error) {
        console.error('Message handler error:', error);
      }
    });
  }

  private findChannelForAgent(agentDID: string): DirectChannel | undefined {
    // In a real implementation, you'd have a registry mapping agents to channels
    // For simplicity, we'll assume channel ID matches agent DID or use a simple lookup
    
    // First try exact match
    let channel = DirectChannel.channels.get(agentDID);
    if (channel) return channel;

    // Try to find by some other mapping logic
    // For now, return the first available channel (for testing)
    for (const [id, ch] of DirectChannel.channels.entries()) {
      if (id !== this.id && ch.isConnected) {
        return ch;
      }
    }

    return undefined;
  }

  // Static methods for managing direct channels

  static getChannel(id: string): DirectChannel | undefined {
    return this.channels.get(id);
  }

  static getAllChannels(): DirectChannel[] {
    return Array.from(this.channels.values());
  }

  static getConnectedChannels(): DirectChannel[] {
    return this.getAllChannels().filter(ch => ch.isConnected);
  }

  static createChannelPair(id1: string, id2: string): [DirectChannel, DirectChannel] {
    const channel1 = new DirectChannel(id1);
    const channel2 = new DirectChannel(id2);
    return [channel1, channel2];
  }

  static async broadcastToAll(envelope: MessageEnvelope, excludeId?: string): Promise<number> {
    const channels = this.getConnectedChannels();
    let delivered = 0;

    for (const channel of channels) {
      if (excludeId && channel.id === excludeId) continue;
      
      try {
        await channel.send(envelope);
        delivered++;
      } catch (error) {
        console.error(`Broadcast failed to ${channel.id}:`, error);
      }
    }

    return delivered;
  }

  // Utility methods for testing and debugging

  getStats(): {
    id: string;
    connected: boolean;
    handlerCount: number;
    options: DirectChannelOptions;
  } {
    return {
      id: this.id,
      connected: this.isConnected,
      handlerCount: this.messageHandlers.size,
      options: this.options
    };
  }

  static getGlobalStats(): {
    totalChannels: number;
    connectedChannels: number;
    channels: Array<{
      id: string;
      connected: boolean;
      handlerCount: number;
    }>;
  } {
    const allChannels = this.getAllChannels();
    
    return {
      totalChannels: allChannels.length,
      connectedChannels: allChannels.filter(ch => ch.isConnected).length,
      channels: allChannels.map(ch => ({
        id: ch.id,
        connected: ch.isConnected,
        handlerCount: ch.messageHandlers.size
      }))
    };
  }
}