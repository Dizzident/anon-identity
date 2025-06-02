import { CommunicationChannel, MessageEnvelope } from '../types';
import { MessageProtocol } from '../message-protocol';

export interface WebSocketChannelOptions {
  url?: string;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
  heartbeatInterval?: number;
  messageTimeout?: number;
}

export class WebSocketChannel implements CommunicationChannel {
  id: string;
  type: 'websocket' = 'websocket';
  isConnected: boolean = false;

  private ws?: WebSocket;
  private messageHandlers: Set<(envelope: MessageEnvelope) => void> = new Set();
  private reconnectAttempts: number = 0;
  private heartbeatTimer?: NodeJS.Timeout;
  private options: Required<WebSocketChannelOptions>;

  constructor(id: string, options: WebSocketChannelOptions = {}) {
    this.id = id;
    this.options = {
      url: options.url || 'ws://localhost:8080',
      reconnectInterval: options.reconnectInterval || 5000,
      maxReconnectAttempts: options.maxReconnectAttempts || 10,
      heartbeatInterval: options.heartbeatInterval || 30000,
      messageTimeout: options.messageTimeout || 10000
    };
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        // Note: WebSocket is not available in Node.js by default
        // This implementation assumes a browser environment or ws library
        if (typeof WebSocket === 'undefined') {
          throw new Error('WebSocket not available in this environment');
        }

        this.ws = new WebSocket(this.options.url);

        this.ws.onopen = () => {
          this.isConnected = true;
          this.reconnectAttempts = 0;
          this.startHeartbeat();
          resolve();
        };

        this.ws.onclose = () => {
          this.isConnected = false;
          this.stopHeartbeat();
          this.attemptReconnect();
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          reject(new Error('WebSocket connection failed'));
        };

        this.ws.onmessage = (event) => {
          this.handleIncomingMessage(event.data);
        };

      } catch (error) {
        reject(error);
      }
    });
  }

  async disconnect(): Promise<void> {
    this.stopHeartbeat();
    
    if (this.ws) {
      this.ws.close();
      this.ws = undefined;
    }
    
    this.isConnected = false;
  }

  async send(envelope: MessageEnvelope): Promise<void> {
    if (!this.isConnected || !this.ws) {
      throw new Error('WebSocket not connected');
    }

    const serialized = MessageProtocol.serialize(envelope.message);
    
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Message send timeout'));
      }, this.options.messageTimeout);

      try {
        this.ws!.send(JSON.stringify({
          envelope,
          serializedMessage: serialized
        }));
        
        clearTimeout(timeout);
        resolve();
      } catch (error) {
        clearTimeout(timeout);
        reject(error);
      }
    });
  }

  onMessage(handler: (envelope: MessageEnvelope) => void): void {
    this.messageHandlers.add(handler);
  }

  removeMessageHandler(handler: (envelope: MessageEnvelope) => void): void {
    this.messageHandlers.delete(handler);
  }

  private handleIncomingMessage(data: string): void {
    try {
      const parsed = JSON.parse(data);
      
      let envelope: MessageEnvelope;
      
      if (parsed.envelope) {
        envelope = parsed.envelope;
        // Deserialize the message if it was serialized
        if (parsed.serializedMessage) {
          envelope.message = MessageProtocol.deserialize(parsed.serializedMessage);
        }
      } else {
        // Assume the data is the envelope itself
        envelope = parsed;
      }

      // Notify all handlers
      this.messageHandlers.forEach(handler => {
        try {
          handler(envelope);
        } catch (error) {
          console.error('Message handler error:', error);
        }
      });

    } catch (error) {
      console.error('Failed to parse incoming message:', error);
    }
  }

  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      if (this.isConnected && this.ws) {
        try {
          this.ws.send(JSON.stringify({ type: 'ping' }));
        } catch (error) {
          console.error('Heartbeat failed:', error);
          this.disconnect();
        }
      }
    }, this.options.heartbeatInterval);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.options.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }

    this.reconnectAttempts++;
    
    setTimeout(() => {
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.options.maxReconnectAttempts})`);
      this.connect().catch(error => {
        console.error('Reconnection failed:', error);
      });
    }, this.options.reconnectInterval);
  }

  getConnectionState(): {
    connected: boolean;
    reconnectAttempts: number;
    url: string;
  } {
    return {
      connected: this.isConnected,
      reconnectAttempts: this.reconnectAttempts,
      url: this.options.url
    };
  }
}