import { WebSocketServer, WebSocket } from 'ws';
import { Server } from 'http';
import { ActivityStreamManager, StreamEvent, StreamFilter, StreamSubscription } from './activity-stream-manager';
import { AgentActivity } from './types';

export interface WebSocketMessage {
  type: MessageType;
  id?: string;
  data?: any;
  error?: string;
}

export enum MessageType {
  // Client to server
  SUBSCRIBE = 'subscribe',
  UNSUBSCRIBE = 'unsubscribe',
  GET_RECENT_EVENTS = 'get_recent_events',
  GET_METRICS = 'get_metrics',
  PING = 'ping',
  
  // Server to client
  EVENT = 'event',
  SUBSCRIBED = 'subscribed',
  UNSUBSCRIBED = 'unsubscribed',
  RECENT_EVENTS = 'recent_events',
  METRICS = 'metrics',
  PONG = 'pong',
  ERROR = 'error'
}

export interface ClientSubscription {
  subscriptionId: string;
  streamSubscription: StreamSubscription;
  filters: StreamFilter;
  clientId: string;
}

export interface WebSocketServerConfig {
  port?: number;
  path?: string;
  enableAuth?: boolean;
  authTimeout?: number;
  maxConnections?: number;
  pingInterval?: number;
  enableCompression?: boolean;
}

export class ActivityWebSocketServer {
  private wss: WebSocketServer;
  private streamManager: ActivityStreamManager;
  private clients: Map<string, WebSocket> = new Map();
  private clientSubscriptions: Map<string, ClientSubscription[]> = new Map();
  private config: Required<WebSocketServerConfig>;
  private pingTimer?: NodeJS.Timeout;

  constructor(
    streamManager: ActivityStreamManager,
    server?: Server,
    config: WebSocketServerConfig = {}
  ) {
    this.streamManager = streamManager;
    this.config = {
      port: config.port || 8080,
      path: config.path || '/activity-stream',
      enableAuth: config.enableAuth ?? false,
      authTimeout: config.authTimeout || 30000,
      maxConnections: config.maxConnections || 1000,
      pingInterval: config.pingInterval || 30000,
      enableCompression: config.enableCompression ?? true
    };

    // Create WebSocket server
    const wsOptions: any = {
      path: this.config.path,
      perMessageDeflate: this.config.enableCompression
    };

    if (server) {
      wsOptions.server = server;
    } else {
      wsOptions.port = this.config.port;
    }

    this.wss = new WebSocketServer(wsOptions);
    
    this.setupEventHandlers();
    this.startPingTimer();
  }

  /**
   * Get server statistics
   */
  getStats(): {
    connectedClients: number;
    totalSubscriptions: number;
    subscriptionsByType: Record<string, number>;
    uptime: number;
  } {
    const subscriptionsByType: Record<string, number> = {};
    let totalSubscriptions = 0;

    this.clientSubscriptions.forEach(subs => {
      totalSubscriptions += subs.length;
      subs.forEach(sub => {
        const filterType = this.getFilterType(sub.filters);
        subscriptionsByType[filterType] = (subscriptionsByType[filterType] || 0) + 1;
      });
    });

    return {
      connectedClients: this.clients.size,
      totalSubscriptions,
      subscriptionsByType,
      uptime: process.uptime()
    };
  }

  /**
   * Broadcast event to all matching clients
   */
  broadcast(event: StreamEvent, filters?: Partial<StreamFilter>): void {
    const message: WebSocketMessage = {
      type: MessageType.EVENT,
      data: event
    };

    this.clients.forEach((ws, clientId) => {
      if (filters) {
        // Check if client has matching subscriptions
        const clientSubs = this.clientSubscriptions.get(clientId) || [];
        const hasMatchingSubscription = clientSubs.some(sub => 
          this.filtersMatch(sub.filters, filters)
        );
        
        if (!hasMatchingSubscription) {
          return;
        }
      }

      this.sendMessage(ws, message);
    });
  }

  /**
   * Send event to specific client
   */
  sendToClient(clientId: string, event: StreamEvent): void {
    const ws = this.clients.get(clientId);
    if (ws && ws.readyState === WebSocket.OPEN) {
      const message: WebSocketMessage = {
        type: MessageType.EVENT,
        data: event
      };
      this.sendMessage(ws, message);
    }
  }

  /**
   * Close the WebSocket server
   */
  close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.pingTimer) {
        clearInterval(this.pingTimer);
      }

      // Close all client connections
      this.clients.forEach(ws => {
        ws.close(1000, 'Server shutting down');
      });

      // Close server
      this.wss.close(() => {
        resolve();
      });
    });
  }

  // Private methods

  private setupEventHandlers(): void {
    this.wss.on('connection', (ws: WebSocket, request: any) => {
      const clientId = this.generateClientId();
      
      // Check connection limit
      if (this.clients.size >= this.config.maxConnections) {
        ws.close(1008, 'Maximum connections exceeded');
        return;
      }

      this.clients.set(clientId, ws);
      this.clientSubscriptions.set(clientId, []);

      console.log(`Client connected: ${clientId} (${this.clients.size} total)`);

      // Set up client event handlers
      ws.on('message', (data: Buffer) => {
        this.handleClientMessage(clientId, ws, data);
      });

      ws.on('close', (code: number, reason: Buffer) => {
        this.handleClientDisconnect(clientId, code, reason.toString());
      });

      ws.on('error', (error: Error) => {
        console.error(`WebSocket error for client ${clientId}:`, error);
        this.handleClientDisconnect(clientId, 1011, 'Unexpected error');
      });

      ws.on('pong', () => {
        // Client responded to ping - connection is alive
        (ws as any).isAlive = true;
      });

      // Send welcome message
      this.sendMessage(ws, {
        type: MessageType.PONG,
        data: {
          clientId,
          message: 'Connected to activity stream',
          serverTime: new Date().toISOString()
        }
      });
    });

    this.wss.on('error', (error: Error) => {
      console.error('WebSocket server error:', error);
    });
  }

  private handleClientMessage(clientId: string, ws: WebSocket, data: Buffer): void {
    try {
      const message: WebSocketMessage = JSON.parse(data.toString());
      
      switch (message.type) {
        case MessageType.SUBSCRIBE:
          this.handleSubscribe(clientId, ws, message);
          break;
          
        case MessageType.UNSUBSCRIBE:
          this.handleUnsubscribe(clientId, ws, message);
          break;
          
        case MessageType.GET_RECENT_EVENTS:
          this.handleGetRecentEvents(clientId, ws, message);
          break;
          
        case MessageType.GET_METRICS:
          this.handleGetMetrics(clientId, ws, message);
          break;
          
        case MessageType.PING:
          this.sendMessage(ws, { type: MessageType.PONG, id: message.id });
          break;
          
        default:
          this.sendError(ws, `Unknown message type: ${message.type}`, message.id);
      }
    } catch (error) {
      this.sendError(ws, `Invalid message format: ${error}`);
    }
  }

  private handleSubscribe(clientId: string, ws: WebSocket, message: WebSocketMessage): void {
    try {
      const filters: StreamFilter = message.data?.filters || {};
      
      // Create stream subscription
      const streamSubscription = this.streamManager.subscribe(
        filters,
        (event: StreamEvent) => {
          this.sendToClient(clientId, event);
        },
        { clientId, subscriptionId: message.id }
      );

      // Store client subscription
      const clientSubscription: ClientSubscription = {
        subscriptionId: message.id || this.generateId(),
        streamSubscription,
        filters,
        clientId
      };

      const clientSubs = this.clientSubscriptions.get(clientId) || [];
      clientSubs.push(clientSubscription);
      this.clientSubscriptions.set(clientId, clientSubs);

      this.sendMessage(ws, {
        type: MessageType.SUBSCRIBED,
        id: message.id,
        data: {
          subscriptionId: clientSubscription.subscriptionId,
          filters
        }
      });

    } catch (error) {
      this.sendError(ws, `Subscription failed: ${error}`, message.id);
    }
  }

  private handleUnsubscribe(clientId: string, ws: WebSocket, message: WebSocketMessage): void {
    const subscriptionId = message.data?.subscriptionId;
    
    if (!subscriptionId) {
      this.sendError(ws, 'Subscription ID required', message.id);
      return;
    }

    const clientSubs = this.clientSubscriptions.get(clientId) || [];
    const subscriptionIndex = clientSubs.findIndex(sub => sub.subscriptionId === subscriptionId);
    
    if (subscriptionIndex === -1) {
      this.sendError(ws, 'Subscription not found', message.id);
      return;
    }

    const subscription = clientSubs[subscriptionIndex];
    subscription.streamSubscription.unsubscribe();
    clientSubs.splice(subscriptionIndex, 1);

    this.sendMessage(ws, {
      type: MessageType.UNSUBSCRIBED,
      id: message.id,
      data: { subscriptionId }
    });
  }

  private handleGetRecentEvents(clientId: string, ws: WebSocket, message: WebSocketMessage): void {
    const { filters, limit } = message.data || {};
    
    const events = this.streamManager.getRecentEvents(filters, limit);
    
    this.sendMessage(ws, {
      type: MessageType.RECENT_EVENTS,
      id: message.id,
      data: { events, count: events.length }
    });
  }

  private handleGetMetrics(clientId: string, ws: WebSocket, message: WebSocketMessage): void {
    const streamMetrics = this.streamManager.getMetrics();
    const subscriptionStats = this.streamManager.getSubscriptionStats();
    const serverStats = this.getStats();
    
    this.sendMessage(ws, {
      type: MessageType.METRICS,
      id: message.id,
      data: {
        stream: streamMetrics,
        subscriptions: subscriptionStats,
        server: serverStats
      }
    });
  }

  private handleClientDisconnect(clientId: string, code: number, reason: string): void {
    console.log(`Client disconnected: ${clientId} (${code}: ${reason})`);
    
    // Clean up subscriptions
    const clientSubs = this.clientSubscriptions.get(clientId) || [];
    clientSubs.forEach(sub => {
      sub.streamSubscription.unsubscribe();
    });
    
    this.clientSubscriptions.delete(clientId);
    this.clients.delete(clientId);
  }

  private sendMessage(ws: WebSocket, message: WebSocketMessage): void {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(message));
      } catch (error) {
        console.error('Failed to send message:', error);
      }
    }
  }

  private sendError(ws: WebSocket, error: string, messageId?: string): void {
    this.sendMessage(ws, {
      type: MessageType.ERROR,
      id: messageId,
      error
    });
  }

  private startPingTimer(): void {
    this.pingTimer = setInterval(() => {
      this.wss.clients.forEach((ws: WebSocket) => {
        if ((ws as any).isAlive === false) {
          ws.terminate();
          return;
        }
        
        (ws as any).isAlive = false;
        ws.ping();
      });
    }, this.config.pingInterval);
  }

  private generateClientId(): string {
    return `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateId(): string {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private getFilterType(filters: StreamFilter): string {
    if (filters.agentDID) return 'agent';
    if (filters.parentDID) return 'user';
    if (filters.critical) return 'critical';
    if (filters.errorOnly) return 'errors';
    if (filters.serviceDID) return 'service';
    if (filters.types) return 'type-specific';
    return 'general';
  }

  private filtersMatch(filter1: StreamFilter, filter2: Partial<StreamFilter>): boolean {
    // Simple filter matching - could be more sophisticated
    if (filter2.agentDID && filter1.agentDID !== filter2.agentDID) return false;
    if (filter2.parentDID && filter1.parentDID !== filter2.parentDID) return false;
    if (filter2.serviceDID && filter1.serviceDID !== filter2.serviceDID) return false;
    if (filter2.critical && !filter1.critical) return false;
    if (filter2.errorOnly && !filter1.errorOnly) return false;
    
    return true;
  }
}