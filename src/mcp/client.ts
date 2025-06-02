/**
 * MCP (Model Context Protocol) Client Implementation
 * 
 * Core client for connecting to MCP servers and managing LLM provider interactions
 */

import { EventEmitter } from 'events';
import {
  MCPMessage,
  MCPMessageType,
  LLMRequest,
  LLMResponse,
  LLMResponseChunk,
  MCPProvider,
  MCPConnection,
  ConnectionStatus,
  MCPConfig,
  MCPClientConfig,
  MCPError,
  MCPErrorCode,
  ResponseStatus,
  RequestMetadata,
  ConversationContext,
  ProviderStatus,
  HealthCheckConfig,
  HealthCheck,
  LLMParameters,
  UsageInfo,
  RequestPriority
} from './types';

/**
 * Connection manager for individual MCP connections
 */
class MCPConnectionManager extends EventEmitter {
  private connections: Map<string, MCPConnection> = new Map();
  private connectionAttempts: Map<string, number> = new Map();
  private lastHeartbeat: Map<string, Date> = new Map();
  
  constructor(private config: MCPClientConfig) {
    super();
    this.startHeartbeatMonitoring();
  }

  /**
   * Create connection to MCP server
   */
  async connect(providerId: string, endpoint: string): Promise<MCPConnection> {
    try {
      const connection = new MCPConnectionImpl(providerId, endpoint, this.config);
      await connection.connect();
      
      this.connections.set(providerId, connection);
      this.connectionAttempts.set(providerId, 0);
      this.lastHeartbeat.set(providerId, new Date());
      
      // Set up connection event handlers
      connection.on('disconnect', () => this.handleDisconnection(providerId));
      connection.on('error', (error) => this.handleConnectionError(providerId, error));
      connection.on('heartbeat', () => this.lastHeartbeat.set(providerId, new Date()));
      
      this.emit('connected', providerId);
      return connection;
    } catch (error) {
      const attempts = this.connectionAttempts.get(providerId) || 0;
      this.connectionAttempts.set(providerId, attempts + 1);
      
      if (attempts < this.config.retryAttempts) {
        // Exponential backoff retry
        const delay = Math.min(
          this.config.retryDelay * Math.pow(this.config.backoffMultiplier, attempts),
          this.config.maxRetryDelay
        );
        
        setTimeout(() => this.connect(providerId, endpoint), delay);
      }
      
      throw new MCPError({
        code: MCPErrorCode.NETWORK_ERROR,
        message: `Failed to connect to provider ${providerId}: ${error}`,
        timestamp: new Date(),
        provider: providerId,
        retryable: attempts < this.config.retryAttempts
      });
    }
  }

  /**
   * Get connection by provider ID
   */
  getConnection(providerId: string): MCPConnection | undefined {
    return this.connections.get(providerId);
  }

  /**
   * Get all active connections
   */
  getAllConnections(): Map<string, MCPConnection> {
    return new Map(this.connections);
  }

  /**
   * Disconnect from provider
   */
  async disconnect(providerId: string): Promise<void> {
    const connection = this.connections.get(providerId);
    if (connection) {
      await connection.disconnect();
      this.connections.delete(providerId);
      this.connectionAttempts.delete(providerId);
      this.lastHeartbeat.delete(providerId);
      this.emit('disconnected', providerId);
    }
  }

  /**
   * Disconnect from all providers
   */
  async disconnectAll(): Promise<void> {
    const disconnectPromises = Array.from(this.connections.keys()).map(
      (providerId) => this.disconnect(providerId)
    );
    await Promise.all(disconnectPromises);
  }

  /**
   * Handle connection disconnection
   */
  private handleDisconnection(providerId: string): void {
    this.connections.delete(providerId);
    this.emit('disconnected', providerId);
    
    // Attempt reconnection if configured
    if (this.config.keepAlive) {
      this.emit('reconnecting', providerId);
    }
  }

  /**
   * Handle connection errors
   */
  private handleConnectionError(providerId: string, error: Error): void {
    this.emit('error', providerId, error);
  }

  /**
   * Monitor connection health via heartbeats
   */
  private startHeartbeatMonitoring(): void {
    if (!this.config.heartbeatInterval) return;

    setInterval(() => {
      const now = new Date();
      
      for (const [providerId, lastHeartbeat] of this.lastHeartbeat.entries()) {
        const timeSinceHeartbeat = now.getTime() - lastHeartbeat.getTime();
        
        if (timeSinceHeartbeat > this.config.heartbeatInterval * 2) {
          // Connection appears dead
          this.handleDisconnection(providerId);
        }
      }
    }, this.config.heartbeatInterval);
  }
}

/**
 * Concrete implementation of MCPConnection
 */
class MCPConnectionImpl extends EventEmitter implements MCPConnection {
  public readonly id: string;
  public readonly providerId: string;
  public status: ConnectionStatus = ConnectionStatus.DISCONNECTED;
  public lastHeartbeat: Date = new Date();
  public createdAt: Date = new Date();
  public metadata: any;

  private ws: WebSocket | null = null;
  private requestId = 0;
  private pendingRequests: Map<string, {
    resolve: (value: LLMResponse) => void;
    reject: (error: MCPError) => void;
    timeout: NodeJS.Timeout;
  }> = new Map();
  
  constructor(
    providerId: string,
    private readonly endpoint: string,
    private readonly config: MCPClientConfig
  ) {
    super();
    this.id = `conn-${providerId}-${Date.now()}`;
    this.providerId = providerId;
    this.metadata = {
      endpoint: this.endpoint,
      version: '1.0.0',
      features: [],
      retryCount: 0
    };
  }

  /**
   * Connect to MCP server
   */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.endpoint);
        
        this.ws.onopen = () => {
          this.status = ConnectionStatus.CONNECTED;
          this.startHeartbeat();
          resolve();
        };
        
        this.ws.onmessage = (event) => {
          this.handleMessage(JSON.parse(event.data));
        };
        
        this.ws.onclose = () => {
          this.status = ConnectionStatus.DISCONNECTED;
          this.emit('disconnect');
        };
        
        this.ws.onerror = (error) => {
          reject(new Error(`WebSocket error: ${error}`));
        };
        
        // Connection timeout
        setTimeout(() => {
          if (this.ws?.readyState !== WebSocket.OPEN) {
            reject(new Error('Connection timeout'));
          }
        }, this.config.timeout);
        
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Disconnect from MCP server
   */
  async disconnect(): Promise<void> {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.status = ConnectionStatus.DISCONNECTED;
    
    // Clear pending requests
    for (const [requestId, { reject, timeout }] of this.pendingRequests.entries()) {
      clearTimeout(timeout);
      reject(new MCPError({
        code: MCPErrorCode.NETWORK_ERROR,
        message: 'Connection closed',
        timestamp: new Date(),
        requestId,
        retryable: false
      }));
    }
    this.pendingRequests.clear();
  }

  /**
   * Send LLM request and await response
   */
  async sendRequest(request: LLMRequest): Promise<LLMResponse> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new MCPError({
        code: MCPErrorCode.NETWORK_ERROR,
        message: 'Connection not available',
        timestamp: new Date(),
        provider: this.providerId,
        retryable: true
      });
    }

    const requestId = `${this.providerId}-${++this.requestId}`;
    const message: MCPMessage = {
      id: requestId,
      type: MCPMessageType.REQUEST,
      timestamp: new Date(),
      sender: 'client',
      recipient: this.providerId,
      payload: request,
      metadata: {
        requestType: request.type,
        agentDID: request.agentDID,
        sessionId: request.sessionId
      }
    };

    return new Promise((resolve, reject) => {
      // Set up timeout
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new MCPError({
          code: MCPErrorCode.TIMEOUT,
          message: `Request timeout after ${this.config.timeout}ms`,
          timestamp: new Date(),
          requestId,
          provider: this.providerId,
          retryable: true
        }));
      }, this.config.timeout);

      // Store pending request
      this.pendingRequests.set(requestId, { resolve, reject, timeout });

      // Send message
      this.ws!.send(JSON.stringify(message));
    });
  }

  /**
   * Send streaming LLM request
   */
  async *streamRequest(request: LLMRequest): AsyncIterable<LLMResponseChunk> {
    // Implementation for streaming would depend on the MCP server protocol
    // This is a placeholder that would need to be implemented based on
    // the actual MCP streaming specification
    throw new Error('Streaming not yet implemented');
  }

  /**
   * Check connection health
   */
  async health(): Promise<{ status: 'healthy' | 'unhealthy'; latency?: number }> {
    const start = Date.now();
    
    try {
      await this.sendHeartbeat();
      const latency = Date.now() - start;
      
      return {
        status: 'healthy',
        latency
      };
    } catch (error) {
      return {
        status: 'unhealthy'
      };
    }
  }

  /**
   * Handle incoming messages from MCP server
   */
  private handleMessage(message: MCPMessage): void {
    switch (message.type) {
      case MCPMessageType.RESPONSE:
        this.handleResponse(message);
        break;
      case MCPMessageType.ERROR:
        this.handleError(message);
        break;
      case MCPMessageType.HEARTBEAT:
        this.lastHeartbeat = new Date();
        this.emit('heartbeat');
        break;
      case MCPMessageType.NOTIFICATION:
        this.emit('notification', message.payload);
        break;
    }
  }

  /**
   * Handle response messages
   */
  private handleResponse(message: MCPMessage): void {
    const pending = this.pendingRequests.get(message.id);
    if (pending) {
      clearTimeout(pending.timeout);
      this.pendingRequests.delete(message.id);
      pending.resolve(message.payload as LLMResponse);
    }
  }

  /**
   * Handle error messages
   */
  private handleError(message: MCPMessage): void {
    const pending = this.pendingRequests.get(message.id);
    if (pending) {
      clearTimeout(pending.timeout);
      this.pendingRequests.delete(message.id);
      pending.reject(message.payload as MCPError);
    }
  }

  /**
   * Send heartbeat to maintain connection
   */
  private async sendHeartbeat(): Promise<void> {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      const heartbeat: MCPMessage = {
        id: `heartbeat-${Date.now()}`,
        type: MCPMessageType.HEARTBEAT,
        timestamp: new Date(),
        sender: 'client',
        recipient: this.providerId,
        payload: {}
      };
      
      this.ws.send(JSON.stringify(heartbeat));
    }
  }

  /**
   * Start periodic heartbeat
   */
  private startHeartbeat(): void {
    if (this.config.heartbeatInterval) {
      setInterval(() => {
        this.sendHeartbeat();
      }, this.config.heartbeatInterval);
    }
  }
}

/**
 * Main MCP Client class
 */
export class MCPClient extends EventEmitter {
  private connectionManager: MCPConnectionManager;
  private providers: Map<string, MCPProvider> = new Map();
  private defaultProvider?: string;
  private requestMetrics: Map<string, UsageInfo[]> = new Map();

  constructor(private config: MCPConfig) {
    super();
    this.connectionManager = new MCPConnectionManager(config.client);
    
    // Set up connection manager event handlers
    this.connectionManager.on('connected', (providerId) => this.emit('connected', providerId));
    this.connectionManager.on('disconnected', (providerId) => this.emit('disconnected', providerId));
    this.connectionManager.on('error', (providerId, error) => this.emit('error', providerId, error));
  }

  /**
   * Initialize MCP client and connect to providers
   */
  async initialize(): Promise<void> {
    // Register and connect to all configured providers
    for (const providerConfig of this.config.providers) {
      if (providerConfig.enabled) {
        await this.addProvider(providerConfig);
      }
    }

    // Set default provider if not set
    if (!this.defaultProvider && this.providers.size > 0) {
      this.defaultProvider = Array.from(this.providers.keys())[0];
    }
  }

  /**
   * Add and connect to a provider
   */
  async addProvider(providerConfig: any): Promise<void> {
    const provider: MCPProvider = {
      id: providerConfig.id,
      name: providerConfig.id,
      version: '1.0.0',
      description: `${providerConfig.id} provider`,
      capabilities: {
        completion: true,
        streaming: false,
        functionCalling: true,
        embeddings: false,
        moderation: false,
        multimodal: false,
        codeGeneration: true,
        jsonMode: true
      },
      models: [],
      rateLimits: providerConfig.rateLimits || {
        requestsPerMinute: 60,
        tokensPerMinute: 100000,
        requestsPerDay: 1000,
        tokensPerDay: 1000000,
        concurrentRequests: 10
      },
      config: providerConfig,
      status: ProviderStatus.AVAILABLE
    };

    this.providers.set(provider.id, provider);
    await this.connectionManager.connect(provider.id, providerConfig.endpoint);
  }

  /**
   * Send request to specific provider
   */
  async sendRequest(request: LLMRequest, providerId?: string): Promise<LLMResponse> {
    const targetProvider = providerId || this.defaultProvider;
    
    if (!targetProvider) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: 'No provider available',
        timestamp: new Date(),
        retryable: false
      });
    }

    const connection = this.connectionManager.getConnection(targetProvider);
    if (!connection) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: `Provider ${targetProvider} not connected`,
        timestamp: new Date(),
        provider: targetProvider,
        retryable: true
      });
    }

    // Add request metadata
    const enhancedRequest: LLMRequest = {
      ...request,
      metadata: {
        ...request.metadata,
        requestId: `${targetProvider}-${Date.now()}`,
        timestamp: new Date(),
        source: 'mcp-client'
      }
    };

    try {
      const response = await connection.sendRequest(enhancedRequest);
      
      // Track usage metrics
      if (response.usage) {
        const providerMetrics = this.requestMetrics.get(targetProvider) || [];
        providerMetrics.push(response.usage);
        this.requestMetrics.set(targetProvider, providerMetrics);
      }

      return response;
    } catch (error) {
      // Handle provider failover if enabled
      if (error instanceof MCPError && error.retryable && this.config.providers.length > 1) {
        const alternativeProviders = Array.from(this.providers.keys())
          .filter(id => id !== targetProvider);
        
        if (alternativeProviders.length > 0) {
          return this.sendRequest(request, alternativeProviders[0]);
        }
      }
      
      throw error;
    }
  }

  /**
   * Send streaming request
   */
  async *streamRequest(request: LLMRequest, providerId?: string): AsyncIterable<LLMResponseChunk> {
    const targetProvider = providerId || this.defaultProvider;
    
    if (!targetProvider) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: 'No provider available',
        timestamp: new Date(),
        retryable: false
      });
    }

    const connection = this.connectionManager.getConnection(targetProvider);
    if (!connection) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: `Provider ${targetProvider} not connected`,
        timestamp: new Date(),
        provider: targetProvider,
        retryable: true
      });
    }

    yield* connection.streamRequest(request);
  }

  /**
   * Get available providers
   */
  getAvailableProviders(): string[] {
    return Array.from(this.providers.keys()).filter(
      (providerId) => this.connectionManager.getConnection(providerId) !== undefined
    );
  }

  /**
   * Get provider information
   */
  getProvider(providerId: string): MCPProvider | undefined {
    return this.providers.get(providerId);
  }

  /**
   * Get usage statistics for provider
   */
  getUsageStats(providerId: string): UsageInfo[] {
    return this.requestMetrics.get(providerId) || [];
  }

  /**
   * Set default provider
   */
  setDefaultProvider(providerId: string): void {
    if (this.providers.has(providerId)) {
      this.defaultProvider = providerId;
    } else {
      throw new Error(`Provider ${providerId} not available`);
    }
  }

  /**
   * Health check for all providers
   */
  async healthCheck(): Promise<Map<string, any>> {
    const results = new Map();
    
    for (const providerId of this.providers.keys()) {
      const connection = this.connectionManager.getConnection(providerId);
      if (connection) {
        try {
          const health = await connection.health();
          results.set(providerId, health);
        } catch (error) {
          results.set(providerId, { status: 'unhealthy', error: (error as Error).message });
        }
      } else {
        results.set(providerId, { status: 'disconnected' });
      }
    }
    
    return results;
  }

  /**
   * Shutdown MCP client
   */
  async shutdown(): Promise<void> {
    await this.connectionManager.disconnectAll();
    this.removeAllListeners();
  }
}

export { MCPConnectionManager, MCPConnectionImpl };