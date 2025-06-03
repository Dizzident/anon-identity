/**
 * Secure Message Router for MCP
 * 
 * Routes messages between agents and LLM providers with security, monitoring, and reliability
 */

import { EventEmitter } from 'events';
import {
  LLMRequest,
  LLMResponse,
  LLMResponseChunk,
  MessageRole,
  ConversationMessage,
  MCPError,
  MCPErrorCode,
  RequestPriority,
  LLMRequestType,
  FunctionCall,
  ConnectionStatus
} from '../types';
import { MCPClient } from '../client';
import { AuthManager } from '../security/auth-manager';
import { AuditLogger, AuditEventType } from '../security/audit-logger';
import { RateLimiterManager } from '../security/rate-limiter';
import { CredentialManager } from '../security/credential-manager';

/**
 * Message routing configuration
 */
export interface RoutingConfig {
  maxRetries: number;
  retryDelay: number;
  timeout: number;
  circuitBreaker: {
    enabled: boolean;
    threshold: number;
    resetTimeout: number;
  };
  loadBalancing: {
    enabled: boolean;
    strategy: 'round-robin' | 'least-connections' | 'weighted' | 'latency-based';
  };
  encryption: {
    enabled: boolean;
    algorithm: string;
  };
}

/**
 * Routed message
 */
export interface RoutedMessage {
  id: string;
  originalRequest: LLMRequest;
  routedTo: string;
  timestamp: Date;
  attempts: number;
  status: 'pending' | 'success' | 'failed' | 'timeout';
  response?: LLMResponse;
  error?: MCPError;
  metrics: {
    queueTime: number;
    routingTime: number;
    responseTime: number;
    totalTime: number;
  };
}

/**
 * Provider health metrics
 */
interface ProviderHealth {
  providerId: string;
  status: ConnectionStatus;
  successRate: number;
  averageLatency: number;
  errorCount: number;
  lastError?: string;
  lastSuccess?: Date;
  circuitBreakerOpen: boolean;
}

/**
 * Message queue entry
 */
interface QueuedMessage {
  request: LLMRequest;
  priority: RequestPriority;
  timestamp: Date;
  resolve: (response: LLMResponse) => void;
  reject: (error: MCPError) => void;
  timeout?: NodeJS.Timeout;
}

/**
 * Secure Message Router
 */
export class MessageRouter extends EventEmitter {
  private messageQueue: Map<RequestPriority, QueuedMessage[]> = new Map();
  private activeRequests: Map<string, RoutedMessage> = new Map();
  private providerHealth: Map<string, ProviderHealth> = new Map();
  private circuitBreakers: Map<string, { open: boolean; resetTime: Date }> = new Map();
  private loadBalancer: LoadBalancer;
  private encryptionKey?: Buffer;
  private isShuttingDown = false;

  constructor(
    private mcpClient: MCPClient,
    private authManager: AuthManager,
    private auditLogger: AuditLogger,
    private rateLimiter: RateLimiterManager,
    private credentialManager: CredentialManager,
    private config: RoutingConfig = {
      maxRetries: 3,
      retryDelay: 1000,
      timeout: 30000,
      circuitBreaker: {
        enabled: true,
        threshold: 5,
        resetTimeout: 60000
      },
      loadBalancing: {
        enabled: true,
        strategy: 'latency-based'
      },
      encryption: {
        enabled: true,
        algorithm: 'aes-256-gcm'
      }
    }
  ) {
    super();
    this.initializeQueues();
    this.loadBalancer = new LoadBalancer(config.loadBalancing.strategy);
    this.setupHealthMonitoring();
    this.startQueueProcessor();
    
    if (config.encryption.enabled) {
      this.initializeEncryption();
    }
  }

  /**
   * Route message to LLM provider
   */
  async routeMessage(request: LLMRequest): Promise<LLMResponse> {
    const routedMessage: RoutedMessage = {
      id: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      originalRequest: request,
      routedTo: '',
      timestamp: new Date(),
      attempts: 0,
      status: 'pending',
      metrics: {
        queueTime: 0,
        routingTime: 0,
        responseTime: 0,
        totalTime: 0
      }
    };

    this.activeRequests.set(routedMessage.id, routedMessage);

    try {
      // Security checks
      await this.performSecurityChecks(request);

      // Encrypt sensitive data if enabled
      if (this.config.encryption.enabled && request.prompt) {
        request = await this.encryptRequest(request);
      }

      // Queue or process immediately based on priority
      if (request.metadata?.priority === RequestPriority.CRITICAL) {
        return await this.processMessageImmediately(routedMessage);
      } else {
        return await this.queueMessage(routedMessage);
      }

    } catch (error) {
      routedMessage.status = 'failed';
      routedMessage.error = error as MCPError;
      
      await this.auditLogger.logResponse(
        {
          id: routedMessage.id,
          status: 'error',
          error: error as MCPError,
          timestamp: new Date(),
          provider: '',
          model: '',
          usage: { totalTokens: 0, promptTokens: 0, completionTokens: 0, model: '', provider: '' }
        },
        request,
        Date.now() - routedMessage.timestamp.getTime()
      );

      throw error;
    } finally {
      this.activeRequests.delete(routedMessage.id);
    }
  }

  /**
   * Stream message to LLM provider
   */
  async *streamMessage(request: LLMRequest): AsyncIterable<LLMResponseChunk> {
    const routedMessage: RoutedMessage = {
      id: `stream-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      originalRequest: request,
      routedTo: '',
      timestamp: new Date(),
      attempts: 0,
      status: 'pending',
      metrics: {
        queueTime: 0,
        routingTime: 0,
        responseTime: 0,
        totalTime: 0
      }
    };

    this.activeRequests.set(routedMessage.id, routedMessage);

    try {
      // Security checks
      await this.performSecurityChecks(request);

      // Select provider
      const provider = await this.selectProvider(request);
      routedMessage.routedTo = provider.id;

      // Get connection
      const connection = await this.mcpClient.getConnection(provider.id);
      if (!connection) {
        throw new MCPError({
          code: MCPErrorCode.CONNECTION_ERROR,
          message: `No connection available for provider ${provider.id}`,
          timestamp: new Date(),
          provider: provider.id,
          retryable: true
        });
      }

      // Start streaming
      const startTime = Date.now();
      let totalTokens = 0;

      for await (const chunk of connection.streamRequest(request)) {
        totalTokens += chunk.tokens || 0;
        
        // Decrypt chunk if needed
        if (this.config.encryption.enabled && chunk.content) {
          chunk.content = await this.decryptContent(chunk.content);
        }

        yield chunk;
      }

      // Log streaming completion
      await this.auditLogger.logResponse(
        {
          id: routedMessage.id,
          status: 'success',
          timestamp: new Date(),
          provider: provider.id,
          model: request.parameters?.model || 'unknown',
          usage: { totalTokens, promptTokens: 0, completionTokens: totalTokens, model: request.parameters?.model || 'unknown', provider: provider.id },
          streaming: true
        },
        request,
        Date.now() - startTime
      );

      // Update provider health
      this.updateProviderHealth(provider.id, true, Date.now() - startTime);

    } catch (error) {
      routedMessage.status = 'failed';
      routedMessage.error = error as MCPError;
      
      this.updateProviderHealth(routedMessage.routedTo, false);
      
      throw error;
    } finally {
      this.activeRequests.delete(routedMessage.id);
    }
  }

  /**
   * Perform security checks
   */
  private async performSecurityChecks(request: LLMRequest): Promise<void> {
    // Check authentication
    const authResult = await this.authManager.authorize(
      request.agentDID,
      'llm:request',
      request.type
    );

    if (!authResult.authorized) {
      throw new MCPError({
        code: MCPErrorCode.FORBIDDEN,
        message: `Authorization denied: ${authResult.deniedReasons?.join(', ')}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Check rate limits
    const rateLimitResult = await this.rateLimiter.checkRateLimit(request);
    
    if (!rateLimitResult.allowed) {
      await this.auditLogger.logSecurityAlert(
        'rate_limit_exceeded',
        request.agentDID,
        { request, reason: rateLimitResult.reason }
      );

      throw new MCPError({
        code: MCPErrorCode.RATE_LIMITED,
        message: rateLimitResult.reason || 'Rate limit exceeded',
        timestamp: new Date(),
        retryable: true,
        details: {
          retryAfter: rateLimitResult.retryAfter,
          resetAt: rateLimitResult.resetAt
        }
      });
    }

    // Check for suspicious patterns
    await this.detectSuspiciousActivity(request);
  }

  /**
   * Detect suspicious activity
   */
  private async detectSuspiciousActivity(request: LLMRequest): Promise<void> {
    const suspiciousPatterns = [
      /jailbreak/i,
      /ignore.*instructions/i,
      /system.*prompt/i,
      /reveal.*instructions/i
    ];

    const isSuspicious = suspiciousPatterns.some(pattern => 
      pattern.test(request.prompt)
    );

    if (isSuspicious) {
      await this.auditLogger.logSecurityAlert(
        'suspicious_prompt',
        request.agentDID,
        { 
          prompt: request.prompt.substring(0, 100),
          patterns: 'jailbreak_attempt'
        }
      );

      this.emit('security_alert', {
        type: 'suspicious_prompt',
        agentDID: request.agentDID,
        timestamp: new Date()
      });
    }
  }

  /**
   * Select provider based on strategy
   */
  private async selectProvider(request: LLMRequest): Promise<{ id: string; score: number }> {
    const availableProviders = await this.getAvailableProviders(request);
    
    if (availableProviders.length === 0) {
      throw new MCPError({
        code: MCPErrorCode.NO_AVAILABLE_PROVIDERS,
        message: 'No available providers for request',
        timestamp: new Date(),
        retryable: true
      });
    }

    // Apply load balancing strategy
    const selected = this.loadBalancer.selectProvider(
      availableProviders,
      this.providerHealth,
      request
    );

    // Check circuit breaker
    if (this.config.circuitBreaker.enabled) {
      const breaker = this.circuitBreakers.get(selected.id);
      if (breaker?.open && breaker.resetTime > new Date()) {
        // Try next best provider
        const alternative = availableProviders.find(p => p.id !== selected.id);
        if (alternative) {
          return alternative;
        }
      }
    }

    return selected;
  }

  /**
   * Get available providers
   */
  private async getAvailableProviders(request: LLMRequest): Promise<Array<{ id: string; score: number }>> {
    const providers = await this.mcpClient.getAvailableProviders();
    const availableProviders: Array<{ id: string; score: number }> = [];

    for (const providerId of providers) {
      // Check if provider supports request type
      const capabilities = await this.mcpClient.getProviderCapabilities(providerId);
      if (!this.supportsRequest(capabilities, request)) {
        continue;
      }

      // Check provider health
      const health = this.providerHealth.get(providerId);
      if (health?.status === ConnectionStatus.ERROR) {
        continue;
      }

      // Check credentials
      const hasCredentials = await this.credentialManager.getCredential(providerId);
      if (!hasCredentials) {
        continue;
      }

      // Calculate provider score
      const score = this.calculateProviderScore(providerId, health, request);
      availableProviders.push({ id: providerId, score });
    }

    // Sort by score
    return availableProviders.sort((a, b) => b.score - a.score);
  }

  /**
   * Calculate provider score
   */
  private calculateProviderScore(
    providerId: string,
    health: ProviderHealth | undefined,
    request: LLMRequest
  ): number {
    let score = 100;

    // Health metrics
    if (health) {
      score *= health.successRate;
      score -= Math.min(health.averageLatency / 100, 50); // Penalize high latency
      score -= health.errorCount * 5;
    }

    // Request-specific scoring
    const provider = this.mcpClient.getProvider(providerId);
    // Provider capability scoring would go here when more detailed capability info is available

    // Priority boost for preferred providers
    if (request.metadata?.preferredProvider === providerId) {
      score *= 1.5;
    }

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Process message immediately
   */
  private async processMessageImmediately(routedMessage: RoutedMessage): Promise<LLMResponse> {
    const startTime = Date.now();
    
    for (let attempt = 0; attempt < this.config.maxRetries; attempt++) {
      routedMessage.attempts = attempt + 1;

      try {
        // Select provider
        const provider = await this.selectProvider(routedMessage.originalRequest);
        routedMessage.routedTo = provider.id;

        // Route to provider
        const response = await this.sendToProvider(
          provider.id,
          routedMessage.originalRequest
        );

        // Update metrics
        routedMessage.metrics.responseTime = Date.now() - startTime;
        routedMessage.metrics.totalTime = Date.now() - routedMessage.timestamp.getTime();
        routedMessage.status = 'success';
        routedMessage.response = response;

        // Update provider health
        this.updateProviderHealth(provider.id, true, routedMessage.metrics.responseTime);

        // Decrypt response if needed
        if (this.config.encryption.enabled && response.content) {
          response.content = await this.decryptContent(response.content);
        }

        return response;

      } catch (error) {
        const mcpError = error as MCPError;
        
        // Update provider health
        if (routedMessage.routedTo) {
          this.updateProviderHealth(routedMessage.routedTo, false);
        }

        // Check if retryable
        if (!mcpError.retryable || attempt === this.config.maxRetries - 1) {
          routedMessage.status = 'failed';
          routedMessage.error = mcpError;
          throw error;
        }

        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 
          this.config.retryDelay * Math.pow(2, attempt)
        ));
      }
    }

    throw new MCPError({
      code: MCPErrorCode.MAX_RETRIES_EXCEEDED,
      message: 'Maximum retries exceeded',
      timestamp: new Date(),
      retryable: false
    });
  }

  /**
   * Queue message for processing
   */
  private async queueMessage(routedMessage: RoutedMessage): Promise<LLMResponse> {
    return new Promise((resolve, reject) => {
      const priority = routedMessage.originalRequest.metadata?.priority || RequestPriority.MEDIUM;
      const queueEntry: QueuedMessage = {
        request: routedMessage.originalRequest,
        priority,
        timestamp: new Date(),
        resolve,
        reject
      };

      // Set timeout
      if (this.config.timeout) {
        queueEntry.timeout = setTimeout(() => {
          reject(new MCPError({
            code: MCPErrorCode.TIMEOUT,
            message: 'Request timeout',
            timestamp: new Date(),
            retryable: true
          }));
          
          // Remove from queue
          const queue = this.messageQueue.get(priority);
          if (queue) {
            const index = queue.indexOf(queueEntry);
            if (index !== -1) {
              queue.splice(index, 1);
            }
          }
        }, this.config.timeout);
      }

      // Add to queue
      const queue = this.messageQueue.get(priority) || [];
      queue.push(queueEntry);
      this.messageQueue.set(priority, queue);

      // Update metrics
      routedMessage.metrics.queueTime = Date.now() - routedMessage.timestamp.getTime();
    });
  }

  /**
   * Send request to provider
   */
  private async sendToProvider(
    providerId: string,
    request: LLMRequest
  ): Promise<LLMResponse> {
    const connection = await this.mcpClient.getConnection(providerId);
    if (!connection) {
      throw new MCPError({
        code: MCPErrorCode.CONNECTION_ERROR,
        message: `No connection available for provider ${providerId}`,
        timestamp: new Date(),
        provider: providerId,
        retryable: true
      });
    }

    // Log request
    const auditId = await this.auditLogger.logRequest(
      request,
      request.agentDID,
      request.sessionId
    );

    try {
      const response = await connection.sendRequest(request);
      
      // Log response
      await this.auditLogger.logResponse(
        response,
        request,
        response.metadata?.duration || 0
      );

      // Record usage
      if (response.usage) {
        await this.rateLimiter.recordUsage(
          request.agentDID,
          response.usage,
          response.provider,
          response.model
        );
      }

      return response;

    } catch (error) {
      // Log error
      await this.auditLogger.logResponse(
        {
          id: auditId,
          status: 'error',
          error: error as MCPError,
          timestamp: new Date(),
          provider: providerId,
          model: request.parameters?.model || 'unknown',
          usage: { totalTokens: 0, promptTokens: 0, completionTokens: 0, model: '', provider: '' }
        },
        request,
        0
      );

      throw error;
    }
  }

  /**
   * Initialize queues
   */
  private initializeQueues(): void {
    this.messageQueue.set(RequestPriority.LOW, []);
    this.messageQueue.set(RequestPriority.MEDIUM, []);
    this.messageQueue.set(RequestPriority.HIGH, []);
    this.messageQueue.set(RequestPriority.CRITICAL, []);
  }

  /**
   * Start queue processor
   */
  private startQueueProcessor(): void {
    setInterval(() => {
      if (this.isShuttingDown) return;
      this.processQueues();
    }, 100); // Process every 100ms
  }

  /**
   * Process message queues
   */
  private async processQueues(): Promise<void> {
    // Process in priority order
    const priorities = [
      RequestPriority.CRITICAL,
      RequestPriority.HIGH,
      RequestPriority.MEDIUM,
      RequestPriority.LOW
    ];

    for (const priority of priorities) {
      const queue = this.messageQueue.get(priority);
      if (!queue || queue.length === 0) continue;

      // Process first message in queue
      const queueEntry = queue.shift();
      if (!queueEntry) continue;

      // Clear timeout
      if (queueEntry.timeout) {
        clearTimeout(queueEntry.timeout);
      }

      // Create routed message
      const routedMessage: RoutedMessage = {
        id: `queued-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        originalRequest: queueEntry.request,
        routedTo: '',
        timestamp: queueEntry.timestamp,
        attempts: 0,
        status: 'pending',
        metrics: {
          queueTime: Date.now() - queueEntry.timestamp.getTime(),
          routingTime: 0,
          responseTime: 0,
          totalTime: 0
        }
      };

      // Process message
      try {
        const response = await this.processMessageImmediately(routedMessage);
        queueEntry.resolve(response);
      } catch (error) {
        queueEntry.reject(error as MCPError);
      }

      // Only process one message per cycle to maintain fairness
      break;
    }
  }

  /**
   * Update provider health metrics
   */
  private updateProviderHealth(
    providerId: string,
    success: boolean,
    latency?: number
  ): void {
    const health = this.providerHealth.get(providerId) || {
      providerId,
      status: ConnectionStatus.CONNECTED,
      successRate: 1,
      averageLatency: 0,
      errorCount: 0,
      circuitBreakerOpen: false
    };

    // Update success rate (exponential moving average)
    const alpha = 0.1; // Smoothing factor
    health.successRate = alpha * (success ? 1 : 0) + (1 - alpha) * health.successRate;

    // Update latency
    if (success && latency) {
      health.averageLatency = alpha * latency + (1 - alpha) * health.averageLatency;
      health.lastSuccess = new Date();
    }

    // Update error count
    if (!success) {
      health.errorCount++;
      
      // Check circuit breaker
      if (this.config.circuitBreaker.enabled && 
          health.errorCount >= this.config.circuitBreaker.threshold) {
        this.openCircuitBreaker(providerId);
        health.circuitBreakerOpen = true;
      }
    } else {
      health.errorCount = 0;
    }

    // Update status
    if (health.successRate < 0.5) {
      health.status = ConnectionStatus.ERROR;
    } else if (health.successRate < 0.8) {
      health.status = ConnectionStatus.RECONNECTING;
    } else {
      health.status = ConnectionStatus.CONNECTED;
    }

    this.providerHealth.set(providerId, health);
    this.emit('provider_health_updated', health);
  }

  /**
   * Open circuit breaker for provider
   */
  private openCircuitBreaker(providerId: string): void {
    const resetTime = new Date(Date.now() + this.config.circuitBreaker.resetTimeout);
    
    this.circuitBreakers.set(providerId, {
      open: true,
      resetTime
    });

    this.emit('circuit_breaker_open', {
      providerId,
      resetTime
    });

    // Schedule circuit breaker reset
    setTimeout(() => {
      this.circuitBreakers.delete(providerId);
      const health = this.providerHealth.get(providerId);
      if (health) {
        health.circuitBreakerOpen = false;
        health.errorCount = 0;
      }
      
      this.emit('circuit_breaker_reset', { providerId });
    }, this.config.circuitBreaker.resetTimeout);
  }

  /**
   * Setup health monitoring
   */
  private setupHealthMonitoring(): void {
    setInterval(async () => {
      if (this.isShuttingDown) return;

      for (const [providerId] of this.providerHealth) {
        try {
          const connection = await this.mcpClient.getConnection(providerId);
          if (connection) {
            const health = await connection.health();
            if (health.status === 'healthy') {
              this.updateProviderHealth(providerId, true, health.latency);
            } else {
              this.updateProviderHealth(providerId, false);
            }
          }
        } catch (error) {
          this.updateProviderHealth(providerId, false);
        }
      }
    }, 30000); // Check every 30 seconds
  }

  /**
   * Initialize encryption
   */
  private async initializeEncryption(): Promise<void> {
    // In production, get key from secure key management
    const crypto = await import('crypto');
    this.encryptionKey = crypto.randomBytes(32);
  }

  /**
   * Encrypt request
   */
  private async encryptRequest(request: LLMRequest): Promise<LLMRequest> {
    if (!this.encryptionKey) return request;

    const encrypted = { ...request };
    if (encrypted.prompt) {
      encrypted.prompt = await this.encryptContent(encrypted.prompt);
    }
    
    return encrypted;
  }

  /**
   * Encrypt content
   */
  private async encryptContent(content: string): Promise<string> {
    if (!this.encryptionKey) return content;

    const crypto = await import('crypto');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      this.config.encryption.algorithm,
      this.encryptionKey,
      iv
    );

    let encrypted = cipher.update(content, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    const tag = (cipher as any).getAuthTag();
    
    return JSON.stringify({
      encrypted,
      iv: iv.toString('base64'),
      tag: tag.toString('base64')
    });
  }

  /**
   * Decrypt content
   */
  private async decryptContent(encryptedData: string): Promise<string> {
    if (!this.encryptionKey) return encryptedData;

    try {
      const { encrypted, iv, tag } = JSON.parse(encryptedData);
      const crypto = await import('crypto');
      
      const decipher = crypto.createDecipheriv(
        this.config.encryption.algorithm,
        this.encryptionKey,
        Buffer.from(iv, 'base64')
      );
      
      (decipher as any).setAuthTag(Buffer.from(tag, 'base64'));

      let decrypted = decipher.update(encrypted, 'base64', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch {
      // If decryption fails, assume content is not encrypted
      return encryptedData;
    }
  }

  /**
   * Check if provider supports request
   */
  private supportsRequest(capabilities: any, request: LLMRequest): boolean {
    switch (request.type) {
      case LLMRequestType.COMPLETION:
        return capabilities?.completion === true;
      case LLMRequestType.FUNCTION_CALL:
        return capabilities?.functionCalling === true;
      case LLMRequestType.EMBEDDING:
        return capabilities?.embeddings === true;
      case LLMRequestType.MODERATION:
        return capabilities?.moderation === true;
      default:
        return false;
    }
  }

  /**
   * Get routing statistics
   */
  getStatistics(): {
    activeRequests: number;
    queuedRequests: Record<RequestPriority, number>;
    providerHealth: ProviderHealth[];
    circuitBreakers: Array<{ providerId: string; open: boolean; resetTime?: Date }>;
    successRate: number;
    averageLatency: number;
  } {
    const queuedRequests: Record<RequestPriority, number> = {} as any;
    for (const [priority, queue] of this.messageQueue) {
      queuedRequests[priority] = queue.length;
    }

    const providerHealthArray = Array.from(this.providerHealth.values());
    const overallSuccessRate = providerHealthArray.reduce((sum, h) => sum + h.successRate, 0) / 
                               (providerHealthArray.length || 1);
    const overallLatency = providerHealthArray.reduce((sum, h) => sum + h.averageLatency, 0) / 
                          (providerHealthArray.length || 1);

    const circuitBreakerStatus = Array.from(this.circuitBreakers.entries()).map(([providerId, breaker]) => ({
      providerId,
      open: breaker.open,
      resetTime: breaker.resetTime
    }));

    return {
      activeRequests: this.activeRequests.size,
      queuedRequests,
      providerHealth: providerHealthArray,
      circuitBreakers: circuitBreakerStatus,
      successRate: overallSuccessRate,
      averageLatency: overallLatency
    };
  }

  /**
   * Route streaming message
   */
  async routeStreamingMessage(request: LLMRequest): Promise<AsyncIterable<LLMResponseChunk> & { providerId?: string; model?: string }> {
    // Set streaming flag
    const streamingRequest = { ...request, streaming: true };
    
    // Route to provider using standard routing logic
    const response = await this.routeMessage(streamingRequest);
    
    // Create async iterable for streaming
    async function* streamGenerator() {
      // Mock streaming implementation
      const content = response.content || '';
      const chunks = content.split(' ');
      
      for (let i = 0; i < chunks.length; i++) {
        const chunk: LLMResponseChunk = {
          id: `chunk-${i}`,
          type: 'chunk',
          delta: i === 0 ? chunks[i] : ' ' + chunks[i],
          tokens: 1,
          timestamp: new Date(),
          metadata: {
            chunkIndex: i,
            isLast: i === chunks.length - 1
          }
        };
        
        yield chunk;
        
        // Add small delay to simulate streaming
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    }
    
    const stream = streamGenerator();
    (stream as any).providerId = response.provider;
    (stream as any).model = response.model;
    
    return stream as AsyncIterable<LLMResponseChunk> & { providerId?: string; model?: string };
  }

  /**
   * Shutdown router
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true;

    // Clear all queues
    for (const [, queue] of this.messageQueue) {
      for (const entry of queue) {
        if (entry.timeout) {
          clearTimeout(entry.timeout);
        }
        entry.reject(new MCPError({
          code: MCPErrorCode.PROVIDER_ERROR,
          message: 'Router shutting down',
          timestamp: new Date(),
          retryable: false
        }));
      }
    }

    this.messageQueue.clear();
    this.activeRequests.clear();
    this.providerHealth.clear();
    this.circuitBreakers.clear();
    
    this.removeAllListeners();
  }
}

/**
 * Load balancer for provider selection
 */
class LoadBalancer {
  private roundRobinIndex = 0;

  constructor(private strategy: string) {}

  selectProvider(
    providers: Array<{ id: string; score: number }>,
    health: Map<string, ProviderHealth>,
    request: LLMRequest
  ): { id: string; score: number } {
    switch (this.strategy) {
      case 'round-robin':
        return this.roundRobin(providers);
      
      case 'least-connections':
        return this.leastConnections(providers, health);
      
      case 'weighted':
        return this.weighted(providers);
      
      case 'latency-based':
        return this.latencyBased(providers, health);
      
      default:
        return providers[0];
    }
  }

  private roundRobin(providers: Array<{ id: string; score: number }>): { id: string; score: number } {
    const selected = providers[this.roundRobinIndex % providers.length];
    this.roundRobinIndex++;
    return selected;
  }

  private leastConnections(
    providers: Array<{ id: string; score: number }>,
    health: Map<string, ProviderHealth>
  ): { id: string; score: number } {
    // In a real implementation, track active connections per provider
    return providers[0];
  }

  private weighted(providers: Array<{ id: string; score: number }>): { id: string; score: number } {
    // Select based on scores
    const totalScore = providers.reduce((sum, p) => sum + p.score, 0);
    let random = Math.random() * totalScore;
    
    for (const provider of providers) {
      random -= provider.score;
      if (random <= 0) {
        return provider;
      }
    }
    
    return providers[0];
  }

  private latencyBased(
    providers: Array<{ id: string; score: number }>,
    health: Map<string, ProviderHealth>
  ): { id: string; score: number } {
    // Sort by latency
    return providers.sort((a, b) => {
      const healthA = health.get(a.id);
      const healthB = health.get(b.id);
      const latencyA = healthA?.averageLatency || Infinity;
      const latencyB = healthB?.averageLatency || Infinity;
      return latencyA - latencyB;
    })[0];
  }
}

export default MessageRouter;