/**
 * Connection Management System for MCP
 * 
 * Handles provider connections, health monitoring, failover, and load balancing
 */

import { EventEmitter } from 'events';
import {
  MCPConnection,
  MCPProvider,
  ProviderStatus,
  ConnectionStatus,
  MCPError,
  MCPErrorCode,
  HealthCheck,
  HealthCheckType,
  LLMRequest,
  LLMResponse,
  RequestPriority,
  MCPClientConfig,
  RateLimitInfo
} from './types';

/**
 * Provider health monitor
 */
class ProviderHealthMonitor extends EventEmitter {
  private healthChecks: Map<string, NodeJS.Timeout> = new Map();
  private healthHistory: Map<string, boolean[]> = new Map();
  private maxHealthHistory = 10;

  constructor(private config: { interval: number; timeout: number }) {
    super();
  }

  /**
   * Start monitoring provider health
   */
  startMonitoring(providerId: string, connection: MCPConnection): void {
    if (this.healthChecks.has(providerId)) {
      this.stopMonitoring(providerId);
    }

    const interval = setInterval(async () => {
      try {
        const healthResult = await Promise.race([
          connection.health(),
          this.createTimeout(this.config.timeout)
        ]);

        const isHealthy = healthResult.status === 'healthy';
        this.recordHealthCheck(providerId, isHealthy);

        if (!isHealthy) {
          this.emit('unhealthy', providerId, healthResult);
        }
      } catch (error) {
        this.recordHealthCheck(providerId, false);
        this.emit('unhealthy', providerId, { status: 'unhealthy', error });
      }
    }, this.config.interval);

    this.healthChecks.set(providerId, interval);
  }

  /**
   * Stop monitoring provider health
   */
  stopMonitoring(providerId: string): void {
    const interval = this.healthChecks.get(providerId);
    if (interval) {
      clearInterval(interval);
      this.healthChecks.delete(providerId);
    }
  }

  /**
   * Get provider health score (0-1)
   */
  getHealthScore(providerId: string): number {
    const history = this.healthHistory.get(providerId) || [];
    if (history.length === 0) return 1; // No history, assume healthy

    const healthyCount = history.filter(Boolean).length;
    return healthyCount / history.length;
  }

  /**
   * Record health check result
   */
  private recordHealthCheck(providerId: string, isHealthy: boolean): void {
    const history = this.healthHistory.get(providerId) || [];
    history.push(isHealthy);

    if (history.length > this.maxHealthHistory) {
      history.shift();
    }

    this.healthHistory.set(providerId, history);
  }

  /**
   * Create timeout promise
   */
  private createTimeout(ms: number): Promise<{ status: 'unhealthy' }> {
    return new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Health check timeout')), ms);
    });
  }

  /**
   * Stop all monitoring
   */
  stopAll(): void {
    for (const providerId of this.healthChecks.keys()) {
      this.stopMonitoring(providerId);
    }
  }
}

/**
 * Load balancer for distributing requests across providers
 */
class LoadBalancer {
  private requestCounts: Map<string, number> = new Map();
  private lastUsed: Map<string, number> = new Map();

  /**
   * Select best provider using round-robin with health weighting
   */
  selectProvider(
    providers: string[],
    healthMonitor: ProviderHealthMonitor,
    strategy: 'round-robin' | 'least-connections' | 'health-weighted' = 'health-weighted'
  ): string | undefined {
    if (providers.length === 0) return undefined;
    if (providers.length === 1) return providers[0];

    switch (strategy) {
      case 'round-robin':
        return this.roundRobinSelection(providers);
      case 'least-connections':
        return this.leastConnectionsSelection(providers);
      case 'health-weighted':
        return this.healthWeightedSelection(providers, healthMonitor);
      default:
        return providers[0];
    }
  }

  /**
   * Record request for load balancing metrics
   */
  recordRequest(providerId: string): void {
    const count = this.requestCounts.get(providerId) || 0;
    this.requestCounts.set(providerId, count + 1);
    this.lastUsed.set(providerId, Date.now());
  }

  /**
   * Round-robin selection
   */
  private roundRobinSelection(providers: string[]): string {
    // Find provider with oldest last used time
    let selected = providers[0];
    let oldestTime = this.lastUsed.get(selected) || 0;

    for (const provider of providers) {
      const lastTime = this.lastUsed.get(provider) || 0;
      if (lastTime < oldestTime) {
        selected = provider;
        oldestTime = lastTime;
      }
    }

    return selected;
  }

  /**
   * Least connections selection
   */
  private leastConnectionsSelection(providers: string[]): string {
    let selected = providers[0];
    let minConnections = this.requestCounts.get(selected) || 0;

    for (const provider of providers) {
      const connections = this.requestCounts.get(provider) || 0;
      if (connections < minConnections) {
        selected = provider;
        minConnections = connections;
      }
    }

    return selected;
  }

  /**
   * Health-weighted selection
   */
  private healthWeightedSelection(
    providers: string[],
    healthMonitor: ProviderHealthMonitor
  ): string {
    // Calculate weighted scores
    const scores = providers.map(provider => ({
      provider,
      score: this.calculateProviderScore(provider, healthMonitor)
    }));

    // Sort by score (highest first)
    scores.sort((a, b) => b.score - a.score);

    // Return best provider
    return scores[0].provider;
  }

  /**
   * Calculate provider score for selection
   */
  private calculateProviderScore(
    provider: string,
    healthMonitor: ProviderHealthMonitor
  ): number {
    const healthScore = healthMonitor.getHealthScore(provider);
    const requestCount = this.requestCounts.get(provider) || 0;
    const lastUsed = this.lastUsed.get(provider) || 0;
    const timeSinceUsed = Date.now() - lastUsed;

    // Weight factors
    const healthWeight = 0.5;
    const loadWeight = 0.3;
    const freshnessWeight = 0.2;

    // Calculate component scores
    const normalizedLoad = Math.max(0, 1 - (requestCount / 100)); // Assume 100 as high load
    const normalizedFreshness = Math.min(1, timeSinceUsed / (5 * 60 * 1000)); // 5 minutes

    return (
      healthScore * healthWeight +
      normalizedLoad * loadWeight +
      normalizedFreshness * freshnessWeight
    );
  }
}

/**
 * Rate limiter for provider requests
 */
class RateLimiter {
  private requestCounts: Map<string, number[]> = new Map();
  private tokenCounts: Map<string, number[]> = new Map();

  /**
   * Check if request is allowed under rate limits
   */
  isAllowed(providerId: string, rateLimits: RateLimitInfo, tokens: number = 0): boolean {
    const now = Date.now();
    const minuteAgo = now - 60 * 1000;
    const dayAgo = now - 24 * 60 * 60 * 1000;

    // Clean old entries
    this.cleanOldEntries(providerId, minuteAgo, dayAgo);

    const recentRequests = this.requestCounts.get(providerId) || [];
    const recentTokens = this.tokenCounts.get(providerId) || [];

    // Check request limits
    const requestsThisMinute = recentRequests.filter(time => time > minuteAgo).length;
    const requestsToday = recentRequests.filter(time => time > dayAgo).length;

    if (requestsThisMinute >= rateLimits.requestsPerMinute) return false;
    if (requestsToday >= rateLimits.requestsPerDay) return false;

    // Check token limits
    const tokensThisMinute = recentTokens
      .filter(entry => entry > minuteAgo)
      .reduce((sum, entry) => sum + (entry as any).tokens, 0);
    const tokensToday = recentTokens
      .filter(entry => entry > dayAgo)
      .reduce((sum, entry) => sum + (entry as any).tokens, 0);

    if (tokensThisMinute + tokens > rateLimits.tokensPerMinute) return false;
    if (tokensToday + tokens > rateLimits.tokensPerDay) return false;

    return true;
  }

  /**
   * Record request for rate limiting
   */
  recordRequest(providerId: string, tokens: number = 0): void {
    const now = Date.now();

    // Record request
    const requests = this.requestCounts.get(providerId) || [];
    requests.push(now);
    this.requestCounts.set(providerId, requests);

    // Record tokens
    if (tokens > 0) {
      const tokenEntries = this.tokenCounts.get(providerId) || [];
      tokenEntries.push({ time: now, tokens } as any);
      this.tokenCounts.set(providerId, tokenEntries);
    }
  }

  /**
   * Clean old entries
   */
  private cleanOldEntries(providerId: string, minuteAgo: number, dayAgo: number): void {
    // Clean request counts
    const requests = this.requestCounts.get(providerId) || [];
    const recentRequests = requests.filter(time => time > dayAgo);
    this.requestCounts.set(providerId, recentRequests);

    // Clean token counts
    const tokens = this.tokenCounts.get(providerId) || [];
    const recentTokens = tokens.filter((entry: any) => entry.time > dayAgo);
    this.tokenCounts.set(providerId, recentTokens);
  }

  /**
   * Get current usage stats
   */
  getUsageStats(providerId: string, rateLimits: RateLimitInfo): {
    requestsPerMinute: { used: number; limit: number };
    tokensPerMinute: { used: number; limit: number };
    requestsPerDay: { used: number; limit: number };
    tokensPerDay: { used: number; limit: number };
  } {
    const now = Date.now();
    const minuteAgo = now - 60 * 1000;
    const dayAgo = now - 24 * 60 * 60 * 1000;

    const requests = this.requestCounts.get(providerId) || [];
    const tokens = this.tokenCounts.get(providerId) || [];

    const requestsThisMinute = requests.filter(time => time > minuteAgo).length;
    const requestsToday = requests.filter(time => time > dayAgo).length;

    const tokensThisMinute = tokens
      .filter((entry: any) => entry.time > minuteAgo)
      .reduce((sum, entry: any) => sum + entry.tokens, 0);
    const tokensToday = tokens
      .filter((entry: any) => entry.time > dayAgo)
      .reduce((sum, entry: any) => sum + entry.tokens, 0);

    return {
      requestsPerMinute: { used: requestsThisMinute, limit: rateLimits.requestsPerMinute },
      tokensPerMinute: { used: tokensThisMinute, limit: rateLimits.tokensPerMinute },
      requestsPerDay: { used: requestsToday, limit: rateLimits.requestsPerDay },
      tokensPerDay: { used: tokensToday, limit: rateLimits.tokensPerDay }
    };
  }
}

/**
 * Failover manager for handling provider failures
 */
class FailoverManager extends EventEmitter {
  private failoverHistory: Map<string, Date[]> = new Map();
  private maxFailoverAttempts = 3;
  private failoverWindow = 5 * 60 * 1000; // 5 minutes

  /**
   * Handle provider failure and attempt failover
   */
  async handleFailure(
    failedProvider: string,
    availableProviders: string[],
    request: LLMRequest,
    error: MCPError
  ): Promise<{ provider: string; shouldRetry: boolean }> {
    this.recordFailure(failedProvider);

    // Check if we should attempt failover
    if (!this.shouldAttemptFailover(failedProvider) || availableProviders.length === 0) {
      return { provider: failedProvider, shouldRetry: false };
    }

    // Find alternative provider
    const alternativeProviders = availableProviders.filter(p => p !== failedProvider);
    if (alternativeProviders.length === 0) {
      return { provider: failedProvider, shouldRetry: false };
    }

    // Select best alternative based on error type and request priority
    const selectedProvider = this.selectFailoverProvider(
      alternativeProviders,
      request,
      error
    );

    this.emit('failover', {
      from: failedProvider,
      to: selectedProvider,
      reason: error.code,
      request: request.id
    });

    return { provider: selectedProvider, shouldRetry: true };
  }

  /**
   * Record provider failure
   */
  private recordFailure(providerId: string): void {
    const failures = this.failoverHistory.get(providerId) || [];
    failures.push(new Date());

    // Keep only recent failures
    const cutoff = new Date(Date.now() - this.failoverWindow);
    const recentFailures = failures.filter(date => date > cutoff);
    this.failoverHistory.set(providerId, recentFailures);
  }

  /**
   * Check if failover should be attempted
   */
  private shouldAttemptFailover(providerId: string): boolean {
    const failures = this.failoverHistory.get(providerId) || [];
    return failures.length < this.maxFailoverAttempts;
  }

  /**
   * Select best provider for failover
   */
  private selectFailoverProvider(
    providers: string[],
    request: LLMRequest,
    error: MCPError
  ): string {
    // For now, select first available provider
    // In production, this would consider:
    // - Provider capabilities matching request type
    // - Historical reliability
    // - Current load
    // - Geographic proximity
    return providers[0];
  }

  /**
   * Reset failure history for provider
   */
  resetFailureHistory(providerId: string): void {
    this.failoverHistory.delete(providerId);
  }

  /**
   * Get failure stats
   */
  getFailureStats(providerId: string): {
    recentFailures: number;
    lastFailure?: Date;
    failoverAvailable: boolean;
  } {
    const failures = this.failoverHistory.get(providerId) || [];
    const recentFailures = failures.length;
    const lastFailure = failures.length > 0 ? failures[failures.length - 1] : undefined;
    const failoverAvailable = recentFailures < this.maxFailoverAttempts;

    return {
      recentFailures,
      lastFailure,
      failoverAvailable
    };
  }
}

/**
 * Main connection manager
 */
export class MCPConnectionManager extends EventEmitter {
  private connections: Map<string, MCPConnection> = new Map();
  private providers: Map<string, MCPProvider> = new Map();
  private healthMonitor: ProviderHealthMonitor;
  private loadBalancer: LoadBalancer;
  private rateLimiter: RateLimiter;
  private failoverManager: FailoverManager;

  constructor(private config: MCPClientConfig) {
    super();
    
    this.healthMonitor = new ProviderHealthMonitor({
      interval: 30000, // 30 seconds
      timeout: 5000    // 5 seconds
    });
    
    this.loadBalancer = new LoadBalancer();
    this.rateLimiter = new RateLimiter();
    this.failoverManager = new FailoverManager();

    this.setupEventHandlers();
  }

  /**
   * Add provider and establish connection
   */
  async addProvider(provider: MCPProvider, connection: MCPConnection): Promise<void> {
    this.providers.set(provider.id, provider);
    this.connections.set(provider.id, connection);

    // Start health monitoring
    this.healthMonitor.startMonitoring(provider.id, connection);

    // Setup connection event handlers
    connection.on('disconnect', () => this.handleDisconnection(provider.id));
    connection.on('error', (error) => this.handleConnectionError(provider.id, error));

    this.emit('provider_added', provider.id);
  }

  /**
   * Remove provider and close connection
   */
  async removeProvider(providerId: string): Promise<void> {
    const connection = this.connections.get(providerId);
    if (connection) {
      await connection.disconnect();
    }

    this.connections.delete(providerId);
    this.providers.delete(providerId);
    this.healthMonitor.stopMonitoring(providerId);

    this.emit('provider_removed', providerId);
  }

  /**
   * Send request with load balancing and failover
   */
  async sendRequest(request: LLMRequest, preferredProvider?: string): Promise<LLMResponse> {
    const availableProviders = this.getAvailableProviders();
    
    if (availableProviders.length === 0) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: 'No providers available',
        timestamp: new Date(),
        retryable: false
      });
    }

    let selectedProvider = preferredProvider;
    
    // If no preferred provider or preferred is not available, use load balancer
    if (!selectedProvider || !availableProviders.includes(selectedProvider)) {
      selectedProvider = this.loadBalancer.selectProvider(
        availableProviders,
        this.healthMonitor
      ) || undefined;
    }

    if (!selectedProvider) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: 'No suitable provider found',
        timestamp: new Date(),
        retryable: false
      });
    }

    return this.sendRequestToProvider(request, selectedProvider);
  }

  /**
   * Send request to specific provider with rate limiting and failover
   */
  private async sendRequestToProvider(
    request: LLMRequest,
    providerId: string
  ): Promise<LLMResponse> {
    const provider = this.providers.get(providerId);
    const connection = this.connections.get(providerId);

    if (!provider || !connection) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: `Provider ${providerId} not available`,
        timestamp: new Date(),
        provider: providerId,
        retryable: true
      });
    }

    // Check rate limits
    const estimatedTokens = Math.ceil((request.prompt?.length || 0) / 4); // Rough estimate
    if (!this.rateLimiter.isAllowed(providerId, provider.rateLimits, estimatedTokens)) {
      throw new MCPError({
        code: MCPErrorCode.RATE_LIMITED,
        message: `Rate limit exceeded for provider ${providerId}`,
        timestamp: new Date(),
        provider: providerId,
        retryable: true
      });
    }

    try {
      // Record request for load balancing
      this.loadBalancer.recordRequest(providerId);
      this.rateLimiter.recordRequest(providerId, estimatedTokens);

      // Send request
      const response = await connection.sendRequest(request);

      // Record actual token usage if available
      if (response.usage) {
        this.rateLimiter.recordRequest(providerId, response.usage.totalTokens);
      }

      return response;

    } catch (error) {
      const mcpError = error instanceof MCPError ? error : new MCPError({
        code: MCPErrorCode.PROVIDER_ERROR,
        message: (error as Error).message,
        timestamp: new Date(),
        provider: providerId,
        retryable: true
      });

      // Attempt failover if appropriate
      const failoverResult = await this.failoverManager.handleFailure(
        providerId,
        this.getAvailableProviders(),
        request,
        mcpError
      );

      if (failoverResult.shouldRetry && failoverResult.provider !== providerId) {
        return this.sendRequestToProvider(request, failoverResult.provider);
      }

      throw mcpError;
    }
  }

  /**
   * Get list of available (connected and healthy) providers
   */
  getAvailableProviders(): string[] {
    return Array.from(this.providers.keys()).filter(providerId => {
      const connection = this.connections.get(providerId);
      const healthScore = this.healthMonitor.getHealthScore(providerId);
      return connection && healthScore > 0.5; // Require minimum health score
    });
  }

  /**
   * Get connection for provider
   */
  getConnection(providerId: string): MCPConnection | undefined {
    return this.connections.get(providerId);
  }

  /**
   * Get provider information
   */
  getProvider(providerId: string): MCPProvider | undefined {
    return this.providers.get(providerId);
  }

  /**
   * Get comprehensive health status
   */
  async getHealthStatus(): Promise<Map<string, any>> {
    const status = new Map();

    for (const [providerId, provider] of this.providers.entries()) {
      const connection = this.connections.get(providerId);
      const healthScore = this.healthMonitor.getHealthScore(providerId);
      const failureStats = this.failoverManager.getFailureStats(providerId);
      const usageStats = this.rateLimiter.getUsageStats(providerId, provider.rateLimits);

      let connectionHealth = { status: 'disconnected' };
      if (connection) {
        try {
          connectionHealth = await connection.health();
        } catch (error) {
          connectionHealth = { status: 'unhealthy', error: (error as Error).message } as any;
        }
      }

      status.set(providerId, {
        provider: provider.name,
        connection: connectionHealth,
        healthScore,
        failureStats,
        usageStats,
        available: this.getAvailableProviders().includes(providerId)
      });
    }

    return status;
  }

  /**
   * Handle connection disconnection
   */
  private handleDisconnection(providerId: string): void {
    this.emit('provider_disconnected', providerId);
  }

  /**
   * Handle connection errors
   */
  private handleConnectionError(providerId: string, error: Error): void {
    this.emit('provider_error', providerId, error);
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    this.healthMonitor.on('unhealthy', (providerId, healthResult) => {
      this.emit('provider_unhealthy', providerId, healthResult);
    });

    this.failoverManager.on('failover', (event) => {
      this.emit('failover', event);
    });
  }

  /**
   * Shutdown connection manager
   */
  async shutdown(): Promise<void> {
    // Stop health monitoring
    this.healthMonitor.stopAll();

    // Close all connections
    const disconnectPromises = Array.from(this.connections.values()).map(
      connection => connection.disconnect()
    );
    await Promise.all(disconnectPromises);

    // Clear all maps
    this.connections.clear();
    this.providers.clear();

    this.removeAllListeners();
  }
}

export {
  ProviderHealthMonitor,
  LoadBalancer,
  RateLimiter,
  FailoverManager
};