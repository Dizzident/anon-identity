/**
 * Provider Selection Engine for MCP
 * 
 * Intelligent provider selection based on capabilities, performance, cost, and availability
 */

import { EventEmitter } from 'events';
import {
  LLMProvider,
  LLMRequest,
  LLMRequestType,
  RequestPriority,
  ProviderHealth,
  ProviderMetrics,
  MCPError,
  MCPErrorCode
} from '../types';

/**
 * Selection criteria for providers
 */
export interface SelectionCriteria {
  requestType: LLMRequestType;
  priority: RequestPriority;
  requirements: {
    streaming?: boolean;
    functionCalling?: boolean;
    maxTokens?: number;
    maxLatency?: number;
    minReliability?: number;
    costConstraint?: number;
    preferredModels?: string[];
  };
  context?: {
    agentDID: string;
    domain: string;
    sensitiveData: boolean;
    regulatoryRequirements?: string[];
  };
}

/**
 * Provider scoring weights
 */
export interface ScoringWeights {
  performance: number;      // Response time, throughput
  reliability: number;      // Uptime, success rate
  capability: number;       // Feature matching
  cost: number;            // Cost efficiency
  availability: number;    // Current capacity
  preference: number;      // User/domain preferences
}

/**
 * Provider selection strategy
 */
export enum SelectionStrategy {
  PERFORMANCE = 'performance',
  COST_OPTIMIZED = 'cost_optimized',
  RELIABILITY = 'reliability',
  CAPABILITY_MATCH = 'capability_match',
  LOAD_BALANCED = 'load_balanced',
  SMART_ADAPTIVE = 'smart_adaptive'
}

/**
 * Selection result
 */
export interface SelectionResult {
  primaryProvider: LLMProvider;
  fallbackProviders: LLMProvider[];
  reasoning: string;
  score: number;
  estimatedCost: number;
  estimatedLatency: number;
  alternativeOptions: Array<{
    provider: LLMProvider;
    score: number;
    tradeoffs: string[];
  }>;
}

/**
 * Load balancing configuration
 */
export interface LoadBalancingConfig {
  strategy: 'round_robin' | 'weighted' | 'least_connections' | 'latency_based';
  weights?: Map<string, number>;
  stickySession: boolean;
  healthCheckInterval: number;
  failoverThreshold: number;
}

/**
 * Provider Selector
 */
export class ProviderSelector extends EventEmitter {
  private providerMetrics: Map<string, ProviderMetrics> = new Map();
  private providerHealth: Map<string, ProviderHealth> = new Map();
  private selectionHistory: Array<{
    timestamp: Date;
    criteria: SelectionCriteria;
    result: SelectionResult;
    actualPerformance?: {
      latency: number;
      success: boolean;
      cost: number;
    };
  }> = [];
  private circuitBreakers: Map<string, {
    failures: number;
    lastFailure: Date;
    state: 'closed' | 'open' | 'half_open';
  }> = new Map();
  private loadBalancer: LoadBalancer;
  private adaptiveLearning: AdaptiveLearning;

  constructor(
    private providers: Map<string, LLMProvider>,
    private config: {
      scoringWeights: ScoringWeights;
      loadBalancing: LoadBalancingConfig;
      circuitBreakerThreshold: number;
      circuitBreakerTimeout: number;
      adaptiveLearningEnabled: boolean;
      fallbackChainLength: number;
    } = {
      scoringWeights: {
        performance: 0.25,
        reliability: 0.25,
        capability: 0.2,
        cost: 0.15,
        availability: 0.1,
        preference: 0.05
      },
      loadBalancing: {
        strategy: 'latency_based',
        stickySession: false,
        healthCheckInterval: 30000,
        failoverThreshold: 3
      },
      circuitBreakerThreshold: 5,
      circuitBreakerTimeout: 60000,
      adaptiveLearningEnabled: true,
      fallbackChainLength: 3
    }
  ) {
    super();
    this.loadBalancer = new LoadBalancer(this.config.loadBalancing);
    this.adaptiveLearning = new AdaptiveLearning();
    this.initializeProviderHealth();
    this.startHealthChecks();
  }

  /**
   * Select optimal provider for request
   */
  async selectProvider(
    request: LLMRequest,
    criteria: SelectionCriteria,
    strategy: SelectionStrategy = SelectionStrategy.SMART_ADAPTIVE
  ): Promise<SelectionResult> {
    // Filter available providers
    const availableProviders = await this.getAvailableProviders(criteria);
    
    if (availableProviders.length === 0) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: 'No providers available for request criteria',
        timestamp: new Date(),
        retryable: true
      });
    }

    // Score providers based on strategy
    const scoredProviders = await this.scoreProviders(
      availableProviders,
      criteria,
      strategy
    );

    // Select primary and fallback providers
    const primaryProvider = scoredProviders[0].provider;
    const fallbackProviders = scoredProviders
      .slice(1, this.config.fallbackChainLength + 1)
      .map(sp => sp.provider);

    // Calculate estimates
    const estimatedCost = await this.estimateCost(primaryProvider, request);
    const estimatedLatency = await this.estimateLatency(primaryProvider, criteria);

    // Build result
    const result: SelectionResult = {
      primaryProvider,
      fallbackProviders,
      reasoning: this.buildReasoning(scoredProviders[0], criteria, strategy),
      score: scoredProviders[0].score,
      estimatedCost,
      estimatedLatency,
      alternativeOptions: scoredProviders.slice(1, 4).map(sp => ({
        provider: sp.provider,
        score: sp.score,
        tradeoffs: this.calculateTradeoffs(sp.provider, primaryProvider)
      }))
    };

    // Record selection
    this.recordSelection(criteria, result);

    // Apply load balancing if needed
    if (scoredProviders.length > 1 && 
        scoredProviders[0].score - scoredProviders[1].score < 0.1) {
      const balancedProvider = await this.loadBalancer.selectProvider(
        scoredProviders.slice(0, 3).map(sp => sp.provider)
      );
      if (balancedProvider && balancedProvider.id !== primaryProvider.id) {
        result.primaryProvider = balancedProvider;
        result.reasoning += ' (Load balanced)';
      }
    }

    this.emit('provider_selected', { request, criteria, result });
    return result;
  }

  /**
   * Get available providers based on criteria
   */
  private async getAvailableProviders(criteria: SelectionCriteria): Promise<LLMProvider[]> {
    const available: LLMProvider[] = [];

    for (const [id, provider] of this.providers) {
      // Check circuit breaker
      const breaker = this.circuitBreakers.get(id);
      if (breaker?.state === 'open') {
        continue;
      }

      // Check health
      const health = this.providerHealth.get(id);
      if (!health || health.status !== 'healthy') {
        continue;
      }

      // Check capabilities
      if (!this.checkCapabilities(provider, criteria)) {
        continue;
      }

      // Check regulatory compliance
      if (criteria.context?.regulatoryRequirements) {
        if (!this.checkCompliance(provider, criteria.context.regulatoryRequirements)) {
          continue;
        }
      }

      available.push(provider);
    }

    return available;
  }

  /**
   * Score providers based on strategy
   */
  private async scoreProviders(
    providers: LLMProvider[],
    criteria: SelectionCriteria,
    strategy: SelectionStrategy
  ): Promise<Array<{ provider: LLMProvider; score: number; breakdown: Record<string, number> }>> {
    const scored: Array<{ provider: LLMProvider; score: number; breakdown: Record<string, number> }> = [];

    for (const provider of providers) {
      const breakdown = await this.calculateProviderScore(provider, criteria, strategy);
      const score = this.aggregateScore(breakdown, strategy);
      
      scored.push({ provider, score, breakdown });
    }

    // Sort by score (highest first)
    scored.sort((a, b) => b.score - a.score);

    // Apply adaptive learning adjustments
    if (this.config.adaptiveLearningEnabled) {
      this.adaptiveLearning.adjustScores(scored, criteria);
    }

    return scored;
  }

  /**
   * Calculate individual provider score
   */
  private async calculateProviderScore(
    provider: LLMProvider,
    criteria: SelectionCriteria,
    strategy: SelectionStrategy
  ): Promise<Record<string, number>> {
    const metrics = this.providerMetrics.get(provider.id);
    const health = this.providerHealth.get(provider.id);
    
    const breakdown = {
      performance: 0,
      reliability: 0,
      capability: 0,
      cost: 0,
      availability: 0,
      preference: 0
    };

    // Performance score
    if (metrics) {
      const avgLatency = metrics.averageLatency;
      const targetLatency = criteria.requirements.maxLatency || 5000;
      breakdown.performance = Math.max(0, 1 - (avgLatency / targetLatency));
      
      // Throughput consideration
      const throughputScore = Math.min(1, metrics.requestsPerSecond / 10);
      breakdown.performance = (breakdown.performance + throughputScore) / 2;
    }

    // Reliability score
    if (metrics && health) {
      breakdown.reliability = (metrics.successRate + health.uptime) / 2;
    }

    // Capability score
    breakdown.capability = this.calculateCapabilityScore(provider, criteria);

    // Cost score (inverse - lower cost = higher score)
    const estimatedCost = await this.estimateCost(provider, {
      id: 'estimate',
      type: criteria.requestType,
      prompt: 'sample',
      agentDID: criteria.context?.agentDID || 'unknown',
      sessionId: 'estimate'
    } as LLMRequest);
    const maxAcceptableCost = criteria.requirements.costConstraint || 1.0;
    breakdown.cost = Math.max(0, 1 - (estimatedCost / maxAcceptableCost));

    // Availability score
    if (health) {
      breakdown.availability = health.responseTime < 1000 ? 1 : 
                              health.responseTime < 3000 ? 0.7 : 0.3;
    }

    // Preference score (based on domain, agent, or historical success)
    breakdown.preference = this.calculatePreferenceScore(provider, criteria);

    return breakdown;
  }

  /**
   * Aggregate scores based on strategy
   */
  private aggregateScore(
    breakdown: Record<string, number>,
    strategy: SelectionStrategy
  ): number {
    let weights = { ...this.config.scoringWeights };

    // Adjust weights based on strategy
    switch (strategy) {
      case SelectionStrategy.PERFORMANCE:
        weights.performance = 0.5;
        weights.reliability = 0.3;
        break;
      case SelectionStrategy.COST_OPTIMIZED:
        weights.cost = 0.5;
        weights.capability = 0.3;
        break;
      case SelectionStrategy.RELIABILITY:
        weights.reliability = 0.5;
        weights.availability = 0.3;
        break;
      case SelectionStrategy.CAPABILITY_MATCH:
        weights.capability = 0.6;
        weights.performance = 0.2;
        break;
    }

    // Normalize weights
    const totalWeight = Object.values(weights).reduce((sum, w) => sum + w, 0);
    for (const key of Object.keys(weights)) {
      weights[key as keyof ScoringWeights] /= totalWeight;
    }

    // Calculate weighted score
    let score = 0;
    for (const [metric, value] of Object.entries(breakdown)) {
      score += value * (weights[metric as keyof ScoringWeights] || 0);
    }

    return Math.min(1, Math.max(0, score));
  }

  /**
   * Check provider capabilities
   */
  private checkCapabilities(provider: LLMProvider, criteria: SelectionCriteria): boolean {
    const caps = provider.capabilities;

    // Check basic capability for request type
    switch (criteria.requestType) {
      case LLMRequestType.COMPLETION:
        if (!caps.completion) return false;
        break;
      case LLMRequestType.FUNCTION_CALL:
        if (!caps.functionCalling) return false;
        break;
      case LLMRequestType.EMBEDDING:
        if (!caps.embeddings) return false;
        break;
      case LLMRequestType.MODERATION:
        if (!caps.moderation) return false;
        break;
    }

    // Check specific requirements
    if (criteria.requirements.streaming && !caps.streaming) {
      return false;
    }

    if (criteria.requirements.preferredModels) {
      const hasPreferredModel = criteria.requirements.preferredModels.some(
        model => provider.models.includes(model)
      );
      if (!hasPreferredModel) return false;
    }

    return true;
  }

  /**
   * Check regulatory compliance
   */
  private checkCompliance(provider: LLMProvider, requirements: string[]): boolean {
    // This would check against provider compliance certifications
    // For now, implement basic checks
    
    const providerCompliance = provider.config.compliance || [];
    
    for (const requirement of requirements) {
      if (!providerCompliance.includes(requirement)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Calculate capability score
   */
  private calculateCapabilityScore(provider: LLMProvider, criteria: SelectionCriteria): number {
    let score = 0.5; // Base score

    // Exact capability match
    if (this.checkCapabilities(provider, criteria)) {
      score += 0.3;
    }

    // Model quality (based on known model rankings)
    const modelQualityScore = this.getModelQualityScore(provider.models);
    score += modelQualityScore * 0.2;

    // Additional features
    if (provider.capabilities.multimodal && criteria.requestType === LLMRequestType.COMPLETION) {
      score += 0.1;
    }

    if (provider.capabilities.jsonMode) {
      score += 0.05;
    }

    return Math.min(1, score);
  }

  /**
   * Get model quality score
   */
  private getModelQualityScore(models: string[]): number {
    // Known model quality rankings (simplified)
    const modelRankings: Record<string, number> = {
      'gpt-4': 1.0,
      'gpt-4-turbo': 0.95,
      'claude-3-opus': 0.95,
      'claude-3-sonnet': 0.9,
      'gpt-3.5-turbo': 0.8,
      'claude-3-haiku': 0.75
    };

    let maxScore = 0;
    for (const model of models) {
      const score = modelRankings[model] || 0.5;
      maxScore = Math.max(maxScore, score);
    }

    return maxScore;
  }

  /**
   * Calculate preference score
   */
  private calculatePreferenceScore(provider: LLMProvider, criteria: SelectionCriteria): number {
    let score = 0.5; // Neutral

    // Domain-specific preferences
    if (criteria.context?.domain) {
      const domainHistory = this.selectionHistory.filter(h => 
        h.criteria.context?.domain === criteria.context?.domain &&
        h.result.primaryProvider.id === provider.id &&
        h.actualPerformance?.success
      );
      
      if (domainHistory.length > 0) {
        const successRate = domainHistory.length / 
          this.selectionHistory.filter(h => h.criteria.context?.domain === criteria.context?.domain).length;
        score = successRate;
      }
    }

    // Agent-specific preferences
    if (criteria.context?.agentDID) {
      const agentHistory = this.selectionHistory.filter(h => 
        h.criteria.context?.agentDID === criteria.context?.agentDID &&
        h.result.primaryProvider.id === provider.id &&
        h.actualPerformance?.success
      );
      
      if (agentHistory.length > 0) {
        const avgPerformance = agentHistory.reduce((sum, h) => 
          sum + (h.actualPerformance?.success ? 1 : 0), 0) / agentHistory.length;
        score = (score + avgPerformance) / 2;
      }
    }

    return score;
  }

  /**
   * Estimate cost for request
   */
  private async estimateCost(provider: LLMProvider, request: LLMRequest): Promise<number> {
    // Simplified cost estimation based on token count and provider rates
    const estimatedTokens = this.estimateTokens(request.prompt);
    const providerCost = provider.config.costPer1kTokens || 0.01;
    
    return (estimatedTokens / 1000) * providerCost;
  }

  /**
   * Estimate latency
   */
  private async estimateLatency(provider: LLMProvider, criteria: SelectionCriteria): Promise<number> {
    const metrics = this.providerMetrics.get(provider.id);
    if (metrics) {
      // Adjust based on request complexity
      let baseLatency = metrics.averageLatency;
      
      if (criteria.requestType === LLMRequestType.FUNCTION_CALL) {
        baseLatency *= 1.3; // Function calls typically take longer
      }
      
      if (criteria.requirements.maxTokens && criteria.requirements.maxTokens > 1000) {
        baseLatency *= 1.2; // Longer responses take more time
      }
      
      return baseLatency;
    }
    
    return 3000; // Default estimate
  }

  /**
   * Estimate token count
   */
  private estimateTokens(text: string): number {
    // Rough estimate: 1 token per 4 characters
    return Math.ceil(text.length / 4);
  }

  /**
   * Build reasoning for selection
   */
  private buildReasoning(
    selectedProvider: { provider: LLMProvider; score: number; breakdown: Record<string, number> },
    criteria: SelectionCriteria,
    strategy: SelectionStrategy
  ): string {
    const { provider, breakdown } = selectedProvider;
    const topFactors = Object.entries(breakdown)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 3)
      .map(([factor, score]) => `${factor}: ${(score * 100).toFixed(1)}%`);

    return `Selected ${provider.name} (${provider.id}) for ${criteria.requestType} request using ${strategy} strategy. ` +
           `Top scoring factors: ${topFactors.join(', ')}. ` +
           `Overall score: ${(selectedProvider.score * 100).toFixed(1)}%`;
  }

  /**
   * Calculate tradeoffs between providers
   */
  private calculateTradeoffs(provider: LLMProvider, primaryProvider: LLMProvider): string[] {
    const tradeoffs: string[] = [];
    
    const providerMetrics = this.providerMetrics.get(provider.id);
    const primaryMetrics = this.providerMetrics.get(primaryProvider.id);
    
    if (providerMetrics && primaryMetrics) {
      if (providerMetrics.averageLatency > primaryMetrics.averageLatency) {
        tradeoffs.push('Higher latency');
      }
      if (providerMetrics.successRate < primaryMetrics.successRate) {
        tradeoffs.push('Lower reliability');
      }
    }
    
    // Compare capabilities
    if (provider.capabilities.functionCalling && !primaryProvider.capabilities.functionCalling) {
      tradeoffs.push('Better function calling support');
    }
    if (provider.capabilities.streaming && !primaryProvider.capabilities.streaming) {
      tradeoffs.push('Streaming support');
    }
    
    return tradeoffs;
  }

  /**
   * Record selection for learning
   */
  private recordSelection(criteria: SelectionCriteria, result: SelectionResult): void {
    this.selectionHistory.push({
      timestamp: new Date(),
      criteria,
      result
    });

    // Keep only recent history
    if (this.selectionHistory.length > 1000) {
      this.selectionHistory = this.selectionHistory.slice(-500);
    }
  }

  /**
   * Record actual performance for learning
   */
  async recordPerformance(
    requestId: string,
    providerId: string,
    performance: {
      latency: number;
      success: boolean;
      cost: number;
    }
  ): Promise<void> {
    // Find the selection record
    const selectionRecord = this.selectionHistory.find(h => 
      h.result.primaryProvider.id === providerId &&
      Math.abs(h.timestamp.getTime() - Date.now()) < 300000 // Within 5 minutes
    );

    if (selectionRecord) {
      selectionRecord.actualPerformance = performance;
    }

    // Update provider metrics
    this.updateProviderMetrics(providerId, performance);

    // Update circuit breaker
    this.updateCircuitBreaker(providerId, performance.success);

    // Feed to adaptive learning
    if (this.config.adaptiveLearningEnabled) {
      this.adaptiveLearning.recordPerformance(providerId, performance);
    }

    this.emit('performance_recorded', { providerId, performance });
  }

  /**
   * Update provider metrics
   */
  private updateProviderMetrics(providerId: string, performance: { latency: number; success: boolean; cost: number }): void {
    let metrics = this.providerMetrics.get(providerId);
    
    if (!metrics) {
      metrics = {
        providerId,
        requestCount: 0,
        successCount: 0,
        errorCount: 0,
        totalLatency: 0,
        averageLatency: 0,
        successRate: 1,
        requestsPerSecond: 0,
        tokensPerSecond: 0,
        costPer1kTokens: 0,
        lastUpdated: new Date()
      };
    }

    metrics.requestCount++;
    if (performance.success) {
      metrics.successCount++;
    } else {
      metrics.errorCount++;
    }

    metrics.totalLatency += performance.latency;
    metrics.averageLatency = metrics.totalLatency / metrics.requestCount;
    metrics.successRate = metrics.successCount / metrics.requestCount;
    metrics.lastUpdated = new Date();

    this.providerMetrics.set(providerId, metrics);
  }

  /**
   * Update circuit breaker
   */
  private updateCircuitBreaker(providerId: string, success: boolean): void {
    let breaker = this.circuitBreakers.get(providerId);
    
    if (!breaker) {
      breaker = {
        failures: 0,
        lastFailure: new Date(),
        state: 'closed'
      };
    }

    if (success) {
      // Reset on success
      if (breaker.state === 'half_open') {
        breaker.state = 'closed';
        breaker.failures = 0;
      }
    } else {
      breaker.failures++;
      breaker.lastFailure = new Date();

      // Trip circuit breaker
      if (breaker.failures >= this.config.circuitBreakerThreshold) {
        breaker.state = 'open';
        
        // Set timer to try half-open
        setTimeout(() => {
          const currentBreaker = this.circuitBreakers.get(providerId);
          if (currentBreaker?.state === 'open') {
            currentBreaker.state = 'half_open';
          }
        }, this.config.circuitBreakerTimeout);
      }
    }

    this.circuitBreakers.set(providerId, breaker);
  }

  /**
   * Initialize provider health
   */
  private initializeProviderHealth(): void {
    for (const [id, provider] of this.providers) {
      this.providerHealth.set(id, {
        providerId: id,
        status: 'healthy',
        lastCheck: new Date(),
        responseTime: 0,
        uptime: 1,
        errorRate: 0,
        connectionCount: 0,
        version: provider.version || '1.0.0'
      });
    }
  }

  /**
   * Start health checks
   */
  private startHealthChecks(): void {
    setInterval(() => {
      this.performHealthChecks();
    }, this.config.loadBalancing.healthCheckInterval);
  }

  /**
   * Perform health checks
   */
  private async performHealthChecks(): Promise<void> {
    const healthPromises = Array.from(this.providers.entries()).map(async ([id, provider]) => {
      try {
        const startTime = Date.now();
        
        // Simple health check request
        const healthResult = await this.performHealthCheck(provider);
        const responseTime = Date.now() - startTime;

        const health: ProviderHealth = {
          providerId: id,
          status: healthResult.healthy ? 'healthy' : 'unhealthy',
          lastCheck: new Date(),
          responseTime,
          uptime: healthResult.uptime || 1,
          errorRate: healthResult.errorRate || 0,
          connectionCount: healthResult.connections || 0,
          version: provider.version || '1.0.0'
        };

        this.providerHealth.set(id, health);
        
      } catch (error) {
        this.providerHealth.set(id, {
          providerId: id,
          status: 'unhealthy',
          lastCheck: new Date(),
          responseTime: 0,
          uptime: 0,
          errorRate: 1,
          connectionCount: 0,
          version: 'unknown'
        });
      }
    });

    await Promise.allSettled(healthPromises);
  }

  /**
   * Perform individual health check
   */
  private async performHealthCheck(provider: LLMProvider): Promise<{
    healthy: boolean;
    uptime?: number;
    errorRate?: number;
    connections?: number;
  }> {
    // This would implement actual health check logic for each provider
    // For now, return mock data
    return {
      healthy: true,
      uptime: 0.99,
      errorRate: 0.01,
      connections: 10
    };
  }

  /**
   * Get provider statistics
   */
  getStatistics(): {
    totalSelections: number;
    providerUsage: Record<string, number>;
    averageScore: number;
    failoverRate: number;
    costSavings: number;
  } {
    const totalSelections = this.selectionHistory.length;
    const providerUsage: Record<string, number> = {};
    let totalScore = 0;
    let failovers = 0;
    let totalCost = 0;

    for (const record of this.selectionHistory) {
      const providerId = record.result.primaryProvider.id;
      providerUsage[providerId] = (providerUsage[providerId] || 0) + 1;
      totalScore += record.result.score;
      totalCost += record.result.estimatedCost;

      if (record.actualPerformance && !record.actualPerformance.success) {
        failovers++;
      }
    }

    return {
      totalSelections,
      providerUsage,
      averageScore: totalSelections > 0 ? totalScore / totalSelections : 0,
      failoverRate: totalSelections > 0 ? failovers / totalSelections : 0,
      costSavings: 0 // Would calculate against baseline
    };
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    this.loadBalancer.shutdown();
    this.removeAllListeners();
  }
}

/**
 * Load Balancer
 */
class LoadBalancer {
  private currentIndex = 0;
  private connectionCounts: Map<string, number> = new Map();

  constructor(private config: LoadBalancingConfig) {}

  async selectProvider(providers: LLMProvider[]): Promise<LLMProvider | null> {
    if (providers.length === 0) return null;

    switch (this.config.strategy) {
      case 'round_robin':
        return this.roundRobin(providers);
      case 'weighted':
        return this.weighted(providers);
      case 'least_connections':
        return this.leastConnections(providers);
      case 'latency_based':
        return this.latencyBased(providers);
      default:
        return providers[0];
    }
  }

  private roundRobin(providers: LLMProvider[]): LLMProvider {
    const provider = providers[this.currentIndex % providers.length];
    this.currentIndex++;
    return provider;
  }

  private weighted(providers: LLMProvider[]): LLMProvider {
    const weights = this.config.weights || new Map();
    const totalWeight = providers.reduce((sum, p) => sum + (weights.get(p.id) || 1), 0);
    const random = Math.random() * totalWeight;
    
    let current = 0;
    for (const provider of providers) {
      current += weights.get(provider.id) || 1;
      if (random <= current) {
        return provider;
      }
    }
    
    return providers[0];
  }

  private leastConnections(providers: LLMProvider[]): LLMProvider {
    let minConnections = Infinity;
    let selected = providers[0];
    
    for (const provider of providers) {
      const connections = this.connectionCounts.get(provider.id) || 0;
      if (connections < minConnections) {
        minConnections = connections;
        selected = provider;
      }
    }
    
    return selected;
  }

  private latencyBased(providers: LLMProvider[]): LLMProvider {
    // Select provider with lowest latency (mock implementation)
    return providers[0];
  }

  shutdown(): void {
    this.connectionCounts.clear();
  }
}

/**
 * Adaptive Learning
 */
class AdaptiveLearning {
  private performanceHistory: Map<string, Array<{
    timestamp: Date;
    latency: number;
    success: boolean;
    cost: number;
  }>> = new Map();

  adjustScores(
    scoredProviders: Array<{ provider: LLMProvider; score: number; breakdown: Record<string, number> }>,
    criteria: SelectionCriteria
  ): void {
    // Apply learning adjustments based on historical performance
    for (const scored of scoredProviders) {
      const history = this.performanceHistory.get(scored.provider.id);
      if (history && history.length > 5) {
        const recentPerformance = history.slice(-10);
        const avgSuccess = recentPerformance.reduce((sum, p) => sum + (p.success ? 1 : 0), 0) / recentPerformance.length;
        const avgLatency = recentPerformance.reduce((sum, p) => sum + p.latency, 0) / recentPerformance.length;
        
        // Adjust score based on actual performance vs. predicted
        if (avgSuccess < 0.9) {
          scored.score *= 0.9; // Penalize for low success rate
        }
        if (avgLatency > 5000) {
          scored.score *= 0.95; // Penalize for high latency
        }
      }
    }

    // Re-sort after adjustments
    scoredProviders.sort((a, b) => b.score - a.score);
  }

  recordPerformance(
    providerId: string,
    performance: { latency: number; success: boolean; cost: number }
  ): void {
    let history = this.performanceHistory.get(providerId);
    if (!history) {
      history = [];
      this.performanceHistory.set(providerId, history);
    }

    history.push({
      timestamp: new Date(),
      ...performance
    });

    // Keep only recent history
    if (history.length > 100) {
      history.splice(0, history.length - 50);
    }
  }
}

export default ProviderSelector;