/**
 * Provider Registry and Selection Logic for MCP
 * 
 * Manages registration, discovery, and selection of LLM providers
 */

import {
  MCPProvider,
  ProviderConfig,
  LLMRequest,
  LLMCapabilities,
  LLMRequestType,
  ModelInfo,
  ProviderStatus,
  MCPError,
  MCPErrorCode
} from './types';
import { BaseLLMProvider, ProviderFactory } from './providers/base-provider';
import { OpenAIProvider, OpenAIProviderFactory } from './providers/openai-provider';
import { AnthropicProvider, AnthropicProviderFactory } from './providers/anthropic-provider';

/**
 * Provider selection criteria
 */
export interface ProviderSelectionCriteria {
  requestType: LLMRequestType;
  modelPreference?: string;
  capabilities?: string[];
  maxCost?: number;
  maxLatency?: number;
  preferredProviders?: string[];
  excludedProviders?: string[];
}

/**
 * Provider selection result
 */
export interface ProviderSelectionResult {
  provider: MCPProvider;
  confidence: number;
  reason: string;
  alternatives: Array<{
    provider: MCPProvider;
    confidence: number;
    reason: string;
  }>;
}

/**
 * Provider scoring weights
 */
interface ProviderScoringWeights {
  capability: number;
  cost: number;
  performance: number;
  reliability: number;
  preference: number;
}

/**
 * Provider Registry
 */
export class ProviderRegistry {
  private providers: Map<string, MCPProvider> = new Map();
  private factories: Map<string, ProviderFactory> = new Map();
  private scoringWeights: ProviderScoringWeights = {
    capability: 0.3,
    cost: 0.2,
    performance: 0.2,
    reliability: 0.2,
    preference: 0.1
  };

  constructor() {
    this.registerBuiltInFactories();
  }

  /**
   * Register built-in provider factories
   */
  private registerBuiltInFactories(): void {
    this.registerProviderFactory('openai', {
      createProvider: OpenAIProviderFactory.createProvider,
      validateConfig: OpenAIProviderFactory.validateConfig,
      getProviderType: OpenAIProviderFactory.getProviderType
    });

    this.registerProviderFactory('anthropic', {
      createProvider: AnthropicProviderFactory.createProvider,
      validateConfig: AnthropicProviderFactory.validateConfig,
      getProviderType: AnthropicProviderFactory.getProviderType
    });
  }

  /**
   * Register a provider factory
   */
  registerProviderFactory(type: string, factory: ProviderFactory): void {
    this.factories.set(type, factory);
  }

  /**
   * Create and register provider from config
   */
  async createProvider(config: ProviderConfig): Promise<MCPProvider> {
    // Determine provider type from config or endpoint
    const providerType = this.detectProviderType(config);
    
    const factory = this.factories.get(providerType);
    if (!factory) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_CONFIG,
        message: `Unknown provider type: ${providerType}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Validate configuration
    if (!factory.validateConfig(config)) {
      throw new MCPError({
        code: MCPErrorCode.CONFIG_VALIDATION_ERROR,
        message: `Invalid configuration for provider type: ${providerType}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Create provider instance
    const provider = factory.createProvider(config);
    
    // Register the provider
    this.providers.set(provider.id, provider);
    
    return provider;
  }

  /**
   * Detect provider type from configuration
   */
  private detectProviderType(config: ProviderConfig): string {
    // Check explicit type first
    if ((config as any).type) {
      return (config as any).type;
    }

    // Detect from endpoint URL
    if (config.endpoint) {
      if (config.endpoint.includes('openai.com')) {
        return 'openai';
      }
      if (config.endpoint.includes('anthropic.com')) {
        return 'anthropic';
      }
    }

    // Default to provider ID if it matches known types
    if (this.factories.has(config.id)) {
      return config.id;
    }

    throw new MCPError({
      code: MCPErrorCode.INVALID_CONFIG,
      message: `Cannot detect provider type for: ${config.id}`,
      timestamp: new Date(),
      retryable: false
    });
  }

  /**
   * Register an existing provider instance
   */
  registerProvider(provider: MCPProvider): void {
    this.providers.set(provider.id, provider);
  }

  /**
   * Unregister a provider
   */
  unregisterProvider(providerId: string): void {
    this.providers.delete(providerId);
  }

  /**
   * Get provider by ID
   */
  getProvider(providerId: string): MCPProvider | undefined {
    return this.providers.get(providerId);
  }

  /**
   * Get all registered providers
   */
  getAllProviders(): MCPProvider[] {
    return Array.from(this.providers.values());
  }

  /**
   * Get available (enabled and healthy) providers
   */
  getAvailableProviders(): MCPProvider[] {
    return this.getAllProviders().filter(provider => 
      provider.status === ProviderStatus.AVAILABLE
    );
  }

  /**
   * Get providers by capability
   */
  getProvidersByCapability(capability: keyof LLMCapabilities): MCPProvider[] {
    return this.getAvailableProviders().filter(provider =>
      provider.capabilities[capability]
    );
  }

  /**
   * Get providers supporting specific model
   */
  getProvidersByModel(modelId: string): MCPProvider[] {
    return this.getAvailableProviders().filter(provider =>
      provider.models.some(model => model.id === modelId)
    );
  }

  /**
   * Select best provider for request
   */
  selectProvider(
    criteria: ProviderSelectionCriteria,
    request?: LLMRequest
  ): ProviderSelectionResult {
    const availableProviders = this.getAvailableProviders();
    
    if (availableProviders.length === 0) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: 'No providers available',
        timestamp: new Date(),
        retryable: true
      });
    }

    // Filter providers by basic requirements
    let candidateProviders = this.filterProviders(availableProviders, criteria);
    
    if (candidateProviders.length === 0) {
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_UNAVAILABLE,
        message: 'No providers meet the selection criteria',
        timestamp: new Date(),
        retryable: false,
        details: { criteria }
      });
    }

    // Score and rank providers
    const scoredProviders = candidateProviders.map(provider => ({
      provider,
      score: this.scoreProvider(provider, criteria, request),
      reason: this.getSelectionReason(provider, criteria)
    }));

    // Sort by score (highest first)
    scoredProviders.sort((a, b) => b.score - a.score);

    const selected = scoredProviders[0];
    const alternatives = scoredProviders.slice(1, 4); // Top 3 alternatives

    return {
      provider: selected.provider,
      confidence: selected.score,
      reason: selected.reason,
      alternatives: alternatives.map(alt => ({
        provider: alt.provider,
        confidence: alt.score,
        reason: alt.reason
      }))
    };
  }

  /**
   * Filter providers by basic requirements
   */
  private filterProviders(
    providers: MCPProvider[],
    criteria: ProviderSelectionCriteria
  ): MCPProvider[] {
    return providers.filter(provider => {
      // Check capability requirements
      if (criteria.requestType === LLMRequestType.COMPLETION && !provider.capabilities.completion) {
        return false;
      }
      if (criteria.requestType === LLMRequestType.STREAMING && !provider.capabilities.streaming) {
        return false;
      }
      if (criteria.requestType === LLMRequestType.FUNCTION_CALL && !provider.capabilities.functionCalling) {
        return false;
      }
      if (criteria.requestType === LLMRequestType.EMBEDDING && !provider.capabilities.embeddings) {
        return false;
      }
      if (criteria.requestType === LLMRequestType.MODERATION && !provider.capabilities.moderation) {
        return false;
      }

      // Check additional capability requirements
      if (criteria.capabilities) {
        for (const capability of criteria.capabilities) {
          if (!(provider.capabilities as any)[capability]) {
            return false;
          }
        }
      }

      // Check model preference
      if (criteria.modelPreference) {
        const hasModel = provider.models.some(model => 
          model.id === criteria.modelPreference ||
          model.name.toLowerCase().includes(criteria.modelPreference!.toLowerCase())
        );
        if (!hasModel) {
          return false;
        }
      }

      // Check excluded providers
      if (criteria.excludedProviders?.includes(provider.id)) {
        return false;
      }

      return true;
    });
  }

  /**
   * Score a provider based on criteria
   */
  private scoreProvider(
    provider: MCPProvider,
    criteria: ProviderSelectionCriteria,
    request?: LLMRequest
  ): number {
    let score = 0;
    const weights = this.scoringWeights;

    // Capability score (0-1)
    const capabilityScore = this.calculateCapabilityScore(provider, criteria);
    score += capabilityScore * weights.capability;

    // Cost score (0-1, lower cost = higher score)
    const costScore = this.calculateCostScore(provider, criteria);
    score += costScore * weights.cost;

    // Performance score (0-1)
    const performanceScore = this.calculatePerformanceScore(provider, criteria);
    score += performanceScore * weights.performance;

    // Reliability score (0-1)
    const reliabilityScore = this.calculateReliabilityScore(provider);
    score += reliabilityScore * weights.reliability;

    // Preference score (0-1)
    const preferenceScore = this.calculatePreferenceScore(provider, criteria);
    score += preferenceScore * weights.preference;

    return Math.min(1, Math.max(0, score));
  }

  /**
   * Calculate capability score
   */
  private calculateCapabilityScore(
    provider: MCPProvider,
    criteria: ProviderSelectionCriteria
  ): number {
    let score = 0;
    let checks = 0;

    // Base capability check
    const hasRequiredCapability = this.checkRequiredCapability(provider, criteria.requestType);
    score += hasRequiredCapability ? 1 : 0;
    checks++;

    // Additional capabilities
    if (criteria.capabilities) {
      for (const capability of criteria.capabilities) {
        const hasCapability = (provider.capabilities as any)[capability];
        score += hasCapability ? 1 : 0;
        checks++;
      }
    }

    // Model availability
    if (criteria.modelPreference) {
      const hasPreferredModel = provider.models.some(model => 
        model.id === criteria.modelPreference ||
        model.name.toLowerCase().includes(criteria.modelPreference!.toLowerCase())
      );
      score += hasPreferredModel ? 1 : 0;
      checks++;
    }

    return checks > 0 ? score / checks : 1;
  }

  /**
   * Check if provider has required capability for request type
   */
  private checkRequiredCapability(provider: MCPProvider, requestType: LLMRequestType): boolean {
    switch (requestType) {
      case LLMRequestType.COMPLETION:
        return provider.capabilities.completion;
      case LLMRequestType.STREAMING:
        return provider.capabilities.streaming;
      case LLMRequestType.FUNCTION_CALL:
        return provider.capabilities.functionCalling;
      case LLMRequestType.EMBEDDING:
        return provider.capabilities.embeddings;
      case LLMRequestType.MODERATION:
        return provider.capabilities.moderation;
      default:
        return true;
    }
  }

  /**
   * Calculate cost score
   */
  private calculateCostScore(
    provider: MCPProvider,
    criteria: ProviderSelectionCriteria
  ): number {
    if (!criteria.maxCost) {
      return 1; // No cost constraint
    }

    // Calculate average cost per model
    const costs = provider.models.map(model => model.inputCost + model.outputCost);
    const avgCost = costs.length > 0 ? costs.reduce((a, b) => a + b, 0) / costs.length : 0;

    if (avgCost > criteria.maxCost) {
      return 0; // Too expensive
    }

    // Higher score for lower cost
    return 1 - (avgCost / criteria.maxCost);
  }

  /**
   * Calculate performance score
   */
  private calculatePerformanceScore(
    provider: MCPProvider,
    criteria: ProviderSelectionCriteria
  ): number {
    // This would use historical performance metrics in a real implementation
    // For now, we'll use some heuristics based on model capabilities
    
    let score = 0.7; // Base score

    // Bonus for streaming capability
    if (provider.capabilities.streaming) {
      score += 0.1;
    }

    // Bonus for multimodal capability
    if (provider.capabilities.multimodal) {
      score += 0.1;
    }

    // Bonus for JSON mode
    if (provider.capabilities.jsonMode) {
      score += 0.1;
    }

    return Math.min(1, score);
  }

  /**
   * Calculate reliability score
   */
  private calculateReliabilityScore(provider: MCPProvider): number {
    // This would use historical reliability metrics in a real implementation
    // For now, we'll use provider status as a proxy
    
    switch (provider.status) {
      case ProviderStatus.AVAILABLE:
        return 1.0;
      case ProviderStatus.RATE_LIMITED:
        return 0.7;
      case ProviderStatus.MAINTENANCE:
        return 0.3;
      case ProviderStatus.ERROR:
        return 0.1;
      case ProviderStatus.UNAVAILABLE:
        return 0.0;
      default:
        return 0.5;
    }
  }

  /**
   * Calculate preference score
   */
  private calculatePreferenceScore(
    provider: MCPProvider,
    criteria: ProviderSelectionCriteria
  ): number {
    if (criteria.preferredProviders?.includes(provider.id)) {
      return 1.0;
    }
    
    return 0.5; // Neutral
  }

  /**
   * Get selection reason for provider
   */
  private getSelectionReason(
    provider: MCPProvider,
    criteria: ProviderSelectionCriteria
  ): string {
    const reasons: string[] = [];

    // Check why this provider was selected
    if (criteria.preferredProviders?.includes(provider.id)) {
      reasons.push('preferred provider');
    }

    if (criteria.modelPreference) {
      const hasModel = provider.models.some(model => 
        model.id === criteria.modelPreference ||
        model.name.toLowerCase().includes(criteria.modelPreference!.toLowerCase())
      );
      if (hasModel) {
        reasons.push(`supports ${criteria.modelPreference}`);
      }
    }

    // Add capability reasons
    const capabilities = [];
    if (provider.capabilities.functionCalling && criteria.requestType === LLMRequestType.FUNCTION_CALL) {
      capabilities.push('function calling');
    }
    if (provider.capabilities.streaming && criteria.requestType === LLMRequestType.STREAMING) {
      capabilities.push('streaming');
    }
    if (provider.capabilities.multimodal) {
      capabilities.push('multimodal');
    }

    if (capabilities.length > 0) {
      reasons.push(`supports ${capabilities.join(', ')}`);
    }

    // Default reason
    if (reasons.length === 0) {
      reasons.push('best overall match');
    }

    return reasons.join(', ');
  }

  /**
   * Update scoring weights
   */
  updateScoringWeights(weights: Partial<ProviderScoringWeights>): void {
    this.scoringWeights = { ...this.scoringWeights, ...weights };
    
    // Normalize weights to sum to 1
    const total = Object.values(this.scoringWeights).reduce((a, b) => a + b, 0);
    if (total > 0) {
      Object.keys(this.scoringWeights).forEach(key => {
        (this.scoringWeights as any)[key] /= total;
      });
    }
  }

  /**
   * Get provider statistics
   */
  getProviderStats(): {
    total: number;
    available: number;
    byType: Record<string, number>;
    byStatus: Record<ProviderStatus, number>;
  } {
    const providers = this.getAllProviders();
    const stats = {
      total: providers.length,
      available: providers.filter(p => p.status === ProviderStatus.AVAILABLE).length,
      byType: {} as Record<string, number>,
      byStatus: {} as Record<ProviderStatus, number>
    };

    // Count by type (inferred from provider name/id)
    providers.forEach(provider => {
      const type = this.detectProviderType(provider.config);
      stats.byType[type] = (stats.byType[type] || 0) + 1;
    });

    // Count by status
    providers.forEach(provider => {
      stats.byStatus[provider.status] = (stats.byStatus[provider.status] || 0) + 1;
    });

    return stats;
  }

  /**
   * Clear all providers
   */
  clear(): void {
    this.providers.clear();
  }
}

export default ProviderRegistry;