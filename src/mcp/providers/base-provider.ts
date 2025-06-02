/**
 * Provider-Agnostic Base Interface for MCP
 * 
 * Abstract base classes and interfaces for LLM providers
 */

import { EventEmitter } from 'events';
import {
  MCPProvider,
  LLMRequest,
  LLMResponse,
  LLMResponseChunk,
  LLMCapabilities,
  ModelInfo,
  RateLimitInfo,
  ProviderConfig,
  ProviderStatus,
  MCPError,
  MCPErrorCode,
  ResponseStatus,
  LLMRequestType,
  FunctionDefinition,
  FunctionCall,
  FunctionResult,
  UsageInfo,
  ModerationResult,
  RequestMetadata
} from '../types';

/**
 * Provider request context
 */
export interface ProviderRequestContext {
  requestId: string;
  agentDID: string;
  sessionId: string;
  timestamp: Date;
  retryCount: number;
  timeout: number;
  metadata?: Record<string, any>;
}

/**
 * Provider response context
 */
export interface ProviderResponseContext {
  requestId: string;
  providerId: string;
  model: string;
  latency: number;
  cached: boolean;
  retryCount: number;
  metadata?: Record<string, any>;
}

/**
 * Abstract base provider class
 */
export abstract class BaseLLMProvider extends EventEmitter implements MCPProvider {
  public readonly id: string;
  public readonly name: string;
  public readonly version: string;
  public readonly description: string;
  public capabilities: LLMCapabilities;
  public models: ModelInfo[];
  public rateLimits: RateLimitInfo;
  public config: ProviderConfig;
  public status: ProviderStatus;

  protected requestCount = 0;
  protected errorCount = 0;
  protected lastRequestTime: Date | null = null;
  protected lastErrorTime: Date | null = null;

  constructor(config: ProviderConfig) {
    super();
    this.id = config.id;
    this.name = config.id;
    this.version = '1.0.0';
    this.description = `${config.id} LLM provider`;
    this.config = config;
    this.status = ProviderStatus.UNAVAILABLE;
    
    // Default capabilities - subclasses should override
    this.capabilities = {
      completion: true,
      streaming: false,
      functionCalling: false,
      embeddings: false,
      moderation: false,
      multimodal: false,
      codeGeneration: false,
      jsonMode: false
    };

    // Default rate limits - subclasses should override
    this.rateLimits = config.rateLimits || {
      requestsPerMinute: 60,
      tokensPerMinute: 100000,
      requestsPerDay: 1000,
      tokensPerDay: 1000000,
      concurrentRequests: 10
    };

    // Default models - subclasses should populate
    this.models = [];
  }

  /**
   * Initialize the provider
   */
  abstract initialize(): Promise<void>;

  /**
   * Check provider health
   */
  abstract health(): Promise<{ status: 'healthy' | 'unhealthy'; latency?: number; details?: any }>;

  /**
   * Send completion request
   */
  abstract completion(request: LLMRequest, context: ProviderRequestContext): Promise<LLMResponse>;

  /**
   * Send streaming completion request
   */
  abstract stream(request: LLMRequest, context: ProviderRequestContext): AsyncIterable<LLMResponseChunk>;

  /**
   * Generate embeddings
   */
  abstract embed(request: LLMRequest, context: ProviderRequestContext): Promise<LLMResponse>;

  /**
   * Moderate content
   */
  abstract moderate(request: LLMRequest, context: ProviderRequestContext): Promise<LLMResponse>;

  /**
   * Process request based on type
   */
  async processRequest(request: LLMRequest, context: ProviderRequestContext): Promise<LLMResponse> {
    this.validateRequest(request);
    this.updateMetrics();

    try {
      let response: LLMResponse;

      switch (request.type) {
        case LLMRequestType.COMPLETION:
          response = await this.completion(request, context);
          break;
        case LLMRequestType.FUNCTION_CALL:
          response = await this.completion(request, context);
          break;
        case LLMRequestType.EMBEDDING:
          if (!this.capabilities.embeddings) {
            throw new MCPError({
              code: MCPErrorCode.FUNCTION_NOT_FOUND,
              message: 'Embeddings not supported by this provider',
              timestamp: new Date(),
              provider: this.id,
              retryable: false
            });
          }
          response = await this.embed(request, context);
          break;
        case LLMRequestType.MODERATION:
          if (!this.capabilities.moderation) {
            throw new MCPError({
              code: MCPErrorCode.FUNCTION_NOT_FOUND,
              message: 'Moderation not supported by this provider',
              timestamp: new Date(),
              provider: this.id,
              retryable: false
            });
          }
          response = await this.moderate(request, context);
          break;
        case LLMRequestType.STREAMING:
          throw new MCPError({
            code: MCPErrorCode.INVALID_REQUEST,
            message: 'Use stream() method for streaming requests',
            timestamp: new Date(),
            provider: this.id,
            retryable: false
          });
        default:
          throw new MCPError({
            code: MCPErrorCode.INVALID_REQUEST,
            message: `Unsupported request type: ${request.type}`,
            timestamp: new Date(),
            provider: this.id,
            retryable: false
          });
      }

      this.emit('request_completed', { request, response, context });
      return response;

    } catch (error) {
      this.handleError(error as Error, request, context);
      throw error;
    }
  }

  /**
   * Process streaming request
   */
  async *processStreamingRequest(
    request: LLMRequest,
    context: ProviderRequestContext
  ): AsyncIterable<LLMResponseChunk> {
    this.validateRequest(request);
    this.updateMetrics();

    if (!this.capabilities.streaming) {
      throw new MCPError({
        code: MCPErrorCode.FUNCTION_NOT_FOUND,
        message: 'Streaming not supported by this provider',
        timestamp: new Date(),
        provider: this.id,
        retryable: false
      });
    }

    try {
      for await (const chunk of this.stream(request, context)) {
        this.emit('stream_chunk', { request, chunk, context });
        yield chunk;
      }
      this.emit('stream_completed', { request, context });
    } catch (error) {
      this.handleError(error as Error, request, context);
      throw error;
    }
  }

  /**
   * Validate request before processing
   */
  protected validateRequest(request: LLMRequest): void {
    if (!request.id) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Request ID is required',
        timestamp: new Date(),
        provider: this.id,
        retryable: false
      });
    }

    if (!request.prompt && request.type !== LLMRequestType.EMBEDDING) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Prompt is required',
        timestamp: new Date(),
        provider: this.id,
        requestId: request.id,
        retryable: false
      });
    }

    if (!request.agentDID) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Agent DID is required',
        timestamp: new Date(),
        provider: this.id,
        requestId: request.id,
        retryable: false
      });
    }

    // Validate function calling requirements
    if (request.type === LLMRequestType.FUNCTION_CALL) {
      if (!this.capabilities.functionCalling) {
        throw new MCPError({
          code: MCPErrorCode.FUNCTION_NOT_FOUND,
          message: 'Function calling not supported by this provider',
          timestamp: new Date(),
          provider: this.id,
          requestId: request.id,
          retryable: false
        });
      }

      if (!request.functions || request.functions.length === 0) {
        throw new MCPError({
          code: MCPErrorCode.INVALID_REQUEST,
          message: 'Functions are required for function calling',
          timestamp: new Date(),
          provider: this.id,
          requestId: request.id,
          retryable: false
        });
      }
    }
  }

  /**
   * Create base response structure
   */
  protected createBaseResponse(
    request: LLMRequest,
    context: ProviderRequestContext
  ): Partial<LLMResponse> {
    return {
      id: `resp-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      requestId: request.id,
      type: request.type,
      provider: this.id,
      model: request.parameters?.model || this.config.defaultModel,
      timestamp: new Date(),
      status: ResponseStatus.SUCCESS
    };
  }

  /**
   * Create error response
   */
  protected createErrorResponse(
    request: LLMRequest,
    context: ProviderRequestContext,
    error: Error | MCPError
  ): LLMResponse {
    const baseResponse = this.createBaseResponse(request, context);
    
    const mcpError = error instanceof MCPError ? error : new MCPError({
      code: MCPErrorCode.PROVIDER_ERROR,
      message: error.message,
      timestamp: new Date(),
      provider: this.id,
      requestId: request.id,
      retryable: false
    });

    return {
      ...baseResponse,
      status: ResponseStatus.ERROR,
      error: mcpError
    } as LLMResponse;
  }

  /**
   * Calculate usage information
   */
  protected calculateUsage(
    request: LLMRequest,
    response: string,
    model: string
  ): UsageInfo {
    // Simplified token calculation - in production this would be more accurate
    const promptTokens = Math.ceil((request.prompt?.length || 0) / 4);
    const completionTokens = Math.ceil(response.length / 4);
    const totalTokens = promptTokens + completionTokens;

    return {
      promptTokens,
      completionTokens,
      totalTokens,
      model,
      provider: this.id,
      cost: this.calculateCost(promptTokens, completionTokens, model)
    };
  }

  /**
   * Calculate cost based on token usage
   */
  protected calculateCost(promptTokens: number, completionTokens: number, model: string): number {
    const modelInfo = this.models.find(m => m.id === model);
    if (!modelInfo) return 0;

    const promptCost = (promptTokens / 1000) * modelInfo.inputCost;
    const completionCost = (completionTokens / 1000) * modelInfo.outputCost;
    
    return promptCost + completionCost;
  }

  /**
   * Handle errors
   */
  protected handleError(error: Error, request: LLMRequest, context: ProviderRequestContext): void {
    this.errorCount++;
    this.lastErrorTime = new Date();
    
    this.emit('request_error', { 
      error, 
      request, 
      context,
      provider: this.id
    });

    // Update provider status based on error frequency
    const errorRate = this.errorCount / this.requestCount;
    if (errorRate > 0.1) { // More than 10% error rate
      this.status = ProviderStatus.ERROR;
    }
  }

  /**
   * Update request metrics
   */
  protected updateMetrics(): void {
    this.requestCount++;
    this.lastRequestTime = new Date();
    
    // Reset status if it was in error state and enough time has passed
    if (this.status === ProviderStatus.ERROR && this.lastErrorTime) {
      const timeSinceError = Date.now() - this.lastErrorTime.getTime();
      if (timeSinceError > 5 * 60 * 1000) { // 5 minutes
        this.status = ProviderStatus.AVAILABLE;
      }
    }
  }

  /**
   * Convert function definitions to provider-specific format
   */
  protected convertFunctions(functions: FunctionDefinition[]): any[] {
    // Base implementation - subclasses should override for provider-specific formats
    return functions.map(fn => ({
      name: fn.name,
      description: fn.description,
      parameters: fn.parameters
    }));
  }

  /**
   * Extract function calls from provider response
   */
  protected extractFunctionCalls(response: any): FunctionCall[] {
    // Base implementation - subclasses should override for provider-specific parsing
    const calls: FunctionCall[] = [];
    
    if (response.function_call) {
      calls.push({
        name: response.function_call.name,
        arguments: JSON.parse(response.function_call.arguments || '{}'),
        id: `call-${Date.now()}`
      });
    }

    return calls;
  }

  /**
   * Get provider statistics
   */
  getStats(): {
    requestCount: number;
    errorCount: number;
    errorRate: number;
    lastRequestTime: Date | null;
    lastErrorTime: Date | null;
    status: ProviderStatus;
  } {
    return {
      requestCount: this.requestCount,
      errorCount: this.errorCount,
      errorRate: this.requestCount > 0 ? this.errorCount / this.requestCount : 0,
      lastRequestTime: this.lastRequestTime,
      lastErrorTime: this.lastErrorTime,
      status: this.status
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.requestCount = 0;
    this.errorCount = 0;
    this.lastRequestTime = null;
    this.lastErrorTime = null;
    this.status = ProviderStatus.AVAILABLE;
  }

  /**
   * Get supported models
   */
  getSupportedModels(): ModelInfo[] {
    return [...this.models];
  }

  /**
   * Check if model is supported
   */
  isModelSupported(modelId: string): boolean {
    return this.models.some(model => model.id === modelId);
  }

  /**
   * Get default model for request type
   */
  getDefaultModel(requestType: LLMRequestType): string {
    // Return configured default or first available model
    if (this.config.defaultModel && this.isModelSupported(this.config.defaultModel)) {
      return this.config.defaultModel;
    }
    
    return this.models.length > 0 ? this.models[0].id : '';
  }

  /**
   * Validate model availability
   */
  protected validateModel(modelId: string): void {
    if (modelId && !this.isModelSupported(modelId)) {
      throw new MCPError({
        code: MCPErrorCode.MODEL_NOT_FOUND,
        message: `Model ${modelId} not supported by provider ${this.id}`,
        timestamp: new Date(),
        provider: this.id,
        retryable: false
      });
    }
  }

  /**
   * Shutdown provider
   */
  async shutdown(): Promise<void> {
    this.status = ProviderStatus.UNAVAILABLE;
    this.removeAllListeners();
  }
}

/**
 * Provider factory interface
 */
export interface ProviderFactory {
  createProvider(config: ProviderConfig): BaseLLMProvider;
  validateConfig(config: ProviderConfig): boolean;
  getProviderType(): string;
}

/**
 * Abstract provider factory
 */
export abstract class BaseProviderFactory implements ProviderFactory {
  abstract createProvider(config: ProviderConfig): BaseLLMProvider;
  
  abstract validateConfig(config: ProviderConfig): boolean;
  
  abstract getProviderType(): string;

  /**
   * Validate base configuration requirements
   */
  protected validateBaseConfig(config: ProviderConfig): boolean {
    if (!config.id || typeof config.id !== 'string') return false;
    if (!config.endpoint || typeof config.endpoint !== 'string') return false;
    if (config.enabled !== undefined && typeof config.enabled !== 'boolean') return false;
    
    return true;
  }
}

// Export interfaces inline above
// export { ProviderRequestContext, ProviderResponseContext };