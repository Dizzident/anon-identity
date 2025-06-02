/**
 * OpenAI MCP Provider Implementation
 * 
 * Provider implementation for OpenAI LLM services
 */

import {
  LLMRequest,
  LLMResponse,
  LLMResponseChunk,
  LLMRequestType,
  ModelInfo,
  ProviderConfig,
  ProviderStatus,
  MCPError,
  MCPErrorCode,
  ResponseStatus,
  UsageInfo,
  FunctionCall,
  FunctionDefinition,
  LLMParameters
} from '../types';
import { BaseLLMProvider, ProviderRequestContext } from './base-provider';

/**
 * OpenAI API response interfaces
 */
interface OpenAICompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string;
      function_call?: {
        name: string;
        arguments: string;
      };
    };
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

interface OpenAIStreamChunk {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    delta: {
      role?: string;
      content?: string;
      function_call?: {
        name?: string;
        arguments?: string;
      };
    };
    finish_reason?: string;
  }>;
}

interface OpenAIEmbeddingResponse {
  object: string;
  data: Array<{
    object: string;
    embedding: number[];
    index: number;
  }>;
  model: string;
  usage: {
    prompt_tokens: number;
    total_tokens: number;
  };
}

interface OpenAIModerationResponse {
  id: string;
  model: string;
  results: Array<{
    flagged: boolean;
    categories: Record<string, boolean>;
    category_scores: Record<string, number>;
  }>;
}

/**
 * OpenAI MCP Provider
 */
export class OpenAIProvider extends BaseLLMProvider {
  private apiKey: string;
  private baseURL: string;
  private organization?: string;

  constructor(config: ProviderConfig) {
    super(config);
    
    this.apiKey = config.apiKey || process.env.OPENAI_API_KEY || '';
    this.baseURL = config.endpoint || 'https://api.openai.com/v1';
    this.organization = config.customHeaders?.['OpenAI-Organization'];

    // Set OpenAI-specific capabilities
    this.capabilities = {
      completion: true,
      streaming: true,
      functionCalling: true,
      embeddings: true,
      moderation: true,
      multimodal: true,
      codeGeneration: true,
      jsonMode: true
    };

    // Set OpenAI models
    this.models = [
      {
        id: 'gpt-4',
        name: 'GPT-4',
        description: 'Most capable GPT-4 model',
        capabilities: ['completion', 'function_calling', 'code_generation'],
        contextLength: 8192,
        inputCost: 0.03,
        outputCost: 0.06,
        deprecated: false
      },
      {
        id: 'gpt-4-turbo-preview',
        name: 'GPT-4 Turbo',
        description: 'Latest GPT-4 Turbo model',
        capabilities: ['completion', 'function_calling', 'json_mode'],
        contextLength: 128000,
        inputCost: 0.01,
        outputCost: 0.03,
        deprecated: false
      },
      {
        id: 'gpt-3.5-turbo',
        name: 'GPT-3.5 Turbo',
        description: 'Fast and efficient model',
        capabilities: ['completion', 'function_calling'],
        contextLength: 4096,
        inputCost: 0.0005,
        outputCost: 0.0015,
        deprecated: false
      },
      {
        id: 'text-embedding-ada-002',
        name: 'Text Embedding Ada 002',
        description: 'Text embedding model',
        capabilities: ['embeddings'],
        contextLength: 8191,
        inputCost: 0.0001,
        outputCost: 0,
        deprecated: false
      }
    ];
  }

  /**
   * Initialize the provider
   */
  async initialize(): Promise<void> {
    if (!this.apiKey) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_CONFIG,
        message: 'OpenAI API key is required',
        timestamp: new Date(),
        provider: this.id,
        retryable: false
      });
    }

    try {
      // Test the API key with a simple request
      await this.testConnection();
      this.status = ProviderStatus.AVAILABLE;
    } catch (error) {
      this.status = ProviderStatus.ERROR;
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_ERROR,
        message: `Failed to initialize OpenAI provider: ${(error as Error).message}`,
        timestamp: new Date(),
        provider: this.id,
        retryable: true
      });
    }
  }

  /**
   * Test connection to OpenAI API
   */
  private async testConnection(): Promise<void> {
    const response = await fetch(`${this.baseURL}/models`, {
      headers: this.getHeaders()
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
  }

  /**
   * Check provider health
   */
  async health(): Promise<{ status: 'healthy' | 'unhealthy'; latency?: number; details?: any }> {
    const start = Date.now();
    
    try {
      await this.testConnection();
      const latency = Date.now() - start;
      
      return {
        status: 'healthy',
        latency,
        details: {
          apiEndpoint: this.baseURL,
          modelsAvailable: this.models.length
        }
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        details: {
          error: (error as Error).message,
          apiEndpoint: this.baseURL
        }
      };
    }
  }

  /**
   * Send completion request
   */
  async completion(request: LLMRequest, context: ProviderRequestContext): Promise<LLMResponse> {
    const model = request.parameters?.model || this.getDefaultModel(request.type);
    this.validateModel(model);

    const requestBody = this.buildCompletionRequest(request, model);
    
    try {
      const response = await fetch(`${this.baseURL}/chat/completions`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw await this.handleAPIError(response);
      }

      const data = await response.json() as OpenAICompletionResponse;
      return this.convertCompletionResponse(request, context, data);

    } catch (error) {
      if (error instanceof MCPError) {
        throw error;
      }
      
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_ERROR,
        message: `OpenAI API error: ${(error as Error).message}`,
        timestamp: new Date(),
        provider: this.id,
        requestId: request.id,
        retryable: true
      });
    }
  }

  /**
   * Send streaming completion request
   */
  async *stream(request: LLMRequest, context: ProviderRequestContext): AsyncIterable<LLMResponseChunk> {
    const model = request.parameters?.model || this.getDefaultModel(request.type);
    this.validateModel(model);

    const requestBody = this.buildCompletionRequest(request, model, true);
    
    try {
      const response = await fetch(`${this.baseURL}/chat/completions`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw await this.handleAPIError(response);
      }

      if (!response.body) {
        throw new Error('No response body for streaming');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      try {
        while (true) {
          const { done, value } = await reader.read();
          
          if (done) break;
          
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = line.slice(6);
              
              if (data === '[DONE]') {
                return;
              }

              try {
                const chunk: OpenAIStreamChunk = JSON.parse(data);
                const responseChunk = this.convertStreamChunk(request, chunk);
                if (responseChunk) {
                  yield responseChunk;
                }
              } catch (parseError) {
                // Skip invalid JSON chunks
                continue;
              }
            }
          }
        }
      } finally {
        reader.releaseLock();
      }

    } catch (error) {
      if (error instanceof MCPError) {
        throw error;
      }
      
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_ERROR,
        message: `OpenAI streaming error: ${(error as Error).message}`,
        timestamp: new Date(),
        provider: this.id,
        requestId: request.id,
        retryable: true
      });
    }
  }

  /**
   * Generate embeddings
   */
  async embed(request: LLMRequest, context: ProviderRequestContext): Promise<LLMResponse> {
    const model = request.parameters?.model || 'text-embedding-ada-002';
    
    const requestBody = {
      input: request.prompt,
      model: model
    };

    try {
      const response = await fetch(`${this.baseURL}/embeddings`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw await this.handleAPIError(response);
      }

      const data = await response.json() as OpenAIEmbeddingResponse;
      return this.convertEmbeddingResponse(request, context, data);

    } catch (error) {
      if (error instanceof MCPError) {
        throw error;
      }
      
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_ERROR,
        message: `OpenAI embedding error: ${(error as Error).message}`,
        timestamp: new Date(),
        provider: this.id,
        requestId: request.id,
        retryable: true
      });
    }
  }

  /**
   * Moderate content
   */
  async moderate(request: LLMRequest, context: ProviderRequestContext): Promise<LLMResponse> {
    const requestBody = {
      input: request.prompt
    };

    try {
      const response = await fetch(`${this.baseURL}/moderations`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw await this.handleAPIError(response);
      }

      const data = await response.json() as OpenAIModerationResponse;
      return this.convertModerationResponse(request, context, data);

    } catch (error) {
      if (error instanceof MCPError) {
        throw error;
      }
      
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_ERROR,
        message: `OpenAI moderation error: ${(error as Error).message}`,
        timestamp: new Date(),
        provider: this.id,
        requestId: request.id,
        retryable: true
      });
    }
  }

  /**
   * Build completion request body
   */
  private buildCompletionRequest(request: LLMRequest, model: string, stream = false): any {
    const messages = this.buildMessages(request);
    const functions = request.functions ? this.convertFunctions(request.functions) : undefined;
    
    const requestBody: any = {
      model,
      messages,
      stream,
      max_tokens: request.parameters?.maxTokens,
      temperature: request.parameters?.temperature,
      top_p: request.parameters?.topP,
      frequency_penalty: request.parameters?.frequencyPenalty,
      presence_penalty: request.parameters?.presencePenalty,
      stop: request.parameters?.stop
    };

    // Add function calling support
    if (functions && functions.length > 0) {
      requestBody.functions = functions;
      if (request.type === LLMRequestType.FUNCTION_CALL) {
        requestBody.function_call = 'auto';
      }
    }

    // Add JSON mode support
    if (request.parameters?.responseFormat?.type === 'json_object') {
      requestBody.response_format = { type: 'json_object' };
    }

    // Remove undefined values
    Object.keys(requestBody).forEach(key => {
      if (requestBody[key] === undefined) {
        delete requestBody[key];
      }
    });

    return requestBody;
  }

  /**
   * Build messages array for OpenAI API
   */
  private buildMessages(request: LLMRequest): any[] {
    const messages: any[] = [];
    
    // Add context messages if available
    if (request.context?.history) {
      for (const msg of request.context.history) {
        messages.push({
          role: msg.role === 'function' ? 'assistant' : msg.role,
          content: msg.content
        });
      }
    }

    // Add current prompt
    messages.push({
      role: 'user',
      content: request.prompt
    });

    return messages;
  }

  /**
   * Convert function definitions to OpenAI format
   */
  protected convertFunctions(functions: FunctionDefinition[]): any[] {
    return functions.map(fn => ({
      name: fn.name,
      description: fn.description,
      parameters: fn.parameters
    }));
  }

  /**
   * Convert OpenAI completion response to standard format
   */
  private convertCompletionResponse(
    request: LLMRequest,
    context: ProviderRequestContext,
    data: OpenAICompletionResponse
  ): LLMResponse {
    const choice = data.choices[0];
    const baseResponse = this.createBaseResponse(request, context);
    
    let functionCall: FunctionCall | undefined;
    if (choice.message.function_call) {
      functionCall = {
        name: choice.message.function_call.name,
        arguments: JSON.parse(choice.message.function_call.arguments || '{}'),
        id: `call-${Date.now()}`
      };
    }

    const usage: UsageInfo = {
      promptTokens: data.usage.prompt_tokens,
      completionTokens: data.usage.completion_tokens,
      totalTokens: data.usage.total_tokens,
      model: data.model,
      provider: this.id,
      cost: this.calculateCost(
        data.usage.prompt_tokens,
        data.usage.completion_tokens,
        data.model
      )
    };

    return {
      ...baseResponse,
      content: choice.message.content,
      functionCall,
      usage,
      model: data.model
    } as LLMResponse;
  }

  /**
   * Convert OpenAI stream chunk to standard format
   */
  private convertStreamChunk(request: LLMRequest, chunk: OpenAIStreamChunk): LLMResponseChunk | null {
    const choice = chunk.choices[0];
    if (!choice?.delta?.content) {
      return null;
    }

    return {
      id: chunk.id,
      requestId: request.id,
      delta: choice.delta.content,
      finished: choice.finish_reason === 'stop'
    };
  }

  /**
   * Convert OpenAI embedding response to standard format
   */
  private convertEmbeddingResponse(
    request: LLMRequest,
    context: ProviderRequestContext,
    data: OpenAIEmbeddingResponse
  ): LLMResponse {
    const baseResponse = this.createBaseResponse(request, context);
    
    const usage: UsageInfo = {
      promptTokens: data.usage.prompt_tokens,
      completionTokens: 0,
      totalTokens: data.usage.total_tokens,
      model: data.model,
      provider: this.id,
      cost: this.calculateCost(data.usage.prompt_tokens, 0, data.model)
    };

    return {
      ...baseResponse,
      embedding: data.data[0]?.embedding,
      usage,
      model: data.model
    } as LLMResponse;
  }

  /**
   * Convert OpenAI moderation response to standard format
   */
  private convertModerationResponse(
    request: LLMRequest,
    context: ProviderRequestContext,
    data: OpenAIModerationResponse
  ): LLMResponse {
    const baseResponse = this.createBaseResponse(request, context);
    const result = data.results[0];
    
    return {
      ...baseResponse,
      moderationResult: {
        flagged: result.flagged,
        categories: result.categories,
        categoryScores: result.category_scores
      },
      model: data.model
    } as LLMResponse;
  }

  /**
   * Get HTTP headers for OpenAI API
   */
  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
      'User-Agent': 'anon-identity-mcp/1.0.0'
    };

    if (this.organization) {
      headers['OpenAI-Organization'] = this.organization;
    }

    // Add custom headers from config
    if (this.config.customHeaders) {
      Object.assign(headers, this.config.customHeaders);
    }

    return headers;
  }

  /**
   * Handle OpenAI API errors
   */
  private async handleAPIError(response: Response): Promise<MCPError> {
    let errorData: any;
    
    try {
      errorData = await response.json();
    } catch {
      errorData = { error: { message: response.statusText } };
    }

    const errorMessage = errorData.error?.message || 'Unknown OpenAI API error';
    let errorCode = MCPErrorCode.PROVIDER_ERROR;

    switch (response.status) {
      case 401:
        errorCode = MCPErrorCode.UNAUTHORIZED;
        break;
      case 403:
        errorCode = MCPErrorCode.FORBIDDEN;
        break;
      case 404:
        errorCode = MCPErrorCode.MODEL_NOT_FOUND;
        break;
      case 429:
        errorCode = MCPErrorCode.RATE_LIMITED;
        break;
      case 500:
      case 502:
      case 503:
        errorCode = MCPErrorCode.PROVIDER_UNAVAILABLE;
        break;
    }

    return new MCPError({
      code: errorCode,
      message: errorMessage,
      timestamp: new Date(),
      provider: this.id,
      retryable: [500, 502, 503, 429].includes(response.status),
      details: {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: errorData
      }
    });
  }
}

/**
 * OpenAI Provider Factory
 */
export class OpenAIProviderFactory {
  static createProvider(config: ProviderConfig): OpenAIProvider {
    return new OpenAIProvider(config);
  }

  static validateConfig(config: ProviderConfig): boolean {
    if (!config.apiKey && !process.env.OPENAI_API_KEY) {
      return false;
    }
    
    return true;
  }

  static getProviderType(): string {
    return 'openai';
  }
}