/**
 * Anthropic MCP Provider Implementation
 * 
 * Provider implementation for Anthropic Claude LLM services
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
 * Anthropic API response interfaces
 */
interface AnthropicMessage {
  id: string;
  type: 'message';
  role: 'assistant';
  content: Array<{
    type: 'text';
    text: string;
  }>;
  model: string;
  stop_reason: 'end_turn' | 'max_tokens' | 'stop_sequence';
  stop_sequence?: string;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

interface AnthropicStreamEvent {
  type: 'message_start' | 'content_block_start' | 'content_block_delta' | 'content_block_stop' | 'message_delta' | 'message_stop';
  message?: AnthropicMessage;
  content_block?: {
    type: 'text';
    text: string;
  };
  delta?: {
    type: 'text_delta';
    text: string;
  };
  usage?: {
    input_tokens: number;
    output_tokens: number;
  };
}

/**
 * Anthropic MCP Provider
 */
export class AnthropicProvider extends BaseLLMProvider {
  private apiKey: string;
  private baseURL: string;
  private apiVersion: string;

  constructor(config: ProviderConfig) {
    super(config);
    
    this.apiKey = config.apiKey || process.env.ANTHROPIC_API_KEY || '';
    this.baseURL = config.endpoint || 'https://api.anthropic.com/v1';
    this.apiVersion = '2023-06-01';

    // Set Anthropic-specific capabilities
    this.capabilities = {
      completion: true,
      streaming: true,
      functionCalling: false, // Claude doesn't have native function calling yet
      embeddings: false,
      moderation: false,
      multimodal: true,
      codeGeneration: true,
      jsonMode: false
    };

    // Set Anthropic models
    this.models = [
      {
        id: 'claude-3-opus-20240229',
        name: 'Claude 3 Opus',
        description: 'Most capable Claude 3 model',
        capabilities: ['completion', 'code_generation', 'multimodal'],
        contextLength: 200000,
        inputCost: 0.015,
        outputCost: 0.075,
        deprecated: false
      },
      {
        id: 'claude-3-sonnet-20240229',
        name: 'Claude 3 Sonnet',
        description: 'Balanced performance and speed',
        capabilities: ['completion', 'code_generation', 'multimodal'],
        contextLength: 200000,
        inputCost: 0.003,
        outputCost: 0.015,
        deprecated: false
      },
      {
        id: 'claude-3-haiku-20240307',
        name: 'Claude 3 Haiku',
        description: 'Fastest Claude 3 model',
        capabilities: ['completion', 'code_generation'],
        contextLength: 200000,
        inputCost: 0.00025,
        outputCost: 0.00125,
        deprecated: false
      },
      {
        id: 'claude-2.1',
        name: 'Claude 2.1',
        description: 'Previous generation Claude model',
        capabilities: ['completion', 'code_generation'],
        contextLength: 200000,
        inputCost: 0.008,
        outputCost: 0.024,
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
        message: 'Anthropic API key is required',
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
        message: `Failed to initialize Anthropic provider: ${(error as Error).message}`,
        timestamp: new Date(),
        provider: this.id,
        retryable: true
      });
    }
  }

  /**
   * Test connection to Anthropic API
   */
  private async testConnection(): Promise<void> {
    // Anthropic doesn't have a models endpoint, so we'll try a minimal message
    const response = await fetch(`${this.baseURL}/messages`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        model: 'claude-3-haiku-20240307',
        max_tokens: 1,
        messages: [
          {
            role: 'user',
            content: 'test'
          }
        ]
      })
    });

    if (!response.ok && response.status !== 400) {
      // 400 is expected for minimal request, but other errors indicate real issues
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
          modelsAvailable: this.models.length,
          version: this.apiVersion
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

    const requestBody = this.buildMessageRequest(request, model);
    
    try {
      const response = await fetch(`${this.baseURL}/messages`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw await this.handleAPIError(response);
      }

      const data = await response.json() as AnthropicMessage;
      return this.convertMessageResponse(request, context, data);

    } catch (error) {
      if (error instanceof MCPError) {
        throw error;
      }
      
      throw new MCPError({
        code: MCPErrorCode.PROVIDER_ERROR,
        message: `Anthropic API error: ${(error as Error).message}`,
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

    const requestBody = this.buildMessageRequest(request, model, true);
    
    try {
      const response = await fetch(`${this.baseURL}/messages`, {
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
                const event: AnthropicStreamEvent = JSON.parse(data);
                const responseChunk = this.convertStreamEvent(request, event);
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
        message: `Anthropic streaming error: ${(error as Error).message}`,
        timestamp: new Date(),
        provider: this.id,
        requestId: request.id,
        retryable: true
      });
    }
  }

  /**
   * Generate embeddings (not supported by Anthropic)
   */
  async embed(request: LLMRequest, context: ProviderRequestContext): Promise<LLMResponse> {
    throw new MCPError({
      code: MCPErrorCode.FUNCTION_NOT_FOUND,
      message: 'Embeddings not supported by Anthropic provider',
      timestamp: new Date(),
      provider: this.id,
      requestId: request.id,
      retryable: false
    });
  }

  /**
   * Moderate content (not supported by Anthropic)
   */
  async moderate(request: LLMRequest, context: ProviderRequestContext): Promise<LLMResponse> {
    throw new MCPError({
      code: MCPErrorCode.FUNCTION_NOT_FOUND,
      message: 'Content moderation not supported by Anthropic provider',
      timestamp: new Date(),
      provider: this.id,
      requestId: request.id,
      retryable: false
    });
  }

  /**
   * Build message request body for Anthropic API
   */
  private buildMessageRequest(request: LLMRequest, model: string, stream = false): any {
    const messages = this.buildMessages(request);
    
    const requestBody: any = {
      model,
      max_tokens: request.parameters?.maxTokens || 4096,
      messages,
      stream
    };

    // Add optional parameters
    if (request.parameters?.temperature !== undefined) {
      requestBody.temperature = request.parameters.temperature;
    }
    if (request.parameters?.topP !== undefined) {
      requestBody.top_p = request.parameters.topP;
    }
    if (request.parameters?.stop) {
      requestBody.stop_sequences = Array.isArray(request.parameters.stop) 
        ? request.parameters.stop 
        : [request.parameters.stop];
    }

    // Add system message if available from context
    if (request.context?.summary) {
      requestBody.system = request.context.summary;
    }

    return requestBody;
  }

  /**
   * Build messages array for Anthropic API
   */
  private buildMessages(request: LLMRequest): any[] {
    const messages: any[] = [];
    
    // Add context messages if available (skip system messages as they go in system field)
    if (request.context?.history) {
      for (const msg of request.context.history) {
        if (msg.role !== 'system') {
          messages.push({
            role: msg.role === 'assistant' ? 'assistant' : 'user',
            content: msg.content
          });
        }
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
   * Convert Anthropic message response to standard format
   */
  private convertMessageResponse(
    request: LLMRequest,
    context: ProviderRequestContext,
    data: AnthropicMessage
  ): LLMResponse {
    const baseResponse = this.createBaseResponse(request, context);
    
    const content = data.content.map(block => block.text).join('');
    
    const usage: UsageInfo = {
      promptTokens: data.usage.input_tokens,
      completionTokens: data.usage.output_tokens,
      totalTokens: data.usage.input_tokens + data.usage.output_tokens,
      model: data.model,
      provider: this.id,
      cost: this.calculateCost(
        data.usage.input_tokens,
        data.usage.output_tokens,
        data.model
      )
    };

    // Handle function calling through tool use (if we implement it later)
    let functionCall: FunctionCall | undefined;
    if (request.type === LLMRequestType.FUNCTION_CALL) {
      // For now, we'll try to extract function calls from the text response
      functionCall = this.extractFunctionCallFromText(content);
    }

    return {
      ...baseResponse,
      content,
      functionCall,
      usage,
      model: data.model
    } as LLMResponse;
  }

  /**
   * Convert Anthropic stream event to standard format
   */
  private convertStreamEvent(request: LLMRequest, event: AnthropicStreamEvent): LLMResponseChunk | null {
    if (event.type === 'content_block_delta' && event.delta?.text) {
      return {
        id: `chunk-${Date.now()}`,
        requestId: request.id,
        delta: event.delta.text,
        finished: false
      };
    }
    
    if (event.type === 'message_stop') {
      return {
        id: `chunk-${Date.now()}`,
        requestId: request.id,
        delta: '',
        finished: true
      };
    }

    return null;
  }

  /**
   * Extract function calls from text response (basic implementation)
   */
  private extractFunctionCallFromText(content: string): FunctionCall | undefined {
    // Look for function call patterns in the response
    const functionCallPattern = /<function_call>\s*\{([^}]+)\}\s*<\/function_call>/;
    const match = content.match(functionCallPattern);
    
    if (match) {
      try {
        const call = JSON.parse(`{${match[1]}}`);
        return {
          name: call.name,
          arguments: call.arguments || {},
          id: `call-${Date.now()}`
        };
      } catch {
        // Invalid function call format
      }
    }

    return undefined;
  }

  /**
   * Get HTTP headers for Anthropic API
   */
  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'x-api-key': this.apiKey,
      'anthropic-version': this.apiVersion,
      'User-Agent': 'anon-identity-mcp/1.0.0'
    };

    // Add custom headers from config
    if (this.config.customHeaders) {
      Object.assign(headers, this.config.customHeaders);
    }

    return headers;
  }

  /**
   * Handle Anthropic API errors
   */
  private async handleAPIError(response: Response): Promise<MCPError> {
    let errorData: any;
    
    try {
      errorData = await response.json();
    } catch {
      errorData = { error: { message: response.statusText } };
    }

    const errorMessage = errorData.error?.message || errorData.message || 'Unknown Anthropic API error';
    let errorCode = MCPErrorCode.PROVIDER_ERROR;

    switch (response.status) {
      case 400:
        errorCode = MCPErrorCode.INVALID_REQUEST;
        break;
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

  /**
   * Override function conversion for Anthropic (currently not supported)
   */
  protected convertFunctions(functions: FunctionDefinition[]): any[] {
    // Anthropic doesn't have native function calling yet
    // We could potentially convert to tool use format in the future
    return [];
  }
}

/**
 * Anthropic Provider Factory
 */
export class AnthropicProviderFactory {
  static createProvider(config: ProviderConfig): AnthropicProvider {
    return new AnthropicProvider(config);
  }

  static validateConfig(config: ProviderConfig): boolean {
    if (!config.apiKey && !process.env.ANTHROPIC_API_KEY) {
      return false;
    }
    
    return true;
  }

  static getProviderType(): string {
    return 'anthropic';
  }
}