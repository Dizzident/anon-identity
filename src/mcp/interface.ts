/**
 * Unified LLM Communication Interface
 * 
 * Provides a consistent API for LLM interactions across different providers
 */

import { EventEmitter } from 'events';
import {
  LLMRequest,
  LLMResponse,
  LLMResponseChunk,
  LLMRequestType,
  ConversationContext,
  FunctionDefinition,
  FunctionCall,
  FunctionResult,
  LLMParameters,
  RequestMetadata,
  RequestPriority,
  UsageInfo,
  MCPError,
  MCPErrorCode,
  ResponseStatus
} from './types';
import { MCPClient } from './client';

/**
 * Request builder for fluent API creation
 */
export class LLMRequestBuilder {
  private request: Partial<LLMRequest> = {};

  constructor(private agentDID: string, private sessionId: string) {
    this.request.agentDID = agentDID;
    this.request.sessionId = sessionId;
    this.request.id = `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Set the prompt/content for the request
   */
  prompt(content: string): this {
    this.request.prompt = content;
    return this;
  }

  /**
   * Set the request type
   */
  type(type: LLMRequestType): this {
    this.request.type = type;
    return this;
  }

  /**
   * Add conversation context
   */
  context(context: ConversationContext): this {
    this.request.context = context;
    return this;
  }

  /**
   * Add function definitions for function calling
   */
  functions(functions: FunctionDefinition[]): this {
    this.request.functions = functions;
    return this;
  }

  /**
   * Set LLM parameters
   */
  parameters(params: LLMParameters): this {
    this.request.parameters = params;
    return this;
  }

  /**
   * Set request priority
   */
  priority(priority: RequestPriority): this {
    if (!this.request.metadata) {
      this.request.metadata = {} as RequestMetadata;
    }
    this.request.metadata.priority = priority;
    return this;
  }

  /**
   * Add metadata tags
   */
  tags(tags: string[]): this {
    if (!this.request.metadata) {
      this.request.metadata = {} as RequestMetadata;
    }
    this.request.metadata.tags = tags;
    return this;
  }

  /**
   * Build the final request
   */
  build(): LLMRequest {
    if (!this.request.prompt) {
      throw new Error('Prompt is required');
    }
    if (!this.request.type) {
      this.request.type = LLMRequestType.COMPLETION;
    }

    // Ensure metadata is complete
    this.request.metadata = {
      agentDID: this.request.agentDID!,
      sessionId: this.request.sessionId!,
      requestId: this.request.id!,
      timestamp: new Date(),
      source: 'llm-interface',
      priority: this.request.metadata?.priority || RequestPriority.MEDIUM,
      tags: this.request.metadata?.tags || [],
      ...this.request.metadata
    };

    return this.request as LLMRequest;
  }
}

/**
 * Response analyzer for processing LLM responses
 */
class LLMResponseAnalyzer {
  /**
   * Extract function calls from response
   */
  static extractFunctionCalls(response: LLMResponse): FunctionCall[] {
    const calls: FunctionCall[] = [];
    
    if (response.functionCall) {
      calls.push(response.functionCall);
    }
    
    // Parse content for additional function calls
    if (response.content) {
      const functionCallPattern = /```function-call\s*\n([\s\S]*?)\n```/g;
      let match;
      
      while ((match = functionCallPattern.exec(response.content)) !== null) {
        try {
          const functionCall = JSON.parse(match[1]);
          calls.push(functionCall);
        } catch (error) {
          // Invalid JSON, skip
        }
      }
    }
    
    return calls;
  }

  /**
   * Extract structured data from response
   */
  static extractStructuredData(response: LLMResponse, schema?: any): any {
    if (!response.content) return null;

    // Try to parse JSON blocks
    const jsonPattern = /```json\s*\n([\s\S]*?)\n```/g;
    let match;
    
    while ((match = jsonPattern.exec(response.content)) !== null) {
      try {
        const data = JSON.parse(match[1]);
        if (schema) {
          // Simple schema validation (would use a proper validator in production)
          return this.validateAgainstSchema(data, schema) ? data : null;
        }
        return data;
      } catch (error) {
        // Invalid JSON, continue
      }
    }

    return null;
  }

  /**
   * Calculate response quality metrics
   */
  static calculateQualityMetrics(response: LLMResponse): {
    completeness: number;
    coherence: number;
    relevance: number;
    confidence: number;
  } {
    // Simplified quality metrics - in production this would be more sophisticated
    const contentLength = response.content?.length || 0;
    const hasError = !!response.error;
    const hasUsage = !!response.usage;
    
    return {
      completeness: hasError ? 0 : Math.min(contentLength / 1000, 1),
      coherence: hasError ? 0 : 0.8, // Would use NLP analysis
      relevance: hasError ? 0 : 0.8, // Would use context similarity
      confidence: hasError ? 0 : 0.9 // Would use model confidence scores
    };
  }

  /**
   * Simple schema validation
   */
  private static validateAgainstSchema(data: any, schema: any): boolean {
    // Simplified validation - in production would use ajv or similar
    if (schema.type === 'object' && typeof data !== 'object') return false;
    if (schema.type === 'array' && !Array.isArray(data)) return false;
    if (schema.type === 'string' && typeof data !== 'string') return false;
    if (schema.type === 'number' && typeof data !== 'number') return false;
    
    return true;
  }
}

/**
 * Context manager for conversation state
 */
class ConversationContextManager {
  private contexts: Map<string, ConversationContext> = new Map();
  private maxContextTokens = 8000; // Default context window

  /**
   * Get or create conversation context
   */
  getContext(agentDID: string, sessionId: string): ConversationContext {
    const contextId = `${agentDID}:${sessionId}`;
    
    if (!this.contexts.has(contextId)) {
      const newContext: ConversationContext = {
        agentDID,
        sessionId,
        conversationId: `conv-${Date.now()}`,
        history: [],
        metadata: {
          agentName: agentDID.split(':').pop() || 'Unknown Agent',
          purpose: 'General conversation',
          domain: 'AI Assistant',
          priority: 'medium' as any,
          retention: {
            duration: 24 * 60 * 60 * 1000, // 24 hours
            autoCompress: true,
            autoDelete: false
          },
          sharedWith: []
        },
        lastUpdated: new Date(),
        tokens: 0,
        maxTokens: this.maxContextTokens
      };
      
      this.contexts.set(contextId, newContext);
    }
    
    return this.contexts.get(contextId)!;
  }

  /**
   * Add message to context
   */
  addMessage(
    agentDID: string, 
    sessionId: string, 
    role: 'user' | 'assistant' | 'system' | 'function',
    content: string,
    functionCall?: FunctionCall,
    functionResult?: FunctionResult
  ): void {
    const context = this.getContext(agentDID, sessionId);
    
    const message = {
      id: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      role: role as any,
      content,
      timestamp: new Date(),
      functionCall,
      functionResult
    };
    
    context.history.push(message);
    context.lastUpdated = new Date();
    context.tokens = this.calculateTokens(context);
    
    // Auto-compress if context is getting too large
    if (context.tokens > context.maxTokens && context.metadata.retention.autoCompress) {
      this.compressContext(context);
    }
  }

  /**
   * Compress context by summarizing older messages
   */
  private compressContext(context: ConversationContext): void {
    if (context.history.length <= 10) return; // Keep recent messages
    
    const recentMessages = context.history.slice(-10);
    const olderMessages = context.history.slice(0, -10);
    
    // Create summary of older messages
    const summary = `Previous conversation summary:\n${olderMessages
      .map(msg => `${msg.role}: ${msg.content.substring(0, 100)}...`)
      .join('\n')}\n\n`;
    
    context.summary = (context.summary || '') + summary;
    context.history = recentMessages;
    context.compressedAt = new Date();
    context.tokens = this.calculateTokens(context);
  }

  /**
   * Calculate approximate token count
   */
  private calculateTokens(context: ConversationContext): number {
    let tokens = 0;
    
    // Summary tokens
    if (context.summary) {
      tokens += Math.ceil(context.summary.length / 4); // Rough approximation
    }
    
    // Message tokens
    for (const message of context.history) {
      tokens += Math.ceil(message.content.length / 4);
      if (message.functionCall) {
        tokens += 50; // Function call overhead
      }
    }
    
    return tokens;
  }

  /**
   * Clear context
   */
  clearContext(agentDID: string, sessionId: string): void {
    const contextId = `${agentDID}:${sessionId}`;
    this.contexts.delete(contextId);
  }

  /**
   * Get all contexts for agent
   */
  getAgentContexts(agentDID: string): ConversationContext[] {
    return Array.from(this.contexts.values()).filter(
      context => context.agentDID === agentDID
    );
  }
}

/**
 * Main unified LLM interface
 */
export class UnifiedLLMInterface extends EventEmitter {
  private contextManager: ConversationContextManager;
  private requestCounter = 0;
  private responseCache: Map<string, LLMResponse> = new Map();
  private cacheTTL = 5 * 60 * 1000; // 5 minutes

  constructor(private mcpClient: MCPClient) {
    super();
    this.contextManager = new ConversationContextManager();
    this.setupEventHandlers();
  }

  /**
   * Create a new request builder
   */
  createRequest(agentDID: string, sessionId: string): LLMRequestBuilder {
    return new LLMRequestBuilder(agentDID, sessionId);
  }

  /**
   * Send completion request
   */
  async completion(
    agentDID: string,
    sessionId: string,
    prompt: string,
    options?: {
      parameters?: LLMParameters;
      providerId?: string;
      priority?: RequestPriority;
      useCache?: boolean;
    }
  ): Promise<LLMResponse> {
    const context = this.contextManager.getContext(agentDID, sessionId);
    
    const request = this.createRequest(agentDID, sessionId)
      .type(LLMRequestType.COMPLETION)
      .prompt(prompt)
      .context(context)
      .parameters(options?.parameters || {})
      .priority(options?.priority || RequestPriority.MEDIUM)
      .build();

    // Check cache if enabled
    if (options?.useCache) {
      const cached = this.getCachedResponse(request);
      if (cached) {
        this.emit('cache_hit', request.id);
        return cached;
      }
    }

    try {
      const response = await this.mcpClient.sendRequest(request, options?.providerId);
      
      // Add to context
      this.contextManager.addMessage(agentDID, sessionId, 'user', prompt);
      if (response.content) {
        this.contextManager.addMessage(agentDID, sessionId, 'assistant', response.content);
      }

      // Cache response
      if (options?.useCache) {
        this.cacheResponse(request, response);
      }

      this.emit('completion', { request, response });
      return response;
      
    } catch (error) {
      this.emit('error', { request, error });
      throw error;
    }
  }

  /**
   * Send function calling request
   */
  async functionCall(
    agentDID: string,
    sessionId: string,
    prompt: string,
    functions: FunctionDefinition[],
    options?: {
      parameters?: LLMParameters;
      providerId?: string;
      priority?: RequestPriority;
    }
  ): Promise<{ response: LLMResponse; functionCalls: FunctionCall[] }> {
    const context = this.contextManager.getContext(agentDID, sessionId);
    
    const request = this.createRequest(agentDID, sessionId)
      .type(LLMRequestType.FUNCTION_CALL)
      .prompt(prompt)
      .context(context)
      .functions(functions)
      .parameters(options?.parameters || {})
      .priority(options?.priority || RequestPriority.MEDIUM)
      .build();

    try {
      const response = await this.mcpClient.sendRequest(request, options?.providerId);
      const functionCalls = LLMResponseAnalyzer.extractFunctionCalls(response);
      
      // Add to context
      this.contextManager.addMessage(agentDID, sessionId, 'user', prompt);
      if (response.content) {
        this.contextManager.addMessage(agentDID, sessionId, 'assistant', response.content);
      }
      
      // Add function calls to context
      for (const functionCall of functionCalls) {
        this.contextManager.addMessage(
          agentDID, 
          sessionId, 
          'assistant', 
          `Function call: ${functionCall.name}`,
          functionCall
        );
      }

      this.emit('function_call', { request, response, functionCalls });
      return { response, functionCalls };
      
    } catch (error) {
      this.emit('error', { request, error });
      throw error;
    }
  }

  /**
   * Send streaming request
   */
  async *stream(
    agentDID: string,
    sessionId: string,
    prompt: string,
    options?: {
      parameters?: LLMParameters;
      providerId?: string;
      priority?: RequestPriority;
    }
  ): AsyncIterable<LLMResponseChunk> {
    const context = this.contextManager.getContext(agentDID, sessionId);
    
    const request = this.createRequest(agentDID, sessionId)
      .type(LLMRequestType.STREAMING)
      .prompt(prompt)
      .context(context)
      .parameters({ ...options?.parameters, stream: true })
      .priority(options?.priority || RequestPriority.MEDIUM)
      .build();

    // Add user message to context
    this.contextManager.addMessage(agentDID, sessionId, 'user', prompt);

    let fullResponse = '';

    try {
      for await (const chunk of this.mcpClient.streamRequest(request, options?.providerId)) {
        fullResponse += chunk.delta;
        this.emit('stream_chunk', { request, chunk });
        yield chunk;
      }

      // Add complete response to context
      this.contextManager.addMessage(agentDID, sessionId, 'assistant', fullResponse);
      
    } catch (error) {
      this.emit('error', { request, error });
      throw error;
    }
  }

  /**
   * Get conversation context
   */
  getContext(agentDID: string, sessionId: string): ConversationContext {
    return this.contextManager.getContext(agentDID, sessionId);
  }

  /**
   * Clear conversation context
   */
  clearContext(agentDID: string, sessionId: string): void {
    this.contextManager.clearContext(agentDID, sessionId);
  }

  /**
   * Get usage statistics
   */
  getUsageStats(providerId?: string): UsageInfo[] {
    if (providerId) {
      return this.mcpClient.getUsageStats(providerId);
    }
    
    // Aggregate stats from all providers
    const allStats: UsageInfo[] = [];
    for (const provider of this.mcpClient.getAvailableProviders()) {
      allStats.push(...this.mcpClient.getUsageStats(provider));
    }
    return allStats;
  }

  /**
   * Health check for all providers
   */
  async healthCheck(): Promise<Map<string, any>> {
    return this.mcpClient.healthCheck();
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    this.mcpClient.on('connected', (providerId) => {
      this.emit('provider_connected', providerId);
    });

    this.mcpClient.on('disconnected', (providerId) => {
      this.emit('provider_disconnected', providerId);
    });

    this.mcpClient.on('error', (providerId, error) => {
      this.emit('provider_error', providerId, error);
    });
  }

  /**
   * Get cached response
   */
  private getCachedResponse(request: LLMRequest): LLMResponse | null {
    const cacheKey = this.generateCacheKey(request);
    const cached = this.responseCache.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp.getTime()) < this.cacheTTL) {
      return cached;
    }
    
    if (cached) {
      this.responseCache.delete(cacheKey); // Expired
    }
    
    return null;
  }

  /**
   * Cache response
   */
  private cacheResponse(request: LLMRequest, response: LLMResponse): void {
    const cacheKey = this.generateCacheKey(request);
    this.responseCache.set(cacheKey, response);
    
    // Clean up expired entries periodically
    if (this.responseCache.size % 100 === 0) {
      this.cleanupCache();
    }
  }

  /**
   * Generate cache key for request
   */
  private generateCacheKey(request: LLMRequest): string {
    const key = JSON.stringify({
      prompt: request.prompt,
      type: request.type,
      parameters: request.parameters,
      functions: request.functions?.map(f => f.name)
    });
    
    return Buffer.from(key).toString('base64');
  }

  /**
   * Clean up expired cache entries
   */
  private cleanupCache(): void {
    const now = Date.now();
    for (const [key, response] of this.responseCache.entries()) {
      if ((now - response.timestamp.getTime()) > this.cacheTTL) {
        this.responseCache.delete(key);
      }
    }
  }
}

export { LLMResponseAnalyzer, ConversationContextManager };