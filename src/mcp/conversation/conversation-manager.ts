/**
 * Conversation Manager for MCP
 * 
 * Orchestrates conversation flow between agents and LLMs with context management
 */

import { EventEmitter } from 'events';
import {
  LLMRequest,
  LLMResponse,
  LLMResponseChunk,
  ConversationContext,
  ConversationMessage,
  MessageRole,
  ContextMetadata,
  ContextPriority,
  ContextRetention,
  RequestPriority,
  LLMRequestType,
  MCPError,
  MCPErrorCode,
  FunctionCall,
  FunctionResult
} from '../types';
import { MessageRouter } from '../routing/message-router';
import { ContextManager } from '../context/context-manager';
import { AgentLLMManager } from '../agent/agent-llm-manager';

/**
 * Conversation session
 */
export interface ConversationSession {
  id: string;
  agentDID: string;
  contextId: string;
  metadata: {
    domain: string;
    purpose: string;
    startedAt: Date;
    lastActivity: Date;
    messageCount: number;
    totalTokens: number;
  };
  status: 'active' | 'paused' | 'ended';
  participants: string[];
}

/**
 * Conversation flow configuration
 */
export interface ConversationFlowConfig {
  autoSummarize: boolean;
  maxIdleTime: number;
  contextSwitchThreshold: number;
  multiTurnEnabled: boolean;
  persistHistory: boolean;
  enableStreaming: boolean;
}

/**
 * Turn result
 */
export interface TurnResult {
  request: LLMRequest;
  response: LLMResponse;
  context: ConversationContext;
  session: ConversationSession;
  functionCalls?: FunctionCall[];
  functionResults?: FunctionResult[];
  metrics: {
    turnDuration: number;
    tokensUsed: number;
    providerUsed: string;
  };
}

/**
 * Multi-turn conversation state
 */
interface MultiTurnState {
  sessionId: string;
  pendingFunctions: FunctionCall[];
  awaitingInput: boolean;
  lastResponse?: LLMResponse;
  turnCount: number;
}

/**
 * Conversation Manager
 */
export class ConversationManager extends EventEmitter {
  private sessions: Map<string, ConversationSession> = new Map();
  private agentSessions: Map<string, Set<string>> = new Map(); // agentDID -> sessionIds
  private multiTurnStates: Map<string, MultiTurnState> = new Map();
  private idleCheckTimer?: NodeJS.Timeout;

  constructor(
    private messageRouter: MessageRouter,
    private contextManager: ContextManager,
    private agentLLMManager: AgentLLMManager,
    private config: ConversationFlowConfig = {
      autoSummarize: true,
      maxIdleTime: 1800000, // 30 minutes
      contextSwitchThreshold: 0.7,
      multiTurnEnabled: true,
      persistHistory: true,
      enableStreaming: true
    }
  ) {
    super();
    this.startIdleCheck();
    this.setupEventHandlers();
  }

  /**
   * Start conversation session
   */
  async startConversation(
    agentDID: string,
    options: {
      domain?: string;
      purpose?: string;
      priority?: ContextPriority;
      retention?: Partial<ContextRetention>;
      systemPrompt?: string;
      metadata?: Record<string, any>;
    } = {}
  ): Promise<ConversationSession> {
    const sessionId = `conv-${agentDID}-${Date.now()}`;
    
    // Create context metadata
    const contextMetadata: ContextMetadata = {
      agentName: agentDID.split(':').pop() || 'Unknown Agent',
      purpose: options.purpose || 'General conversation',
      domain: options.domain || 'general',
      priority: options.priority || ContextPriority.MEDIUM,
      retention: {
        duration: 24 * 60 * 60 * 1000, // 24 hours default
        autoCompress: true,
        autoDelete: false,
        archiveAfter: 30 * 24 * 60 * 60 * 1000, // 30 days
        ...options.retention
      },
      sharedWith: []
    };

    // Create conversation context
    const context = await this.contextManager.createContext(
      agentDID,
      sessionId,
      contextMetadata
    );

    // Add system message if provided
    if (options.systemPrompt) {
      await this.contextManager.addMessage(context.conversationId, {
        role: MessageRole.SYSTEM,
        content: options.systemPrompt,
        metadata: {
          source: 'conversation-manager',
          type: 'system-prompt'
        }
      });
    }

    // Create session
    const session: ConversationSession = {
      id: sessionId,
      agentDID,
      contextId: context.conversationId,
      metadata: {
        domain: context.metadata.domain,
        purpose: context.metadata.purpose,
        startedAt: new Date(),
        lastActivity: new Date(),
        messageCount: 0,
        totalTokens: 0
      },
      status: 'active',
      participants: [agentDID]
    };

    this.sessions.set(sessionId, session);
    
    // Update agent sessions index
    const agentSessions = this.agentSessions.get(agentDID) || new Set();
    agentSessions.add(sessionId);
    this.agentSessions.set(agentDID, agentSessions);

    this.emit('conversation_started', session);
    return session;
  }

  /**
   * Send message in conversation
   */
  async sendMessage(
    sessionId: string,
    content: string,
    options: {
      role?: MessageRole;
      priority?: RequestPriority;
      providerId?: string;
      temperature?: number;
      maxTokens?: number;
      enableFunctions?: boolean;
      streamResponse?: boolean;
      metadata?: Record<string, any>;
    } = {}
  ): Promise<TurnResult> {
    const session = this.sessions.get(sessionId);
    if (!session || session.status !== 'active') {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: `Invalid or inactive session: ${sessionId}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    const turnStartTime = Date.now();
    const context = this.contextManager.getContext(session.contextId);
    if (!context) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: `Context not found: ${session.contextId}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    try {
      // Add user message to context
      const userMessage = await this.contextManager.addMessage(context.conversationId, {
        role: options.role || MessageRole.USER,
        content,
        metadata: {
          ...options.metadata,
          source: 'user',
          sessionId
        }
      });

      // Create LLM request
      const request: LLMRequest = {
        id: `req-${sessionId}-${Date.now()}`,
        type: options.enableFunctions ? LLMRequestType.FUNCTION_CALL : LLMRequestType.COMPLETION,
        prompt: await this.buildPrompt(context),
        agentDID: session.agentDID,
        sessionId,
        parameters: {
          temperature: options.temperature,
          maxTokens: options.maxTokens,
          model: undefined // Let provider selection handle this
        },
        metadata: {
          agentDID: session.agentDID,
          sessionId,
          requestId: `req-${sessionId}-${Date.now()}`,
          timestamp: new Date(),
          source: 'conversation-manager',
          priority: options.priority || RequestPriority.MEDIUM,
          conversationId: context.conversationId,
          providerId: options.providerId
        }
      };

      // Handle function definitions if enabled
      if (options.enableFunctions) {
        request.functions = await this.getFunctionDefinitions(session.agentDID);
      }

      let response: LLMResponse;
      let functionCalls: FunctionCall[] = [];
      let functionResults: FunctionResult[] = [];

      // Route request
      if (options.streamResponse && this.config.enableStreaming) {
        response = await this.handleStreamingRequest(request, session, context);
      } else {
        response = await this.messageRouter.routeMessage(request);
      }

      // Handle function calls
      if (response.functionCall) {
        functionCalls = [response.functionCall];
        
        // Execute function if handler available
        const result = await this.agentLLMManager.executeFunctionCall(response.functionCall);
        functionResults = [{
          functionCallId: response.functionCall.id || `func-${Date.now()}`,
          result,
          executionTime: 0, // Will be calculated by the function handler
          timestamp: new Date()
        }];

        // Add function call message
        await this.contextManager.addMessage(context.conversationId, {
          role: MessageRole.ASSISTANT,
          content: response.content || '',
          functionCall: response.functionCall,
          metadata: {
            source: 'llm',
            provider: response.provider,
            model: response.model
          }
        });

        // Add function result message
        await this.contextManager.addMessage(context.conversationId, {
          role: MessageRole.FUNCTION,
          content: JSON.stringify(result),
          functionResult: functionResults[0],
          metadata: {
            source: 'function',
            functionName: response.functionCall.name
          }
        });

        // Handle multi-turn if enabled
        if (this.config.multiTurnEnabled) {
          const followUpResponse = await this.handleMultiTurn(
            session,
            context,
            response,
            functionResults[0]
          );
          if (followUpResponse) {
            response = followUpResponse;
          }
        }
      } else {
        // Add assistant response to context
        await this.contextManager.addMessage(context.conversationId, {
          role: MessageRole.ASSISTANT,
          content: response.content || '',
          metadata: {
            source: 'llm',
            provider: response.provider,
            model: response.model,
            usage: response.usage
          }
        });
      }

      // Update session metadata
      session.metadata.lastActivity = new Date();
      session.metadata.messageCount++;
      if (response.usage) {
        session.metadata.totalTokens += response.usage.totalTokens || 0;
      }

      // Check if context switch needed
      if (this.shouldSwitchContext(context)) {
        await this.handleContextSwitch(session);
      }

      const turnResult: TurnResult = {
        request,
        response,
        context,
        session,
        functionCalls,
        functionResults,
        metrics: {
          turnDuration: Date.now() - turnStartTime,
          tokensUsed: response.usage?.totalTokens || 0,
          providerUsed: response.provider || 'unknown'
        }
      };

      this.emit('turn_completed', turnResult);
      return turnResult;

    } catch (error) {
      this.emit('turn_error', {
        sessionId,
        error,
        context
      });
      throw error;
    }
  }

  /**
   * Stream message in conversation
   */
  async *streamMessage(
    sessionId: string,
    content: string,
    options: {
      role?: MessageRole;
      priority?: RequestPriority;
      providerId?: string;
      temperature?: number;
      maxTokens?: number;
      enableFunctions?: boolean;
      metadata?: Record<string, any>;
    } = {}
  ): AsyncIterable<LLMResponseChunk> {
    const session = this.sessions.get(sessionId);
    if (!session || session.status !== 'active') {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: `Invalid or inactive session: ${sessionId}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    const context = this.contextManager.getContext(session.contextId);
    if (!context) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: `Context not found: ${session.contextId}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Add user message
    await this.contextManager.addMessage(context.conversationId, {
      role: options.role || MessageRole.USER,
      content,
      metadata: {
        ...options.metadata,
        source: 'user',
        sessionId
      }
    });

    // Create request
    const request: LLMRequest = {
      id: `stream-${sessionId}-${Date.now()}`,
      type: LLMRequestType.COMPLETION,
      prompt: await this.buildPrompt(context),
      agentDID: session.agentDID,
      sessionId,
      parameters: {
        temperature: options.temperature,
        maxTokens: options.maxTokens,
        stream: true
      },
      metadata: {
        agentDID: session.agentDID,
        sessionId,
        requestId: `stream-${sessionId}-${Date.now()}`,
        timestamp: new Date(),
        source: 'conversation-manager',
        priority: options.priority || RequestPriority.MEDIUM,
        conversationId: context.conversationId
      }
    };

    let fullContent = '';
    let totalTokens = 0;

    try {
      for await (const chunk of this.messageRouter.streamMessage(request)) {
        fullContent += chunk.content || '';
        totalTokens += chunk.tokens || 0;
        yield chunk;
      }

      // Add complete response to context
      await this.contextManager.addMessage(context.conversationId, {
        role: MessageRole.ASSISTANT,
        content: fullContent,
        metadata: {
          source: 'llm',
          streaming: true,
          totalTokens
        }
      });

      // Update session
      session.metadata.lastActivity = new Date();
      session.metadata.messageCount++;
      session.metadata.totalTokens += totalTokens;

    } catch (error) {
      this.emit('stream_error', {
        sessionId,
        error,
        partialContent: fullContent
      });
      throw error;
    }
  }

  /**
   * Handle streaming request
   */
  private async handleStreamingRequest(
    request: LLMRequest,
    session: ConversationSession,
    context: ConversationContext
  ): Promise<LLMResponse> {
    let fullContent = '';
    let totalTokens = 0;
    let provider = '';
    let model = '';

    for await (const chunk of this.messageRouter.streamMessage(request)) {
      fullContent += chunk.content || '';
      totalTokens += chunk.tokens || 0;
      provider = chunk.provider || provider;
      model = chunk.model || model;

      // Emit streaming chunk
      this.emit('streaming_chunk', {
        sessionId: session.id,
        chunk
      });
    }

    return {
      id: request.id,
      status: 'success',
      content: fullContent,
      provider,
      model,
      timestamp: new Date(),
      usage: {
        totalTokens,
        promptTokens: 0,
        completionTokens: totalTokens,
        model,
        provider
      }
    };
  }

  /**
   * Handle multi-turn conversation
   */
  private async handleMultiTurn(
    session: ConversationSession,
    context: ConversationContext,
    lastResponse: LLMResponse,
    functionResult: FunctionResult
  ): Promise<LLMResponse | null> {
    const state = this.multiTurnStates.get(session.id) || {
      sessionId: session.id,
      pendingFunctions: [],
      awaitingInput: false,
      turnCount: 0
    };

    state.turnCount++;
    state.lastResponse = lastResponse;

    // Check if we need to continue the conversation
    const needsContinuation = this.shouldContinueMultiTurn(lastResponse, functionResult);
    
    if (needsContinuation) {
      // Build follow-up request
      const followUpRequest: LLMRequest = {
        id: `followup-${session.id}-${Date.now()}`,
        type: LLMRequestType.COMPLETION,
        prompt: await this.buildPrompt(context),
        agentDID: session.agentDID,
        sessionId: session.id,
        parameters: {
          temperature: 0.7,
          maxTokens: 500
        },
        metadata: {
          agentDID: session.agentDID,
          sessionId: session.id,
          requestId: `followup-${session.id}-${Date.now()}`,
          timestamp: new Date(),
          source: 'multi-turn',
          priority: RequestPriority.MEDIUM,
          conversationId: context.conversationId,
          multiTurn: true
        }
      };

      try {
        const response = await this.messageRouter.routeMessage(followUpRequest);
        
        // Add follow-up response to context
        await this.contextManager.addMessage(context.conversationId, {
          role: MessageRole.ASSISTANT,
          content: response.content || '',
          metadata: {
            source: 'llm-followup',
            provider: response.provider,
            model: response.model,
            multiTurn: true
          }
        });

        this.multiTurnStates.set(session.id, state);
        return response;

      } catch (error) {
        // Clean up state on error
        this.multiTurnStates.delete(session.id);
        throw error;
      }
    } else {
      // Clean up multi-turn state
      this.multiTurnStates.delete(session.id);
      return null;
    }
  }

  /**
   * Check if multi-turn should continue
   */
  private shouldContinueMultiTurn(
    lastResponse: LLMResponse,
    functionResult: FunctionResult
  ): boolean {
    // Continue if function result indicates more work needed
    if (functionResult.result?.continue === true) {
      return true;
    }

    // Continue if response asks for more information
    const content = lastResponse.content?.toLowerCase() || '';
    if (content.includes('need more') || 
        content.includes('additional information') ||
        content.includes('clarification')) {
      return true;
    }

    // Continue if response is incomplete
    if (content.endsWith('...') || 
        content.includes('let me continue') ||
        content.includes('furthermore')) {
      return true;
    }

    return false;
  }

  /**
   * Build prompt from context
   */
  private async buildPrompt(context: ConversationContext): Promise<string> {
    let prompt = '';

    // Add context summary if available
    if (context.summary) {
      prompt += `Previous conversation summary:\n${context.summary}\n\n`;
    }

    // Add recent messages
    const recentMessages = context.history.slice(-10); // Last 10 messages
    for (const message of recentMessages) {
      let roleLabel: string = message.role;
      if (message.role === MessageRole.ASSISTANT) {
        roleLabel = 'Assistant';
      } else if (message.role === MessageRole.USER) {
        roleLabel = 'User';
      } else if (message.role === MessageRole.SYSTEM) {
        roleLabel = 'System';
      } else if (message.role === MessageRole.FUNCTION) {
        roleLabel = `Function (${message.functionCall?.name || 'unknown'})`;
      }

      prompt += `${roleLabel}: ${message.content}\n`;
      
      if (message.functionCall) {
        prompt += `Function Call: ${message.functionCall.name}(${JSON.stringify(message.functionCall.arguments)})\n`;
      }
    }

    return prompt.trim();
  }

  /**
   * Get function definitions for agent
   */
  private async getFunctionDefinitions(agentDID: string): Promise<any[]> {
    // This would integrate with the agent's available functions
    // For now, return empty array
    return [];
  }

  /**
   * Check if context should be switched
   */
  private shouldSwitchContext(context: ConversationContext): boolean {
    const tokenRatio = context.tokens / context.maxTokens;
    return tokenRatio > this.config.contextSwitchThreshold;
  }

  /**
   * Handle context switch
   */
  private async handleContextSwitch(session: ConversationSession): Promise<void> {
    const oldContext = this.contextManager.getContext(session.contextId);
    if (!oldContext) return;

    // Compress old context
    await this.contextManager.compressContext(oldContext);

    // Create new context
    const newContext = await this.contextManager.createContext(
      session.agentDID,
      `${session.id}-continued`,
      {
        ...oldContext.metadata,
        purpose: `Continued from ${session.contextId}`
      }
    );

    // Add summary message
    if (oldContext.summary) {
      await this.contextManager.addMessage(newContext.conversationId, {
        role: MessageRole.SYSTEM,
        content: `Previous conversation summary: ${oldContext.summary}`,
        metadata: {
          source: 'context-switch',
          previousContextId: oldContext.conversationId
        }
      });
    }

    // Update session
    session.contextId = newContext.conversationId;

    this.emit('context_switched', {
      session,
      oldContextId: oldContext.conversationId,
      newContextId: newContext.conversationId
    });
  }

  /**
   * Pause conversation
   */
  pauseConversation(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.status = 'paused';
      this.emit('conversation_paused', session);
    }
  }

  /**
   * Resume conversation
   */
  resumeConversation(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session && session.status === 'paused') {
      session.status = 'active';
      session.metadata.lastActivity = new Date();
      this.emit('conversation_resumed', session);
    }
  }

  /**
   * End conversation
   */
  async endConversation(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.status = 'ended';
    session.metadata.lastActivity = new Date();

    // Clean up multi-turn state
    this.multiTurnStates.delete(sessionId);

    // Remove from agent sessions
    const agentSessions = this.agentSessions.get(session.agentDID);
    if (agentSessions) {
      agentSessions.delete(sessionId);
      if (agentSessions.size === 0) {
        this.agentSessions.delete(session.agentDID);
      }
    }

    // Auto-summarize if enabled
    if (this.config.autoSummarize) {
      const context = this.contextManager.getContext(session.contextId);
      if (context && context.history.length > 5) {
        await this.contextManager.compressContext(context);
      }
    }

    this.emit('conversation_ended', session);
  }

  /**
   * Get agent conversations
   */
  getAgentConversations(agentDID: string): ConversationSession[] {
    const sessionIds = this.agentSessions.get(agentDID) || new Set();
    const sessions = Array.from(sessionIds)
      .map(id => this.sessions.get(id))
      .filter(Boolean) as ConversationSession[];
    
    return sessions.sort((a, b) => b.metadata.lastActivity.getTime() - a.metadata.lastActivity.getTime());
  }

  /**
   * Get conversation statistics
   */
  getStatistics(): {
    totalSessions: number;
    activeSessions: number;
    pausedSessions: number;
    endedSessions: number;
    averageMessagesPerSession: number;
    averageTokensPerSession: number;
    multiTurnSessions: number;
  } {
    const sessions = Array.from(this.sessions.values());
    
    return {
      totalSessions: sessions.length,
      activeSessions: sessions.filter(s => s.status === 'active').length,
      pausedSessions: sessions.filter(s => s.status === 'paused').length,
      endedSessions: sessions.filter(s => s.status === 'ended').length,
      averageMessagesPerSession: sessions.reduce((sum, s) => sum + s.metadata.messageCount, 0) / 
                                 (sessions.length || 1),
      averageTokensPerSession: sessions.reduce((sum, s) => sum + s.metadata.totalTokens, 0) / 
                              (sessions.length || 1),
      multiTurnSessions: this.multiTurnStates.size
    };
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    this.messageRouter.on('provider_health_updated', (health) => {
      this.emit('provider_health_updated', health);
    });

    this.contextManager.on('context_compressed', (event) => {
      this.emit('context_compressed', event);
    });

    this.agentLLMManager.on('function_executed', (event) => {
      this.emit('function_executed', event);
    });
  }

  /**
   * Start idle session check
   */
  private startIdleCheck(): void {
    this.idleCheckTimer = setInterval(() => {
      this.checkIdleSessions();
    }, 60000); // Check every minute
  }

  /**
   * Check for idle sessions
   */
  private checkIdleSessions(): void {
    const now = Date.now();
    const idleSessions: string[] = [];

    for (const [id, session] of this.sessions) {
      const idleTime = now - session.metadata.lastActivity.getTime();
      if (idleTime > this.config.maxIdleTime && session.status === 'active') {
        this.pauseConversation(id);
        idleSessions.push(id);
      }
    }

    if (idleSessions.length > 0) {
      this.emit('sessions_idle', idleSessions);
    }
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    if (this.idleCheckTimer) {
      clearInterval(this.idleCheckTimer);
    }

    // End all active sessions
    for (const [sessionId, session] of this.sessions) {
      if (session.status === 'active') {
        this.endConversation(sessionId);
      }
    }

    this.sessions.clear();
    this.agentSessions.clear();
    this.multiTurnStates.clear();
    
    this.removeAllListeners();
  }
}

export default ConversationManager;