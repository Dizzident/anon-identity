/**
 * Context Manager for MCP
 * 
 * Manages conversation contexts across agent-LLM interactions with compression and sharing
 */

import { EventEmitter } from 'events';
import {
  ConversationContext,
  ConversationMessage,
  MessageRole,
  ContextMetadata,
  ContextPriority,
  ContextRetention,
  MCPError,
  MCPErrorCode,
  MessageMetadata,
  FunctionCall,
  FunctionResult
} from '../types';
import { MemoryStorageProvider } from '../../storage/providers/memory-storage-provider';

/**
 * Context compression result
 */
export interface CompressionResult {
  originalTokens: number;
  compressedTokens: number;
  compressionRatio: number;
  summary: string;
  droppedMessages: number;
}

/**
 * Context sharing configuration
 */
export interface ContextSharingConfig {
  allowSharing: boolean;
  requireConsent: boolean;
  maxShareDepth: number;
  shareableFields: string[];
}

/**
 * Context search options
 */
export interface ContextSearchOptions {
  agentDID?: string;
  sessionId?: string;
  conversationId?: string;
  priority?: ContextPriority;
  domain?: string;
  includeArchived?: boolean;
  limit?: number;
}

/**
 * Context statistics
 */
export interface ContextStatistics {
  totalContexts: number;
  activeContexts: number;
  archivedContexts: number;
  totalTokens: number;
  averageTokensPerContext: number;
  compressionsSaved: number;
  contextsByPriority: Record<ContextPriority, number>;
  contextsByDomain: Record<string, number>;
}

/**
 * Context Manager
 */
export class ContextManager extends EventEmitter {
  private contexts: Map<string, ConversationContext> = new Map();
  private sessionIndex: Map<string, Set<string>> = new Map(); // sessionId -> contextIds
  private agentIndex: Map<string, Set<string>> = new Map(); // agentDID -> contextIds
  private domainIndex: Map<string, Set<string>> = new Map(); // domain -> contextIds
  private archivedContexts: Map<string, ConversationContext> = new Map();
  private compressionTimer?: NodeJS.Timeout;
  private retentionTimer?: NodeJS.Timeout;
  private storageProvider: MemoryStorageProvider;

  constructor(
    private config: {
      maxTokensPerContext: number;
      compressionThreshold: number;
      compressionStrategy: 'summary' | 'sliding-window' | 'importance';
      retentionCheckInterval: number;
      sharing: ContextSharingConfig;
      archiveAfterDays: number;
    } = {
      maxTokensPerContext: 4000,
      compressionThreshold: 0.8, // Compress at 80% capacity
      compressionStrategy: 'importance',
      retentionCheckInterval: 3600000, // 1 hour
      sharing: {
        allowSharing: true,
        requireConsent: true,
        maxShareDepth: 2,
        shareableFields: ['domain', 'purpose', 'summary']
      },
      archiveAfterDays: 30
    },
    storageProvider?: MemoryStorageProvider
  ) {
    super();
    this.storageProvider = storageProvider || new MemoryStorageProvider();
    this.loadContexts();
    this.startMaintenanceTasks();
  }

  /**
   * Create or update context
   */
  async createContext(
    agentDID: string,
    sessionId: string,
    metadata: ContextMetadata
  ): Promise<ConversationContext> {
    const conversationId = `conv-${agentDID}-${sessionId}-${Date.now()}`;
    
    const context: ConversationContext = {
      agentDID,
      sessionId,
      conversationId,
      history: [],
      metadata,
      lastUpdated: new Date(),
      tokens: 0,
      maxTokens: this.config.maxTokensPerContext
    };

    this.contexts.set(conversationId, context);
    this.updateIndices(context);
    await this.saveContexts();

    this.emit('context_created', context);
    return context;
  }

  /**
   * Get context
   */
  getContext(conversationId: string): ConversationContext | null {
    return this.contexts.get(conversationId) || this.archivedContexts.get(conversationId) || null;
  }

  /**
   * Get contexts for agent
   */
  getAgentContexts(agentDID: string, includeArchived = false): ConversationContext[] {
    const contextIds = this.agentIndex.get(agentDID) || new Set();
    const contexts = Array.from(contextIds)
      .map(id => this.contexts.get(id))
      .filter(Boolean) as ConversationContext[];

    if (includeArchived) {
      const archivedIds = Array.from(this.archivedContexts.values())
        .filter(ctx => ctx.agentDID === agentDID);
      contexts.push(...archivedIds);
    }

    return contexts.sort((a, b) => b.lastUpdated.getTime() - a.lastUpdated.getTime());
  }

  /**
   * Add message to context
   */
  async addMessage(
    conversationId: string,
    message: Omit<ConversationMessage, 'id' | 'timestamp'>
  ): Promise<ConversationMessage> {
    const context = this.contexts.get(conversationId);
    if (!context) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: `Context not found: ${conversationId}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    const fullMessage: ConversationMessage = {
      ...message,
      id: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date()
    };

    context.history.push(fullMessage);
    context.lastUpdated = new Date();
    
    // Update token count
    context.tokens += this.estimateTokens(fullMessage.content);

    // Check if compression needed
    if (context.tokens > context.maxTokens * this.config.compressionThreshold) {
      await this.compressContext(context);
    }

    await this.saveContexts();
    this.emit('message_added', { context, message: fullMessage });

    return fullMessage;
  }

  /**
   * Compress context
   */
  async compressContext(context: ConversationContext): Promise<CompressionResult> {
    const originalTokens = context.tokens;
    let compressedTokens = 0;
    let droppedMessages = 0;
    let summary = '';

    switch (this.config.compressionStrategy) {
      case 'summary':
        const result = await this.summarizeContext(context);
        summary = result.summary;
        compressedTokens = result.tokens;
        droppedMessages = result.droppedMessages;
        break;

      case 'sliding-window':
        const windowResult = this.applySlidingWindow(context);
        compressedTokens = windowResult.tokens;
        droppedMessages = windowResult.droppedMessages;
        break;

      case 'importance':
        const importanceResult = await this.compressByImportance(context);
        summary = importanceResult.summary;
        compressedTokens = importanceResult.tokens;
        droppedMessages = importanceResult.droppedMessages;
        break;
    }

    context.tokens = compressedTokens;
    context.compressedAt = new Date();
    if (summary) {
      context.summary = summary;
    }

    await this.saveContexts();

    const compressionResult: CompressionResult = {
      originalTokens,
      compressedTokens,
      compressionRatio: compressedTokens / originalTokens,
      summary,
      droppedMessages
    };

    this.emit('context_compressed', { context, result: compressionResult });
    return compressionResult;
  }

  /**
   * Summarize context
   */
  private async summarizeContext(context: ConversationContext): Promise<{
    summary: string;
    tokens: number;
    droppedMessages: number;
  }> {
    // Group messages by topic/function
    const topics = this.groupMessagesByTopic(context.history);
    
    // Create summary of key points
    const summaryParts: string[] = [];
    let keptMessages: ConversationMessage[] = [];
    
    for (const [topic, messages] of topics) {
      // Keep most recent message per topic
      const recent = messages[messages.length - 1];
      keptMessages.push(recent);
      
      // Add to summary
      if (messages.length > 1) {
        summaryParts.push(`${topic}: ${messages.length} messages, latest: ${recent.content.substring(0, 100)}...`);
      }
    }

    // Keep system messages and function calls
    const importantMessages = context.history.filter(msg => 
      msg.role === MessageRole.SYSTEM || 
      msg.functionCall || 
      msg.functionResult
    );
    
    keptMessages.push(...importantMessages);
    
    // Sort by timestamp
    keptMessages.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    
    // Update context
    const droppedMessages = context.history.length - keptMessages.length;
    context.history = keptMessages;
    
    const summary = summaryParts.join('\n');
    const tokens = keptMessages.reduce((sum, msg) => sum + this.estimateTokens(msg.content), 0);
    
    return { summary, tokens, droppedMessages };
  }

  /**
   * Apply sliding window compression
   */
  private applySlidingWindow(context: ConversationContext): {
    tokens: number;
    droppedMessages: number;
  } {
    const targetTokens = context.maxTokens * 0.6; // Keep 60% after compression
    let currentTokens = context.tokens;
    let droppedMessages = 0;
    
    // Remove oldest messages until under target
    while (currentTokens > targetTokens && context.history.length > 10) {
      const removed = context.history.shift();
      if (removed) {
        currentTokens -= this.estimateTokens(removed.content);
        droppedMessages++;
      }
    }
    
    return { tokens: currentTokens, droppedMessages };
  }

  /**
   * Compress by importance
   */
  private async compressByImportance(context: ConversationContext): Promise<{
    summary: string;
    tokens: number;
    droppedMessages: number;
  }> {
    // Score each message by importance
    const scoredMessages = context.history.map(msg => ({
      message: msg,
      score: this.calculateMessageImportance(msg, context)
    }));
    
    // Sort by importance
    scoredMessages.sort((a, b) => b.score - a.score);
    
    // Keep top messages within token limit
    const targetTokens = context.maxTokens * 0.7;
    let currentTokens = 0;
    const keptMessages: ConversationMessage[] = [];
    const droppedSummary: string[] = [];
    
    for (const { message, score } of scoredMessages) {
      const messageTokens = this.estimateTokens(message.content);
      
      if (currentTokens + messageTokens <= targetTokens || score > 0.8) {
        keptMessages.push(message);
        currentTokens += messageTokens;
      } else {
        droppedSummary.push(`[${message.role}]: ${message.content.substring(0, 50)}...`);
      }
    }
    
    // Sort kept messages by timestamp
    keptMessages.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    
    const droppedMessages = context.history.length - keptMessages.length;
    context.history = keptMessages;
    
    const summary = droppedMessages > 0 
      ? `Compressed ${droppedMessages} messages:\n${droppedSummary.slice(0, 5).join('\n')}`
      : '';
    
    return { summary, tokens: currentTokens, droppedMessages };
  }

  /**
   * Calculate message importance
   */
  private calculateMessageImportance(
    message: ConversationMessage,
    context: ConversationContext
  ): number {
    let score = 0.5; // Base score
    
    // Role importance
    if (message.role === MessageRole.SYSTEM) score += 0.3;
    if (message.role === MessageRole.FUNCTION) score += 0.2;
    
    // Function calls are important
    if (message.functionCall) score += 0.3;
    if (message.functionResult) score += 0.2;
    
    // Recent messages are more important
    const age = Date.now() - message.timestamp.getTime();
    const ageHours = age / (1000 * 60 * 60);
    score += Math.max(0, 0.2 - ageHours / 24);
    
    // Messages with errors or warnings
    if (message.content.toLowerCase().includes('error')) score += 0.2;
    if (message.content.toLowerCase().includes('warning')) score += 0.1;
    
    // Long messages might contain more information
    const length = message.content.length;
    if (length > 500) score += 0.1;
    
    // Priority context messages
    if (context.metadata.priority === ContextPriority.CRITICAL) score += 0.2;
    if (context.metadata.priority === ContextPriority.HIGH) score += 0.1;
    
    return Math.min(1, score);
  }

  /**
   * Share context with another agent
   */
  async shareContext(
    conversationId: string,
    targetAgentDID: string,
    options: {
      shareHistory?: boolean;
      shareSummary?: boolean;
      shareMetadata?: boolean;
    } = {}
  ): Promise<ConversationContext> {
    if (!this.config.sharing.allowSharing) {
      throw new MCPError({
        code: MCPErrorCode.FORBIDDEN,
        message: 'Context sharing is disabled',
        timestamp: new Date(),
        retryable: false
      });
    }

    const sourceContext = this.contexts.get(conversationId);
    if (!sourceContext) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: `Context not found: ${conversationId}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Check if already shared with target
    if (sourceContext.metadata.sharedWith.includes(targetAgentDID)) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Context already shared with target agent',
        timestamp: new Date(),
        retryable: false
      });
    }

    // Create shared context
    const sharedMetadata: ContextMetadata = {
      ...sourceContext.metadata,
      sharedWith: [sourceContext.agentDID], // Original owner
      agentName: `Shared from ${sourceContext.metadata.agentName}`
    };

    // Filter metadata based on shareable fields
    if (options.shareMetadata !== false) {
      for (const key of Object.keys(sharedMetadata)) {
        if (!this.config.sharing.shareableFields.includes(key)) {
          delete (sharedMetadata as any)[key];
        }
      }
    }

    const sharedContext = await this.createContext(
      targetAgentDID,
      `shared-${sourceContext.sessionId}`,
      sharedMetadata
    );

    // Copy history if requested
    if (options.shareHistory !== false) {
      const historyToShare = sourceContext.history.slice(-20); // Last 20 messages
      sharedContext.history = historyToShare.map(msg => ({
        ...msg,
        metadata: {
          ...msg.metadata,
          sharedFrom: sourceContext.agentDID
        }
      }));
    }

    // Copy summary if available
    if (options.shareSummary !== false && sourceContext.summary) {
      sharedContext.summary = sourceContext.summary;
    }

    // Update source context
    sourceContext.metadata.sharedWith.push(targetAgentDID);
    
    await this.saveContexts();
    
    this.emit('context_shared', {
      source: sourceContext,
      target: sharedContext,
      sharedWith: targetAgentDID
    });

    return sharedContext;
  }

  /**
   * Search contexts
   */
  async searchContexts(options: ContextSearchOptions): Promise<ConversationContext[]> {
    let contexts = Array.from(this.contexts.values());
    
    if (options.includeArchived) {
      contexts.push(...Array.from(this.archivedContexts.values()));
    }

    // Apply filters
    if (options.agentDID) {
      contexts = contexts.filter(ctx => ctx.agentDID === options.agentDID);
    }
    if (options.sessionId) {
      contexts = contexts.filter(ctx => ctx.sessionId === options.sessionId);
    }
    if (options.conversationId) {
      contexts = contexts.filter(ctx => ctx.conversationId === options.conversationId);
    }
    if (options.priority) {
      contexts = contexts.filter(ctx => ctx.metadata.priority === options.priority);
    }
    if (options.domain) {
      contexts = contexts.filter(ctx => ctx.metadata.domain === options.domain);
    }

    // Sort by last updated
    contexts.sort((a, b) => b.lastUpdated.getTime() - a.lastUpdated.getTime());

    // Apply limit
    if (options.limit) {
      contexts = contexts.slice(0, options.limit);
    }

    return contexts;
  }

  /**
   * Archive old contexts
   */
  private async archiveOldContexts(): Promise<void> {
    const archiveDate = new Date(Date.now() - this.config.archiveAfterDays * 24 * 60 * 60 * 1000);
    const toArchive: ConversationContext[] = [];

    for (const [id, context] of this.contexts) {
      if (context.lastUpdated < archiveDate && 
          context.metadata.retention.autoDelete !== false) {
        toArchive.push(context);
      }
    }

    for (const context of toArchive) {
      this.contexts.delete(context.conversationId);
      this.archivedContexts.set(context.conversationId, context);
      
      // Update indices
      this.removeFromIndices(context);
      
      this.emit('context_archived', context);
    }

    if (toArchive.length > 0) {
      await this.saveContexts();
    }
  }

  /**
   * Apply retention policies
   */
  private async applyRetentionPolicies(): Promise<void> {
    const now = Date.now();
    const toDelete: string[] = [];

    // Check active contexts
    for (const [id, context] of this.contexts) {
      const retention = context.metadata.retention;
      if (retention.duration && 
          now - context.lastUpdated.getTime() > retention.duration) {
        
        if (retention.autoDelete) {
          toDelete.push(id);
        } else if (retention.archiveAfter) {
          // Move to archive instead
          this.archivedContexts.set(id, context);
          this.contexts.delete(id);
        }
      }
    }

    // Check archived contexts
    for (const [id, context] of this.archivedContexts) {
      const retention = context.metadata.retention;
      if (retention.autoDelete && retention.duration &&
          now - context.lastUpdated.getTime() > retention.duration * 2) {
        this.archivedContexts.delete(id);
        this.emit('context_deleted', context);
      }
    }

    // Delete contexts
    for (const id of toDelete) {
      const context = this.contexts.get(id);
      if (context) {
        this.contexts.delete(id);
        this.removeFromIndices(context);
        this.emit('context_deleted', context);
      }
    }

    if (toDelete.length > 0) {
      await this.saveContexts();
    }
  }

  /**
   * Group messages by topic
   */
  private groupMessagesByTopic(messages: ConversationMessage[]): Map<string, ConversationMessage[]> {
    const topics = new Map<string, ConversationMessage[]>();
    
    for (const message of messages) {
      let topic = 'general';
      
      // Determine topic based on content
      if (message.functionCall) {
        topic = `function:${message.functionCall.name}`;
      } else if (message.content.includes('error')) {
        topic = 'errors';
      } else if (message.content.includes('delegation')) {
        topic = 'delegation';
      } else if (message.metadata?.topic) {
        topic = message.metadata.topic as string;
      }
      
      const topicMessages = topics.get(topic) || [];
      topicMessages.push(message);
      topics.set(topic, topicMessages);
    }
    
    return topics;
  }

  /**
   * Estimate token count
   */
  private estimateTokens(text: string): number {
    // Rough estimate: 1 token per 4 characters
    return Math.ceil(text.length / 4);
  }

  /**
   * Update indices
   */
  private updateIndices(context: ConversationContext): void {
    // Session index
    const sessionContexts = this.sessionIndex.get(context.sessionId) || new Set();
    sessionContexts.add(context.conversationId);
    this.sessionIndex.set(context.sessionId, sessionContexts);

    // Agent index
    const agentContexts = this.agentIndex.get(context.agentDID) || new Set();
    agentContexts.add(context.conversationId);
    this.agentIndex.set(context.agentDID, agentContexts);

    // Domain index
    const domainContexts = this.domainIndex.get(context.metadata.domain) || new Set();
    domainContexts.add(context.conversationId);
    this.domainIndex.set(context.metadata.domain, domainContexts);
  }

  /**
   * Remove from indices
   */
  private removeFromIndices(context: ConversationContext): void {
    this.sessionIndex.get(context.sessionId)?.delete(context.conversationId);
    this.agentIndex.get(context.agentDID)?.delete(context.conversationId);
    this.domainIndex.get(context.metadata.domain)?.delete(context.conversationId);
  }

  /**
   * Load contexts from storage
   */
  private async loadContexts(): Promise<void> {
    try {
      const storage = (this.storageProvider as any)._storage;
      if (!storage) return;

      const storedContexts = storage.get('mcp:contexts');
      if (storedContexts) {
        const contexts = JSON.parse(storedContexts);
        for (const context of contexts) {
          // Convert dates
          context.lastUpdated = new Date(context.lastUpdated);
          if (context.compressedAt) {
            context.compressedAt = new Date(context.compressedAt);
          }
          context.history.forEach((msg: any) => {
            msg.timestamp = new Date(msg.timestamp);
          });
          
          this.contexts.set(context.conversationId, context);
          this.updateIndices(context);
        }
      }

      const storedArchived = storage.get('mcp:contexts:archived');
      if (storedArchived) {
        const archived = JSON.parse(storedArchived);
        for (const context of archived) {
          // Convert dates
          context.lastUpdated = new Date(context.lastUpdated);
          if (context.compressedAt) {
            context.compressedAt = new Date(context.compressedAt);
          }
          context.history.forEach((msg: any) => {
            msg.timestamp = new Date(msg.timestamp);
          });
          
          this.archivedContexts.set(context.conversationId, context);
        }
      }
    } catch (error) {
      this.emit('error', error);
    }
  }

  /**
   * Save contexts to storage
   */
  private async saveContexts(): Promise<void> {
    try {
      const storage = (this.storageProvider as any)._storage || new Map();
      
      storage.set('mcp:contexts', JSON.stringify(Array.from(this.contexts.values())));
      storage.set('mcp:contexts:archived', JSON.stringify(Array.from(this.archivedContexts.values())));
      
      (this.storageProvider as any)._storage = storage;
    } catch (error) {
      this.emit('error', error);
    }
  }

  /**
   * Start maintenance tasks
   */
  private startMaintenanceTasks(): void {
    // Compression check every 5 minutes
    this.compressionTimer = setInterval(() => {
      this.checkCompressionNeeded();
    }, 5 * 60 * 1000);

    // Retention check
    this.retentionTimer = setInterval(() => {
      this.applyRetentionPolicies();
      this.archiveOldContexts();
    }, this.config.retentionCheckInterval);
  }

  /**
   * Check if compression needed
   */
  private async checkCompressionNeeded(): Promise<void> {
    for (const [, context] of this.contexts) {
      if (context.tokens > context.maxTokens * this.config.compressionThreshold) {
        await this.compressContext(context);
      }
    }
  }

  /**
   * Get statistics
   */
  getStatistics(): ContextStatistics {
    const stats: ContextStatistics = {
      totalContexts: this.contexts.size + this.archivedContexts.size,
      activeContexts: this.contexts.size,
      archivedContexts: this.archivedContexts.size,
      totalTokens: 0,
      averageTokensPerContext: 0,
      compressionsSaved: 0,
      contextsByPriority: {
        [ContextPriority.LOW]: 0,
        [ContextPriority.MEDIUM]: 0,
        [ContextPriority.HIGH]: 0,
        [ContextPriority.CRITICAL]: 0
      },
      contextsByDomain: {}
    };

    let totalCompressed = 0;

    for (const context of this.contexts.values()) {
      stats.totalTokens += context.tokens;
      stats.contextsByPriority[context.metadata.priority]++;
      stats.contextsByDomain[context.metadata.domain] = 
        (stats.contextsByDomain[context.metadata.domain] || 0) + 1;
      
      if (context.compressedAt) {
        totalCompressed++;
      }
    }

    stats.averageTokensPerContext = stats.activeContexts > 0 
      ? stats.totalTokens / stats.activeContexts 
      : 0;
    
    stats.compressionsSaved = totalCompressed;

    return stats;
  }

  /**
   * Clear context
   */
  async clearContext(conversationId: string): Promise<void> {
    const context = this.contexts.get(conversationId);
    if (context) {
      context.history = [];
      context.tokens = 0;
      context.summary = undefined;
      context.compressedAt = undefined;
      context.lastUpdated = new Date();
      
      await this.saveContexts();
      this.emit('context_cleared', context);
    }
  }

  /**
   * Delete context
   */
  async deleteContext(conversationId: string): Promise<void> {
    const context = this.contexts.get(conversationId) || this.archivedContexts.get(conversationId);
    
    if (context) {
      this.contexts.delete(conversationId);
      this.archivedContexts.delete(conversationId);
      this.removeFromIndices(context);
      
      await this.saveContexts();
      this.emit('context_deleted', context);
    }
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    if (this.compressionTimer) {
      clearInterval(this.compressionTimer);
    }
    if (this.retentionTimer) {
      clearInterval(this.retentionTimer);
    }

    this.saveContexts().catch(() => {});
    
    this.contexts.clear();
    this.archivedContexts.clear();
    this.sessionIndex.clear();
    this.agentIndex.clear();
    this.domainIndex.clear();
    
    this.removeAllListeners();
  }
}

export default ContextManager;