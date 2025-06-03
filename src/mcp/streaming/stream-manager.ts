/**
 * Stream Manager for MCP
 * 
 * Manages streaming responses for real-time LLM interactions
 */

import { EventEmitter } from 'events';
import {
  LLMRequest,
  LLMResponse,
  LLMResponseChunk,
  StreamingConfig,
  MCPError,
  MCPErrorCode,
  MessageRole
} from '../types';
import { MessageRouter } from '../routing/message-router';
import { AuthManager } from '../security/auth-manager';
import { AuditLogger } from '../security/audit-logger';

/**
 * Stream session
 */
export interface StreamSession {
  id: string;
  agentDID: string;
  requestId: string;
  providerId: string;
  status: 'active' | 'paused' | 'completed' | 'error' | 'cancelled';
  startedAt: Date;
  lastChunkAt?: Date;
  completedAt?: Date;
  totalChunks: number;
  totalTokens: number;
  metadata: {
    purpose: string;
    priority: 'low' | 'medium' | 'high' | 'critical';
    maxDuration?: number;
    bufferSize?: number;
  };
}

/**
 * Stream chunk with metadata
 */
export interface EnhancedStreamChunk extends LLMResponseChunk {
  sessionId: string;
  chunkIndex: number;
  bufferStatus: {
    size: number;
    flushed: boolean;
  };
  latency: number;
  timestamp: Date;
}

/**
 * Stream buffer configuration
 */
export interface StreamBufferConfig {
  maxSize: number;           // Maximum buffer size in characters
  flushInterval: number;     // Auto-flush interval in ms
  flushOnComplete: boolean;  // Flush when sentence/thought is complete
  adaptiveBuffering: boolean; // Adjust buffer size based on stream speed
}

/**
 * Real-time processing configuration
 */
export interface RealTimeConfig {
  enableInterruption: boolean;   // Allow interrupting ongoing streams
  priorityPreemption: boolean;   // Higher priority streams can preempt lower ones
  multiplexing: boolean;         // Support multiple concurrent streams
  backpressureHandling: 'drop' | 'buffer' | 'throttle';
  qualityOfService: {
    targetLatency: number;       // Target chunk latency in ms
    maxJitter: number;           // Maximum acceptable jitter
    adaptiveQuality: boolean;    // Adjust quality based on network conditions
  };
}

/**
 * Stream Manager
 */
export class StreamManager extends EventEmitter {
  private activeSessions: Map<string, StreamSession> = new Map();
  private sessionBuffers: Map<string, StreamBuffer> = new Map();
  private sessionTimers: Map<string, NodeJS.Timeout> = new Map();
  private priorityQueue: PriorityQueue<StreamSession> = new PriorityQueue();
  private realTimeProcessor: RealTimeProcessor;

  constructor(
    private messageRouter: MessageRouter,
    private authManager: AuthManager,
    private auditLogger: AuditLogger,
    private config: {
      streaming: StreamingConfig;
      buffer: StreamBufferConfig;
      realTime: RealTimeConfig;
      maxConcurrentStreams: number;
      sessionTimeout: number;
    } = {
      streaming: {
        enabled: true,
        chunkSize: 512,
        flushInterval: 100,
        maxConcurrentStreams: 10,
        backpressureThreshold: 1000,
        compressionEnabled: false
      },
      buffer: {
        maxSize: 2048,
        flushInterval: 150,
        flushOnComplete: true,
        adaptiveBuffering: true
      },
      realTime: {
        enableInterruption: true,
        priorityPreemption: true,
        multiplexing: true,
        backpressureHandling: 'buffer',
        qualityOfService: {
          targetLatency: 50,
          maxJitter: 20,
          adaptiveQuality: true
        }
      },
      maxConcurrentStreams: 20,
      sessionTimeout: 300000 // 5 minutes
    }
  ) {
    super();
    this.realTimeProcessor = new RealTimeProcessor(this.config.realTime);
    this.setupEventHandlers();
  }

  /**
   * Start streaming session
   */
  async startStream(
    request: LLMRequest,
    options: {
      bufferConfig?: Partial<StreamBufferConfig>;
      priority?: 'low' | 'medium' | 'high' | 'critical';
      maxDuration?: number;
      onChunk?: (chunk: EnhancedStreamChunk) => void;
      onComplete?: (response: LLMResponse) => void;
      onError?: (error: MCPError) => void;
    } = {}
  ): Promise<StreamSession> {
    // Check authorization
    const authResult = await this.authManager.authorize(
      request.agentDID,
      'stream:create',
      'execute'
    );

    if (!authResult.authorized) {
      throw new MCPError({
        code: MCPErrorCode.FORBIDDEN,
        message: 'Not authorized to create stream',
        timestamp: new Date(),
        retryable: false
      });
    }

    // Check concurrent stream limit
    if (this.activeSessions.size >= this.config.maxConcurrentStreams) {
      if (this.config.realTime.priorityPreemption && options.priority === 'critical') {
        await this.preemptLowestPriorityStream();
      } else {
        throw new MCPError({
          code: MCPErrorCode.RATE_LIMITED,
          message: 'Maximum concurrent streams reached',
          timestamp: new Date(),
          retryable: true
        });
      }
    }

    // Create session
    const sessionId = `stream-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const session: StreamSession = {
      id: sessionId,
      agentDID: request.agentDID,
      requestId: request.id,
      providerId: 'auto-select', // Will be updated when provider is selected
      status: 'active',
      startedAt: new Date(),
      totalChunks: 0,
      totalTokens: 0,
      metadata: {
        purpose: request.metadata?.purpose || 'general',
        priority: options.priority || 'medium',
        maxDuration: options.maxDuration,
        bufferSize: options.bufferConfig?.maxSize
      }
    };

    // Create buffer
    const bufferConfig = { ...this.config.buffer, ...options.bufferConfig };
    const buffer = new StreamBuffer(sessionId, bufferConfig);
    
    this.activeSessions.set(sessionId, session);
    this.sessionBuffers.set(sessionId, buffer);

    // Add to priority queue
    this.priorityQueue.enqueue(session, this.getPriorityScore(session));

    // Set session timeout
    if (options.maxDuration || this.config.sessionTimeout) {
      const timeout = setTimeout(() => {
        this.timeoutSession(sessionId);
      }, options.maxDuration || this.config.sessionTimeout);
      
      this.sessionTimers.set(sessionId, timeout);
    }

    // Start real-time processing
    this.realTimeProcessor.startSession(session);

    // Audit stream creation
    await this.auditLogger.logRequest(
      request,
      request.agentDID,
      sessionId
    );

    this.emit('stream_started', session);

    // Start the actual streaming
    this.processStreamRequest(session, request, options).catch(error => {
      this.handleStreamError(sessionId, error);
    });

    return session;
  }

  /**
   * Process streaming request
   */
  private async processStreamRequest(
    session: StreamSession,
    request: LLMRequest,
    options: {
      onChunk?: (chunk: EnhancedStreamChunk) => void;
      onComplete?: (response: LLMResponse) => void;
      onError?: (error: MCPError) => void;
    }
  ): Promise<void> {
    try {
      // Route request with streaming enabled
      const streamingRequest = {
        ...request,
        streaming: true,
        metadata: {
          ...request.metadata,
          sessionId: session.id,
          streaming: true
        }
      };

      // Get stream from message router
      const stream = await this.messageRouter.routeStreamingMessage(streamingRequest);
      
      // Update session with actual provider
      session.providerId = stream.providerId || 'unknown';

      const buffer = this.sessionBuffers.get(session.id)!;
      let accumulatedContent = '';
      let chunkIndex = 0;

      // Process stream chunks
      for await (const chunk of stream) {
        if (session.status !== 'active') {
          break; // Session was cancelled or paused
        }

        const enhancedChunk = await this.processChunk(
          session,
          chunk,
          chunkIndex++,
          buffer
        );

        accumulatedContent += chunk.delta || '';
        session.totalChunks++;
        session.totalTokens += chunk.tokens || 0;
        session.lastChunkAt = new Date();

        // Call chunk handler
        if (options.onChunk) {
          options.onChunk(enhancedChunk);
        }

        this.emit('chunk_received', enhancedChunk);

        // Check for natural breakpoints
        if (this.isNaturalBreakpoint(accumulatedContent) && buffer.shouldFlush()) {
          await this.flushBuffer(session.id);
        }

        // Apply backpressure if needed
        if (this.shouldApplyBackpressure(session)) {
          await this.applyBackpressure(session);
        }
      }

      // Flush final buffer
      await this.flushBuffer(session.id, true);

      // Create final response
      const finalResponse: LLMResponse = {
        id: `response-${session.id}`,
        content: accumulatedContent,
        role: MessageRole.ASSISTANT,
        model: stream.model || 'unknown',
        provider: session.providerId,
        tokens: session.totalTokens,
        finishReason: 'stop',
        timestamp: new Date(),
        metadata: {
          sessionId: session.id,
          totalChunks: session.totalChunks,
          streamDuration: Date.now() - session.startedAt.getTime()
        }
      };

      // Complete session
      session.status = 'completed';
      session.completedAt = new Date();

      // Call completion handler
      if (options.onComplete) {
        options.onComplete(finalResponse);
      }

      this.emit('stream_completed', { session, response: finalResponse });

      // Cleanup
      await this.cleanupSession(session.id);

    } catch (error) {
      await this.handleStreamError(session.id, error as Error);
      if (options.onError) {
        options.onError(error as MCPError);
      }
    }
  }

  /**
   * Process individual chunk
   */
  private async processChunk(
    session: StreamSession,
    chunk: LLMResponseChunk,
    chunkIndex: number,
    buffer: StreamBuffer
  ): Promise<EnhancedStreamChunk> {
    const startTime = Date.now();

    // Add to buffer
    if (chunk.delta) {
      buffer.add(chunk.delta);
    }

    // Calculate latency
    const latency = Date.now() - (chunk.timestamp?.getTime() || startTime);

    // Create enhanced chunk
    const enhancedChunk: EnhancedStreamChunk = {
      ...chunk,
      sessionId: session.id,
      chunkIndex,
      bufferStatus: {
        size: buffer.getSize(),
        flushed: false
      },
      latency,
      timestamp: new Date()
    };

    // Real-time processing
    await this.realTimeProcessor.processChunk(session, enhancedChunk);

    // Quality of service monitoring
    this.monitorQualityOfService(session, enhancedChunk);

    return enhancedChunk;
  }

  /**
   * Check if natural breakpoint
   */
  private isNaturalBreakpoint(content: string): boolean {
    // Look for sentence endings, paragraph breaks, or logical pauses
    const patterns = [
      /\.\s*$/,          // Sentence ending
      /\?\s*$/,          // Question ending
      /!\s*$/,           // Exclamation ending
      /\n\n/,            // Paragraph break
      /:\s*$/,           // Colon (list start)
      /,\s*$/            // Comma pause
    ];

    return patterns.some(pattern => pattern.test(content.slice(-20)));
  }

  /**
   * Flush buffer
   */
  private async flushBuffer(sessionId: string, force = false): Promise<void> {
    const buffer = this.sessionBuffers.get(sessionId);
    if (!buffer) return;

    if (force || buffer.shouldFlush()) {
      const content = buffer.flush();
      if (content) {
        this.emit('buffer_flushed', {
          sessionId,
          content,
          size: content.length,
          forced: force
        });
      }
    }
  }

  /**
   * Check if backpressure should be applied
   */
  private shouldApplyBackpressure(session: StreamSession): boolean {
    const buffer = this.sessionBuffers.get(session.id);
    if (!buffer) return false;

    // Check buffer size
    if (buffer.getSize() > this.config.streaming.backpressureThreshold) {
      return true;
    }

    // Check system load
    if (this.activeSessions.size > this.config.maxConcurrentStreams * 0.8) {
      return true;
    }

    return false;
  }

  /**
   * Apply backpressure
   */
  private async applyBackpressure(session: StreamSession): Promise<void> {
    switch (this.config.realTime.backpressureHandling) {
      case 'buffer':
        // Buffer is already handling this
        break;
      case 'throttle':
        await new Promise(resolve => setTimeout(resolve, 50));
        break;
      case 'drop':
        // Skip this chunk (already processed)
        break;
    }
  }

  /**
   * Monitor quality of service
   */
  private monitorQualityOfService(session: StreamSession, chunk: EnhancedStreamChunk): void {
    const qos = this.config.realTime.qualityOfService;
    
    // Check latency
    if (chunk.latency > qos.targetLatency + qos.maxJitter) {
      this.emit('qos_violation', {
        sessionId: session.id,
        metric: 'latency',
        value: chunk.latency,
        threshold: qos.targetLatency + qos.maxJitter
      });

      // Apply adaptive quality if enabled
      if (qos.adaptiveQuality) {
        this.adaptStreamQuality(session, 'reduce');
      }
    }
  }

  /**
   * Adapt stream quality
   */
  private adaptStreamQuality(session: StreamSession, direction: 'increase' | 'reduce'): void {
    const buffer = this.sessionBuffers.get(session.id);
    if (!buffer) return;

    if (direction === 'reduce') {
      // Increase buffer size to reduce chunk frequency
      buffer.adaptBufferSize(1.2);
    } else {
      // Decrease buffer size for better responsiveness
      buffer.adaptBufferSize(0.8);
    }

    this.emit('quality_adapted', {
      sessionId: session.id,
      direction,
      newBufferSize: buffer.getMaxSize()
    });
  }

  /**
   * Pause stream
   */
  async pauseStream(sessionId: string): Promise<void> {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Stream session not found',
        timestamp: new Date(),
        retryable: false
      });
    }

    session.status = 'paused';
    this.realTimeProcessor.pauseSession(sessionId);
    
    this.emit('stream_paused', session);
  }

  /**
   * Resume stream
   */
  async resumeStream(sessionId: string): Promise<void> {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Stream session not found',
        timestamp: new Date(),
        retryable: false
      });
    }

    session.status = 'active';
    this.realTimeProcessor.resumeSession(sessionId);
    
    this.emit('stream_resumed', session);
  }

  /**
   * Cancel stream
   */
  async cancelStream(sessionId: string): Promise<void> {
    const session = this.activeSessions.get(sessionId);
    if (!session) return;

    session.status = 'cancelled';
    session.completedAt = new Date();

    // Flush any remaining buffer content
    await this.flushBuffer(sessionId, true);

    this.emit('stream_cancelled', session);
    await this.cleanupSession(sessionId);
  }

  /**
   * Handle stream error
   */
  private async handleStreamError(sessionId: string, error: Error): Promise<void> {
    const session = this.activeSessions.get(sessionId);
    if (session) {
      session.status = 'error';
      session.completedAt = new Date();
    }

    this.emit('stream_error', { sessionId, error });
    await this.cleanupSession(sessionId);
  }

  /**
   * Timeout session
   */
  private async timeoutSession(sessionId: string): Promise<void> {
    const session = this.activeSessions.get(sessionId);
    if (session && session.status === 'active') {
      await this.cancelStream(sessionId);
      
      this.emit('stream_timeout', session);
    }
  }

  /**
   * Preempt lowest priority stream
   */
  private async preemptLowestPriorityStream(): Promise<void> {
    const lowestPrioritySession = this.priorityQueue.dequeue();
    if (lowestPrioritySession) {
      await this.cancelStream(lowestPrioritySession.id);
      
      this.emit('stream_preempted', lowestPrioritySession);
    }
  }

  /**
   * Get priority score
   */
  private getPriorityScore(session: StreamSession): number {
    const priorityScores = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1
    };
    
    return priorityScores[session.metadata.priority] || 2;
  }

  /**
   * Cleanup session
   */
  private async cleanupSession(sessionId: string): Promise<void> {
    this.activeSessions.delete(sessionId);
    this.sessionBuffers.delete(sessionId);
    this.realTimeProcessor.endSession(sessionId);

    const timer = this.sessionTimers.get(sessionId);
    if (timer) {
      clearTimeout(timer);
      this.sessionTimers.delete(sessionId);
    }
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    this.on('stream_error', ({ sessionId, error }) => {
      console.error(`Stream error in session ${sessionId}:`, error);
    });

    this.on('qos_violation', ({ sessionId, metric, value, threshold }) => {
      console.warn(`QoS violation in session ${sessionId}: ${metric} = ${value} (threshold: ${threshold})`);
    });
  }

  /**
   * Get active sessions
   */
  getActiveSessions(): StreamSession[] {
    return Array.from(this.activeSessions.values());
  }

  /**
   * Get session statistics
   */
  getSessionStatistics(sessionId: string): {
    duration: number;
    chunksPerSecond: number;
    tokensPerSecond: number;
    averageLatency: number;
    bufferUtilization: number;
  } | null {
    const session = this.activeSessions.get(sessionId);
    if (!session) return null;

    const duration = Date.now() - session.startedAt.getTime();
    const durationSeconds = duration / 1000;

    return {
      duration,
      chunksPerSecond: durationSeconds > 0 ? session.totalChunks / durationSeconds : 0,
      tokensPerSecond: durationSeconds > 0 ? session.totalTokens / durationSeconds : 0,
      averageLatency: 0, // Would track this
      bufferUtilization: 0 // Would calculate from buffer
    };
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    // Cancel all active sessions
    for (const sessionId of this.activeSessions.keys()) {
      this.cancelStream(sessionId).catch(() => {});
    }

    // Clear timers
    for (const timer of this.sessionTimers.values()) {
      clearTimeout(timer);
    }

    this.realTimeProcessor.shutdown();
    this.removeAllListeners();
  }
}

/**
 * Stream Buffer
 */
class StreamBuffer {
  private buffer: string = '';
  private lastFlush: Date = new Date();

  constructor(
    private sessionId: string,
    private config: StreamBufferConfig
  ) {}

  add(content: string): void {
    this.buffer += content;
  }

  shouldFlush(): boolean {
    // Size-based flush
    if (this.buffer.length >= this.config.maxSize) {
      return true;
    }

    // Time-based flush
    if (Date.now() - this.lastFlush.getTime() >= this.config.flushInterval) {
      return true;
    }

    // Complete thought flush
    if (this.config.flushOnComplete && this.isCompleteThought()) {
      return true;
    }

    return false;
  }

  flush(): string {
    const content = this.buffer;
    this.buffer = '';
    this.lastFlush = new Date();
    return content;
  }

  getSize(): number {
    return this.buffer.length;
  }

  getMaxSize(): number {
    return this.config.maxSize;
  }

  adaptBufferSize(factor: number): void {
    if (this.config.adaptiveBuffering) {
      this.config.maxSize = Math.max(256, Math.min(4096, 
        Math.round(this.config.maxSize * factor)
      ));
    }
  }

  private isCompleteThought(): boolean {
    // Simple heuristic for complete thoughts
    return /[.!?]\s*$/.test(this.buffer.trim());
  }
}

/**
 * Real-Time Processor
 */
class RealTimeProcessor {
  private activeSessions: Set<string> = new Set();
  private pausedSessions: Set<string> = new Set();

  constructor(private config: RealTimeConfig) {}

  startSession(session: StreamSession): void {
    this.activeSessions.add(session.id);
  }

  pauseSession(sessionId: string): void {
    this.pausedSessions.add(sessionId);
  }

  resumeSession(sessionId: string): void {
    this.pausedSessions.delete(sessionId);
  }

  endSession(sessionId: string): void {
    this.activeSessions.delete(sessionId);
    this.pausedSessions.delete(sessionId);
  }

  async processChunk(session: StreamSession, chunk: EnhancedStreamChunk): Promise<void> {
    if (this.pausedSessions.has(session.id)) {
      return; // Skip processing for paused sessions
    }

    // Real-time processing logic would go here
    // For now, just track the chunk
  }

  shutdown(): void {
    this.activeSessions.clear();
    this.pausedSessions.clear();
  }
}

/**
 * Priority Queue
 */
class PriorityQueue<T> {
  private items: Array<{ item: T; priority: number }> = [];

  enqueue(item: T, priority: number): void {
    this.items.push({ item, priority });
    this.items.sort((a, b) => a.priority - b.priority); // Lower priority number = higher priority
  }

  dequeue(): T | null {
    const item = this.items.shift();
    return item ? item.item : null;
  }

  size(): number {
    return this.items.length;
  }
}

export default StreamManager;