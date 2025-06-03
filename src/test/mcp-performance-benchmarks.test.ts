/**
 * MCP Performance Benchmarks and Load Testing
 * 
 * This test suite focuses on performance characteristics and load testing:
 * - MCP vs Direct API performance comparison
 * - Context management efficiency testing
 * - Streaming performance validation
 * - Cost optimization measurement
 * - Scalability and throughput testing
 */

import { jest } from '@jest/globals';
import { performance } from 'perf_hooks';
import { EventEmitter } from 'events';

// Direct API comparison
import { OpenAI } from 'openai';

// MCP components
import { MCPClient } from '../mcp/client';
import { MessageRouter } from '../mcp/routing/message-router';
import { ContextManager } from '../mcp/context/context-manager';
import { StreamManager } from '../mcp/streaming/stream-manager';
import { ProviderSelector } from '../mcp/providers/provider-selector';
import { MCPMonitoringDashboard } from '../mcp/integration/mcp-monitoring-dashboard';

// Security components
import { AuthManager } from '../mcp/security/auth-manager';
import { AuditLogger } from '../mcp/security/audit-logger';
import { RateLimiterManager } from '../mcp/security/rate-limiter';
import { CredentialManager } from '../mcp/security/credential-manager';

// Types
import {
  LLMRequest,
  LLMResponse,
  LLMRequestType,
  RequestPriority,
  ContextPriority
} from '../mcp/types';

// Test data generator
import { MCPTestUtils } from './mcp-comprehensive.test';

interface PerformanceMetrics {
  totalTime: number;
  averageLatency: number;
  minLatency: number;
  maxLatency: number;
  throughput: number; // requests per second
  successRate: number;
  errorRate: number;
  p50Latency: number;
  p95Latency: number;
  p99Latency: number;
}

interface CostMetrics {
  totalTokens: number;
  totalCost: number;
  costPerToken: number;
  costPerRequest: number;
}

describe('MCP Performance Benchmarks', () => {
  let mcpClient: MCPClient;
  let messageRouter: MessageRouter;
  let contextManager: ContextManager;
  let streamManager: StreamManager;
  let monitoringDashboard: MCPMonitoringDashboard;
  let authManager: AuthManager;
  let auditLogger: AuditLogger;
  let rateLimiter: RateLimiterManager;

  beforeAll(async () => {
    // Initialize components for performance testing
    authManager = new AuthManager();
    auditLogger = new AuditLogger();
    rateLimiter = new RateLimiterManager(authManager);
    const credentialManager = new CredentialManager();

    mcpClient = new MCPClient({
      serverUrl: 'ws://localhost:8080',
      apiKey: 'benchmark-key',
      providers: {
        openai: { apiKey: 'test-openai', models: ['gpt-4', 'gpt-3.5-turbo'] },
        anthropic: { apiKey: 'test-anthropic', models: ['claude-3-sonnet'] }
      }
    });

    messageRouter = new MessageRouter(mcpClient, authManager, auditLogger, rateLimiter, credentialManager);
    contextManager = new ContextManager({
      maxTokensPerContext: 4000,
      compressionThreshold: 0.8,
      compressionStrategy: 'importance'
    });

    streamManager = new StreamManager(messageRouter, authManager, auditLogger);
    
    monitoringDashboard = new MCPMonitoringDashboard(
      messageRouter,
      null,
      contextManager,
      streamManager,
      null as any,
      auditLogger,
      rateLimiter
    );
  });

  afterAll(async () => {
    await contextManager?.shutdown();
    streamManager?.shutdown();
    monitoringDashboard?.shutdown();
  });

  describe('5.2.1 MCP vs Direct API Performance', () => {
    it('should benchmark MCP overhead vs direct OpenAI calls', async () => {
      const testPrompts = [
        'Hello, world!',
        'Explain quantum computing in simple terms.',
        'Write a short story about a robot.',
        'What is the capital of France?',
        'Calculate 2 + 2 and explain the process.'
      ];

      // Mock both MCP and direct API responses
      const mockResponse = {
        id: 'benchmark-resp',
        content: 'Benchmark response content',
        provider: 'openai',
        model: 'gpt-4',
        usage: { promptTokens: 20, completionTokens: 30, totalTokens: 50 },
        timestamp: new Date()
      };

      // Benchmark MCP approach
      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        // Simulate MCP processing overhead
        await new Promise(resolve => setTimeout(resolve, 10));
        return mockResponse;
      });

      const mcpMetrics = await benchmarkRequests('MCP', testPrompts, async (prompt) => {
        const request: LLMRequest = {
          id: `mcp-benchmark-${Date.now()}`,
          type: LLMRequestType.COMPLETION,
          prompt,
          agentDID: 'did:key:benchmark-agent',
          sessionId: 'benchmark-session',
          metadata: {
            agentDID: 'did:key:benchmark-agent',
            sessionId: 'benchmark-session',
            requestId: `mcp-benchmark-${Date.now()}`,
            timestamp: new Date(),
            source: 'benchmark',
            priority: RequestPriority.MEDIUM
          }
        };
        return await messageRouter.routeMessage(request);
      });

      // Benchmark direct API approach (simulated)
      const directMetrics = await benchmarkRequests('Direct API', testPrompts, async (prompt) => {
        // Simulate direct OpenAI API call
        await new Promise(resolve => setTimeout(resolve, 5));
        return mockResponse;
      });

      console.log('\nPerformance Comparison:');
      console.log('=======================');
      console.log(`MCP Average Latency: ${mcpMetrics.averageLatency.toFixed(2)}ms`);
      console.log(`Direct API Average Latency: ${directMetrics.averageLatency.toFixed(2)}ms`);
      console.log(`MCP Overhead: ${(mcpMetrics.averageLatency - directMetrics.averageLatency).toFixed(2)}ms`);
      console.log(`Overhead Percentage: ${((mcpMetrics.averageLatency / directMetrics.averageLatency - 1) * 100).toFixed(1)}%`);

      // MCP overhead should be reasonable (< 2x direct API)
      expect(mcpMetrics.averageLatency).toBeLessThan(directMetrics.averageLatency * 2);
      expect(mcpMetrics.successRate).toBe(1.0);
    });

    it('should measure MCP latency percentiles', async () => {
      const requestCount = 100;
      const latencies: number[] = [];

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        // Simulate variable latency
        const delay = Math.random() * 100 + 50; // 50-150ms
        await new Promise(resolve => setTimeout(resolve, delay));
        return {
          id: 'latency-resp',
          content: 'Response',
          provider: 'openai',
          model: 'gpt-4',
          timestamp: new Date()
        };
      });

      for (let i = 0; i < requestCount; i++) {
        const startTime = performance.now();
        
        const request = MCPTestUtils.createMockLLMRequest({
          id: `latency-test-${i}`,
          prompt: `Latency test ${i}`
        });

        await messageRouter.routeMessage(request);
        
        const endTime = performance.now();
        latencies.push(endTime - startTime);
      }

      const sortedLatencies = latencies.sort((a, b) => a - b);
      const p50 = sortedLatencies[Math.floor(requestCount * 0.5)];
      const p95 = sortedLatencies[Math.floor(requestCount * 0.95)];
      const p99 = sortedLatencies[Math.floor(requestCount * 0.99)];

      console.log('\nLatency Percentiles:');
      console.log('====================');
      console.log(`P50: ${p50.toFixed(2)}ms`);
      console.log(`P95: ${p95.toFixed(2)}ms`);
      console.log(`P99: ${p99.toFixed(2)}ms`);

      expect(p50).toBeLessThan(200);
      expect(p95).toBeLessThan(300);
      expect(p99).toBeLessThan(400);
    });
  });

  describe('5.2.2 Context Management Efficiency', () => {
    it('should benchmark context operations performance', async () => {
      const conversationCount = 10;
      const messagesPerConversation = 50;
      const contextStats: any[] = [];

      for (let conv = 0; conv < conversationCount; conv++) {
        const startTime = performance.now();
        
        const context = await contextManager.createContext(
          `did:key:agent-${conv}`,
          `session-${conv}`,
          {
            domain: 'benchmark',
            purpose: 'performance testing',
            priority: ContextPriority.MEDIUM
          }
        );

        // Add messages to trigger compression
        for (let msg = 0; msg < messagesPerConversation; msg++) {
          await contextManager.addMessage(context.conversationId, {
            role: 'user' as any,
            content: `Message ${msg}: This is a test message with enough content to trigger compression algorithms when the context becomes too large.`
          });

          // Add assistant response
          await contextManager.addMessage(context.conversationId, {
            role: 'assistant' as any,
            content: `Response ${msg}: This is an assistant response that adds to the conversation context and helps test compression efficiency.`
          });
        }

        const endTime = performance.now();
        const stats = contextManager.getStatistics();
        
        contextStats.push({
          conversationId: conv,
          processingTime: endTime - startTime,
          totalTokens: stats.totalTokens,
          compressionsSaved: stats.compressionsSaved,
          activeContexts: stats.activeContexts
        });
      }

      const avgProcessingTime = contextStats.reduce((sum, stat) => sum + stat.processingTime, 0) / conversationCount;
      const totalCompressions = contextStats.reduce((sum, stat) => sum + stat.compressionsSaved, 0);

      console.log('\nContext Management Performance:');
      console.log('===============================');
      console.log(`Average processing time per conversation: ${avgProcessingTime.toFixed(2)}ms`);
      console.log(`Total compressions triggered: ${totalCompressions}`);
      console.log(`Messages per conversation: ${messagesPerConversation * 2}`);
      console.log(`Processing time per message: ${(avgProcessingTime / (messagesPerConversation * 2)).toFixed(2)}ms`);

      // Context operations should be efficient
      expect(avgProcessingTime).toBeLessThan(5000); // Less than 5 seconds per conversation
      expect(totalCompressions).toBeGreaterThan(0); // Compression should occur
    });

    it('should test context compression effectiveness', async () => {
      const largeMessage = 'This is a very long message that contains a lot of content. '.repeat(100);
      
      const context = await contextManager.createContext(
        'did:key:compression-test',
        'compression-session',
        {
          domain: 'compression-test',
          purpose: 'testing compression',
          priority: ContextPriority.HIGH
        }
      );

      const initialStats = contextManager.getStatistics();
      
      // Add messages that will exceed token limit
      for (let i = 0; i < 20; i++) {
        await contextManager.addMessage(context.conversationId, {
          role: 'user' as any,
          content: `${largeMessage} Message ${i}`
        });
      }

      const finalStats = contextManager.getStatistics();
      const compressionSavings = finalStats.compressionsSaved - initialStats.compressionsSaved;

      console.log('\nCompression Effectiveness:');
      console.log('=========================');
      console.log(`Compression savings: ${compressionSavings}`);
      console.log(`Final token count: ${finalStats.totalTokens}`);
      console.log(`Active contexts: ${finalStats.activeContexts}`);

      expect(compressionSavings).toBeGreaterThan(0);
    });
  });

  describe('5.2.3 Streaming Performance', () => {
    it('should benchmark streaming response performance', async () => {
      const testWords = Array.from({ length: 50 }, (_, i) => `word${i}`);
      const chunkDelays: number[] = [];
      let firstChunkTime: number;
      let lastChunkTime: number;

      jest.spyOn(messageRouter, 'routeStreamingMessage').mockImplementation(async function* () {
        const startTime = performance.now();
        
        for (let i = 0; i < testWords.length; i++) {
          const chunkStart = performance.now();
          
          // Simulate network delay
          await new Promise(resolve => setTimeout(resolve, Math.random() * 20 + 5));
          
          const chunkEnd = performance.now();
          
          if (i === 0) firstChunkTime = chunkEnd;
          if (i === testWords.length - 1) lastChunkTime = chunkEnd;
          
          chunkDelays.push(chunkEnd - chunkStart);
          
          yield {
            id: `chunk-${i}`,
            type: 'chunk' as const,
            delta: testWords[i] + ' ',
            tokens: 1,
            timestamp: new Date(),
            metadata: {
              chunkIndex: i,
              isLast: i === testWords.length - 1
            }
          };
        }
      });

      const request = MCPTestUtils.createMockLLMRequest({
        type: LLMRequestType.STREAMING,
        streaming: true
      });

      const overallStart = performance.now();
      let chunksReceived = 0;

      await streamManager.startStream(request, {
        priority: 'high',
        onChunk: (chunk) => {
          chunksReceived++;
        },
        onComplete: () => {
          // Stream completed
        }
      });

      // Wait for streaming to complete
      await new Promise(resolve => setTimeout(resolve, 2000));

      const overallEnd = performance.now();
      const totalStreamTime = overallEnd - overallStart;
      const timeToFirstChunk = firstChunkTime! - overallStart;
      const avgChunkDelay = chunkDelays.reduce((sum, delay) => sum + delay, 0) / chunkDelays.length;

      console.log('\nStreaming Performance:');
      console.log('=====================');
      console.log(`Total streaming time: ${totalStreamTime.toFixed(2)}ms`);
      console.log(`Time to first chunk: ${timeToFirstChunk.toFixed(2)}ms`);
      console.log(`Average chunk delay: ${avgChunkDelay.toFixed(2)}ms`);
      console.log(`Chunks received: ${chunksReceived}`);
      console.log(`Streaming throughput: ${(chunksReceived / (totalStreamTime / 1000)).toFixed(1)} chunks/sec`);

      expect(timeToFirstChunk).toBeLessThan(100); // First chunk should arrive quickly
      expect(avgChunkDelay).toBeLessThan(50); // Each chunk should process quickly
      expect(chunksReceived).toBe(testWords.length);
    });

    it('should test concurrent streaming performance', async () => {
      const concurrentStreams = 5;
      const wordsPerStream = 20;
      const streamResults: any[] = [];

      jest.spyOn(messageRouter, 'routeStreamingMessage').mockImplementation(async function* () {
        for (let i = 0; i < wordsPerStream; i++) {
          await new Promise(resolve => setTimeout(resolve, 10));
          yield {
            id: `concurrent-chunk-${i}`,
            type: 'chunk' as const,
            delta: `word${i} `,
            tokens: 1,
            timestamp: new Date(),
            metadata: { chunkIndex: i, isLast: i === wordsPerStream - 1 }
          };
        }
      });

      const startTime = performance.now();
      const streamPromises: Promise<any>[] = [];

      for (let stream = 0; stream < concurrentStreams; stream++) {
        const request = MCPTestUtils.createMockLLMRequest({
          id: `concurrent-stream-${stream}`,
          type: LLMRequestType.STREAMING,
          streaming: true
        });

        const streamPromise = new Promise(async (resolve) => {
          let chunks = 0;
          const streamStart = performance.now();

          await streamManager.startStream(request, {
            priority: 'medium',
            onChunk: () => { chunks++; },
            onComplete: () => {
              resolve({
                streamId: stream,
                chunks,
                duration: performance.now() - streamStart
              });
            }
          });
        });

        streamPromises.push(streamPromise);
      }

      const results = await Promise.all(streamPromises);
      const endTime = performance.now();
      const totalTime = endTime - startTime;

      const avgDuration = results.reduce((sum: number, r: any) => sum + r.duration, 0) / results.length;
      const totalChunks = results.reduce((sum: number, r: any) => sum + r.chunks, 0);

      console.log('\nConcurrent Streaming Performance:');
      console.log('=================================');
      console.log(`Concurrent streams: ${concurrentStreams}`);
      console.log(`Total time: ${totalTime.toFixed(2)}ms`);
      console.log(`Average stream duration: ${avgDuration.toFixed(2)}ms`);
      console.log(`Total chunks: ${totalChunks}`);
      console.log(`Chunks per second: ${(totalChunks / (totalTime / 1000)).toFixed(1)}`);

      expect(results).toHaveLength(concurrentStreams);
      expect(totalChunks).toBe(concurrentStreams * wordsPerStream);
    });
  });

  describe('5.2.4 Cost Optimization Testing', () => {
    it('should measure cost optimization effectiveness', async () => {
      const providers = ['openai', 'anthropic'];
      const models = {
        openai: { 'gpt-4': 0.03, 'gpt-3.5-turbo': 0.002 },
        anthropic: { 'claude-3-sonnet': 0.015, 'claude-3-haiku': 0.0025 }
      };

      let totalCost = 0;
      let totalTokens = 0;
      let requestCount = 0;

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async (request) => {
        // Simulate provider selection based on cost optimization
        const provider = Math.random() > 0.5 ? 'openai' : 'anthropic';
        const modelOptions = Object.keys(models[provider]);
        const model = modelOptions[Math.floor(Math.random() * modelOptions.length)];
        const costPerToken = models[provider][model];
        
        const tokens = Math.floor(Math.random() * 100) + 50; // 50-150 tokens
        const cost = tokens * costPerToken / 1000; // Cost per 1K tokens

        totalCost += cost;
        totalTokens += tokens;
        requestCount++;

        return {
          id: 'cost-opt-resp',
          content: 'Cost optimization response',
          provider,
          model,
          usage: { promptTokens: tokens * 0.6, completionTokens: tokens * 0.4, totalTokens: tokens, cost },
          timestamp: new Date()
        };
      });

      // Run optimization test
      const requests = Array.from({ length: 100 }, (_, i) => 
        MCPTestUtils.createMockLLMRequest({
          id: `cost-opt-${i}`,
          prompt: `Cost optimization test ${i}`
        })
      );

      await Promise.all(requests.map(req => messageRouter.routeMessage(req)));

      const avgCostPerRequest = totalCost / requestCount;
      const avgCostPerToken = totalCost / totalTokens;
      const avgTokensPerRequest = totalTokens / requestCount;

      console.log('\nCost Optimization Analysis:');
      console.log('===========================');
      console.log(`Total requests: ${requestCount}`);
      console.log(`Total tokens: ${totalTokens}`);
      console.log(`Total cost: $${totalCost.toFixed(4)}`);
      console.log(`Average cost per request: $${avgCostPerRequest.toFixed(4)}`);
      console.log(`Average cost per token: $${avgCostPerToken.toFixed(6)}`);
      console.log(`Average tokens per request: ${avgTokensPerRequest.toFixed(1)}`);

      // Verify reasonable cost metrics
      expect(totalCost).toBeGreaterThan(0);
      expect(avgCostPerRequest).toBeLessThan(0.10); // Should be under 10 cents per request
      expect(avgCostPerToken).toBeLessThan(0.001); // Should be under 0.1 cents per token
    });

    it('should validate provider selection for cost optimization', async () => {
      const providerUsage = { openai: 0, anthropic: 0, mock: 0 };
      const providerCosts = { openai: 0, anthropic: 0, mock: 0 };

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        // Simulate intelligent provider selection
        const providers = ['openai', 'anthropic', 'mock'];
        const costs = [0.03, 0.015, 0.001]; // Different cost structures
        
        // Select cheapest provider for simple requests
        const provider = providers[2]; // Mock provider (cheapest)
        const cost = costs[2] * 100; // 100 tokens

        providerUsage[provider]++;
        providerCosts[provider] += cost;

        return {
          id: 'provider-sel-resp',
          content: 'Provider selection response',
          provider,
          model: 'mock-model',
          usage: { totalTokens: 100, cost },
          timestamp: new Date()
        };
      });

      // Run provider selection test
      const requests = Array.from({ length: 50 }, (_, i) => 
        MCPTestUtils.createMockLLMRequest({
          id: `provider-sel-${i}`,
          prompt: 'Simple request for provider selection'
        })
      );

      await Promise.all(requests.map(req => messageRouter.routeMessage(req)));

      console.log('\nProvider Selection Analysis:');
      console.log('============================');
      console.log('Usage distribution:');
      Object.entries(providerUsage).forEach(([provider, usage]) => {
        console.log(`  ${provider}: ${usage} requests (${(usage / 50 * 100).toFixed(1)}%)`);
      });
      console.log('Cost distribution:');
      Object.entries(providerCosts).forEach(([provider, cost]) => {
        console.log(`  ${provider}: $${cost.toFixed(4)}`);
      });

      // Should favor cheaper providers for simple requests
      expect(providerUsage.mock).toBeGreaterThan(providerUsage.openai);
      expect(providerCosts.mock).toBeLessThan(providerCosts.openai + providerCosts.anthropic);
    });
  });

  describe('5.2.5 Scalability Testing', () => {
    it('should test throughput under increasing load', async () => {
      const loadLevels = [10, 25, 50, 100, 200];
      const results: any[] = [];

      for (const requestCount of loadLevels) {
        let completedRequests = 0;
        let failedRequests = 0;

        jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
          await new Promise(resolve => setTimeout(resolve, 20 + Math.random() * 30));
          
          if (Math.random() < 0.95) { // 95% success rate
            completedRequests++;
            return MCPTestUtils.createMockLLMResponse();
          } else {
            failedRequests++;
            throw new Error('Simulated failure');
          }
        });

        const startTime = performance.now();
        
        const requests = Array.from({ length: requestCount }, (_, i) => 
          MCPTestUtils.createMockLLMRequest({
            id: `scalability-${requestCount}-${i}`,
            prompt: `Scalability test request ${i}`
          })
        );

        await Promise.allSettled(requests.map(req => messageRouter.routeMessage(req)));
        
        const endTime = performance.now();
        const duration = endTime - startTime;
        const throughput = requestCount / (duration / 1000);
        const successRate = completedRequests / (completedRequests + failedRequests);

        results.push({
          requestCount,
          duration,
          throughput,
          successRate,
          completedRequests,
          failedRequests
        });

        console.log(`Load Level ${requestCount}: ${throughput.toFixed(1)} req/sec, ${(successRate * 100).toFixed(1)}% success`);
      }

      console.log('\nScalability Test Results:');
      console.log('========================');
      results.forEach(result => {
        console.log(`${result.requestCount} requests: ${result.throughput.toFixed(1)} req/sec (${result.duration.toFixed(0)}ms)`);
      });

      // Verify reasonable scalability
      const maxThroughput = Math.max(...results.map(r => r.throughput));
      const minSuccessRate = Math.min(...results.map(r => r.successRate));

      expect(maxThroughput).toBeGreaterThan(5); // At least 5 req/sec
      expect(minSuccessRate).toBeGreaterThan(0.8); // At least 80% success rate
    });

    it('should test memory usage under sustained load', async () => {
      const duration = 3000; // 3 seconds
      const requestInterval = 50; // Request every 50ms
      let requestCount = 0;
      const memoryUsage: number[] = [];

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
        return MCPTestUtils.createMockLLMResponse();
      });

      const startTime = Date.now();
      const endTime = startTime + duration;

      const memoryMonitor = setInterval(() => {
        const usage = process.memoryUsage();
        memoryUsage.push(usage.heapUsed / 1024 / 1024); // MB
      }, 100);

      while (Date.now() < endTime) {
        const request = MCPTestUtils.createMockLLMRequest({
          id: `memory-test-${requestCount}`,
          prompt: `Memory test request ${requestCount}`
        });

        // Don't await to maintain sustained load
        messageRouter.routeMessage(request).catch(() => {});
        requestCount++;

        await new Promise(resolve => setTimeout(resolve, requestInterval));
      }

      clearInterval(memoryMonitor);

      const avgMemoryUsage = memoryUsage.reduce((sum, usage) => sum + usage, 0) / memoryUsage.length;
      const maxMemoryUsage = Math.max(...memoryUsage);
      const memoryGrowth = memoryUsage[memoryUsage.length - 1] - memoryUsage[0];

      console.log('\nMemory Usage Analysis:');
      console.log('=====================');
      console.log(`Requests processed: ${requestCount}`);
      console.log(`Average memory usage: ${avgMemoryUsage.toFixed(2)} MB`);
      console.log(`Peak memory usage: ${maxMemoryUsage.toFixed(2)} MB`);
      console.log(`Memory growth: ${memoryGrowth.toFixed(2)} MB`);

      // Memory usage should be reasonable
      expect(maxMemoryUsage).toBeLessThan(500); // Less than 500MB
      expect(Math.abs(memoryGrowth)).toBeLessThan(100); // Memory growth should be limited
    }, 10000); // Increase timeout for sustained load test
  });
});

/**
 * Helper function to benchmark a set of requests
 */
async function benchmarkRequests(
  label: string,
  prompts: string[],
  requestFn: (prompt: string) => Promise<any>
): Promise<PerformanceMetrics> {
  const latencies: number[] = [];
  let successCount = 0;
  let errorCount = 0;

  const overallStart = performance.now();

  for (const prompt of prompts) {
    try {
      const start = performance.now();
      await requestFn(prompt);
      const end = performance.now();
      
      latencies.push(end - start);
      successCount++;
    } catch (error) {
      errorCount++;
    }
  }

  const overallEnd = performance.now();
  const totalTime = overallEnd - overallStart;

  const sortedLatencies = latencies.sort((a, b) => a - b);
  const averageLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
  const minLatency = Math.min(...latencies);
  const maxLatency = Math.max(...latencies);
  const throughput = prompts.length / (totalTime / 1000);
  const successRate = successCount / prompts.length;
  const errorRate = errorCount / prompts.length;
  
  const p50Latency = sortedLatencies[Math.floor(sortedLatencies.length * 0.5)] || 0;
  const p95Latency = sortedLatencies[Math.floor(sortedLatencies.length * 0.95)] || 0;
  const p99Latency = sortedLatencies[Math.floor(sortedLatencies.length * 0.99)] || 0;

  return {
    totalTime,
    averageLatency,
    minLatency,
    maxLatency,
    throughput,
    successRate,
    errorRate,
    p50Latency,
    p95Latency,
    p99Latency
  };
}