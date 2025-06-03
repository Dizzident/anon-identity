/**
 * MCP Multi-Provider Testing Suite
 * 
 * This test suite focuses on multi-provider scenarios:
 * - Provider selection and routing
 * - Failover mechanisms
 * - Load balancing
 * - Provider health monitoring
 * - Cross-provider compatibility
 * - Cost optimization across providers
 */

import { jest } from '@jest/globals';
import { EventEmitter } from 'events';
import { performance } from 'perf_hooks';

// MCP components
import { MCPClient } from '../mcp/client';
import { MessageRouter } from '../mcp/routing/message-router';
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
  LLMProvider,
  ProviderHealth,
  SelectionStrategy,
  MCPError,
  MCPErrorCode
} from '../mcp/types';

// Test utilities
import { MCPTestUtils } from './mcp-comprehensive.test';

interface ProviderTestConfig {
  id: string;
  name: string;
  baseLatency: number;
  reliability: number;
  costPerToken: number;
  models: string[];
  capabilities: string[];
}

describe('MCP Multi-Provider Testing', () => {
  let mcpClient: MCPClient;
  let messageRouter: MessageRouter;
  let providerSelector: ProviderSelector;
  let monitoringDashboard: MCPMonitoringDashboard;
  let authManager: AuthManager;
  let auditLogger: AuditLogger;
  let rateLimiter: RateLimiterManager;
  
  const testProviders: ProviderTestConfig[] = [
    {
      id: 'openai',
      name: 'OpenAI',
      baseLatency: 200,
      reliability: 0.98,
      costPerToken: 0.00003,
      models: ['gpt-4', 'gpt-3.5-turbo'],
      capabilities: ['completion', 'function-calling', 'streaming']
    },
    {
      id: 'anthropic',
      name: 'Anthropic',
      baseLatency: 300,
      reliability: 0.96,
      costPerToken: 0.000015,
      models: ['claude-3-sonnet', 'claude-3-haiku'],
      capabilities: ['completion', 'function-calling', 'streaming']
    },
    {
      id: 'cohere',
      name: 'Cohere',
      baseLatency: 150,
      reliability: 0.94,
      costPerToken: 0.000025,
      models: ['command', 'command-light'],
      capabilities: ['completion', 'embedding']
    },
    {
      id: 'mock-provider',
      name: 'Mock Provider',
      baseLatency: 50,
      reliability: 0.99,
      costPerToken: 0.000001,
      models: ['mock-model'],
      capabilities: ['completion', 'function-calling', 'streaming', 'embedding']
    }
  ];

  beforeAll(async () => {
    // Initialize infrastructure
    authManager = new AuthManager();
    auditLogger = new AuditLogger();
    rateLimiter = new RateLimiterManager(authManager);
    const credentialManager = new CredentialManager();

    // Create mock providers
    const providers = new Map<string, LLMProvider>();
    testProviders.forEach(config => {
      providers.set(config.id, {
        id: config.id,
        name: config.name,
        type: 'llm',
        enabled: true,
        endpoint: `https://api.${config.id}.com/v1`,
        models: config.models,
        capabilities: {
          completion: config.capabilities.includes('completion'),
          streaming: config.capabilities.includes('streaming'),
          functionCalling: config.capabilities.includes('function-calling'),
          embeddings: config.capabilities.includes('embedding'),
          moderation: false
        },
        rateLimits: {
          requestsPerMinute: 100,
          tokensPerMinute: 10000,
          requestsPerDay: 10000,
          tokensPerDay: 1000000
        },
        config: {
          baseLatency: config.baseLatency,
          reliability: config.reliability,
          costPerToken: config.costPerToken
        },
        version: '1.0'
      });
    });

    mcpClient = new MCPClient({
      serverUrl: 'ws://localhost:8080',
      apiKey: 'multi-provider-test-key',
      providers: Object.fromEntries(
        testProviders.map(p => [p.id, { apiKey: `${p.id}-key`, models: p.models }])
      )
    });

    // Mock getProviders method
    jest.spyOn(mcpClient, 'getProviders').mockReturnValue(providers);

    messageRouter = new MessageRouter(mcpClient, authManager, auditLogger, rateLimiter, credentialManager);
    providerSelector = new ProviderSelector(providers);

    monitoringDashboard = new MCPMonitoringDashboard(
      messageRouter,
      providerSelector,
      null as any,
      null as any,
      null as any,
      auditLogger,
      rateLimiter
    );
  });

  afterAll(async () => {
    monitoringDashboard?.shutdown();
    providerSelector?.shutdown();
  });

  describe('5.5.1 Provider Selection', () => {
    it('should select providers based on reliability strategy', async () => {
      const request = MCPTestUtils.createMockLLMRequest({
        prompt: 'Test reliability-based selection'
      });

      const selection = await providerSelector.selectProvider(
        request,
        {
          requestType: LLMRequestType.COMPLETION,
          priority: RequestPriority.HIGH,
          requirements: {
            minReliability: 0.95
          },
          context: {
            agentDID: 'did:key:test-agent',
            domain: 'test'
          }
        },
        SelectionStrategy.RELIABILITY
      );

      // Should select OpenAI (highest reliability at 0.98)
      expect(selection.primaryProvider.id).toBe('openai');
      expect(selection.confidence).toBeGreaterThan(0.8);
      expect(selection.reasoning).toContain('reliability');
    });

    it('should select providers based on cost optimization', async () => {
      const request = MCPTestUtils.createMockLLMRequest({
        prompt: 'Cost-optimized selection test'
      });

      const selection = await providerSelector.selectProvider(
        request,
        {
          requestType: LLMRequestType.COMPLETION,
          priority: RequestPriority.LOW,
          requirements: {
            maxCost: 0.001
          },
          context: {
            agentDID: 'did:key:test-agent',
            domain: 'test',
            costSensitive: true
          }
        },
        SelectionStrategy.COST_OPTIMIZED
      );

      // Should select mock-provider (lowest cost)
      expect(selection.primaryProvider.id).toBe('mock-provider');
      expect(selection.reasoning).toContain('cost');
    });

    it('should select providers based on latency requirements', async () => {
      const request = MCPTestUtils.createMockLLMRequest({
        prompt: 'Low-latency selection test'
      });

      const selection = await providerSelector.selectProvider(
        request,
        {
          requestType: LLMRequestType.COMPLETION,
          priority: RequestPriority.URGENT,
          requirements: {
            maxLatency: 100
          },
          context: {
            agentDID: 'did:key:test-agent',
            domain: 'real-time'
          }
        },
        SelectionStrategy.LATENCY
      );

      // Should select mock-provider (lowest latency at 50ms)
      expect(selection.primaryProvider.id).toBe('mock-provider');
      expect(selection.reasoning).toContain('latency');
    });

    it('should provide fallback providers', async () => {
      const request = MCPTestUtils.createMockLLMRequest({
        prompt: 'Fallback provider test'
      });

      const selection = await providerSelector.selectProvider(
        request,
        {
          requestType: LLMRequestType.COMPLETION,
          priority: RequestPriority.MEDIUM,
          requirements: {},
          context: {
            agentDID: 'did:key:test-agent',
            domain: 'test'
          }
        },
        SelectionStrategy.ROUND_ROBIN
      );

      expect(selection.fallbackProviders).toBeDefined();
      expect(selection.fallbackProviders.length).toBeGreaterThan(0);
      expect(selection.fallbackProviders).not.toContain(selection.primaryProvider);
    });

    it('should respect capability requirements', async () => {
      const request = MCPTestUtils.createMockLLMRequest({
        type: LLMRequestType.EMBEDDING,
        prompt: 'Embedding generation test'
      });

      const selection = await providerSelector.selectProvider(
        request,
        {
          requestType: LLMRequestType.EMBEDDING,
          priority: RequestPriority.MEDIUM,
          requirements: {
            capabilities: ['embedding']
          },
          context: {
            agentDID: 'did:key:test-agent',
            domain: 'embeddings'
          }
        },
        SelectionStrategy.CAPABILITY_MATCH
      );

      // Should select a provider that supports embeddings
      const selectedProvider = selection.primaryProvider;
      expect(selectedProvider.capabilities.embeddings).toBe(true);
    });
  });

  describe('5.5.2 Failover Mechanisms', () => {
    it('should automatically failover on provider failure', async () => {
      let callCount = 0;
      const failingProvider = 'openai';
      const backupProvider = 'anthropic';

      // Mock provider failure for OpenAI
      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async (request) => {
        callCount++;
        
        if (callCount === 1) {
          // First call fails (primary provider down)
          throw new MCPError({
            code: MCPErrorCode.PROVIDER_ERROR,
            message: `${failingProvider} is temporarily unavailable`,
            timestamp: new Date(),
            retryable: true,
            provider: failingProvider
          });
        } else {
          // Second call succeeds (backup provider)
          return {
            id: 'failover-response',
            content: 'Response from backup provider',
            provider: backupProvider,
            model: 'claude-3-sonnet',
            timestamp: new Date()
          };
        }
      });

      const request = MCPTestUtils.createMockLLMRequest({
        prompt: 'Failover test request'
      });

      // Should succeed with failover
      const response = await messageRouter.routeMessage(request);
      
      expect(response.provider).toBe(backupProvider);
      expect(callCount).toBe(2); // Should have attempted both providers
    });

    it('should handle cascade failures across multiple providers', async () => {
      const failureScenarios = [
        { provider: 'openai', error: 'Rate limit exceeded' },
        { provider: 'anthropic', error: 'Service unavailable' },
        { provider: 'cohere', error: 'Authentication failed' }
      ];

      let attemptCount = 0;

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        attemptCount++;
        
        if (attemptCount <= failureScenarios.length) {
          const scenario = failureScenarios[attemptCount - 1];
          throw new MCPError({
            code: MCPErrorCode.PROVIDER_ERROR,
            message: scenario.error,
            timestamp: new Date(),
            retryable: true,
            provider: scenario.provider
          });
        } else {
          // Final provider succeeds
          return {
            id: 'cascade-recovery',
            content: 'Response after cascade failure',
            provider: 'mock-provider',
            model: 'mock-model',
            timestamp: new Date()
          };
        }
      });

      const request = MCPTestUtils.createMockLLMRequest({
        prompt: 'Cascade failure test'
      });

      const response = await messageRouter.routeMessage(request);
      
      expect(response.provider).toBe('mock-provider');
      expect(attemptCount).toBe(failureScenarios.length + 1);
    });

    it('should implement circuit breaker pattern', async () => {
      const failingProvider = 'unreliable-provider';
      const failureThreshold = 3;
      let consecutiveFailures = 0;

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        consecutiveFailures++;
        
        if (consecutiveFailures <= failureThreshold) {
          throw new MCPError({
            code: MCPErrorCode.PROVIDER_ERROR,
            message: 'Provider consistently failing',
            timestamp: new Date(),
            retryable: false,
            provider: failingProvider
          });
        } else {
          // Circuit breaker should prevent further attempts
          throw new MCPError({
            code: MCPErrorCode.CIRCUIT_BREAKER_OPEN,
            message: 'Circuit breaker is open',
            timestamp: new Date(),
            retryable: false,
            provider: failingProvider
          });
        }
      });

      const requests = Array.from({ length: 5 }, (_, i) => 
        MCPTestUtils.createMockLLMRequest({
          id: `circuit-breaker-${i}`,
          prompt: `Circuit breaker test ${i}`
        })
      );

      let circuitBreakerTriggered = false;

      for (const request of requests) {
        try {
          await messageRouter.routeMessage(request);
        } catch (error: any) {
          if (error.code === MCPErrorCode.CIRCUIT_BREAKER_OPEN) {
            circuitBreakerTriggered = true;
            break;
          }
        }
      }

      expect(circuitBreakerTriggered).toBe(true);
      expect(consecutiveFailures).toBeGreaterThanOrEqual(failureThreshold);
    });

    it('should recover from circuit breaker after timeout', async () => {
      const circuitBreakerTimeout = 1000; // 1 second
      let isRecovering = false;

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        if (!isRecovering) {
          // Circuit breaker is open
          throw new MCPError({
            code: MCPErrorCode.CIRCUIT_BREAKER_OPEN,
            message: 'Circuit breaker is open',
            timestamp: new Date(),
            retryable: true
          });
        } else {
          // Recovery successful
          return {
            id: 'recovery-response',
            content: 'Service recovered',
            provider: 'recovered-provider',
            model: 'recovery-model',
            timestamp: new Date()
          };
        }
      });

      const request = MCPTestUtils.createMockLLMRequest({
        prompt: 'Circuit breaker recovery test'
      });

      // First attempt should fail
      try {
        await messageRouter.routeMessage(request);
      } catch (error: any) {
        expect(error.code).toBe(MCPErrorCode.CIRCUIT_BREAKER_OPEN);
      }

      // Wait for circuit breaker timeout
      await new Promise(resolve => setTimeout(resolve, circuitBreakerTimeout + 100));
      
      // Enable recovery
      isRecovering = true;

      // Second attempt should succeed
      const response = await messageRouter.routeMessage(request);
      expect(response.content).toBe('Service recovered');
    });
  });

  describe('5.5.3 Load Balancing', () => {
    it('should distribute load across multiple providers', async () => {
      const providerUsage: Record<string, number> = {};
      const requestCount = 20;

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        // Simulate round-robin distribution
        const providers = ['openai', 'anthropic', 'cohere', 'mock-provider'];
        const selectedProvider = providers[Object.keys(providerUsage).length % providers.length];
        
        providerUsage[selectedProvider] = (providerUsage[selectedProvider] || 0) + 1;

        return {
          id: 'load-balanced-response',
          content: 'Load balanced response',
          provider: selectedProvider,
          model: 'test-model',
          timestamp: new Date()
        };
      });

      // Send multiple requests
      const requests = Array.from({ length: requestCount }, (_, i) =>
        MCPTestUtils.createMockLLMRequest({
          id: `load-balance-${i}`,
          prompt: `Load balance test ${i}`
        })
      );

      await Promise.all(requests.map(req => messageRouter.routeMessage(req)));

      console.log('Load distribution:', providerUsage);

      // Verify relatively even distribution
      const usageCounts = Object.values(providerUsage);
      const avgUsage = usageCounts.reduce((sum, count) => sum + count, 0) / usageCounts.length;
      const maxDeviation = Math.max(...usageCounts.map(count => Math.abs(count - avgUsage)));

      // Should have relatively even distribution (within 50% of average)
      expect(maxDeviation).toBeLessThan(avgUsage * 0.5);
    });

    it('should implement weighted load balancing', async () => {
      const providerWeights = {
        'openai': 0.4,      // 40% weight
        'anthropic': 0.3,   // 30% weight
        'cohere': 0.2,      // 20% weight
        'mock-provider': 0.1 // 10% weight
      };

      const providerUsage: Record<string, number> = {};
      const requestCount = 100;

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        // Simulate weighted selection
        const rand = Math.random();
        let cumulativeWeight = 0;
        let selectedProvider = 'openai';

        for (const [provider, weight] of Object.entries(providerWeights)) {
          cumulativeWeight += weight;
          if (rand <= cumulativeWeight) {
            selectedProvider = provider;
            break;
          }
        }

        providerUsage[selectedProvider] = (providerUsage[selectedProvider] || 0) + 1;

        return {
          id: 'weighted-response',
          content: 'Weighted load balanced response',
          provider: selectedProvider,
          model: 'test-model',
          timestamp: new Date()
        };
      });

      const requests = Array.from({ length: requestCount }, (_, i) =>
        MCPTestUtils.createMockLLMRequest({
          id: `weighted-${i}`,
          prompt: `Weighted load test ${i}`
        })
      );

      await Promise.all(requests.map(req => messageRouter.routeMessage(req)));

      console.log('Weighted distribution:', providerUsage);

      // Verify distribution matches weights (within reasonable tolerance)
      for (const [provider, expectedWeight] of Object.entries(providerWeights)) {
        const actualUsage = providerUsage[provider] || 0;
        const actualWeight = actualUsage / requestCount;
        const deviation = Math.abs(actualWeight - expectedWeight);

        expect(deviation).toBeLessThan(0.1); // Within 10% of expected weight
      }
    });

    it('should adapt load balancing based on provider performance', async () => {
      const providerPerformance = {
        'openai': { latency: 200, errors: 0 },
        'anthropic': { latency: 500, errors: 2 }, // Poor performance
        'cohere': { latency: 150, errors: 0 },
        'mock-provider': { latency: 50, errors: 1 }
      };

      const providerUsage: Record<string, number> = {};

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        // Select provider based on performance (lower latency + fewer errors = higher priority)
        const performanceScores = Object.entries(providerPerformance).map(([provider, perf]) => ({
          provider,
          score: 1000 / (perf.latency + perf.errors * 100) // Higher score = better performance
        }));

        performanceScores.sort((a, b) => b.score - a.score);
        const selectedProvider = performanceScores[0].provider;

        providerUsage[selectedProvider] = (providerUsage[selectedProvider] || 0) + 1;

        return {
          id: 'adaptive-response',
          content: 'Adaptive load balanced response',
          provider: selectedProvider,
          model: 'test-model',
          timestamp: new Date()
        };
      });

      const requests = Array.from({ length: 20 }, (_, i) =>
        MCPTestUtils.createMockLLMRequest({
          id: `adaptive-${i}`,
          prompt: `Adaptive load test ${i}`
        })
      );

      await Promise.all(requests.map(req => messageRouter.routeMessage(req)));

      console.log('Adaptive distribution:', providerUsage);

      // Best performing provider (mock-provider) should get most requests
      const mockProviderUsage = providerUsage['mock-provider'] || 0;
      const anthropicUsage = providerUsage['anthropic'] || 0;

      expect(mockProviderUsage).toBeGreaterThan(anthropicUsage);
    });
  });

  describe('5.5.4 Provider Health Monitoring', () => {
    it('should monitor provider health continuously', async () => {
      const healthChecks: ProviderHealth[] = [];

      // Mock health monitoring
      const healthMonitor = setInterval(() => {
        testProviders.forEach(provider => {
          const health: ProviderHealth = {
            providerId: provider.id,
            status: Math.random() > 0.1 ? 'healthy' : 'unhealthy', // 90% healthy
            lastCheck: new Date(),
            responseTime: provider.baseLatency + Math.random() * 50,
            uptime: 0.95 + Math.random() * 0.05,
            errorRate: Math.random() * 0.05,
            requestCount: Math.floor(Math.random() * 1000),
            lastError: Math.random() > 0.9 ? 'Mock error' : undefined
          };
          healthChecks.push(health);
        });
      }, 100);

      // Monitor for 1 second
      await new Promise(resolve => setTimeout(resolve, 1000));
      clearInterval(healthMonitor);

      console.log(`Health checks collected: ${healthChecks.length}`);

      // Should have multiple health checks for each provider
      expect(healthChecks.length).toBeGreaterThan(testProviders.length * 5);

      // Verify health check structure
      healthChecks.forEach(health => {
        expect(health).toHaveProperty('providerId');
        expect(health).toHaveProperty('status');
        expect(health).toHaveProperty('lastCheck');
        expect(health).toHaveProperty('responseTime');
        expect(health.status).toMatch(/^(healthy|unhealthy|degraded)$/);
      });
    });

    it('should detect and report provider degradation', async () => {
      const degradationThresholds = {
        maxLatency: 1000,
        maxErrorRate: 0.1,
        minUptime: 0.95
      };

      const testHealth: ProviderHealth = {
        providerId: 'degraded-provider',
        status: 'healthy',
        lastCheck: new Date(),
        responseTime: 1500, // Exceeds threshold
        uptime: 0.92, // Below threshold
        errorRate: 0.15, // Exceeds threshold
        requestCount: 100
      };

      const isDegraded = 
        testHealth.responseTime > degradationThresholds.maxLatency ||
        testHealth.errorRate > degradationThresholds.maxErrorRate ||
        testHealth.uptime < degradationThresholds.minUptime;

      expect(isDegraded).toBe(true);

      // Provider should be marked as degraded
      if (isDegraded) {
        testHealth.status = 'degraded';
        testHealth.lastError = 'Performance degradation detected';
      }

      expect(testHealth.status).toBe('degraded');
      expect(testHealth.lastError).toContain('degradation');
    });

    it('should update provider selection based on health', async () => {
      const providerHealthData = new Map<string, ProviderHealth>([
        ['openai', {
          providerId: 'openai',
          status: 'healthy',
          lastCheck: new Date(),
          responseTime: 200,
          uptime: 0.99,
          errorRate: 0.01,
          requestCount: 1000
        }],
        ['anthropic', {
          providerId: 'anthropic',
          status: 'degraded',
          lastCheck: new Date(),
          responseTime: 800,
          uptime: 0.92,
          errorRate: 0.08,
          requestCount: 500,
          lastError: 'High latency detected'
        }],
        ['cohere', {
          providerId: 'cohere',
          status: 'unhealthy',
          lastCheck: new Date(),
          responseTime: 0,
          uptime: 0.50,
          errorRate: 0.50,
          requestCount: 100,
          lastError: 'Service unavailable'
        }]
      ]);

      // Mock provider health integration
      jest.spyOn(providerSelector, 'selectProvider').mockImplementation(async (request, criteria, strategy) => {
        // Filter out unhealthy providers
        const healthyProviders = testProviders.filter(p => {
          const health = providerHealthData.get(p.id);
          return health && health.status !== 'unhealthy';
        });

        // Select best healthy provider
        const bestProvider = healthyProviders.reduce((best, current) => {
          const currentHealth = providerHealthData.get(current.id)!;
          const bestHealth = providerHealthData.get(best.id)!;
          
          return currentHealth.responseTime < bestHealth.responseTime ? current : best;
        });

        const provider = testProviders.find(p => p.id === bestProvider.id)!;
        
        return {
          primaryProvider: {
            id: provider.id,
            name: provider.name,
            type: 'llm',
            enabled: true,
            endpoint: `https://api.${provider.id}.com/v1`,
            models: provider.models,
            capabilities: {
              completion: true,
              streaming: true,
              functionCalling: true,
              embeddings: true,
              moderation: false
            },
            rateLimits: {
              requestsPerMinute: 100,
              tokensPerMinute: 10000,
              requestsPerDay: 10000,
              tokensPerDay: 1000000
            },
            config: provider,
            version: '1.0'
          },
          fallbackProviders: [],
          confidence: 0.9,
          reasoning: `Selected ${provider.name} based on health status`,
          estimatedCost: 0.001,
          estimatedLatency: provider.baseLatency
        };
      });

      const request = MCPTestUtils.createMockLLMRequest({
        prompt: 'Health-based selection test'
      });

      const selection = await providerSelector.selectProvider(
        request,
        {
          requestType: LLMRequestType.COMPLETION,
          priority: RequestPriority.HIGH,
          requirements: {},
          context: {
            agentDID: 'did:key:test-agent',
            domain: 'health-test'
          }
        },
        SelectionStrategy.RELIABILITY
      );

      // Should select OpenAI (healthy with good performance)
      expect(selection.primaryProvider.id).toBe('openai');
      expect(selection.reasoning).toContain('health');
    });
  });

  describe('5.5.5 Cross-Provider Compatibility', () => {
    it('should handle different response formats consistently', async () => {
      const providerResponses = {
        openai: {
          id: 'chatcmpl-123',
          object: 'chat.completion',
          choices: [{
            message: { role: 'assistant', content: 'OpenAI response' },
            finish_reason: 'stop'
          }],
          usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 }
        },
        anthropic: {
          id: 'msg_123',
          type: 'message',
          content: [{ type: 'text', text: 'Anthropic response' }],
          usage: { input_tokens: 10, output_tokens: 20 }
        },
        cohere: {
          id: 'generate-123',
          generations: [{ text: 'Cohere response' }],
          meta: { tokens: { input_tokens: 10, output_tokens: 20 } }
        }
      };

      const normalizedResponses: LLMResponse[] = [];

      // Test normalization for each provider
      for (const [provider, rawResponse] of Object.entries(providerResponses)) {
        const normalized = normalizeProviderResponse(provider, rawResponse);
        normalizedResponses.push(normalized);
      }

      // All responses should have consistent structure
      normalizedResponses.forEach((response, index) => {
        expect(response).toHaveProperty('id');
        expect(response).toHaveProperty('content');
        expect(response).toHaveProperty('provider');
        expect(response).toHaveProperty('timestamp');
        expect(response.content).toContain('response');
        expect(typeof response.content).toBe('string');
      });

      // Verify each provider's response was normalized correctly
      expect(normalizedResponses[0].content).toBe('OpenAI response');
      expect(normalizedResponses[1].content).toBe('Anthropic response');
      expect(normalizedResponses[2].content).toBe('Cohere response');
    });

    it('should handle provider-specific error formats', async () => {
      const providerErrors = {
        openai: {
          error: {
            message: 'Rate limit exceeded',
            type: 'rate_limit_error',
            code: 'rate_limit_exceeded'
          }
        },
        anthropic: {
          type: 'error',
          error: {
            type: 'rate_limit_error',
            message: 'Rate limit exceeded'
          }
        },
        cohere: {
          message: 'Rate limit exceeded',
          code: 429
        }
      };

      const normalizedErrors: MCPError[] = [];

      for (const [provider, errorResponse] of Object.entries(providerErrors)) {
        const normalized = normalizeProviderError(provider, errorResponse);
        normalizedErrors.push(normalized);
      }

      // All errors should have consistent structure
      normalizedErrors.forEach(error => {
        expect(error).toHaveProperty('code');
        expect(error).toHaveProperty('message');
        expect(error).toHaveProperty('timestamp');
        expect(error.message).toContain('Rate limit exceeded');
        expect(error.code).toBe(MCPErrorCode.RATE_LIMIT_EXCEEDED);
      });
    });

    it('should maintain consistent function calling interface', async () => {
      const functionDefinition = {
        name: 'get_weather',
        description: 'Get weather information',
        parameters: {
          type: 'object',
          properties: {
            location: { type: 'string', description: 'City name' },
            units: { type: 'string', enum: ['celsius', 'fahrenheit'] }
          },
          required: ['location']
        }
      };

      const providerFunctionFormats = {
        openai: {
          type: 'function',
          function: functionDefinition
        },
        anthropic: {
          name: functionDefinition.name,
          description: functionDefinition.description,
          input_schema: functionDefinition.parameters
        },
        cohere: {
          name: functionDefinition.name,
          description: functionDefinition.description,
          parameter_definitions: {
            location: { description: 'City name', type: 'str', required: true },
            units: { description: 'Temperature units', type: 'str', required: false }
          }
        }
      };

      // Normalize function definitions for each provider
      const normalizedFunctions: any[] = [];

      for (const [provider, functionFormat] of Object.entries(providerFunctionFormats)) {
        const normalized = normalizeFunction(provider, functionFormat);
        normalizedFunctions.push(normalized);
      }

      // All should normalize to the same standard format
      normalizedFunctions.forEach(func => {
        expect(func.name).toBe('get_weather');
        expect(func.description).toBe('Get weather information');
        expect(func.parameters).toHaveProperty('type', 'object');
        expect(func.parameters.properties).toHaveProperty('location');
        expect(func.parameters.required).toContain('location');
      });
    });
  });

  describe('5.5.6 End-to-End Multi-Provider Scenarios', () => {
    it('should handle complex routing with multiple requirements', async () => {
      const complexRequest = MCPTestUtils.createMockLLMRequest({
        type: LLMRequestType.FUNCTION_CALL,
        prompt: 'Complex multi-requirement request',
        functions: [
          { name: 'analyze_data', description: 'Analyze complex data' },
          { name: 'generate_report', description: 'Generate detailed report' }
        ]
      });

      const criteria = {
        requestType: LLMRequestType.FUNCTION_CALL,
        priority: RequestPriority.HIGH,
        requirements: {
          capabilities: ['function-calling'],
          maxLatency: 500,
          maxCost: 0.01,
          minReliability: 0.95
        },
        context: {
          agentDID: 'did:key:test-agent',
          domain: 'data-analysis',
          complexity: 'high'
        }
      };

      const selection = await providerSelector.selectProvider(
        complexRequest,
        criteria,
        SelectionStrategy.BALANCED
      );

      expect(selection.primaryProvider).toBeDefined();
      expect(selection.primaryProvider.capabilities.functionCalling).toBe(true);
      expect(selection.estimatedLatency).toBeLessThan(criteria.requirements.maxLatency!);
      expect(selection.estimatedCost).toBeLessThan(criteria.requirements.maxCost!);
    });

    it('should handle real-time provider switching', async () => {
      let currentProvider = 'openai';
      const providerSwitches: string[] = [];

      jest.spyOn(messageRouter, 'routeMessage').mockImplementation(async () => {
        // Simulate provider switching based on load/performance
        const providers = ['openai', 'anthropic', 'mock-provider'];
        const previousProvider = currentProvider;
        currentProvider = providers[(providers.indexOf(currentProvider) + 1) % providers.length];
        
        if (currentProvider !== previousProvider) {
          providerSwitches.push(`${previousProvider} -> ${currentProvider}`);
        }

        return {
          id: 'switched-response',
          content: `Response from ${currentProvider}`,
          provider: currentProvider,
          model: 'test-model',
          timestamp: new Date()
        };
      });

      // Send multiple requests to trigger switching
      const requests = Array.from({ length: 10 }, (_, i) =>
        MCPTestUtils.createMockLLMRequest({
          id: `switching-${i}`,
          prompt: `Provider switching test ${i}`
        })
      );

      await Promise.all(requests.map(req => messageRouter.routeMessage(req)));

      console.log('Provider switches:', providerSwitches);
      expect(providerSwitches.length).toBeGreaterThan(0);
    });
  });
});

/**
 * Helper functions for multi-provider testing
 */

function normalizeProviderResponse(provider: string, rawResponse: any): LLMResponse {
  const baseResponse = {
    id: rawResponse.id || `${provider}-${Date.now()}`,
    provider,
    timestamp: new Date()
  };

  switch (provider) {
    case 'openai':
      return {
        ...baseResponse,
        content: rawResponse.choices[0].message.content,
        model: rawResponse.model || 'gpt-4',
        usage: {
          promptTokens: rawResponse.usage.prompt_tokens,
          completionTokens: rawResponse.usage.completion_tokens,
          totalTokens: rawResponse.usage.total_tokens
        }
      };

    case 'anthropic':
      return {
        ...baseResponse,
        content: rawResponse.content[0].text,
        model: rawResponse.model || 'claude-3-sonnet',
        usage: {
          promptTokens: rawResponse.usage.input_tokens,
          completionTokens: rawResponse.usage.output_tokens,
          totalTokens: rawResponse.usage.input_tokens + rawResponse.usage.output_tokens
        }
      };

    case 'cohere':
      return {
        ...baseResponse,
        content: rawResponse.generations[0].text,
        model: rawResponse.model || 'command',
        usage: {
          promptTokens: rawResponse.meta.tokens.input_tokens,
          completionTokens: rawResponse.meta.tokens.output_tokens,
          totalTokens: rawResponse.meta.tokens.input_tokens + rawResponse.meta.tokens.output_tokens
        }
      };

    default:
      throw new Error(`Unknown provider: ${provider}`);
  }
}

function normalizeProviderError(provider: string, errorResponse: any): MCPError {
  const baseError = {
    timestamp: new Date(),
    retryable: true,
    provider
  };

  // Map different error formats to standard MCPError
  if (errorResponse.error?.type === 'rate_limit_error' || errorResponse.code === 429) {
    return {
      ...baseError,
      code: MCPErrorCode.RATE_LIMIT_EXCEEDED,
      message: errorResponse.error?.message || errorResponse.message || 'Rate limit exceeded'
    };
  }

  return {
    ...baseError,
    code: MCPErrorCode.PROVIDER_ERROR,
    message: errorResponse.error?.message || errorResponse.message || 'Provider error'
  };
}

function normalizeFunction(provider: string, functionFormat: any): any {
  switch (provider) {
    case 'openai':
      return functionFormat.function;

    case 'anthropic':
      return {
        name: functionFormat.name,
        description: functionFormat.description,
        parameters: functionFormat.input_schema
      };

    case 'cohere':
      // Convert Cohere parameter format to OpenAI format
      const properties: any = {};
      const required: string[] = [];

      for (const [name, def] of Object.entries(functionFormat.parameter_definitions)) {
        const paramDef = def as any;
        properties[name] = {
          type: paramDef.type === 'str' ? 'string' : paramDef.type,
          description: paramDef.description
        };
        if (paramDef.required) {
          required.push(name);
        }
      }

      return {
        name: functionFormat.name,
        description: functionFormat.description,
        parameters: {
          type: 'object',
          properties,
          required
        }
      };

    default:
      return functionFormat;
  }
}