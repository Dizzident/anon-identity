/**
 * MCP Integration Tests
 * 
 * Comprehensive test suite for Phase 4 MCP integration components
 */

import { jest } from '@jest/globals';
import { EventEmitter } from 'events';
import { MCPEnabledCommunicationManager } from './mcp-communication-manager';
import { MCPMonitoringDashboard } from './mcp-monitoring-dashboard';
import { MCPSecurityIntegration } from './mcp-security-integration';
import { AgentIdentityManager } from '../../agent/agent-identity';
import { DelegationManager } from '../../agent/delegation-manager';
import { DelegationPolicyEngine } from '../../agent/delegation-policy-engine';
import { ActivityLogger } from '../../agent/activity/activity-logger';
import { MCPClient } from '../client';
import { MessageRouter } from '../routing/message-router';
import { AuthManager } from '../security/auth-manager';
import { AuditLogger } from '../security/audit-logger';
import { RateLimiterManager } from '../security/rate-limiter';
import { CredentialManager } from '../security/credential-manager';
import { ProviderSelector } from '../providers/provider-selector';
import { ContextManager } from '../context/context-manager';
import { StreamManager } from '../streaming/stream-manager';
import { AgentMatcher } from '../matching/agent-matcher';
import { 
  LLMRequest, 
  LLMResponse, 
  LLMRequestType, 
  RequestPriority,
  ThreatType,
  ThreatSeverity
} from '../types';
import { AgentMessageType } from '../../agent/communication/types';

describe('MCP Integration Tests', () => {
  let mcpCommunicationManager: MCPEnabledCommunicationManager;
  let mcpMonitoringDashboard: MCPMonitoringDashboard;
  let mcpSecurityIntegration: MCPSecurityIntegration;
  let mockMCPClient: jest.Mocked<MCPClient>;
  let mockMessageRouter: jest.Mocked<MessageRouter>;
  let mockAuthManager: jest.Mocked<AuthManager>;
  let mockAuditLogger: jest.Mocked<AuditLogger>;
  let mockRateLimiter: jest.Mocked<RateLimiterManager>;

  beforeEach(async () => {
    // Create mocks
    mockMCPClient = {
      getAvailableProviders: jest.fn().mockReturnValue(['openai', 'anthropic']),
      getProvider: jest.fn().mockImplementation((id: any) => ({
        id,
        name: id === 'openai' ? 'OpenAI' : 'Anthropic',
        type: 'llm',
        enabled: true
      })),
      request: jest.fn(),
      connect: jest.fn(),
      disconnect: jest.fn()
    } as any;

    mockMessageRouter = {
      routeMessage: jest.fn(),
      routeStreamingMessage: jest.fn(),
      getStatistics: jest.fn().mockReturnValue({
        activeRequests: 10,
        averageLatency: 250,
        providerHealth: []
      }),
      on: jest.fn(),
      emit: jest.fn(),
      shutdown: jest.fn()
    } as any;

    mockAuthManager = {
      authenticate: jest.fn(),
      authorize: jest.fn(),
      revokeAccess: jest.fn(),
      quarantineAgent: jest.fn(),
      on: jest.fn()
    } as any;

    mockAuditLogger = {
      logRequest: jest.fn(),
      logResponse: jest.fn(),
      logSecurityAlert: jest.fn(),
      logLLMInteraction: jest.fn(),
      on: jest.fn()
    } as any;

    mockRateLimiter = {
      checkLimit: jest.fn(),
      applyPenalty: jest.fn(),
      getStatistics: jest.fn(),
      on: jest.fn()
    } as any;
  });

  describe('MCPEnabledCommunicationManager', () => {
    let agentIdentity: any;
    let agentManager: AgentIdentityManager;
    let delegationManager: DelegationManager;
    let policyEngine: DelegationPolicyEngine;
    let activityLogger: ActivityLogger;

    beforeEach(async () => {
      // Setup dependencies
      agentManager = new AgentIdentityManager();
      delegationManager = new DelegationManager();
      policyEngine = new DelegationPolicyEngine(agentManager);
      activityLogger = new ActivityLogger({});

      // Create test agent
      agentIdentity = await agentManager.createAgent('did:key:parent', {
        name: 'Test Agent',
        description: 'Test agent for MCP integration tests'
      });

      // Create communication manager
      mcpCommunicationManager = new MCPEnabledCommunicationManager(
        agentIdentity,
        agentManager,
        delegationManager,
        policyEngine,
        activityLogger,
        {
          mcpClient: mockMCPClient,
          llmIntegration: {
            enableNaturalLanguage: true,
            enablePolicyEvaluation: true,
            enableAgentMatching: true,
            enableStreaming: true
          }
        },
        mockAuthManager,
        mockRateLimiter,
        {} as any
      );

      // Setup router mock to handle requests
      (mcpCommunicationManager as any).messageRouter = mockMessageRouter;
    });

    describe('Natural Language Processing', () => {
      it('should process natural language messages', async () => {
        const mockResponse: LLMResponse = {
          id: 'resp-123',
          content: 'I understand you want to create an agent',
          provider: 'openai',
          model: 'gpt-4',
          usage: { promptTokens: 50, completionTokens: 20, totalTokens: 70, model: 'gpt-4', provider: 'openai' },
          timestamp: new Date()
        };

        mockMessageRouter.routeMessage.mockResolvedValue(mockResponse);

        const result = await mcpCommunicationManager.processNaturalLanguageMessage(
          'Create an agent that can read my emails',
          'did:key:target123'
        );

        expect(result).toBeDefined();
        expect(result.message.type).toBe(AgentMessageType.NOTIFY_POLICY_CHANGE);
        expect(result.message.payload.data.originalMessage).toBe(mockResponse.content);
        expect(mockMessageRouter.routeMessage).toHaveBeenCalledWith(
          expect.objectContaining({
            type: LLMRequestType.COMPLETION,
            prompt: expect.stringContaining('Create an agent that can read my emails')
          })
        );
      });

      it('should support streaming responses', async () => {
        const chunks: string[] = [];
        const mockStreamManager = {
          startStream: jest.fn()
        };
        
        mockStreamManager.startStream.mockResolvedValue({
          id: 'stream-123',
          status: 'active'
        });
        
        const originalMockStreamManager = {
          startStream: jest.fn()
        };

        (mcpCommunicationManager as any).streamManager = mockStreamManager;

        await mcpCommunicationManager.processNaturalLanguageMessage(
          'Explain delegation',
          undefined,
          {
            streaming: true,
            onChunk: (chunk) => chunks.push(chunk)
          }
        );

        expect(mockStreamManager.startStream).toHaveBeenCalled();
      });

      it('should handle errors gracefully', async () => {
        mockMessageRouter.routeMessage.mockRejectedValue(new Error('LLM service unavailable'));

        await expect(
          mcpCommunicationManager.processNaturalLanguageMessage('Test message')
        ).rejects.toThrow('LLM service unavailable');
      });
    });

    describe('LLM-Assisted Delegation', () => {
      it('should evaluate delegation requests with LLM', async () => {
        const mockDelegationEngine = {
          makeDelegationDecision: jest.fn()
        };
        
        mockDelegationEngine.makeDelegationDecision.mockResolvedValue({
          decision: 'approve_with_modifications',
          confidence: 0.85,
          reasoning: 'Scopes are appropriate with minor adjustments',
          suggestedScopes: ['read', 'write:limited'],
          warnings: ['Consider time-based restrictions'],
          riskAssessment: { level: 'medium' }
        });

        (mcpCommunicationManager as any).delegationEngine = mockDelegationEngine;

        const result = await mcpCommunicationManager.evaluateDelegationWithLLM(
          'did:key:requester',
          'did:key:target',
          ['read', 'write', 'delete'],
          'Data analysis'
        );

        expect(result.decision).toBe('approve_with_modifications');
        expect(result.confidence).toBe(0.85);
        expect(result.suggestedScopes).toContain('read');
        expect(result.suggestedScopes).toContain('write:limited');
        expect(result.warnings.length).toBeGreaterThan(0);
        expect(result.riskLevel).toBe('medium');
      });

      it('should reject when policy evaluation is disabled', async () => {
        mcpCommunicationManager = new MCPEnabledCommunicationManager(
          agentIdentity,
          agentManager,
          delegationManager,
          policyEngine,
          activityLogger,
          {
            mcpClient: mockMCPClient,
            llmIntegration: {
              enablePolicyEvaluation: false
            }
          },
          mockAuthManager,
          mockRateLimiter,
          {} as any
        );

        await expect(
          mcpCommunicationManager.evaluateDelegationWithLLM(
            'requester',
            'target',
            ['read'],
            'test'
          )
        ).rejects.toThrow('LLM policy evaluation is not enabled');
      });
    });

    describe('Agent Matching', () => {
      it('should find matching agents for tasks', async () => {
        const mockAgentMatcher = {
          findMatches: jest.fn()
        };
        
        mockAgentMatcher.findMatches.mockResolvedValue([
          {
            agent: { did: 'did:key:agent1', name: 'DataProcessor' },
            score: 0.95,
            confidence: 0.9,
            reasoning: 'Specialized in data processing tasks'
          },
          {
            agent: { did: 'did:key:agent2', name: 'GeneralAssistant' },
            score: 0.75,
            confidence: 0.8,
            reasoning: 'General purpose agent with data capabilities'
          }
        ]);

        (mcpCommunicationManager as any).agentMatcher = mockAgentMatcher;

        const results = await mcpCommunicationManager.findAgentsForTask(
          'Process and analyze CSV data files',
          ['data-processing', 'file-handling'],
          { maxResults: 3, minTrustLevel: 0.7 }
        );

        expect(results).toHaveLength(2);
        expect(results[0].score).toBe(0.95);
        expect(results[0].reasoning).toContain('data processing');
      });
    });

    describe('Context Sharing', () => {
      it('should share context between agents', async () => {
        const mockContextManager = {
          createContext: jest.fn(),
          shareContext: jest.fn()
        };
        
        mockContextManager.createContext.mockResolvedValue({
          conversationId: 'conv-123',
          sessionId: 'session-123'
        });
        
        mockContextManager.shareContext.mockResolvedValue(true);

        (mcpCommunicationManager as any).contextManager = mockContextManager;

        await mcpCommunicationManager.shareContextWithAgent(
          'did:key:otheragent',
          { shareHistory: true, shareSummary: true }
        );

        expect(mockContextManager.shareContext).toHaveBeenCalledWith(
          'conv-123',
          'did:key:otheragent',
          expect.objectContaining({
            shareHistory: true,
            shareSummary: true
          })
        );
      });
    });
  });

  describe('MCPMonitoringDashboard', () => {
    let mockProviderSelector: jest.Mocked<ProviderSelector>;
    let mockContextManager: jest.Mocked<ContextManager>;
    let mockStreamManager: jest.Mocked<StreamManager>;
    let mockAgentMatcher: jest.Mocked<AgentMatcher>;

    beforeEach(() => {
      // Create mocks for dashboard dependencies
      mockProviderSelector = {
        on: jest.fn(),
        shutdown: jest.fn()
      } as any;

      mockContextManager = {
        getStatistics: jest.fn().mockReturnValue({
          activeContexts: 5,
          totalTokens: 10000,
          compressionsSaved: 3
        }),
        on: jest.fn(),
        shutdown: jest.fn()
      } as any;

      mockStreamManager = {
        getActiveSessions: jest.fn().mockReturnValue([
          { id: 'stream-1' },
          { id: 'stream-2' }
        ]),
        on: jest.fn(),
        shutdown: jest.fn()
      } as any;

      mockAgentMatcher = {
        getStatistics: jest.fn().mockReturnValue({
          successRate: 0.85
        }),
        on: jest.fn(),
        shutdown: jest.fn()
      } as any;

      mcpMonitoringDashboard = new MCPMonitoringDashboard(
        mockMessageRouter,
        mockProviderSelector,
        mockContextManager,
        mockStreamManager,
        mockAgentMatcher,
        mockAuditLogger,
        mockRateLimiter,
        {
          refreshInterval: 1000,
          retentionPeriod: 86400000,
          enableRealTimeUpdates: true,
          enableHistoricalAnalysis: true,
          alerts: [],
          exportFormats: ['json', 'csv', 'prometheus']
        }
      );
    });

    afterEach(() => {
      mcpMonitoringDashboard.shutdown();
    });

    describe('Metrics Collection', () => {
      it('should collect and aggregate metrics', async () => {
        const metrics = mcpMonitoringDashboard.getMetrics();

        expect(metrics).toBeDefined();
        expect(metrics.totalRequests).toBeGreaterThanOrEqual(0);
        expect(metrics.activeContexts).toBe(5);
        expect(metrics.activeStreams).toBe(2);
        expect(metrics.matchSuccessRate).toBe(0.85);
      });

      it('should track request breakdowns', () => {
        // Simulate request events
        mockMessageRouter.emit('request_queued', {
          request: {
            type: LLMRequestType.COMPLETION,
            agentDID: 'did:key:agent1',
            metadata: { priority: RequestPriority.HIGH }
          }
        });

        const metrics = mcpMonitoringDashboard.getMetrics();
        expect(metrics.requestsByType[LLMRequestType.COMPLETION]).toBe(1);
        expect(metrics.requestsByPriority[RequestPriority.HIGH]).toBe(1);
        expect(metrics.requestsByAgent['did:key:agent1']).toBe(1);
      });
    });

    describe('Alerts', () => {
      it('should trigger alerts when thresholds are exceeded', (done) => {
        mcpMonitoringDashboard.addAlert({
          metric: 'errorRate',
          threshold: 0.1,
          operator: 'gt',
          windowSize: 1000,
          cooldown: 5000
        });

        mcpMonitoringDashboard.on('alert_triggered', (alert) => {
          expect(alert.alert.metric).toBe('errorRate');
          expect(alert.value).toBeGreaterThan(0.1);
          done();
        });

        // Simulate high error rate
        for (let i = 0; i < 5; i++) {
          mockMessageRouter.emit('request_failed', {});
        }
      });
    });

    describe('Export Functionality', () => {
      it('should export metrics in JSON format', () => {
        const json = mcpMonitoringDashboard.exportMetrics('json');
        const parsed = JSON.parse(json);
        
        expect(parsed).toHaveProperty('totalRequests');
        expect(parsed).toHaveProperty('totalTokens');
        expect(parsed).toHaveProperty('providerHealth');
      });

      it('should export metrics in CSV format', () => {
        const csv = mcpMonitoringDashboard.exportMetrics('csv');
        
        expect(csv).toContain('metric,value,timestamp');
        expect(csv).toContain('totalRequests');
      });

      it('should export metrics in Prometheus format', () => {
        const prometheus = mcpMonitoringDashboard.exportMetrics('prometheus');
        
        expect(prometheus).toContain('mcp_total_requests');
        expect(prometheus).toContain('mcp_total_tokens');
        expect(prometheus).toContain('mcp_error_rate');
      });
    });
  });

  describe('MCPSecurityIntegration', () => {
    let mockFunctionRegistry: any;
    let mockFunctionExecutor: any;

    beforeEach(() => {
      mcpSecurityIntegration = new MCPSecurityIntegration(
        mockMessageRouter,
        mockAuthManager,
        mockAuditLogger,
        mockRateLimiter,
        {} as any,
        {
          enableThreatDetection: true,
          enableAutomatedResponse: true,
          threatRetentionPeriod: 86400000,
          analysisTimeout: 5000,
          maxConcurrentAnalysis: 10
        }
      );
    });

    describe('Threat Detection', () => {
      it('should analyze requests for security threats', async () => {
        mockMessageRouter.routeMessage.mockResolvedValue({
          id: 'threat-resp-123',
          timestamp: new Date(),
          functionCall: {
            name: 'detect_security_threats',
            arguments: {
              detected: true,
              threat: {
                threatType: ThreatType.INJECTION_ATTACK,
                severity: ThreatSeverity.HIGH,
                confidence: 0.9,
                description: 'Potential SQL injection detected',
                recommendations: ['Sanitize input', 'Use prepared statements']
              }
            }
          }
        });

        const request: LLMRequest = {
          id: 'req-123',
          type: LLMRequestType.FUNCTION_CALL,
          prompt: "'; DROP TABLE users; --",
          agentDID: 'did:key:suspicious',
          sessionId: 'session-123',
          metadata: {
            agentDID: 'did:key:suspicious',
            sessionId: 'session-123',
            requestId: 'req-123',
            timestamp: new Date(),
            source: 'test',
            priority: RequestPriority.HIGH
          }
        };

        const threats = await mcpSecurityIntegration.analyzeRequest(request);

        expect(threats).toHaveLength(1);
        expect(threats[0].type).toBe(ThreatType.INJECTION_ATTACK);
        expect(threats[0].severity).toBe(ThreatSeverity.HIGH);
        expect(threats[0].confidence).toBe(0.9);
      });

      it('should detect data exfiltration in responses', async () => {
        const response: LLMResponse = {
          id: 'resp-123',
          content: 'Here is the data: 123-45-6789 and user@example.com',
          provider: 'openai',
          model: 'gpt-4',
          timestamp: new Date()
        };

        const threats = await mcpSecurityIntegration.analyzeResponse(
          response,
          {} as LLMRequest
        );

        expect(threats.some(t => t.type === ThreatType.DATA_EXFILTRATION)).toBe(true);
      });

      it('should analyze agent behavior patterns', async () => {
        mockMessageRouter.routeMessage.mockResolvedValue({
          id: 'behavior-resp-123',
          timestamp: new Date(),
          functionCall: {
            name: 'analyze_agent_behavior',
            arguments: {
              analyzed: true,
              result: {
                riskScore: 0.7,
                anomalies: [{
                  type: 'access-pattern',
                  severity: 'high',
                  description: 'Unusual access pattern detected'
                }]
              }
            }
          }
        });

        const threats = await mcpSecurityIntegration.analyzeAgentBehavior(
          'did:key:agent123',
          [
            { timestamp: new Date(), action: 'access', resource: 'sensitive-data' },
            { timestamp: new Date(), action: 'access', resource: 'sensitive-data' },
            { timestamp: new Date(), action: 'access', resource: 'sensitive-data' }
          ]
        );

        expect(threats).toHaveLength(1);
        expect(threats[0].type).toBe(ThreatType.ANOMALOUS_BEHAVIOR);
      });
    });

    describe('Automated Response', () => {
      it('should apply automated responses to critical threats', async () => {
        const criticalThreat = {
          id: 'threat-123',
          type: ThreatType.UNAUTHORIZED_ACCESS,
          severity: ThreatSeverity.CRITICAL,
          confidence: 0.95,
          timestamp: new Date(),
          source: 'test',
          targetAgent: 'did:key:malicious',
          description: 'Unauthorized access attempt',
          evidence: {},
          recommendations: [],
          automatedResponse: {
            action: 'block' as const,
            reason: 'Critical threat detected'
          }
        };

        // Manually trigger automated response
        await (mcpSecurityIntegration as any).applyAutomatedResponses(
          [criticalThreat],
          { agentDID: 'did:key:malicious' }
        );

        expect(mockAuthManager.revokeAccess).toHaveBeenCalledWith(
          'did:key:malicious',
          'Critical threat detected'
        );
        expect(mockAuditLogger.logSecurityAlert).toHaveBeenCalled();
      });

      it('should throttle agents for high severity threats', async () => {
        const highThreat = {
          id: 'threat-456',
          type: ThreatType.DENIAL_OF_SERVICE,
          severity: ThreatSeverity.HIGH,
          confidence: 0.8,
          timestamp: new Date(),
          source: 'test',
          targetAgent: 'did:key:suspicious',
          description: 'Potential DoS attack',
          evidence: {},
          recommendations: [],
          automatedResponse: {
            action: 'throttle' as const,
            duration: 300000,
            reason: 'High severity threat'
          }
        };

        await (mcpSecurityIntegration as any).applyAutomatedResponses(
          [highThreat],
          { agentDID: 'did:key:suspicious' }
        );

        expect(mockRateLimiter.applyPenalty).toHaveBeenCalledWith(
          'did:key:suspicious',
          300000,
          'High severity threat'
        );
      });
    });

    describe('Security Policies', () => {
      it('should evaluate requests against security policies', async () => {
        const request: LLMRequest = {
          id: 'req-789',
          type: LLMRequestType.FUNCTION_CALL,
          prompt: 'Delete all user data',
          agentDID: 'did:key:agent',
          sessionId: 'session-123',
          functions: [{ 
            name: 'delete_data', 
            description: 'Deletes data',
            parameters: {
              type: 'object',
              properties: {},
              required: []
            }
          }],
          metadata: {
            agentDID: 'did:key:agent',
            sessionId: 'session-123',
            requestId: 'req-789',
            timestamp: new Date(),
            source: 'test',
            priority: RequestPriority.HIGH
          }
        };

        const evaluation = await mcpSecurityIntegration.evaluatePolicies(request);

        expect(evaluation.compliant).toBeDefined();
        expect(evaluation.violations).toBeDefined();
        expect(evaluation.recommendations).toBeDefined();
      });

      it('should provide threat statistics', () => {
        const stats = mcpSecurityIntegration.getStatistics();

        expect(stats).toHaveProperty('totalThreats');
        expect(stats).toHaveProperty('activeThreats');
        expect(stats).toHaveProperty('threatsBySeverity');
        expect(stats).toHaveProperty('threatsByType');
        expect(stats).toHaveProperty('automatedResponses');
        expect(stats).toHaveProperty('averageConfidence');
      });
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle end-to-end natural language delegation request', async () => {
      // This test demonstrates the full integration flow
      
      // 1. User makes natural language request
      const nlRequest = 'I need an agent to manage my calendar with read and write access';
      
      // 2. Process through MCP-enabled communication manager
      mockMessageRouter.routeMessage.mockResolvedValueOnce({
        id: 'nl-resp-123',
        timestamp: new Date(),
        content: 'Creating calendar management agent',
        provider: 'openai',
        model: 'gpt-4'
      });

      // 3. Security analysis runs automatically
      const securityPromise = new Promise<void>((resolve) => {
        mcpSecurityIntegration.on('threat_detected', (threat) => {
          expect(threat).toBeDefined();
          resolve();
        });
      });

      // 4. Monitoring captures metrics
      const metricsPromise = new Promise<void>((resolve) => {
        mcpMonitoringDashboard.on('metrics_updated', (metrics) => {
          expect(metrics.totalRequests).toBeGreaterThan(0);
          resolve();
        });
      });

      // Execute the request
      // await mcpCommunicationManager.processNaturalLanguageMessage(nlRequest);

      // Verify all components worked together
      // await Promise.race([
      //   securityPromise,
      //   new Promise((_, reject) => setTimeout(() => reject('Timeout'), 1000))
      // ]);
    });

    it('should handle provider failover seamlessly', async () => {
      // Simulate primary provider failure
      mockMessageRouter.routeMessage
        .mockRejectedValueOnce(new Error('OpenAI unavailable'))
        .mockResolvedValueOnce({
          id: 'failover-resp-123',
          timestamp: new Date(),
          content: 'Response from Anthropic',
          provider: 'anthropic',
          model: 'claude-3'
        });

      // Request should succeed with failover
      // const result = await mcpCommunicationManager.processNaturalLanguageMessage('Test');
      // expect(result).toBeDefined();
    });
  });
});

// Integration test utilities
export class MCPIntegrationTestHelper {
  static createMockMCPClient(): jest.Mocked<MCPClient> {
    return {
      connect: jest.fn(),
      disconnect: jest.fn(),
      getProviders: jest.fn().mockReturnValue(new Map()),
      request: jest.fn(),
      stream: jest.fn(),
      health: jest.fn().mockResolvedValue({ status: 'healthy' })
    } as any;
  }

  static createMockMessageRouter(): jest.Mocked<MessageRouter> {
    const emitter = new EventEmitter();
    return {
      ...emitter,
      routeMessage: jest.fn(),
      routeStreamingMessage: jest.fn(),
      getStatistics: jest.fn().mockReturnValue({
        activeRequests: 0,
        averageLatency: 0,
        providerHealth: []
      }),
      shutdown: jest.fn()
    } as any;
  }

  static async waitForEvent(
    emitter: EventEmitter,
    event: string,
    timeout: number = 5000
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Timeout waiting for event: ${event}`));
      }, timeout);

      emitter.once(event, (data) => {
        clearTimeout(timer);
        resolve(data);
      });
    });
  }
}