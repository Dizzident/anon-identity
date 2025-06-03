/**
 * MCP Phase 3 Advanced Features Example
 * 
 * Demonstrates advanced MCP features including:
 * - Intelligent provider selection and load balancing
 * - Real-time streaming with adaptive quality
 * - Embedding-based agent matching
 * - Context compression and sharing
 * - Multi-provider failover scenarios
 */

import { EventEmitter } from 'events';

// Core MCP imports
import { MCPClient } from '../src/mcp/client';
import { UnifiedLLMInterface } from '../src/mcp/interface';

// Phase 3 Advanced Features
import { ProviderSelector, SelectionStrategy, SelectionCriteria } from '../src/mcp/providers';
import { StreamManager, StreamSession, RealTimeConfig } from '../src/mcp/streaming';
import { AgentMatcher, AgentCapabilityProfile, TaskDescription } from '../src/mcp/matching';
import { ContextManager } from '../src/mcp/context/context-manager';

// Security and routing
import { MessageRouter } from '../src/mcp/routing/message-router';
import { AuthManager } from '../src/mcp/security/auth-manager';
import { AuditLogger } from '../src/mcp/security/audit-logger';
import { RateLimiterManager } from '../src/mcp/security/rate-limiter';
import { CredentialManager } from '../src/mcp/security/credential-manager';

// Types
import {
  MCPConfig,
  LLMRequest,
  LLMRequestType,
  RequestPriority,
  MessageRole,
  ContextPriority
} from '../src/mcp/types';

/**
 * Advanced MCP Phase 3 Demo
 */
export class MCPPhase3AdvancedDemo extends EventEmitter {
  private mcpClient: MCPClient;
  private providerSelector: ProviderSelector;
  private streamManager: StreamManager;
  private agentMatcher: AgentMatcher;
  private contextManager: ContextManager;
  private messageRouter: MessageRouter;
  private authManager: AuthManager;
  private auditLogger: AuditLogger;
  private rateLimiter: RateLimiterManager;
  private credentialManager: CredentialManager;

  constructor() {
    super();
    this.initializeAdvancedComponents();
  }

  /**
   * Initialize all advanced MCP components
   */
  private async initializeAdvancedComponents(): Promise<void> {
    console.log('🚀 Initializing MCP Phase 3 Advanced Features...');

    // Initialize core components (simplified for demo)
    const mcpConfig: MCPConfig = {
      server: {
        host: 'localhost',
        port: 8080,
        tls: { enabled: false, certFile: '', keyFile: '' },
        compression: true,
        timeout: 30000,
        maxConnections: 100
      },
      client: {
        timeout: 30000,
        retryAttempts: 3,
        retryDelay: 1000,
        maxConcurrentRequests: 50,
        keepAlive: true,
        compression: true
      },
      providers: [
        {
          id: 'openai-primary',
          name: 'OpenAI Primary',
          type: 'openai',
          enabled: true,
          endpoint: 'https://api.openai.com/v1',
          models: ['gpt-4', 'gpt-3.5-turbo'],
          capabilities: {
            completion: true,
            streaming: true,
            functionCalling: true,
            embeddings: true,
            moderation: true,
            multimodal: false,
            jsonMode: true
          },
          rateLimits: {
            requestsPerMinute: 60,
            tokensPerMinute: 150000,
            requestsPerDay: 10000,
            tokensPerDay: 1000000,
            concurrentRequests: 10
          },
          config: {
            apiKey: process.env.OPENAI_API_KEY || 'demo-key',
            organization: '',
            baseURL: 'https://api.openai.com/v1'
          }
        },
        {
          id: 'anthropic-backup',
          name: 'Anthropic Backup',
          type: 'anthropic',
          enabled: true,
          endpoint: 'https://api.anthropic.com/v1',
          models: ['claude-3-sonnet', 'claude-3-haiku'],
          capabilities: {
            completion: true,
            streaming: true,
            functionCalling: false,
            embeddings: false,
            moderation: false,
            multimodal: true,
            jsonMode: false
          },
          rateLimits: {
            requestsPerMinute: 50,
            tokensPerMinute: 100000,
            requestsPerDay: 8000,
            tokensPerDay: 800000,
            concurrentRequests: 8
          },
          config: {
            apiKey: process.env.ANTHROPIC_API_KEY || 'demo-key'
          }
        },
        {
          id: 'google-experimental',
          name: 'Google Experimental',
          type: 'google',
          enabled: true,
          endpoint: 'https://generativelanguage.googleapis.com/v1beta',
          models: ['gemini-pro', 'gemini-pro-vision'],
          capabilities: {
            completion: true,
            streaming: true,
            functionCalling: true,
            embeddings: true,
            moderation: false,
            multimodal: true,
            jsonMode: true
          },
          rateLimits: {
            requestsPerMinute: 30,
            tokensPerMinute: 80000,
            requestsPerDay: 5000,
            tokensPerDay: 500000,
            concurrentRequests: 5
          },
          config: {
            apiKey: process.env.GOOGLE_API_KEY || 'demo-key'
          }
        }
      ],
      security: {
        authentication: {
          method: 'api_key',
          credentials: {}
        },
        authorization: {
          agent_permissions: new Map(),
          resource_access: {}
        },
        encryption: {
          inTransit: true,
          atRest: true,
          keyRotationInterval: 86400000,
          algorithm: 'aes-256-gcm',
          keyLength: 256
        },
        audit: {
          enabled: true,
          logAllRequests: true,
          logResponses: true,
          logSensitiveData: false,
          retentionPeriod: 86400000 * 30,
          exportFormat: ['json']
        }
      },
      monitoring: {
        enabled: true,
        metricsInterval: 60000,
        healthCheck: {
          enabled: true,
          interval: 30000,
          timeout: 5000,
          unhealthyThreshold: 3,
          healthyThreshold: 2
        },
        alerts: {
          enabled: true,
          channels: ['console'],
          thresholds: {
            errorRate: 0.1,
            latency: 5000,
            availability: 0.95
          }
        }
      },
      performance: {
        caching: {
          enabled: true,
          ttl: 300000,
          maxSize: 1000,
          strategy: 'lru'
        },
        compression: {
          enabled: true,
          algorithm: 'gzip',
          level: 6,
          threshold: 1024
        },
        pooling: {
          enabled: true,
          maxConnections: 50,
          idleTimeout: 30000,
          acquireTimeout: 10000
        }
      }
    };

    // Initialize security components
    this.credentialManager = new CredentialManager({
      storage: 'memory' as any,
      encryption: true,
      rotation: {
        enabled: false,
        interval: 0,
        notifyBefore: 0,
        retentionCount: 1
      },
      validation: {
        validateOnLoad: true,
        validateOnUse: false,
        cacheValidation: true,
        validationTimeout: 300000
      }
    });

    this.authManager = new AuthManager({
      sessionTimeout: 3600000,
      tokenExpiry: 86400000,
      maxConcurrentSessions: 10,
      requireMFA: false,
      allowedMethods: ['api_key'],
      sessionConfig: {
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
      }
    }, this.credentialManager);

    this.auditLogger = new AuditLogger({
      enabled: true,
      logAllRequests: true,
      logResponses: true,
      logSensitiveData: false,
      retentionPeriod: 86400000 * 30,
      exportFormat: ['json']
    });

    this.rateLimiter = new RateLimiterManager({
      enabled: true,
      defaultLimits: {
        requestsPerMinute: 60,
        tokensPerMinute: 150000,
        requestsPerDay: 10000,
        tokensPerDay: 1000000,
        concurrentRequests: 10
      },
      quotaConfig: {
        enabled: true,
        resetInterval: 86400000,
        warningThreshold: 0.8,
        hardLimit: true
      }
    });

    // Initialize core MCP client
    this.mcpClient = new MCPClient(mcpConfig);
    await this.mcpClient.initialize();

    // Initialize message router
    this.messageRouter = new MessageRouter(
      this.mcpClient,
      this.authManager,
      this.auditLogger,
      this.rateLimiter,
      this.credentialManager
    );

    // Initialize advanced components
    this.contextManager = new ContextManager({
      maxTokensPerContext: 4000,
      compressionThreshold: 0.8,
      compressionStrategy: 'importance',
      retentionCheckInterval: 3600000,
      sharing: {
        allowSharing: true,
        requireConsent: true,
        maxShareDepth: 2,
        shareableFields: ['domain', 'purpose', 'summary']
      },
      archiveAfterDays: 30
    });

    // Initialize provider selector with advanced strategies
    const providersMap = new Map();
    for (const provider of mcpConfig.providers) {
      providersMap.set(provider.id, provider);
    }

    this.providerSelector = new ProviderSelector(providersMap, {
      scoringWeights: {
        performance: 0.25,
        reliability: 0.25,
        capability: 0.2,
        cost: 0.15,
        availability: 0.1,
        preference: 0.05
      },
      loadBalancing: {
        strategy: 'latency_based',
        stickySession: false,
        healthCheckInterval: 30000,
        failoverThreshold: 3
      },
      circuitBreakerThreshold: 5,
      circuitBreakerTimeout: 60000,
      adaptiveLearningEnabled: true,
      fallbackChainLength: 3
    });

    // Initialize stream manager for real-time interactions
    this.streamManager = new StreamManager(
      this.messageRouter,
      this.authManager,
      this.auditLogger,
      {
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
        sessionTimeout: 300000
      }
    );

    // Initialize agent matcher for capability discovery
    this.agentMatcher = new AgentMatcher(
      this.messageRouter,
      this.authManager,
      this.auditLogger,
      {
        embeddingModel: 'text-embedding-ada-002',
        similarityThreshold: 0.7,
        maxResults: 10,
        weightings: {
          capabilityMatch: 0.3,
          performance: 0.25,
          availability: 0.15,
          cost: 0.1,
          trust: 0.1,
          experience: 0.1
        },
        enableSemanticMatching: true,
        enableLearning: true,
        cacheEmbeddings: true
      }
    );

    // Setup event handlers
    this.setupAdvancedEventHandlers();

    console.log('✅ MCP Phase 3 Advanced Features initialized successfully!');
  }

  /**
   * Demo 1: Intelligent Provider Selection with Load Balancing
   */
  async demoIntelligentProviderSelection(): Promise<void> {
    console.log('\n🧠 Demo 1: Intelligent Provider Selection with Load Balancing');

    try {
      // Define various request scenarios
      const scenarios = [
        {
          name: 'High-priority function calling',
          criteria: {
            requestType: LLMRequestType.FUNCTION_CALL,
            priority: RequestPriority.HIGH,
            requirements: {
              streaming: false,
              functionCalling: true,
              maxLatency: 2000,
              minReliability: 0.95
            },
            context: {
              agentDID: 'did:key:critical-system',
              domain: 'finance',
              sensitiveData: true
            }
          },
          strategy: SelectionStrategy.RELIABILITY
        },
        {
          name: 'Cost-optimized completion',
          criteria: {
            requestType: LLMRequestType.COMPLETION,
            priority: RequestPriority.MEDIUM,
            requirements: {
              costConstraint: 0.50,
              maxTokens: 2000
            },
            context: {
              agentDID: 'did:key:budget-agent',
              domain: 'general',
              sensitiveData: false
            }
          },
          strategy: SelectionStrategy.COST_OPTIMIZED
        },
        {
          name: 'Performance-critical streaming',
          criteria: {
            requestType: LLMRequestType.COMPLETION,
            priority: RequestPriority.CRITICAL,
            requirements: {
              streaming: true,
              maxLatency: 500,
              preferredModels: ['gpt-4', 'claude-3-sonnet']
            },
            context: {
              agentDID: 'did:key:real-time-agent',
              domain: 'customer_service',
              sensitiveData: false
            }
          },
          strategy: SelectionStrategy.PERFORMANCE
        }
      ];

      for (const scenario of scenarios) {
        console.log(`\n📊 Scenario: ${scenario.name}`);
        
        const mockRequest: LLMRequest = {
          id: `demo-${Date.now()}`,
          type: scenario.criteria.requestType,
          prompt: `Test request for ${scenario.name}`,
          agentDID: scenario.criteria.context?.agentDID || 'demo-agent',
          sessionId: `demo-session-${Date.now()}`,
          metadata: {
            agentDID: scenario.criteria.context?.agentDID || 'demo-agent',
            sessionId: `demo-session-${Date.now()}`,
            requestId: `demo-${Date.now()}`,
            timestamp: new Date(),
            source: 'phase3-demo',
            priority: scenario.criteria.priority
          }
        };

        const selection = await this.providerSelector.selectProvider(
          mockRequest,
          scenario.criteria as SelectionCriteria,
          scenario.strategy
        );

        console.log(`✅ Selected Provider: ${selection.primaryProvider.name}`);
        console.log(`   Score: ${(selection.score * 100).toFixed(1)}%`);
        console.log(`   Estimated Cost: $${selection.estimatedCost.toFixed(4)}`);
        console.log(`   Estimated Latency: ${selection.estimatedLatency}ms`);
        console.log(`   Reasoning: ${selection.reasoning}`);
        console.log(`   Fallbacks: ${selection.fallbackProviders.map(p => p.name).join(', ')}`);

        // Simulate provider performance recording
        await this.providerSelector.recordPerformance(
          mockRequest.id,
          selection.primaryProvider.id,
          {
            latency: selection.estimatedLatency + Math.random() * 500,
            success: Math.random() > 0.1, // 90% success rate
            cost: selection.estimatedCost * (0.8 + Math.random() * 0.4)
          }
        );
      }

      // Show provider statistics
      const stats = this.providerSelector.getStatistics();
      console.log('\n📈 Provider Selection Statistics:');
      console.log(`   Total Selections: ${stats.totalSelections}`);
      console.log(`   Provider Usage: ${JSON.stringify(stats.providerUsage)}`);
      console.log(`   Average Score: ${(stats.averageScore * 100).toFixed(1)}%`);
      console.log(`   Failover Rate: ${(stats.failoverRate * 100).toFixed(1)}%`);

    } catch (error) {
      console.error('❌ Provider selection demo failed:', error);
    }
  }

  /**
   * Demo 2: Real-time Streaming with Adaptive Quality
   */
  async demoRealTimeStreaming(): Promise<void> {
    console.log('\n🎬 Demo 2: Real-time Streaming with Adaptive Quality');

    try {
      // Create streaming scenarios
      const streamingScenarios = [
        {
          name: 'Interactive customer support',
          request: {
            id: 'stream-demo-1',
            type: LLMRequestType.COMPLETION,
            prompt: 'You are a helpful customer support agent. Please assist the customer with their billing inquiry in a conversational manner.',
            agentDID: 'did:key:support-agent',
            sessionId: 'support-session-1',
            metadata: {
              agentDID: 'did:key:support-agent',
              sessionId: 'support-session-1',
              requestId: 'stream-demo-1',
              timestamp: new Date(),
              source: 'customer-support',
              priority: RequestPriority.HIGH
            }
          },
          options: {
            priority: 'high' as const,
            maxDuration: 30000,
            bufferConfig: {
              maxSize: 1024,
              flushOnComplete: true
            }
          }
        },
        {
          name: 'Real-time content generation',
          request: {
            id: 'stream-demo-2',
            type: LLMRequestType.COMPLETION,
            prompt: 'Write a comprehensive technical blog post about the benefits of microservices architecture. Structure it with clear sections and provide practical examples.',
            agentDID: 'did:key:content-agent',
            sessionId: 'content-session-1',
            metadata: {
              agentDID: 'did:key:content-agent',
              sessionId: 'content-session-1',
              requestId: 'stream-demo-2',
              timestamp: new Date(),
              source: 'content-generation',
              priority: RequestPriority.MEDIUM
            }
          },
          options: {
            priority: 'medium' as const,
            maxDuration: 60000,
            bufferConfig: {
              maxSize: 2048,
              flushInterval: 200,
              adaptiveBuffering: true
            }
          }
        }
      ];

      const activeStreams: StreamSession[] = [];

      for (const scenario of streamingScenarios) {
        console.log(`\n📡 Starting stream: ${scenario.name}`);

        const streamSession = await this.streamManager.startStream(
          scenario.request as LLMRequest,
          {
            ...scenario.options,
            onChunk: (chunk) => {
              console.log(`   📦 Chunk ${chunk.chunkIndex}: "${chunk.delta?.substring(0, 50)}..." (${chunk.latency}ms)`);
            },
            onComplete: (response) => {
              console.log(`   ✅ Stream completed: ${response.content?.length || 0} characters`);
            },
            onError: (error) => {
              console.error(`   ❌ Stream error: ${error.message}`);
            }
          }
        );

        activeStreams.push(streamSession);
        console.log(`   Stream ID: ${streamSession.id}`);
        console.log(`   Status: ${streamSession.status}`);
        console.log(`   Priority: ${streamSession.metadata.priority}`);

        // Simulate some processing time
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

      // Monitor stream progress
      console.log('\n📊 Monitoring stream progress...');
      for (let i = 0; i < 5; i++) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        for (const stream of activeStreams) {
          const stats = this.streamManager.getSessionStatistics(stream.id);
          if (stats) {
            console.log(`   📈 ${stream.id}: ${stats.chunksPerSecond.toFixed(1)} chunks/s, ${stats.tokensPerSecond.toFixed(1)} tokens/s`);
          }
        }
      }

      // Show streaming statistics
      const activeSessions = this.streamManager.getActiveSessions();
      console.log(`\n📊 Active streaming sessions: ${activeSessions.length}`);
      for (const session of activeSessions) {
        console.log(`   - ${session.id}: ${session.totalChunks} chunks, ${session.totalTokens} tokens`);
      }

    } catch (error) {
      console.error('❌ Real-time streaming demo failed:', error);
    }
  }

  /**
   * Demo 3: Embedding-based Agent Matching
   */
  async demoAgentMatching(): Promise<void> {
    console.log('\n🎯 Demo 3: Embedding-based Agent Matching');

    try {
      // Register some mock agent profiles
      const agentProfiles: AgentCapabilityProfile[] = [
        {
          agentDID: 'did:key:data-analyst-alice',
          name: 'Alice - Data Analyst',
          description: 'Expert data analyst specializing in business intelligence and machine learning',
          capabilities: ['data_analysis', 'machine_learning', 'statistical_modeling', 'data_visualization'],
          expertise: ['python', 'sql', 'tableau', 'machine_learning'],
          availableActions: ['analyze_data', 'create_visualizations', 'build_models', 'generate_insights'],
          performance: {
            averageResponseTime: 3000,
            successRate: 0.94,
            reliability: 0.96,
            costEfficiency: 0.85
          },
          constraints: {
            maxConcurrentTasks: 5,
            workingHours: {
              start: '09:00',
              end: '17:00',
              timezone: 'UTC'
            },
            dataRestrictions: [],
            geographicLimitations: []
          },
          lastUpdated: new Date(),
          trustLevel: 0.92
        },
        {
          agentDID: 'did:key:customer-service-bob',
          name: 'Bob - Customer Service Specialist',
          description: 'Experienced customer service agent with expertise in technical support and relationship management',
          capabilities: ['customer_service', 'technical_support', 'issue_resolution', 'communication'],
          expertise: ['customer_relations', 'problem_solving', 'product_knowledge'],
          availableActions: ['answer_questions', 'resolve_issues', 'escalate_problems', 'create_tickets'],
          performance: {
            averageResponseTime: 1500,
            successRate: 0.97,
            reliability: 0.98,
            costEfficiency: 0.90
          },
          constraints: {
            maxConcurrentTasks: 15,
            workingHours: {
              start: '08:00',
              end: '20:00',
              timezone: 'UTC'
            },
            dataRestrictions: ['pii_restricted'],
            geographicLimitations: []
          },
          lastUpdated: new Date(),
          trustLevel: 0.88
        },
        {
          agentDID: 'did:key:security-analyst-charlie',
          name: 'Charlie - Security Analyst',
          description: 'Cybersecurity specialist focusing on threat detection and incident response',
          capabilities: ['security_analysis', 'threat_detection', 'incident_response', 'risk_assessment'],
          expertise: ['cybersecurity', 'network_security', 'forensics', 'compliance'],
          availableActions: ['analyze_threats', 'investigate_incidents', 'assess_risks', 'implement_controls'],
          performance: {
            averageResponseTime: 4500,
            successRate: 0.91,
            reliability: 0.94,
            costEfficiency: 0.75
          },
          constraints: {
            maxConcurrentTasks: 3,
            workingHours: {
              start: '00:00',
              end: '23:59',
              timezone: 'UTC'
            },
            dataRestrictions: ['classified'],
            geographicLimitations: ['US', 'EU']
          },
          lastUpdated: new Date(),
          trustLevel: 0.95
        }
      ];

      // Register agents
      for (const profile of agentProfiles) {
        await this.agentMatcher.registerAgent(profile);
        console.log(`✅ Registered agent: ${profile.name}`);
      }

      // Define test tasks
      const testTasks: TaskDescription[] = [
        {
          id: 'task-data-analysis',
          title: 'Quarterly Sales Data Analysis',
          description: 'Analyze Q4 sales data to identify trends, top-performing products, and regional performance variations',
          requiredCapabilities: ['data_analysis', 'statistical_modeling'],
          preferredCapabilities: ['data_visualization', 'machine_learning'],
          priority: 'high',
          constraints: {
            maxCost: 500,
            maxDuration: 7200000, // 2 hours
            minTrustLevel: 0.85,
            dataClassification: 'internal'
          },
          context: {
            domain: 'business_intelligence',
            urgency: false,
            complexity: 'moderate',
            estimatedDuration: 5400000 // 1.5 hours
          }
        },
        {
          id: 'task-customer-support',
          title: 'Handle Product Return Inquiry',
          description: 'Assist customer with product return process, check return policy, and process refund if applicable',
          requiredCapabilities: ['customer_service', 'issue_resolution'],
          preferredCapabilities: ['technical_support'],
          priority: 'medium',
          constraints: {
            maxCost: 50,
            maxDuration: 1800000, // 30 minutes
            minTrustLevel: 0.80,
            dataClassification: 'public'
          },
          context: {
            domain: 'customer_service',
            urgency: true,
            complexity: 'simple',
            estimatedDuration: 900000 // 15 minutes
          }
        },
        {
          id: 'task-security-incident',
          title: 'Investigate Security Breach',
          description: 'Investigate potential data breach, assess impact, and recommend containment measures',
          requiredCapabilities: ['security_analysis', 'threat_detection', 'incident_response'],
          preferredCapabilities: ['risk_assessment'],
          priority: 'critical',
          constraints: {
            maxCost: 2000,
            maxDuration: 10800000, // 3 hours
            minTrustLevel: 0.90,
            dataClassification: 'restricted',
            requiredCertifications: ['security_clearance']
          },
          context: {
            domain: 'cybersecurity',
            urgency: true,
            complexity: 'expert',
            estimatedDuration: 7200000 // 2 hours
          }
        }
      ];

      // Find matches for each task
      for (const task of testTasks) {
        console.log(`\n🎯 Finding matches for: ${task.title}`);
        
        const matches = await this.agentMatcher.findMatches(task);
        
        if (matches.length === 0) {
          console.log('   ❌ No suitable agents found');
          continue;
        }

        console.log(`   ✅ Found ${matches.length} suitable agents:`);
        
        for (let i = 0; i < Math.min(3, matches.length); i++) {
          const match = matches[i];
          console.log(`   ${i + 1}. ${match.agent.name}`);
          console.log(`      Score: ${(match.score * 100).toFixed(1)}%`);
          console.log(`      Confidence: ${(match.confidence * 100).toFixed(1)}%`);
          console.log(`      Estimated Cost: $${match.estimatedMetrics.cost.toFixed(2)}`);
          console.log(`      Estimated Duration: ${(match.estimatedMetrics.duration / 60000).toFixed(1)} minutes`);
          console.log(`      Success Probability: ${(match.estimatedMetrics.successProbability * 100).toFixed(1)}%`);
          console.log(`      Risk Level: ${match.riskAssessment.level}`);
          console.log(`      Reasoning: ${match.reasoning}`);

          // Show capability alignment
          const requiredMatches = match.capabilityAlignment.required.filter(r => r.match).length;
          const requiredTotal = match.capabilityAlignment.required.length;
          console.log(`      Required Capabilities: ${requiredMatches}/${requiredTotal} matched`);
        }

        // Record a simulated outcome for learning
        if (matches.length > 0) {
          const selectedAgent = matches[0];
          await this.agentMatcher.recordMatchOutcome(
            task.id,
            selectedAgent.agent.agentDID,
            Math.random() > 0.2 ? 'success' : 'failure', // 80% success rate
            {
              cost: selectedAgent.estimatedMetrics.cost * (0.8 + Math.random() * 0.4),
              duration: selectedAgent.estimatedMetrics.duration * (0.8 + Math.random() * 0.4),
              quality: 0.7 + Math.random() * 0.3
            }
          );
        }
      }

      // Demo agent similarity search
      console.log('\n🔍 Finding similar agents to Alice (Data Analyst):');
      const similarAgents = await this.agentMatcher.findSimilarAgents(
        'did:key:data-analyst-alice',
        { maxResults: 5, minSimilarity: 0.3 }
      );

      for (const similar of similarAgents) {
        console.log(`   - ${similar.agent.name}: ${(similar.similarity * 100).toFixed(1)}% similar`);
      }

      // Show matching statistics
      const matchingStats = this.agentMatcher.getStatistics();
      console.log('\n📊 Agent Matching Statistics:');
      console.log(`   Total Profiles: ${matchingStats.totalProfiles}`);
      console.log(`   Total Matches: ${matchingStats.totalMatches}`);
      console.log(`   Success Rate: ${(matchingStats.successRate * 100).toFixed(1)}%`);
      console.log(`   Embedding Cache Size: ${matchingStats.embeddingCacheSize}`);

    } catch (error) {
      console.error('❌ Agent matching demo failed:', error);
    }
  }

  /**
   * Demo 4: Advanced Context Management and Sharing
   */
  async demoAdvancedContextManagement(): Promise<void> {
    console.log('\n🧠 Demo 4: Advanced Context Management and Sharing');

    try {
      // Create contexts for different agents
      const agentContexts = [
        {
          agentDID: 'did:key:project-manager',
          sessionId: 'project-planning-session',
          metadata: {
            domain: 'project_management',
            purpose: 'Plan Q1 product roadmap',
            priority: ContextPriority.HIGH,
            agentName: 'Project Manager',
            systemPrompt: 'You are an experienced project manager helping to plan product roadmaps.',
            sharedWith: [],
            retention: {
              duration: 86400000 * 7, // 7 days
              autoDelete: false,
              archiveAfter: 86400000 * 30 // 30 days
            }
          }
        },
        {
          agentDID: 'did:key:developer',
          sessionId: 'development-session',
          metadata: {
            domain: 'software_development',
            purpose: 'Technical implementation planning',
            priority: ContextPriority.MEDIUM,
            agentName: 'Senior Developer',
            systemPrompt: 'You are a senior software developer providing technical guidance.',
            sharedWith: [],
            retention: {
              duration: 86400000 * 3, // 3 days
              autoDelete: true,
              archiveAfter: 86400000 * 7 // 7 days
            }
          }
        }
      ];

      const createdContexts = [];

      for (const contextConfig of agentContexts) {
        const context = await this.contextManager.createContext(
          contextConfig.agentDID,
          contextConfig.sessionId,
          contextConfig.metadata
        );
        createdContexts.push(context);
        console.log(`✅ Created context: ${context.conversationId} for ${contextConfig.metadata.agentName}`);

        // Add some sample messages to demonstrate compression
        const sampleMessages = [
          {
            role: MessageRole.USER,
            content: 'Let\'s start planning the Q1 roadmap. What are the key priorities we should focus on?',
            metadata: {}
          },
          {
            role: MessageRole.ASSISTANT,
            content: 'Great! For Q1 planning, I suggest we focus on three main areas: 1) Customer feedback implementation, 2) Performance optimizations, and 3) New feature development. Let me break down each area with specific recommendations.',
            metadata: {}
          },
          {
            role: MessageRole.USER,
            content: 'That sounds good. Can you elaborate on the customer feedback implementation? What specific items should we prioritize?',
            metadata: {}
          },
          {
            role: MessageRole.ASSISTANT,
            content: 'Based on our recent customer surveys and support tickets, here are the top feedback items to address: 1) Improved search functionality - customers report difficulty finding products, 2) Mobile app performance - slow loading times on older devices, 3) Checkout process simplification - too many steps causing cart abandonment.',
            metadata: {}
          },
          {
            role: MessageRole.USER,
            content: 'Excellent analysis. Now, regarding performance optimizations, what technical debt should we address first?',
            metadata: {}
          }
        ];

        for (const message of sampleMessages) {
          await this.contextManager.addMessage(context.conversationId, message);
        }

        console.log(`   Added ${sampleMessages.length} messages to context`);
      }

      // Demonstrate context compression
      console.log('\n🗜️ Demonstrating context compression...');
      const projectContext = createdContexts[0];
      
      console.log(`Before compression: ${projectContext.tokens} tokens, ${projectContext.history.length} messages`);
      
      const compressionResult = await this.contextManager.compressContext(projectContext);
      
      console.log(`After compression: ${compressionResult.compressedTokens} tokens, ${projectContext.history.length} messages`);
      console.log(`Compression ratio: ${(compressionResult.compressionRatio * 100).toFixed(1)}%`);
      console.log(`Dropped messages: ${compressionResult.droppedMessages}`);
      if (compressionResult.summary) {
        console.log(`Summary: ${compressionResult.summary.substring(0, 200)}...`);
      }

      // Demonstrate context sharing
      console.log('\n🤝 Demonstrating context sharing...');
      const developerDID = 'did:key:developer';
      
      const sharedContext = await this.contextManager.shareContext(
        projectContext.conversationId,
        developerDID,
        {
          shareHistory: true,
          shareSummary: true,
          shareMetadata: true
        }
      );

      console.log(`✅ Shared context with developer: ${sharedContext.conversationId}`);
      console.log(`   Shared messages: ${sharedContext.history.length}`);
      console.log(`   Summary included: ${sharedContext.summary ? 'Yes' : 'No'}`);

      // Demonstrate context search
      console.log('\n🔍 Demonstrating context search...');
      const searchResults = await this.contextManager.searchContexts({
        domain: 'project_management',
        priority: ContextPriority.HIGH,
        limit: 5
      });

      console.log(`Found ${searchResults.length} matching contexts:`);
      for (const result of searchResults) {
        console.log(`   - ${result.conversationId}: ${result.metadata.purpose}`);
        console.log(`     Agent: ${result.agentDID}, Tokens: ${result.tokens}, Messages: ${result.history.length}`);
      }

      // Show context statistics
      const contextStats = this.contextManager.getStatistics();
      console.log('\n📊 Context Management Statistics:');
      console.log(`   Total Contexts: ${contextStats.totalContexts}`);
      console.log(`   Active Contexts: ${contextStats.activeContexts}`);
      console.log(`   Archived Contexts: ${contextStats.archivedContexts}`);
      console.log(`   Total Tokens: ${contextStats.totalTokens}`);
      console.log(`   Average Tokens per Context: ${contextStats.averageTokensPerContext.toFixed(0)}`);
      console.log(`   Compressions Saved: ${contextStats.compressionsSaved}`);
      console.log(`   Contexts by Priority: ${JSON.stringify(contextStats.contextsByPriority)}`);

    } catch (error) {
      console.error('❌ Advanced context management demo failed:', error);
    }
  }

  /**
   * Demo 5: Multi-provider Failover Scenario
   */
  async demoMultiProviderFailover(): Promise<void> {
    console.log('\n🔄 Demo 5: Multi-provider Failover Scenario');

    try {
      // Simulate a high-stakes scenario where failover is critical
      console.log('Simulating a critical system with provider failover...');

      const criticalRequest: LLMRequest = {
        id: 'critical-financial-analysis',
        type: LLMRequestType.FUNCTION_CALL,
        prompt: 'Analyze the attached financial data and provide risk assessment for Q1 investment portfolio',
        agentDID: 'did:key:financial-analyst',
        sessionId: 'emergency-financial-session',
        metadata: {
          agentDID: 'did:key:financial-analyst',
          sessionId: 'emergency-financial-session',
          requestId: 'critical-financial-analysis',
          timestamp: new Date(),
          source: 'financial-system',
          priority: RequestPriority.CRITICAL
        }
      };

      const criticalCriteria: SelectionCriteria = {
        requestType: LLMRequestType.FUNCTION_CALL,
        priority: RequestPriority.CRITICAL,
        requirements: {
          functionCalling: true,
          maxLatency: 1000,
          minReliability: 0.99,
          preferredModels: ['gpt-4', 'claude-3-opus']
        },
        context: {
          agentDID: 'did:key:financial-analyst',
          domain: 'finance',
          sensitiveData: true,
          regulatoryRequirements: ['SOX', 'PCI_DSS']
        }
      };

      // First attempt - select primary provider
      console.log('\n1️⃣ Primary provider selection...');
      const primarySelection = await this.providerSelector.selectProvider(
        criticalRequest,
        criticalCriteria,
        SelectionStrategy.RELIABILITY
      );

      console.log(`   Selected: ${primarySelection.primaryProvider.name}`);
      console.log(`   Fallbacks: ${primarySelection.fallbackProviders.map(p => p.name).join(', ')}`);

      // Simulate primary provider failure
      console.log('\n⚠️ Simulating primary provider failure...');
      await this.providerSelector.recordPerformance(
        criticalRequest.id,
        primarySelection.primaryProvider.id,
        {
          latency: 0,
          success: false,
          cost: 0
        }
      );

      // Attempt with fallback
      console.log('\n2️⃣ Falling back to secondary provider...');
      const fallbackSelection = await this.providerSelector.selectProvider(
        criticalRequest,
        criticalCriteria,
        SelectionStrategy.RELIABILITY
      );

      console.log(`   Selected: ${fallbackSelection.primaryProvider.name}`);
      console.log(`   This should be different from the failed primary provider`);

      // Simulate successful execution on fallback
      await this.providerSelector.recordPerformance(
        `${criticalRequest.id}-fallback`,
        fallbackSelection.primaryProvider.id,
        {
          latency: 1200,
          success: true,
          cost: 0.15
        }
      );

      console.log('   ✅ Successfully executed on fallback provider');

      // Show updated statistics after failover
      console.log('\n📊 Post-failover statistics:');
      const updatedStats = this.providerSelector.getStatistics();
      console.log(`   Total Selections: ${updatedStats.totalSelections}`);
      console.log(`   Failover Rate: ${(updatedStats.failoverRate * 100).toFixed(1)}%`);
      console.log(`   Provider Usage: ${JSON.stringify(updatedStats.providerUsage)}`);

      // Demonstrate circuit breaker behavior
      console.log('\n🔌 Demonstrating circuit breaker behavior...');
      console.log('   Simulating multiple failures to trigger circuit breaker...');
      
      for (let i = 0; i < 6; i++) {
        await this.providerSelector.recordPerformance(
          `failure-${i}`,
          primarySelection.primaryProvider.id,
          {
            latency: 0,
            success: false,
            cost: 0
          }
        );
      }

      // Try to select the failed provider again
      const postCircuitBreakerSelection = await this.providerSelector.selectProvider(
        criticalRequest,
        criticalCriteria,
        SelectionStrategy.RELIABILITY
      );

      console.log(`   Selected after circuit breaker: ${postCircuitBreakerSelection.primaryProvider.name}`);
      console.log('   (Should avoid the failed provider due to circuit breaker)');

    } catch (error) {
      console.error('❌ Multi-provider failover demo failed:', error);
    }
  }

  /**
   * Setup advanced event handlers
   */
  private setupAdvancedEventHandlers(): void {
    // Provider selector events
    this.providerSelector.on('provider_selected', (event) => {
      console.log(`🎯 Provider selected: ${event.result.primaryProvider.name} (${event.result.score.toFixed(2)})`);
    });

    // Stream manager events
    this.streamManager.on('stream_started', (session) => {
      console.log(`🎬 Stream started: ${session.id} (${session.metadata.priority} priority)`);
    });

    this.streamManager.on('stream_completed', (event) => {
      console.log(`✅ Stream completed: ${event.session.id} (${event.session.totalTokens} tokens)`);
    });

    this.streamManager.on('qos_violation', (event) => {
      console.warn(`⚠️ QoS violation in ${event.sessionId}: ${event.metric} = ${event.value}`);
    });

    // Agent matcher events
    this.agentMatcher.on('matches_found', (event) => {
      console.log(`🎯 Found ${event.matches.length} matches for task: ${event.task.title}`);
    });

    this.agentMatcher.on('match_outcome_recorded', (event) => {
      console.log(`📊 Recorded outcome for ${event.selectedAgentDID}: ${event.outcome}`);
    });

    // Context manager events
    this.contextManager.on('context_compressed', (event) => {
      console.log(`🗜️ Context compressed: ${event.context.conversationId} (${event.result.compressionRatio.toFixed(2)} ratio)`);
    });

    this.contextManager.on('context_shared', (event) => {
      console.log(`🤝 Context shared: ${event.source.conversationId} → ${event.sharedWith}`);
    });
  }

  /**
   * Run all advanced demos
   */
  async runAllAdvancedDemos(): Promise<void> {
    console.log('🎭 Running MCP Phase 3 Advanced Features Demos\n');
    console.log('=' .repeat(80));

    try {
      await this.demoIntelligentProviderSelection();
      await this.demoRealTimeStreaming();
      await this.demoAgentMatching();
      await this.demoAdvancedContextManagement();
      await this.demoMultiProviderFailover();

      console.log('\n' + '='.repeat(80));
      console.log('✅ All Phase 3 advanced demos completed successfully!');
      
      console.log('\n🚀 Phase 3 Advanced Features Summary:');
      console.log('   ✅ Intelligent provider selection with adaptive learning');
      console.log('   ✅ Real-time streaming with quality-of-service monitoring');
      console.log('   ✅ Embedding-based agent matching and capability discovery');
      console.log('   ✅ Advanced context compression and sharing');
      console.log('   ✅ Multi-provider failover with circuit breakers');

    } catch (error) {
      console.error('❌ Advanced demo execution failed:', error);
    }
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    console.log('\n🧹 Cleaning up MCP Phase 3 Advanced Features...');

    try {
      this.streamManager.shutdown();
      this.providerSelector.shutdown();
      this.agentMatcher.shutdown();
      this.contextManager.shutdown();
      this.messageRouter.shutdown();
      await this.mcpClient.shutdown();

      console.log('✅ Cleanup completed');
    } catch (error) {
      console.error('❌ Cleanup failed:', error);
    }
  }
}

/**
 * Main execution
 */
async function main() {
  const demo = new MCPPhase3AdvancedDemo();
  
  try {
    await demo.runAllAdvancedDemos();
  } finally {
    await demo.cleanup();
  }
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}

export { MCPPhase3AdvancedDemo };