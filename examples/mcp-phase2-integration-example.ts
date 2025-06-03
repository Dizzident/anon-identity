/**
 * MCP Phase 2 Integration Example
 * 
 * Demonstrates the complete Agent-LLM Communication Layer with:
 * - Secure message routing
 * - Context preservation
 * - Conversation management
 * - Function calling integration
 * - LLM-assisted delegation decisions
 */

import { EventEmitter } from 'events';

// Core MCP imports
import { MCPClient } from '../src/mcp/client';
import { UnifiedLLMInterface } from '../src/mcp/interface';

// Routing and communication
import { MessageRouter } from '../src/mcp/routing/message-router';
import { ContextManager } from '../src/mcp/context/context-manager';
import { ConversationManager } from '../src/mcp/conversation/conversation-manager';

// Security components
import { AuthManager } from '../src/mcp/security/auth-manager';
import { AuditLogger } from '../src/mcp/security/audit-logger';
import { RateLimiterManager } from '../src/mcp/security/rate-limiter';
import { CredentialManager } from '../src/mcp/security/credential-manager';

// Function calling
import { FunctionRegistry } from '../src/mcp/functions/function-registry';
import { FunctionAdapter } from '../src/mcp/functions/function-adapter';
import { FunctionExecutor } from '../src/mcp/functions/function-executor';
import { ResultValidator } from '../src/mcp/functions/result-validator';

// Delegation
import { LLMDelegationEngine } from '../src/mcp/delegation/llm-delegation-engine';
import { DelegationIntegration } from '../src/mcp/delegation/delegation-integration';

// Agent system
import { AgentLLMManager } from '../src/mcp/agent/agent-llm-manager';

// Types
import {
  MCPConfig,
  RequestPriority,
  MessageRole,
  ContextPriority,
  FunctionRiskLevel,
  LLMRequestType
} from '../src/mcp/types';

/**
 * Complete MCP Phase 2 Integration Demo
 */
export class MCPPhase2Demo extends EventEmitter {
  private mcpClient: MCPClient;
  private messageRouter: MessageRouter;
  private contextManager: ContextManager;
  private conversationManager: ConversationManager;
  private authManager: AuthManager;
  private auditLogger: AuditLogger;
  private rateLimiter: RateLimiterManager;
  private credentialManager: CredentialManager;
  private functionRegistry: FunctionRegistry;
  private functionAdapter: FunctionAdapter;
  private functionExecutor: FunctionExecutor;
  private resultValidator: ResultValidator;
  private delegationEngine: LLMDelegationEngine;
  private delegationIntegration: DelegationIntegration;
  private agentLLMManager: AgentLLMManager;

  constructor() {
    super();
    this.initializeComponents();
  }

  /**
   * Initialize all MCP components
   */
  private async initializeComponents(): Promise<void> {
    console.log('🚀 Initializing MCP Phase 2 Integration...');

    // Core configuration
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
          id: 'openai',
          name: 'OpenAI',
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
          retentionPeriod: 86400000 * 30, // 30 days
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

    this.authManager = new AuthManager(
      {
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
      },
      this.credentialManager
    );

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

    // Initialize core MCP components
    this.mcpClient = new MCPClient(mcpConfig);
    await this.mcpClient.initialize();

    // Initialize routing and communication
    this.messageRouter = new MessageRouter(
      this.mcpClient,
      this.authManager,
      this.auditLogger,
      this.rateLimiter,
      this.credentialManager
    );

    this.contextManager = new ContextManager();

    this.conversationManager = new ConversationManager(
      this.messageRouter,
      this.contextManager,
      new AgentLLMManager(
        this.mcpClient,
        this.authManager,
        this.auditLogger,
        this.rateLimiter
      )
    );

    // Initialize function calling
    this.functionRegistry = new FunctionRegistry();
    this.functionAdapter = new FunctionAdapter();
    this.functionExecutor = new FunctionExecutor(
      this.functionRegistry,
      this.authManager,
      this.auditLogger
    );
    this.resultValidator = new ResultValidator();

    // Initialize delegation
    this.delegationEngine = new LLMDelegationEngine(
      this.messageRouter,
      this.authManager,
      this.auditLogger
    );

    this.delegationIntegration = new DelegationIntegration(
      this.delegationEngine,
      this.messageRouter,
      this.conversationManager,
      this.authManager,
      this.auditLogger
    );

    // Initialize agent manager
    this.agentLLMManager = new AgentLLMManager(
      this.mcpClient,
      this.authManager,
      this.auditLogger,
      this.rateLimiter
    );

    console.log('✅ MCP Phase 2 Integration initialized successfully!');
  }

  /**
   * Demo 1: Secure Message Routing and Context Management
   */
  async demoSecureMessaging(): Promise<void> {
    console.log('\n📡 Demo 1: Secure Message Routing and Context Management');

    const agentDID = 'did:key:demo-agent-123';
    
    try {
      // Start a conversation
      const session = await this.conversationManager.startConversation(agentDID, {
        domain: 'delegation',
        purpose: 'Demonstrate secure messaging',
        priority: ContextPriority.HIGH
      });

      console.log(`Started conversation: ${session.id}`);

      // Send a message with context preservation
      const turnResult = await this.conversationManager.sendMessage(
        session.id,
        'I need to delegate some permissions to analyze customer data. Can you help me understand the process?',
        {
          priority: RequestPriority.HIGH,
          enableFunctions: true,
          temperature: 0.7
        }
      );

      console.log(`Response: ${turnResult.response.content?.substring(0, 200)}...`);
      console.log(`Tokens used: ${turnResult.metrics.tokensUsed}`);
      console.log(`Provider: ${turnResult.metrics.providerUsed}`);

    } catch (error) {
      console.error('❌ Secure messaging demo failed:', error);
    }
  }

  /**
   * Demo 2: Function Calling Integration
   */
  async demoFunctionCalling(): Promise<void> {
    console.log('\n🔧 Demo 2: Function Calling Integration');

    try {
      // Register a custom delegation function
      await this.functionRegistry.registerFunction(
        {
          name: 'assess_delegation_risk',
          description: 'Assess the risk level of a delegation request',
          parameters: {
            type: 'object',
            properties: {
              requestedScopes: {
                type: 'array',
                description: 'Array of requested permission scopes',
                items: { type: 'string' }
              },
              targetAgent: {
                type: 'string',
                description: 'Target agent identifier'
              },
              purpose: {
                type: 'string',
                description: 'Purpose of the delegation'
              }
            },
            required: ['requestedScopes', 'targetAgent', 'purpose']
          }
        },
        async (args, context) => {
          // Simulate risk assessment logic
          const { requestedScopes, targetAgent, purpose } = args;
          
          let riskScore = 0;
          const riskFactors = [];

          // Check for high-risk scopes
          const highRiskScopes = ['admin', 'delete', 'finance', 'hr'];
          const hasHighRisk = requestedScopes.some((scope: string) => 
            highRiskScopes.some(risk => scope.toLowerCase().includes(risk))
          );
          
          if (hasHighRisk) {
            riskScore += 0.4;
            riskFactors.push('High-risk scopes detected');
          }

          // Check target agent
          if (targetAgent.includes('external')) {
            riskScore += 0.3;
            riskFactors.push('External agent target');
          }

          // Check purpose
          if (purpose.toLowerCase().includes('urgent') || purpose.toLowerCase().includes('emergency')) {
            riskScore += 0.2;
            riskFactors.push('Urgent request - reduced review time');
          }

          return {
            riskScore: Math.min(riskScore, 1.0),
            riskLevel: riskScore > 0.7 ? 'high' : riskScore > 0.4 ? 'medium' : 'low',
            riskFactors,
            recommendations: riskScore > 0.5 ? ['Require additional approval', 'Limit scope duration'] : ['Standard approval process']
          };
        },
        {
          security: {
            requiredScopes: ['delegation:assess'],
            riskLevel: FunctionRiskLevel.LOW,
            auditRequired: true,
            approvalRequired: false
          }
        }
      );

      // Execute the function
      const functionResult = await this.functionExecutor.executeFunction(
        {
          name: 'assess_delegation_risk',
          arguments: {
            requestedScopes: ['read:customer_data', 'write:reports', 'admin:user_management'],
            targetAgent: 'did:key:external-analytics-service',
            purpose: 'Urgent customer analytics for quarterly report'
          },
          id: 'risk-assessment-1'
        },
        {
          agentDID: 'did:key:demo-agent-123',
          sessionId: 'demo-session',
          requestId: 'demo-request-1',
          provider: 'system',
          model: 'function-executor',
          timestamp: new Date()
        }
      );

      console.log('Function execution result:', JSON.stringify(functionResult.result, null, 2));
      console.log(`Execution time: ${functionResult.executionTime}ms`);

    } catch (error) {
      console.error('❌ Function calling demo failed:', error);
    }
  }

  /**
   * Demo 3: LLM-Assisted Delegation Decisions
   */
  async demoDelegationDecisions(): Promise<void> {
    console.log('\n🤖 Demo 3: LLM-Assisted Delegation Decisions');

    try {
      // Create a delegation request
      const delegationRequest = {
        requestId: 'del-req-001',
        parentAgentDID: 'did:key:hr-manager-alice',
        targetAgentDID: 'did:key:analytics-bot-beta',
        requestedScopes: ['read:employee_data', 'generate:reports', 'access:payroll_summary'],
        purpose: 'Generate automated HR analytics reports for quarterly review',
        context: 'The HR department needs automated reporting capabilities to analyze employee performance metrics and compensation data for the Q4 review process.',
        duration: 7 * 24 * 60 * 60 * 1000, // 7 days
        urgency: 'medium' as const,
        requestedAt: new Date()
      };

      // Build decision context
      const decisionContext = {
        parentAgent: {
          did: 'did:key:hr-manager-alice',
          name: 'Alice (HR Manager)',
          type: 'user' as const,
          trustLevel: 0.9,
          capabilities: ['hr:management', 'employee:oversight', 'reports:generate'],
          permissions: ['hr:read', 'hr:write', 'reports:create'],
          history: {
            totalDelegations: 15,
            successfulDelegations: 14,
            revokedDelegations: 1,
            averageDelegationDuration: 5 * 24 * 60 * 60 * 1000,
            lastActivity: new Date(Date.now() - 2 * 60 * 60 * 1000) // 2 hours ago
          },
          riskFactors: []
        },
        organizationalPolicies: [
          {
            id: 'hr-data-policy',
            name: 'HR Data Access Policy',
            rules: ['Require approval for payroll access', 'Limit external agent access']
          }
        ],
        systemPolicies: [
          {
            id: 'delegation-policy',
            name: 'Agent Delegation Policy',
            rules: ['Maximum 7-day delegations', 'Require human review for admin scopes']
          }
        ],
        currentDelegations: [
          {
            targetAgent: 'did:key:training-bot-gamma',
            scopes: ['read:training_data'],
            grantedAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
            expiresAt: new Date(Date.now() + 6 * 24 * 60 * 60 * 1000)
          }
        ],
        systemLoad: {
          cpu: 45,
          memory: 62,
          activeAgents: 23
        },
        securityLevel: 'normal' as const,
        timeOfDay: new Date().toLocaleTimeString(),
        workingHours: true
      };

      // Process the delegation request
      const workflow = await this.delegationIntegration.processDelegationRequest(
        {
          ...delegationRequest,
          requireExplanation: true,
          allowModifications: true,
          maxResponseTime: 30000
        },
        decisionContext
      );

      console.log(`Delegation decision: ${workflow.decision?.decision}`);
      console.log(`Confidence: ${workflow.decision?.confidence}`);
      console.log(`Reasoning: ${workflow.decision?.reasoning}`);
      console.log(`Risk level: ${workflow.decision?.riskAssessment.level}`);
      console.log(`Processing time: ${workflow.metadata.totalProcessingTime}ms`);

      if (workflow.decision?.warnings.length) {
        console.log('Warnings:', workflow.decision.warnings);
      }

    } catch (error) {
      console.error('❌ Delegation decisions demo failed:', error);
    }
  }

  /**
   * Demo 4: Natural Language Delegation Processing
   */
  async demoNaturalLanguageDelegation(): Promise<void> {
    console.log('\n💬 Demo 4: Natural Language Delegation Processing');

    try {
      const naturalRequest = "I need to give our customer service bot permission to access customer profiles and create support tickets. This is for handling the holiday rush and should last about 2 weeks. The bot should not be able to delete anything or access payment information.";

      const workflow = await this.delegationIntegration.processConversationalDelegation(
        naturalRequest,
        'did:key:customer-service-manager-bob'
      );

      console.log('Extracted delegation request:');
      console.log(`- Purpose: ${workflow.request.purpose}`);
      console.log(`- Requested scopes: ${workflow.request.requestedScopes.join(', ')}`);
      console.log(`- Target agent: ${workflow.request.targetAgentDID}`);
      console.log(`- Duration: ${workflow.request.duration ? workflow.request.duration / (24 * 60 * 60 * 1000) + ' days' : 'Not specified'}`);
      console.log(`- Urgency: ${workflow.request.urgency}`);

      if (workflow.decision) {
        console.log(`\nDecision: ${workflow.decision.decision}`);
        console.log(`Confidence: ${workflow.decision.confidence}`);
        console.log(`Risk level: ${workflow.decision.riskAssessment.level}`);
      }

    } catch (error) {
      console.error('❌ Natural language delegation demo failed:', error);
    }
  }

  /**
   * Demo 5: Complete Integration Workflow
   */
  async demoCompleteWorkflow(): Promise<void> {
    console.log('\n🚀 Demo 5: Complete Integration Workflow');

    try {
      const agentDID = 'did:key:demo-manager-charlie';

      // 1. Start conversation
      const session = await this.conversationManager.startConversation(agentDID, {
        domain: 'delegation',
        purpose: 'Complete delegation workflow demo'
      });

      // 2. Natural language request
      const nlRequest = "I need to delegate data analysis permissions to our AI assistant for the next 3 days to help with the monthly sales report.";

      // 3. Process with full integration
      const workflow = await this.delegationIntegration.processConversationalDelegation(
        nlRequest,
        agentDID,
        session.id
      );

      // 4. Show conversation context
      const context = this.contextManager.getContext(session.contextId);
      if (context) {
        console.log(`Conversation messages: ${context.history.length}`);
        console.log(`Context tokens: ${context.tokens}`);
      }

      // 5. Function call for additional analysis
      if (workflow.decision && workflow.decision.confidence < 0.8) {
        console.log('Running additional risk assessment...');
        
        const riskAssessment = await this.functionExecutor.executeFunction(
          {
            name: 'assess_delegation_risk',
            arguments: {
              requestedScopes: workflow.request.requestedScopes,
              targetAgent: workflow.request.targetAgentDID,
              purpose: workflow.request.purpose
            },
            id: 'additional-risk-check'
          },
          {
            agentDID,
            sessionId: session.id,
            requestId: 'risk-check-1',
            provider: 'system',
            model: 'function',
            timestamp: new Date()
          }
        );

        console.log('Additional risk assessment:', riskAssessment.result);
      }

      // 6. Final summary
      console.log('\n📊 Workflow Summary:');
      console.log(`- Request processed: ${workflow.request.purpose}`);
      console.log(`- Decision: ${workflow.decision?.decision}`);
      console.log(`- Confidence: ${workflow.decision?.confidence}`);
      console.log(`- Steps completed: ${workflow.steps.length}`);
      console.log(`- Total processing time: ${workflow.metadata.totalProcessingTime}ms`);
      console.log(`- Security checks: ✅ Passed`);
      console.log(`- Audit trail: ✅ Logged`);

    } catch (error) {
      console.error('❌ Complete workflow demo failed:', error);
    }
  }

  /**
   * Run all demos
   */
  async runAllDemos(): Promise<void> {
    console.log('🎭 Running MCP Phase 2 Integration Demos\n');
    console.log('=' .repeat(60));

    try {
      await this.demoSecureMessaging();
      await this.demoFunctionCalling();
      await this.demoDelegationDecisions();
      await this.demoNaturalLanguageDelegation();
      await this.demoCompleteWorkflow();

      console.log('\n' + '='.repeat(60));
      console.log('✅ All demos completed successfully!');
      console.log('\n📈 Integration Statistics:');
      
      // Get statistics from all components
      const routingStats = this.messageRouter.getStatistics();
      const contextStats = this.contextManager.getStatistics();
      const functionStats = this.functionRegistry.getStatistics();
      const delegationStats = this.delegationIntegration.getStatistics();

      console.log(`- Active requests: ${routingStats.activeRequests}`);
      console.log(`- Context compressions: ${contextStats.compressionsSaved}`);
      console.log(`- Functions registered: ${functionStats.totalFunctions}`);
      console.log(`- Delegation workflows: ${delegationStats.completedWorkflows}`);

    } catch (error) {
      console.error('❌ Demo execution failed:', error);
    }
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    console.log('\n🧹 Cleaning up MCP Phase 2 Integration...');

    try {
      await this.conversationManager.shutdown();
      this.messageRouter.shutdown();
      this.contextManager.shutdown();
      this.functionExecutor.shutdown();
      this.functionRegistry.shutdown();
      this.delegationEngine.shutdown();
      this.delegationIntegration.shutdown();
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
  const demo = new MCPPhase2Demo();
  
  try {
    await demo.runAllDemos();
  } finally {
    await demo.cleanup();
  }
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}

export { MCPPhase2Demo };