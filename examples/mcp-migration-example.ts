/**
 * MCP Migration Example
 * 
 * This example demonstrates how to migrate existing delegation code to use the MCP integration.
 * It shows both the old approach (direct LLM API calls) and the new MCP-based approach.
 */

import { AgentIdentityManager } from '../src/agent/agent-identity';
import { DelegationManager } from '../src/agent/delegation-manager';
import { DelegationPolicyEngine } from '../src/agent/delegation-policy-engine';
import { ActivityLogger } from '../src/agent/activity/activity-logger';
import { CommunicationManager } from '../src/agent/communication/communication-manager';
import { AgentMessage, AgentMessageType } from '../src/agent/communication/types';
import { 
  AuthManager,
  RateLimiterManager, 
  CredentialManager 
} from '../src/mcp/security';
import { MCPClient } from '../src/mcp/client';
import { MCPEnabledCommunicationManager } from '../src/mcp/integration/mcp-communication-manager';
import { LLMRequestType, RequestPriority } from '../src/mcp/types';
import { OpenAI } from 'openai';

/**
 * OLD APPROACH: Direct OpenAI API calls for delegation decisions
 */
class LegacyDelegationProcessor {
  private openai: OpenAI;

  constructor() {
    // Direct initialization of OpenAI client
    this.openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY
    });
  }

  async processNaturalLanguageRequest(
    request: string,
    agentDID: string
  ): Promise<any> {
    try {
      // Direct API call to OpenAI
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: 'You are a delegation assistant. Help process delegation requests.'
          },
          {
            role: 'user',
            content: request
          }
        ],
        temperature: 0.7,
        max_tokens: 500
      });

      return {
        response: completion.choices[0].message.content,
        model: 'gpt-4',
        usage: completion.usage
      };
    } catch (error) {
      console.error('Direct OpenAI API error:', error);
      throw error;
    }
  }

  async evaluateDelegation(
    requestingAgent: string,
    targetAgent: string,
    scopes: string[]
  ): Promise<{ approved: boolean; reason: string }> {
    // Simple rule-based evaluation without LLM
    const allowedScopes = ['read', 'write'];
    const approved = scopes.every(scope => allowedScopes.includes(scope));
    
    return {
      approved,
      reason: approved 
        ? 'All requested scopes are allowed' 
        : 'Some requested scopes are not allowed'
    };
  }
}

/**
 * NEW APPROACH: MCP-based LLM integration
 */
class MCPDelegationProcessor {
  private communicationManager: MCPEnabledCommunicationManager;

  constructor(
    agentIdentity: any,
    agentManager: AgentIdentityManager,
    delegationManager: DelegationManager,
    policyEngine: DelegationPolicyEngine,
    activityLogger: ActivityLogger,
    mcpClient: MCPClient,
    authManager: AuthManager,
    rateLimiter: RateLimiterManager,
    credentialManager: CredentialManager
  ) {
    // Initialize MCP-enabled communication manager
    this.communicationManager = new MCPEnabledCommunicationManager(
      agentIdentity,
      agentManager,
      delegationManager,
      policyEngine,
      activityLogger,
      {
        mcpClient,
        llmIntegration: {
          enableNaturalLanguage: true,
          enablePolicyEvaluation: true,
          enableAgentMatching: true,
          enableStreaming: true,
          defaultProvider: 'openai',
          defaultModel: 'gpt-4'
        },
        contextSettings: {
          maxTokensPerContext: 4000,
          compressionStrategy: 'importance',
          shareContextBetweenAgents: true
        }
      },
      authManager,
      rateLimiter,
      credentialManager
    );
  }

  /**
   * Process natural language requests with MCP
   * Benefits:
   * - Automatic provider selection and failover
   * - Context preservation across conversations
   * - Built-in rate limiting and security
   * - Comprehensive audit logging
   * - Streaming support for real-time interaction
   */
  async processNaturalLanguageRequest(
    request: string,
    agentDID: string
  ): Promise<AgentMessage> {
    return await this.communicationManager.processNaturalLanguageMessage(
      request,
      agentDID,
      {
        streaming: true, // Enable streaming for real-time response
        priority: RequestPriority.MEDIUM,
        onChunk: (chunk) => {
          process.stdout.write(chunk); // Stream output in real-time
        }
      }
    );
  }

  /**
   * Evaluate delegation with LLM assistance
   * Benefits:
   * - Intelligent policy interpretation
   * - Context-aware decisions
   * - Risk assessment
   * - Suggested scope modifications
   * - Natural language reasoning
   */
  async evaluateDelegation(
    requestingAgent: string,
    targetAgent: string,
    scopes: string[],
    purpose: string
  ): Promise<{
    decision: string;
    confidence: number;
    reasoning: string;
    suggestedScopes?: string[];
    warnings: string[];
    riskLevel: string;
  }> {
    return await this.communicationManager.evaluateDelegationWithLLM(
      requestingAgent,
      targetAgent,
      scopes,
      purpose,
      86400000 // 24 hours
    );
  }

  /**
   * Find matching agents for a task
   * New capability enabled by MCP integration
   */
  async findAgentsForTask(
    taskDescription: string,
    requiredCapabilities: string[]
  ): Promise<Array<{
    agent: any;
    score: number;
    confidence: number;
    reasoning: string;
  }>> {
    return await this.communicationManager.findAgentsForTask(
      taskDescription,
      requiredCapabilities,
      {
        maxResults: 5,
        minTrustLevel: 0.7,
        urgency: 'medium'
      }
    );
  }

  /**
   * Get usage statistics
   * New monitoring capability
   */
  async getUsageStats() {
    return await this.communicationManager.getLLMUsageStatistics();
  }
}

/**
 * Migration Example: Side-by-side comparison
 */
async function demonstrateMigration() {
  console.log('=== MCP Migration Example ===\n');

  // Setup common infrastructure
  const agentManager = new AgentIdentityManager();
  const delegationManager = new DelegationManager();
  const policyEngine = new DelegationPolicyEngine();
  const activityLogger = new ActivityLogger();

  // Create test agent
  const agentIdentity = await agentManager.createAgentIdentity({
    name: 'Migration Test Agent',
    type: 'service',
    scopes: ['read', 'write', 'delegate'],
    metadata: {
      purpose: 'MCP migration demonstration'
    }
  });

  console.log('1. OLD APPROACH - Direct OpenAI API:\n');
  console.log('----------------------------------------');
  
  const legacyProcessor = new LegacyDelegationProcessor();
  
  // Old approach: Natural language processing
  console.log('Processing natural language request...');
  try {
    const legacyResponse = await legacyProcessor.processNaturalLanguageRequest(
      'I need an agent that can read my calendar and schedule meetings',
      agentIdentity.did
    );
    console.log('Response:', legacyResponse.response);
    console.log('Tokens used:', legacyResponse.usage?.total_tokens);
  } catch (error) {
    console.log('Error:', error.message);
    console.log('(This would fail without API key)');
  }

  // Old approach: Delegation evaluation
  console.log('\nEvaluating delegation request...');
  const legacyEvaluation = await legacyProcessor.evaluateDelegation(
    agentIdentity.did,
    'did:key:target123',
    ['read', 'write', 'delete']
  );
  console.log('Decision:', legacyEvaluation.approved ? 'Approved' : 'Denied');
  console.log('Reason:', legacyEvaluation.reason);

  console.log('\n\n2. NEW APPROACH - MCP Integration:\n');
  console.log('----------------------------------------');

  // Initialize MCP infrastructure
  const authManager = new AuthManager();
  const rateLimiter = new RateLimiterManager(authManager);
  const credentialManager = new CredentialManager();
  
  // Mock MCP client for demonstration
  const mcpClient = {
    getProviders: () => new Map([
      ['openai', { id: 'openai', name: 'OpenAI', type: 'llm', enabled: true }],
      ['anthropic', { id: 'anthropic', name: 'Anthropic', type: 'llm', enabled: true }]
    ]),
    request: async (request: any) => ({
      content: 'I can help you create a calendar agent with the following capabilities...',
      provider: 'openai',
      model: 'gpt-4',
      usage: { totalTokens: 150, cost: 0.003 }
    })
  } as any;

  const mcpProcessor = new MCPDelegationProcessor(
    agentIdentity,
    agentManager,
    delegationManager,
    policyEngine,
    activityLogger,
    mcpClient,
    authManager,
    rateLimiter,
    credentialManager
  );

  // New approach: Natural language processing with streaming
  console.log('Processing natural language request with MCP...');
  console.log('Response (streaming): ');
  
  // Mock streaming response for demonstration
  const mockStreamingResponse = 'I can help you create a calendar agent with read and schedule permissions...';
  for (const char of mockStreamingResponse) {
    process.stdout.write(char);
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  console.log('\n');

  // New approach: Intelligent delegation evaluation
  console.log('\nEvaluating delegation with LLM assistance...');
  
  // Mock LLM-assisted evaluation
  const mcpEvaluation = {
    decision: 'approve_with_modifications',
    confidence: 0.85,
    reasoning: 'The requested "delete" scope presents unnecessary risk for calendar management. I recommend limiting to read and write operations.',
    suggestedScopes: ['read', 'write'],
    warnings: ['Delete permission could result in permanent data loss'],
    riskLevel: 'medium'
  };

  console.log('Decision:', mcpEvaluation.decision);
  console.log('Confidence:', `${(mcpEvaluation.confidence * 100).toFixed(0)}%`);
  console.log('Reasoning:', mcpEvaluation.reasoning);
  console.log('Suggested Scopes:', mcpEvaluation.suggestedScopes.join(', '));
  console.log('Risk Level:', mcpEvaluation.riskLevel);
  console.log('Warnings:', mcpEvaluation.warnings.join('; '));

  // New capability: Find matching agents
  console.log('\n\n3. NEW CAPABILITIES with MCP:\n');
  console.log('----------------------------------------');
  console.log('Finding agents for task...');

  // Mock agent matching results
  const matchingAgents = [
    {
      agent: { did: 'did:key:calendar123', name: 'CalendarBot', trustLevel: 0.9 },
      score: 0.95,
      confidence: 0.88,
      reasoning: 'Specialized calendar agent with proven track record'
    },
    {
      agent: { did: 'did:key:assistant456', name: 'PersonalAssistant', trustLevel: 0.85 },
      score: 0.82,
      confidence: 0.75,
      reasoning: 'General assistant with calendar capabilities'
    }
  ];

  console.log('\nMatching agents found:');
  matchingAgents.forEach((match, i) => {
    console.log(`\n${i + 1}. ${match.agent.name} (${match.agent.did})`);
    console.log(`   Score: ${(match.score * 100).toFixed(0)}%`);
    console.log(`   Confidence: ${(match.confidence * 100).toFixed(0)}%`);
    console.log(`   Reasoning: ${match.reasoning}`);
  });

  // Usage statistics
  console.log('\n\n4. MONITORING & ANALYTICS:\n');
  console.log('----------------------------------------');
  
  const usageStats = {
    totalRequests: 3,
    totalTokens: 450,
    totalCost: 0.009,
    averageLatency: 250,
    providerBreakdown: {
      openai: { requests: 2, tokens: 300, cost: 0.006 },
      anthropic: { requests: 1, tokens: 150, cost: 0.003 }
    }
  };

  console.log('LLM Usage Statistics:');
  console.log(`Total Requests: ${usageStats.totalRequests}`);
  console.log(`Total Tokens: ${usageStats.totalTokens}`);
  console.log(`Total Cost: $${usageStats.totalCost.toFixed(3)}`);
  console.log(`Average Latency: ${usageStats.averageLatency}ms`);
  console.log('\nProvider Breakdown:');
  Object.entries(usageStats.providerBreakdown).forEach(([provider, stats]) => {
    console.log(`  ${provider}: ${stats.requests} requests, ${stats.tokens} tokens, $${stats.cost.toFixed(3)}`);
  });

  console.log('\n\n=== MIGRATION BENEFITS SUMMARY ===\n');
  console.log('1. Unified Interface: Single API for all LLM providers');
  console.log('2. Automatic Failover: Seamless switching between providers');
  console.log('3. Context Management: Conversation history preserved');
  console.log('4. Security: Built-in authentication, rate limiting, and audit logging');
  console.log('5. Cost Optimization: Intelligent provider selection');
  console.log('6. Real-time Streaming: Better user experience');
  console.log('7. Advanced Features: Agent matching, policy interpretation');
  console.log('8. Monitoring: Comprehensive usage analytics');
}

// Migration guide as code comments
/**
 * MIGRATION CHECKLIST:
 * 
 * 1. Replace direct LLM client initialization:
 *    - OLD: new OpenAI({ apiKey: ... })
 *    - NEW: Initialize MCPClient and MCPEnabledCommunicationManager
 * 
 * 2. Update natural language processing:
 *    - OLD: openai.chat.completions.create(...)
 *    - NEW: communicationManager.processNaturalLanguageMessage(...)
 * 
 * 3. Enhance delegation evaluation:
 *    - OLD: Rule-based evaluation
 *    - NEW: communicationManager.evaluateDelegationWithLLM(...)
 * 
 * 4. Add new capabilities:
 *    - Agent matching: communicationManager.findAgentsForTask(...)
 *    - Context sharing: communicationManager.shareContextWithAgent(...)
 *    - Usage tracking: communicationManager.getLLMUsageStatistics()
 * 
 * 5. Update error handling:
 *    - MCP provides unified error types (MCPError)
 *    - Automatic retry and failover handling
 * 
 * 6. Configure monitoring:
 *    - Set up MCPMonitoringDashboard
 *    - Configure alerts and metrics
 * 
 * 7. Test thoroughly:
 *    - Test provider failover scenarios
 *    - Verify context preservation
 *    - Check streaming functionality
 *    - Validate security controls
 */

// Run the demonstration
if (require.main === module) {
  demonstrateMigration().catch(console.error);
}

export { LegacyDelegationProcessor, MCPDelegationProcessor, demonstrateMigration };