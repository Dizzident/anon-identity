/**
 * MCP-Enhanced Agent Example
 * 
 * This example demonstrates agent functionality enhanced with MCP (Model Context Protocol):
 * - Natural language delegation requests
 * - LLM-assisted policy evaluation
 * - Intelligent agent matching
 * - Real-time decision making
 * - Enhanced security monitoring
 */

import { 
  UserWallet, 
  IdentityProvider, 
  AgentEnabledServiceProvider,
  ServiceManifestBuilder,
  ScopeRegistry
} from '../src';

// MCP imports
import { 
  MCPClient,
  MCPEnabledCommunicationManager,
  AuthManager,
  RateLimiterManager,
  CredentialManager,
  MCPMonitoringDashboard,
  MCPSecurityIntegration
} from '../src/mcp';

import { RequestPriority } from '../src/mcp/types';

async function mcpEnhancedAgentDemo() {
  console.log('=== MCP-Enhanced Agent Delegation Example ===\n');

  // 1. Initialize MCP Infrastructure
  console.log('1. Initializing MCP infrastructure...');
  
  const mcpConfig = {
    serverUrl: process.env.MCP_SERVER_URL || 'ws://localhost:8080',
    apiKey: process.env.MCP_API_KEY || 'demo-mcp-key',
    providers: {
      openai: {
        apiKey: process.env.OPENAI_API_KEY || 'demo-openai-key',
        models: ['gpt-4', 'gpt-3.5-turbo']
      },
      anthropic: {
        apiKey: process.env.ANTHROPIC_API_KEY || 'demo-anthropic-key',
        models: ['claude-3-sonnet', 'claude-3-haiku']
      }
    }
  };

  const mcpClient = new MCPClient(mcpConfig);
  const authManager = new AuthManager();
  const rateLimiter = new RateLimiterManager(authManager);
  const credentialManager = new CredentialManager();

  console.log('✅ MCP infrastructure initialized\n');

  // 2. Create traditional identity components
  console.log('2. Creating user wallet and identity provider...');
  const userWallet = await UserWallet.create();
  const userDID = userWallet.getDID();
  
  const idp = await IdentityProvider.create('MCP-Enhanced IDP');
  const userCredential = await idp.issueCredential(userDID, {
    name: 'Alice Cooper',
    email: 'alice.cooper@example.com',
    dateOfBirth: '1985-07-15',
    role: 'Senior Developer',
    clearanceLevel: 'High'
  }, 'PersonalInfo');
  
  await userWallet.storeCredential(userCredential);
  console.log(`User DID: ${userDID}`);
  console.log('✅ User credential issued and stored\n');

  // 3. Create MCP-Enhanced Communication Manager
  console.log('3. Creating MCP-enhanced communication manager...');
  
  const agentManager = userWallet.getAgentManager();
  const delegationManager = userWallet.getDelegationManager();
  const policyEngine = userWallet.getPolicyEngine();
  const activityLogger = userWallet.getActivityLogger();

  const mcpCommunicationManager = new MCPEnabledCommunicationManager(
    userWallet.getAgentIdentity(),
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
        maxTokensPerContext: 8000,
        compressionStrategy: 'importance',
        shareContextBetweenAgents: true
      }
    },
    authManager,
    rateLimiter,
    credentialManager
  );

  console.log('✅ MCP-enhanced communication manager created\n');

  // 4. Set up monitoring and security
  console.log('4. Setting up monitoring and security...');
  
  const dashboard = new MCPMonitoringDashboard(
    mcpCommunicationManager.getMessageRouter(),
    mcpCommunicationManager.getProviderSelector(),
    mcpCommunicationManager.getContextManager(),
    mcpCommunicationManager.getStreamManager(),
    mcpCommunicationManager.getAgentMatcher(),
    activityLogger,
    rateLimiter
  );

  const security = new MCPSecurityIntegration(
    mcpCommunicationManager.getMessageRouter(),
    authManager,
    activityLogger,
    rateLimiter,
    credentialManager
  );

  // Monitor security events
  security.on('threat_detected', (threat) => {
    console.log(`🔒 Security threat detected: ${threat.type} (${threat.severity})`);
    console.log(`   Description: ${threat.description}`);
  });

  console.log('✅ Monitoring and security configured\n');

  // 5. Create multiple agents with different capabilities
  console.log('5. Creating specialized agents...');
  
  const agents = [];
  
  // Email assistant agent
  const emailAgent = await userWallet.createAgent({
    name: 'Email Assistant',
    description: 'AI agent specialized in email management and communication',
    capabilities: ['email:read', 'email:send', 'email:organize', 'calendar:read']
  });
  agents.push(emailAgent);

  // Financial assistant agent
  const financeAgent = await userWallet.createAgent({
    name: 'Financial Assistant', 
    description: 'AI agent for financial management and transactions',
    capabilities: ['finance:read', 'finance:transfer', 'finance:analyze', 'budget:manage']
  });
  agents.push(financeAgent);

  // Development assistant agent
  const devAgent = await userWallet.createAgent({
    name: 'Development Assistant',
    description: 'AI agent for software development and code review',
    capabilities: ['code:read', 'code:write', 'repo:manage', 'deploy:execute']
  });
  agents.push(devAgent);

  agents.forEach(agent => {
    console.log(`   Agent: ${agent.name} (${agent.did})`);
  });
  console.log();

  // 6. Natural Language Delegation Requests
  console.log('6. Processing natural language delegation requests...\n');

  const naturalLanguageRequests = [
    "I need an agent to help me manage my emails and schedule meetings for the next month",
    "Create a financial agent that can analyze my spending patterns and make budget recommendations",
    "Set up a development assistant that can review code and deploy to staging environments",
    "I want an agent with temporary access to my calendar but not my private messages"
  ];

  for (const [index, request] of naturalLanguageRequests.entries()) {
    console.log(`--- Request ${index + 1}: "${request}" ---`);
    
    try {
      // Process natural language request with streaming
      console.log('🤖 Processing with LLM...');
      
      const response = await mcpCommunicationManager.processNaturalLanguageMessage(
        request,
        undefined,
        {
          streaming: true,
          priority: RequestPriority.HIGH,
          onChunk: (chunk) => {
            process.stdout.write(chunk);
          }
        }
      );

      console.log('\n✅ LLM Analysis Complete');
      console.log(`   Confidence: ${response.metadata?.confidence || 'N/A'}`);
      console.log(`   Recommended Actions: ${response.metadata?.actions?.length || 0}`);
      
      // Find suitable agents for the task
      console.log('\n🔍 Finding suitable agents...');
      
      const agentMatches = await mcpCommunicationManager.findAgentsForTask(
        request,
        response.metadata?.requiredCapabilities || [],
        {
          maxResults: 3,
          minimumScore: 0.7,
          includeCreateNewOption: true
        }
      );

      console.log(`Found ${agentMatches.length} suitable agent(s):`);
      agentMatches.forEach(match => {
        console.log(`   - ${match.agent.name}: ${(match.score * 100).toFixed(1)}% match`);
        console.log(`     Capabilities: ${match.matchingCapabilities.join(', ')}`);
        console.log(`     Reasoning: ${match.reasoning}`);
      });

      // Evaluate delegation with LLM assistance
      if (agentMatches.length > 0) {
        const bestMatch = agentMatches[0];
        console.log(`\n📋 Evaluating delegation to ${bestMatch.agent.name}...`);
        
        const evaluation = await mcpCommunicationManager.evaluateDelegationWithLLM(
          userDID,
          bestMatch.agent.did,
          response.metadata?.requiredScopes || ['basic:access'],
          request,
          24 * 60 * 60 * 1000 // 24 hours
        );

        console.log(`   Decision: ${evaluation.decision.toUpperCase()}`);
        console.log(`   Confidence: ${(evaluation.confidence * 100).toFixed(1)}%`);
        console.log(`   Risk Level: ${evaluation.riskLevel.toUpperCase()}`);
        console.log(`   Reasoning: ${evaluation.reasoning}`);
        
        if (evaluation.warnings.length > 0) {
          console.log('   Warnings:');
          evaluation.warnings.forEach(warning => {
            console.log(`     ⚠️ ${warning}`);
          });
        }

        if (evaluation.suggestedScopes && evaluation.suggestedScopes.length > 0) {
          console.log(`   Suggested Scopes: ${evaluation.suggestedScopes.join(', ')}`);
        }
      }

    } catch (error) {
      console.error(`❌ Error processing request: ${error.message}`);
    }
    
    console.log();
  }

  // 7. Real-time Context Sharing Between Agents
  console.log('7. Demonstrating context sharing between agents...\n');

  try {
    // Simulate a complex task requiring multiple agents
    console.log('📧 Email agent processing: "Schedule a team meeting and send financial report"');
    
    // Email agent shares context with financial agent
    await mcpCommunicationManager.shareContextWithAgent(
      financeAgent.did,
      {
        contextType: 'task_delegation',
        summary: 'Email agent needs financial report for team meeting',
        sharedData: {
          meeting: { topic: 'Q4 Budget Review', attendees: ['team@company.com'] },
          reportType: 'quarterly_summary'
        },
        permissions: ['read:context', 'contribute:context']
      }
    );

    console.log('✅ Context shared between Email Assistant and Financial Assistant');
    console.log('   Both agents now have coordinated understanding of the task');

  } catch (error) {
    console.error(`❌ Error in context sharing: ${error.message}`);
  }

  // 8. Monitor LLM Usage and Performance
  console.log('\n8. LLM Usage Statistics and Performance...\n');

  try {
    const metrics = dashboard.getMetrics();
    console.log('📊 Current MCP Metrics:');
    console.log(`   Total Requests: ${metrics.totalRequests}`);
    console.log(`   Total Tokens: ${metrics.totalTokens}`);
    console.log(`   Average Latency: ${metrics.averageLatency.toFixed(2)}ms`);
    console.log(`   Error Rate: ${(metrics.errorRate * 100).toFixed(2)}%`);
    console.log(`   Active Contexts: ${metrics.activeContexts}`);
    console.log(`   Total Cost: $${metrics.totalCost.toFixed(4)}`);

    console.log('\n📈 Provider Performance:');
    metrics.providerHealth.forEach(health => {
      console.log(`   ${health.providerId}: ${health.status.toUpperCase()}`);
      console.log(`     Response Time: ${health.responseTime.toFixed(2)}ms`);
      console.log(`     Uptime: ${(health.uptime * 100).toFixed(1)}%`);
      console.log(`     Error Rate: ${(health.errorRate * 100).toFixed(2)}%`);
    });

    const usageStats = await mcpCommunicationManager.getLLMUsageStatistics();
    console.log('\n💰 Cost Analysis:');
    console.log(`   Most Expensive Provider: ${usageStats.costByProvider[0]?.provider || 'N/A'}`);
    console.log(`   Average Cost per Request: $${usageStats.averageCostPerRequest.toFixed(6)}`);
    console.log(`   Token Efficiency: ${usageStats.tokenEfficiency.toFixed(2)} tokens/request`);

  } catch (error) {
    console.error(`❌ Error retrieving metrics: ${error.message}`);
  }

  // 9. Security Monitoring Results
  console.log('\n9. Security Monitoring Summary...\n');

  try {
    const securityStats = security.getStatistics();
    console.log('🔒 Security Analysis:');
    console.log(`   Total Threats Detected: ${securityStats.totalThreats}`);
    console.log(`   High Priority Threats: ${securityStats.highPriorityThreats}`);
    console.log(`   Automated Responses: ${securityStats.automatedResponses}`);
    console.log(`   Average Analysis Time: ${securityStats.averageAnalysisTime.toFixed(2)}ms`);

    const activeThreats = security.getActiveThreats();
    if (activeThreats.length > 0) {
      console.log('\n⚠️ Active Security Threats:');
      activeThreats.slice(0, 3).forEach(threat => {
        console.log(`   - ${threat.type}: ${threat.description}`);
        console.log(`     Severity: ${threat.severity}, Confidence: ${(threat.confidence * 100).toFixed(1)}%`);
      });
    } else {
      console.log('\n✅ No active security threats detected');
    }

  } catch (error) {
    console.error(`❌ Error retrieving security stats: ${error.message}`);
  }

  // 10. Advanced Agent Coordination
  console.log('\n10. Advanced agent coordination scenario...\n');

  try {
    // Simulate a complex multi-agent workflow
    console.log('🔗 Coordinating multi-agent workflow: "Prepare for investor meeting"');
    
    const workflowRequest = `
      I have an investor meeting next week. I need:
      1. Financial reports and projections
      2. Development progress summary  
      3. Email invitations to stakeholders
      4. Calendar scheduling for all participants
    `;

    console.log('Processing complex workflow request...');
    
    const workflowResponse = await mcpCommunicationManager.processNaturalLanguageMessage(
      workflowRequest,
      undefined,
      {
        streaming: false,
        priority: RequestPriority.HIGH
      }
    );

    console.log('✅ Workflow Analysis Complete');
    console.log(`   Identified ${workflowResponse.metadata?.taskCount || 0} subtasks`);
    console.log(`   Requires ${workflowResponse.metadata?.agentTypes?.length || 0} different agent types`);
    console.log(`   Estimated completion time: ${workflowResponse.metadata?.estimatedDuration || 'N/A'}`);

    // Demonstrate task distribution among agents
    const taskAssignments = [
      { agent: financeAgent, task: 'Generate financial reports and projections' },
      { agent: devAgent, task: 'Compile development progress summary' },
      { agent: emailAgent, task: 'Send invitations and schedule meetings' }
    ];

    console.log('\n📋 Task Assignments:');
    for (const assignment of taskAssignments) {
      console.log(`   ${assignment.agent.name}: ${assignment.task}`);
      
      // Evaluate each task assignment
      const taskEvaluation = await mcpCommunicationManager.evaluateDelegationWithLLM(
        userDID,
        assignment.agent.did,
        ['task:execute', 'data:read', 'external:api'],
        assignment.task,
        7 * 24 * 60 * 60 * 1000 // 1 week
      );

      console.log(`     Status: ${taskEvaluation.decision.toUpperCase()}`);
      console.log(`     Risk: ${taskEvaluation.riskLevel.toUpperCase()}`);
    }

  } catch (error) {
    console.error(`❌ Error in workflow coordination: ${error.message}`);
  }

  // 11. Export Analytics and Reports
  console.log('\n11. Exporting analytics and reports...\n');

  try {
    // Export dashboard metrics
    const metricsReport = dashboard.exportMetrics('json');
    console.log('📊 Dashboard metrics exported (JSON format)');
    
    // Export security report
    const securityReport = security.exportThreatReport('json');
    console.log('🔒 Security threat report exported');

    // Log analysis summary
    console.log('\n📋 Session Summary:');
    console.log(`   Natural Language Requests Processed: ${naturalLanguageRequests.length}`);
    console.log(`   Agents Created: ${agents.length}`);
    console.log(`   LLM Evaluations Performed: ${naturalLanguageRequests.length * 2}`); // Request + evaluation
    console.log(`   Context Sharing Operations: 1`);
    console.log(`   Security Scans: ${naturalLanguageRequests.length}`);

  } catch (error) {
    console.error(`❌ Error exporting reports: ${error.message}`);
  }

  // 12. Cleanup
  console.log('\n12. Cleaning up resources...\n');

  try {
    await mcpCommunicationManager.cleanup();
    dashboard.shutdown();
    security.shutdown();
    console.log('✅ MCP resources cleaned up successfully');

  } catch (error) {
    console.error(`❌ Error during cleanup: ${error.message}`);
  }

  console.log('\n=== MCP-Enhanced Agent Delegation Demo Complete ===');
  console.log('\nKey Benefits Demonstrated:');
  console.log('• Natural language processing for delegation requests');
  console.log('• Intelligent agent matching and capability assessment');
  console.log('• LLM-assisted policy evaluation and risk assessment');
  console.log('• Real-time context sharing between agents');
  console.log('• Comprehensive security monitoring and threat detection');
  console.log('• Cost optimization and performance analytics');
  console.log('• Multi-provider failover and load balancing');
  console.log('• Advanced multi-agent workflow coordination');
}

// Run the demo
if (require.main === module) {
  mcpEnhancedAgentDemo().catch(error => {
    console.error('Demo failed:', error);
    process.exit(1);
  });
}

export { mcpEnhancedAgentDemo };