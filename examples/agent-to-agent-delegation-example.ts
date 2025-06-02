/**
 * Basic Agent-to-Agent Delegation Example
 * 
 * This example demonstrates the core functionality of agent-to-agent delegation:
 * 1. Creating a user identity
 * 2. Creating a primary agent under the user
 * 3. Using the primary agent to create sub-agents with limited scopes
 * 4. Validating delegation chains
 * 5. Service provider verification of delegated credentials
 */

import { AgentIdentityManager } from '../src/agent/agent-identity';
import { DelegationManager } from '../src/agent/delegation-manager';
import { DelegationChainValidator } from '../src/agent/delegation-chain-validator';
import { DelegationPolicyEngine } from '../src/agent/delegation-policy-engine';
import { ServiceProviderAgent } from '../src/sp/service-provider-agent';
import { generateKeyPair } from '../src/core/crypto';
import { DIDService } from '../src/core/did';

async function basicAgentToAgentDelegationExample() {
  console.log('🚀 Basic Agent-to-Agent Delegation Example\n');

  // Initialize core components
  const agentManager = new AgentIdentityManager();
  const delegationManager = new DelegationManager();
  const chainValidator = new DelegationChainValidator(delegationManager, agentManager);
  const policyEngine = new DelegationPolicyEngine(agentManager);
  const serviceProvider = new ServiceProviderAgent(['example-service'], chainValidator);

  try {
    // 1. Create a user identity
    console.log('1️⃣  Creating user identity...');
    const userKeyPair = await generateKeyPair();
    const userDID = DIDService.createDIDKey(userKeyPair.publicKey).id;
    console.log(`✅ User DID: ${userDID}\n`);

    // 2. Create a primary agent for the user
    console.log('2️⃣  Creating primary agent...');
    const primaryAgent = await agentManager.createAgent(userDID, {
      name: 'Primary Assistant Agent',
      description: 'Main agent for handling user tasks',
      canDelegate: true,
      maxDelegationDepth: 3
    });
    console.log(`✅ Primary agent created: ${primaryAgent.name}`);
    console.log(`   DID: ${primaryAgent.did}`);
    console.log(`   Can delegate: ${primaryAgent.canDelegate}`);
    console.log(`   Max delegation depth: ${primaryAgent.maxDelegationDepth}\n`);

    // 3. Grant some scopes to the primary agent
    console.log('3️⃣  Granting scopes to primary agent...');
    const primaryScopes = ['read:profile', 'read:contacts', 'write:calendar', 'read:documents'];
    
    // Create delegation credential for primary agent
    const primaryCredential = await delegationManager.createDelegationCredential(
      userDID,
      userKeyPair,
      primaryAgent.did,
      primaryAgent.name,
      {
        serviceDID: 'example-service',
        scopes: primaryScopes,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
      }
    );
    
    agentManager.addDelegationCredential(primaryAgent.did, primaryCredential);
    console.log(`✅ Granted scopes: ${primaryScopes.join(', ')}\n`);

    // 4. Primary agent creates a specialized sub-agent
    console.log('4️⃣  Primary agent creating calendar sub-agent...');
    const calendarAgent = await agentManager.createSubAgent(primaryAgent.did, {
      name: 'Calendar Management Agent',
      description: 'Specialized agent for calendar operations',
      parentAgentDID: primaryAgent.did,
      requestedScopes: ['read:calendar', 'write:calendar']
    });
    
    console.log(`✅ Calendar agent created: ${calendarAgent.name}`);
    console.log(`   DID: ${calendarAgent.did}`);
    console.log(`   Parent: ${calendarAgent.parentDID}`);
    console.log(`   Delegation depth: ${calendarAgent.delegationDepth}\n`);

    // 5. Create delegation credential for calendar agent
    console.log('5️⃣  Creating delegation credential for calendar agent...');
    const calendarCredential = await delegationManager.createDelegationCredential(
      primaryAgent.did,
      primaryAgent.keyPair,
      calendarAgent.did,
      calendarAgent.name,
      {
        serviceDID: 'example-service',
        scopes: ['write:calendar'], // Reduced scopes
        expiresAt: new Date(Date.now() + 12 * 60 * 60 * 1000) // 12 hours
      }
    );
    
    agentManager.addDelegationCredential(calendarAgent.did, calendarCredential);
    console.log(`✅ Calendar agent granted scopes: write:calendar\n`);

    // 6. Calendar agent creates a read-only sub-agent
    console.log('6️⃣  Calendar agent creating read-only sub-agent...');
    const readOnlyAgent = await agentManager.createSubAgent(calendarAgent.did, {
      name: 'Calendar Reader Agent',
      description: 'Read-only access to calendar',
      parentAgentDID: calendarAgent.did,
      requestedScopes: ['read:calendar']
    });
    
    // Try to grant read access (should be reduced from parent's scopes)
    const readOnlyCredential = await delegationManager.createDelegationCredential(
      calendarAgent.did,
      calendarAgent.keyPair,
      readOnlyAgent.did,
      readOnlyAgent.name,
      {
        serviceDID: 'example-service',
        scopes: ['read:calendar'], // This should be reduced since parent only has write
        expiresAt: new Date(Date.now() + 6 * 60 * 60 * 1000) // 6 hours
      }
    );
    
    agentManager.addDelegationCredential(readOnlyAgent.did, readOnlyCredential);
    console.log(`✅ Read-only agent created: ${readOnlyAgent.name}`);
    console.log(`   Delegation depth: ${readOnlyAgent.delegationDepth}\n`);

    // 7. Validate delegation chains
    console.log('7️⃣  Validating delegation chains...\n');
    
    // Validate primary agent chain
    const primaryChainResult = await chainValidator.validateChain(primaryAgent.did, 'example-service');
    console.log(`Primary agent chain valid: ${primaryChainResult.valid}`);
    if (!primaryChainResult.valid) {
      console.log(`Errors: ${primaryChainResult.errors.join(', ')}`);
    }
    
    // Validate calendar agent chain
    const calendarChainResult = await chainValidator.validateChain(calendarAgent.did, 'example-service');
    console.log(`Calendar agent chain valid: ${calendarChainResult.valid}`);
    if (!calendarChainResult.valid) {
      console.log(`Errors: ${calendarChainResult.errors.join(', ')}`);
    }
    
    // Validate read-only agent chain
    const readOnlyChainResult = await chainValidator.validateChain(readOnlyAgent.did, 'example-service');
    console.log(`Read-only agent chain valid: ${readOnlyChainResult.valid}`);
    if (!readOnlyChainResult.valid) {
      console.log(`Errors: ${readOnlyChainResult.errors.join(', ')}`);
    }
    console.log();

    // 8. Service provider verification
    console.log('8️⃣  Service provider verification...\n');
    
    // Create presentations from each agent
    const presentations = [];
    
    // Primary agent presentation
    const primaryPresentation = await delegationManager.createPresentation(
      primaryAgent.did,
      primaryAgent.keyPair,
      'example-service',
      ['read:profile'],
      { challenge: 'service-challenge-123' }
    );
    presentations.push({ agent: 'Primary Agent', presentation: primaryPresentation });
    
    // Calendar agent presentation
    const calendarPresentation = await delegationManager.createPresentation(
      calendarAgent.did,
      calendarAgent.keyPair,
      'example-service',
      ['write:calendar'],
      { challenge: 'service-challenge-123' }
    );
    presentations.push({ agent: 'Calendar Agent', presentation: calendarPresentation });

    // Verify each presentation
    for (const { agent, presentation } of presentations) {
      try {
        const verification = await serviceProvider.verifyPresentation(presentation);
        console.log(`${agent} verification: ${verification.verified ? '✅ VALID' : '❌ INVALID'}`);
        if (verification.verified) {
          console.log(`  Granted scopes: ${verification.grantedScopes?.join(', ') || 'none'}`);
        } else {
          console.log(`  Errors: ${verification.error || 'Unknown error'}`);
        }
      } catch (error) {
        console.log(`${agent} verification: ❌ ERROR - ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    console.log();

    // 9. Display delegation hierarchy
    console.log('9️⃣  Delegation Hierarchy:\n');
    console.log(`👤 User (${userDID.substring(0, 20)}...)`);
    console.log(`├── 🤖 ${primaryAgent.name} (depth: ${primaryAgent.delegationDepth})`);
    console.log(`    ├── 📅 ${calendarAgent.name} (depth: ${calendarAgent.delegationDepth})`);
    console.log(`        └── 👁️ ${readOnlyAgent.name} (depth: ${readOnlyAgent.delegationDepth})`);
    console.log();

    // 10. Scope reduction demonstration
    console.log('🔟 Scope Reduction Analysis:\n');
    const allAgents = [primaryAgent, calendarAgent, readOnlyAgent];
    
    for (const agent of allAgents) {
      const credentials = agentManager.getDelegationCredentials(agent.did);
      const scopes = credentials.flatMap(cred => cred.credentialSubject.scopes);
      console.log(`${agent.name}:`);
      console.log(`  Available scopes: ${scopes.join(', ') || 'none'}`);
      console.log(`  Delegation depth: ${agent.delegationDepth}/${agent.maxDelegationDepth}`);
      console.log(`  Can delegate: ${agent.canDelegate}`);
      console.log();
    }

    console.log('✅ Basic agent-to-agent delegation example completed successfully!');
    
  } catch (error) {
    console.error('❌ Example failed:', error);
    throw error;
  }
}

// Run the example
if (require.main === module) {
  basicAgentToAgentDelegationExample()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('Example failed:', error);
      process.exit(1);
    });
}

export { basicAgentToAgentDelegationExample };