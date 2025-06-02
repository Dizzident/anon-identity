/**
 * Multi-Level Delegation Chains Example
 * 
 * This example demonstrates complex delegation scenarios with multiple levels:
 * 1. Creating a corporate hierarchy with multiple delegation levels
 * 2. Policy-based delegation with different strategies
 * 3. Cross-department delegation chains
 * 4. Delegation chain visualization and analysis
 * 5. Depth limit enforcement and validation
 */

import { AgentIdentityManager } from '../src/agent/agent-identity';
import { DelegationManager } from '../src/agent/delegation-manager';
import { DelegationChainValidator } from '../src/agent/delegation-chain-validator';
import { DelegationPolicyEngine } from '../src/agent/delegation-policy-engine';
import { DelegationChainVisualizer } from '../src/agent/delegation-chain-visualizer';
import { ScopeReductionStrategies } from '../src/agent/scope-reduction-strategies';
import { generateKeyPair } from '../src/core/crypto';
import { DIDService } from '../src/core/did';

async function multiLevelDelegationExample() {
  console.log('🏢 Multi-Level Delegation Chains Example\n');

  // Initialize components
  const agentManager = new AgentIdentityManager();
  const delegationManager = new DelegationManager();
  const chainValidator = new DelegationChainValidator(delegationManager, agentManager);
  const policyEngine = new DelegationPolicyEngine(agentManager);
  const visualizer = new DelegationChainVisualizer(agentManager);

  try {
    // 1. Create corporate structure
    console.log('1️⃣  Setting up corporate structure...\n');

    // CEO identity
    const ceoKeyPair = await generateKeyPair();
    const ceoDID = DIDService.createDIDKey(ceoKeyPair.publicKey).id;
    console.log(`👑 CEO DID: ${ceoDID.substring(0, 30)}...`);

    // 2. Create department heads (Level 1)
    console.log('\n2️⃣  Creating department heads...\n');
    
    const departments = ['engineering', 'marketing', 'finance', 'operations'];
    const departmentHeads = new Map();
    const departmentScopes = {
      engineering: ['read:code', 'write:code', 'deploy:staging', 'read:docs', 'write:docs'],
      marketing: ['read:campaigns', 'write:campaigns', 'read:analytics', 'read:customers'],
      finance: ['read:budget', 'write:budget', 'read:reports', 'generate:reports'],
      operations: ['read:infrastructure', 'write:infrastructure', 'read:monitoring', 'manage:deployments']
    };

    for (const dept of departments) {
      const head = await agentManager.createAgent(ceoDID, {
        name: `${dept.charAt(0).toUpperCase() + dept.slice(1)} Head`,
        description: `Head of ${dept} department`,
        canDelegate: true,
        maxDelegationDepth: 4
      });

      // Grant department-specific scopes
      const credential = await delegationManager.createDelegationCredential(
        ceoDID,
        ceoKeyPair,
        head.did,
        head.name,
        {
          serviceDID: `${dept}-service`,
          scopes: departmentScopes[dept as keyof typeof departmentScopes],
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
        }
      );

      agentManager.addDelegationCredential(head.did, credential);
      departmentHeads.set(dept, head);
      
      console.log(`👔 ${head.name}: ${head.did.substring(0, 20)}...`);
      console.log(`   Scopes: ${departmentScopes[dept as keyof typeof departmentScopes].join(', ')}`);
    }

    // 3. Create team leads (Level 2)
    console.log('\n3️⃣  Creating team leads...\n');
    
    const teamLeads = new Map();
    const engineeringHead = departmentHeads.get('engineering');

    // Frontend team lead
    const frontendLead = await agentManager.createSubAgent(engineeringHead.did, {
      name: 'Frontend Team Lead',
      description: 'Lead for frontend development team',
      parentAgentDID: engineeringHead.did,
      requestedScopes: ['read:code', 'write:code', 'read:docs']
    });

    const frontendCredential = await delegationManager.createDelegationCredential(
      engineeringHead.did,
      engineeringHead.keyPair,
      frontendLead.did,
      frontendLead.name,
      {
        serviceDID: 'engineering-service',
        scopes: ['read:code', 'write:code'],
        expiresAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14 days
      }
    );

    agentManager.addDelegationCredential(frontendLead.did, frontendCredential);
    teamLeads.set('frontend', frontendLead);

    // Backend team lead
    const backendLead = await agentManager.createSubAgent(engineeringHead.did, {
      name: 'Backend Team Lead',
      description: 'Lead for backend development team',
      parentAgentDID: engineeringHead.did,
      requestedScopes: ['read:code', 'write:code', 'deploy:staging']
    });

    const backendCredential = await delegationManager.createDelegationCredential(
      engineeringHead.did,
      engineeringHead.keyPair,
      backendLead.did,
      backendLead.name,
      {
        serviceDID: 'engineering-service',
        scopes: ['read:code', 'write:code', 'deploy:staging'],
        expiresAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14 days
      }
    );

    agentManager.addDelegationCredential(backendLead.did, backendCredential);
    teamLeads.set('backend', backendLead);

    console.log(`💻 ${frontendLead.name}: depth ${frontendLead.delegationDepth}`);
    console.log(`🔧 ${backendLead.name}: depth ${backendLead.delegationDepth}`);

    // 4. Create developers (Level 3)
    console.log('\n4️⃣  Creating senior developers...\n');
    
    const developers = new Map();

    // Senior frontend developer
    const frontendDev = await agentManager.createSubAgent(frontendLead.did, {
      name: 'Senior Frontend Developer',
      description: 'Senior developer for frontend team',
      parentAgentDID: frontendLead.did,
      requestedScopes: ['read:code', 'write:code']
    });

    const frontendDevCredential = await delegationManager.createDelegationCredential(
      frontendLead.did,
      frontendLead.keyPair,
      frontendDev.did,
      frontendDev.name,
      {
        serviceDID: 'engineering-service',
        scopes: ['read:code', 'write:code'],
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      }
    );

    agentManager.addDelegationCredential(frontendDev.did, frontendDevCredential);
    developers.set('frontend-senior', frontendDev);

    // DevOps specialist under backend lead
    const devopsSpecialist = await agentManager.createSubAgent(backendLead.did, {
      name: 'DevOps Specialist',
      description: 'DevOps specialist with deployment access',
      parentAgentDID: backendLead.did,
      requestedScopes: ['deploy:staging', 'read:code']
    });

    const devopsCredential = await delegationManager.createDelegationCredential(
      backendLead.did,
      backendLead.keyPair,
      devopsSpecialist.did,
      devopsSpecialist.name,
      {
        serviceDID: 'engineering-service',
        scopes: ['deploy:staging'],
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      }
    );

    agentManager.addDelegationCredential(devopsSpecialist.did, devopsCredential);
    developers.set('devops', devopsSpecialist);

    console.log(`🎨 ${frontendDev.name}: depth ${frontendDev.delegationDepth}`);
    console.log(`🚀 ${devopsSpecialist.name}: depth ${devopsSpecialist.delegationDepth}`);

    // 5. Create contractors (Level 4 - maximum depth)
    console.log('\n5️⃣  Creating contractors at maximum depth...\n');

    const contractor = await agentManager.createSubAgent(frontendDev.did, {
      name: 'UI/UX Contractor',
      description: 'Temporary contractor for UI work',
      parentAgentDID: frontendDev.did,
      requestedScopes: ['read:code']
    });

    const contractorCredential = await delegationManager.createDelegationCredential(
      frontendDev.did,
      frontendDev.keyPair,
      contractor.did,
      contractor.name,
      {
        serviceDID: 'engineering-service',
        scopes: ['read:code'],
        expiresAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000) // 2 days
      }
    );

    agentManager.addDelegationCredential(contractor.did, contractorCredential);
    console.log(`🎯 ${contractor.name}: depth ${contractor.delegationDepth}`);

    // 6. Test depth limit enforcement
    console.log('\n6️⃣  Testing depth limit enforcement...\n');

    try {
      await agentManager.createSubAgent(contractor.did, {
        name: 'Intern Agent',
        description: 'This should fail due to depth limit',
        parentAgentDID: contractor.did,
        requestedScopes: ['read:code']
      });
      console.log('❌ Depth limit enforcement failed!');
    } catch (error) {
      console.log('✅ Depth limit properly enforced');
      console.log(`   Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    // 7. Validate all delegation chains
    console.log('\n7️⃣  Validating delegation chains...\n');

    const agentsToValidate = [
      { name: 'Engineering Head', agent: engineeringHead },
      { name: 'Frontend Lead', agent: frontendLead },
      { name: 'Backend Lead', agent: backendLead },
      { name: 'Frontend Developer', agent: frontendDev },
      { name: 'DevOps Specialist', agent: devopsSpecialist },
      { name: 'Contractor', agent: contractor }
    ];

    for (const { name, agent } of agentsToValidate) {
      const result = await chainValidator.validateChain(agent.did, 'engineering-service');
      console.log(`${name}: ${result.valid ? '✅ VALID' : '❌ INVALID'}`);
      if (!result.valid) {
        console.log(`  Errors: ${result.errors.join(', ')}`);
      }
      if (result.warnings.length > 0) {
        console.log(`  Warnings: ${result.warnings.join(', ')}`);
      }
    }

    // 8. Cross-department delegation
    console.log('\n8️⃣  Testing cross-department delegation...\n');

    const marketingHead = departmentHeads.get('marketing');
    
    // Marketing head requests engineering access for a joint project
    try {
      const crossDeptAgent = await agentManager.createSubAgent(marketingHead.did, {
        name: 'Marketing-Engineering Liaison',
        description: 'Joint project coordination agent',
        parentAgentDID: marketingHead.did,
        requestedScopes: ['read:docs'] // Marketing head doesn't have engineering scopes
      });

      // This should work if we had given marketing head some engineering scopes
      console.log('⚠️  Cross-department delegation created (limited scopes)');
      console.log(`   Agent: ${crossDeptAgent.name}`);
      
    } catch (error) {
      console.log('❌ Cross-department delegation failed (as expected)');
      console.log(`   Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    // 9. Visualization of delegation chains
    console.log('\n9️⃣  Delegation Chain Visualization:\n');

    // ASCII tree visualization
    const engineeringTree = visualizer.generateTree(engineeringHead.did);
    console.log('Engineering Department Delegation Tree:');
    console.log(engineeringTree);

    // Detailed chain analysis
    console.log('\n📊 Chain Analysis:');
    const chainAnalysis = visualizer.analyzeChain(contractor.did);
    console.log(`Chain length: ${chainAnalysis.chainLength}`);
    console.log(`Scope reduction: ${chainAnalysis.scopeReduction.join(' → ')}`);
    console.log(`Total agents in chain: ${chainAnalysis.totalAgents}`);
    console.log(`Root agent: ${chainAnalysis.rootAgent.substring(0, 20)}...`);

    // 10. Policy evaluation demonstration
    console.log('\n🔟 Policy Evaluation Examples:\n');

    // Test different policies
    const policies = [
      { name: 'Default Policy', policy: policyEngine.getBuiltInPolicy('default') },
      { name: 'High Security Policy', policy: policyEngine.getBuiltInPolicy('high-security') },
      { name: 'Development Policy', policy: policyEngine.getBuiltInPolicy('development') }
    ];

    for (const { name, policy } of policies) {
      const evaluation = await policyEngine.evaluatePolicy({
        parentAgent: frontendLead,
        requestedScopes: ['read:code', 'write:code', 'deploy:production'],
        serviceDID: 'engineering-service'
      }, policy);

      console.log(`${name}:`);
      console.log(`  Allowed: ${evaluation.allowed}`);
      console.log(`  Violations: ${evaluation.violations.join(', ') || 'none'}`);
      console.log(`  Applied constraints: ${evaluation.appliedConstraints?.join(', ') || 'none'}`);
      console.log();
    }

    // 11. Scope reduction strategies demonstration
    console.log('1️⃣1️⃣ Scope Reduction Strategies:\n');

    const parentScopes = ['read:code', 'write:code', 'deploy:staging', 'deploy:production'];
    const requestedScopes = ['read:code', 'write:code', 'deploy:production'];

    const strategies = ['intersection', 'subset', 'hierarchical', 'risk-based'];
    const scopeReducer = new ScopeReductionStrategies();

    for (const strategy of strategies) {
      const reduced = scopeReducer.reduceScopes(
        parentScopes,
        requestedScopes,
        strategy as any
      );
      console.log(`${strategy}: ${reduced.join(', ')}`);
    }

    // 12. Summary statistics
    console.log('\n📈 Summary Statistics:\n');
    
    const allAgents = agentManager.getAllAgents();
    const engineeringAgents = allAgents.filter(agent => 
      agent.parentDID === ceoDID || 
      agentManager.getDelegationCredentials(agent.did).some(cred => 
        cred.credentialSubject.serviceDID === 'engineering-service'
      )
    );

    console.log(`Total agents created: ${allAgents.length}`);
    console.log(`Engineering department agents: ${engineeringAgents.length}`);
    console.log(`Maximum delegation depth reached: ${Math.max(...allAgents.map(a => a.delegationDepth))}`);
    console.log(`Agents with delegation capability: ${allAgents.filter(a => a.canDelegate).length}`);

    // Depth distribution
    const depthDistribution = new Map();
    allAgents.forEach(agent => {
      const depth = agent.delegationDepth;
      depthDistribution.set(depth, (depthDistribution.get(depth) || 0) + 1);
    });

    console.log('\nDelegation depth distribution:');
    for (const [depth, count] of depthDistribution.entries()) {
      console.log(`  Depth ${depth}: ${count} agents`);
    }

    console.log('\n✅ Multi-level delegation chains example completed successfully!');

  } catch (error) {
    console.error('❌ Example failed:', error);
    throw error;
  }
}

// Run the example
if (require.main === module) {
  multiLevelDelegationExample()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('Example failed:', error);
      process.exit(1);
    });
}

export { multiLevelDelegationExample };