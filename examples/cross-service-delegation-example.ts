/**
 * Cross-Service Delegation Example
 * 
 * This example demonstrates delegation across multiple services:
 * 1. Creating agents with access to multiple services
 * 2. Service-specific scope isolation
 * 3. Cross-service delegation patterns
 * 4. Service provider integration with multi-service agents
 * 5. Partial revocation of service access
 */

import { AgentIdentityManager } from '../src/agent/agent-identity';
import { DelegationManager } from '../src/agent/delegation-manager';
import { DelegationChainValidator } from '../src/agent/delegation-chain-validator';
import { ServiceProviderAgent } from '../src/sp/service-provider-agent';
import { CascadingRevocationManager } from '../src/agent/revocation/cascading-revocation-manager';
import { ActivityLogger } from '../src/agent/activity/activity-logger';
import { CommunicationManager } from '../src/agent/communication/communication-manager';
import { generateKeyPair } from '../src/core/crypto';
import { DIDService } from '../src/core/did';

interface ServiceDefinition {
  id: string;
  name: string;
  scopes: string[];
  description: string;
}

async function crossServiceDelegationExample() {
  console.log('🌐 Cross-Service Delegation Example\n');

  // Initialize components
  const agentManager = new AgentIdentityManager();
  const delegationManager = new DelegationManager();
  const chainValidator = new DelegationChainValidator(delegationManager, agentManager);
  const activityLogger = new ActivityLogger();
  
  // Mock communication manager for revocation
  const mockCommManager = {
    sendMessage: async () => {}
  } as any;
  
  const revocationManager = new CascadingRevocationManager(
    agentManager,
    chainValidator,
    mockCommManager,
    activityLogger
  );

  // Define multiple services
  const services: ServiceDefinition[] = [
    {
      id: 'email-service',
      name: 'Email Management Service',
      scopes: ['read:emails', 'write:emails', 'delete:emails', 'manage:folders'],
      description: 'Corporate email system'
    },
    {
      id: 'calendar-service',
      name: 'Calendar Management Service',
      scopes: ['read:calendar', 'write:calendar', 'delete:events', 'manage:invites'],
      description: 'Corporate calendar system'
    },
    {
      id: 'file-service',
      name: 'File Storage Service',
      scopes: ['read:files', 'write:files', 'delete:files', 'share:files', 'admin:storage'],
      description: 'Corporate file storage'
    },
    {
      id: 'hr-service',
      name: 'Human Resources Service',
      scopes: ['read:employee-data', 'write:employee-data', 'read:payroll', 'manage:benefits'],
      description: 'HR management system'
    },
    {
      id: 'analytics-service',
      name: 'Business Analytics Service',
      scopes: ['read:metrics', 'generate:reports', 'view:dashboards', 'export:data'],
      description: 'Business intelligence platform'
    }
  ];

  try {
    // 1. Create user and service providers
    console.log('1️⃣  Setting up user and service providers...\n');

    const userKeyPair = await generateKeyPair();
    const userDID = DIDService.createDIDKey(userKeyPair.publicKey).id;
    console.log(`👤 User DID: ${userDID.substring(0, 30)}...`);

    // Create service providers
    const serviceProviders = new Map();
    for (const service of services) {
      const provider = new ServiceProviderAgent([service.id], chainValidator);
      serviceProviders.set(service.id, provider);
      console.log(`🏢 ${service.name} (${service.id})`);
    }

    // 2. Create an executive assistant with multi-service access
    console.log('\n2️⃣  Creating executive assistant with multi-service access...\n');

    const executiveAssistant = await agentManager.createAgent(userDID, {
      name: 'Executive Assistant Agent',
      description: 'Multi-service assistant for executive tasks',
      canDelegate: true,
      maxDelegationDepth: 3
    });

    // Grant access to multiple services
    const assistantServices = ['email-service', 'calendar-service', 'file-service'];
    const assistantCredentials = [];

    for (const serviceId of assistantServices) {
      const service = services.find(s => s.id === serviceId)!;
      const credential = await delegationManager.createDelegationCredential(
        userDID,
        userKeyPair,
        executiveAssistant.did,
        executiveAssistant.name,
        {
          serviceDID: serviceId,
          scopes: service.scopes.filter(scope => !scope.includes('delete') && !scope.includes('admin')),
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
        }
      );
      
      agentManager.addDelegationCredential(executiveAssistant.did, credential);
      assistantCredentials.push({ serviceId, credential });
    }

    console.log(`🤖 ${executiveAssistant.name} created with access to:`);
    for (const { serviceId } of assistantCredentials) {
      const service = services.find(s => s.id === serviceId)!;
      const creds = agentManager.getDelegationCredentials(executiveAssistant.did)
        .filter(c => c.credentialSubject.serviceDID === serviceId);
      const scopes = creds.flatMap(c => c.credentialSubject.scopes);
      console.log(`   📧 ${service.name}: ${scopes.join(', ')}`);
    }

    // 3. Create specialized sub-agents for specific services
    console.log('\n3️⃣  Creating specialized sub-agents...\n');

    // Email specialist
    const emailSpecialist = await agentManager.createSubAgent(executiveAssistant.did, {
      name: 'Email Management Specialist',
      description: 'Specialized agent for email operations',
      parentAgentDID: executiveAssistant.did,
      requestedScopes: ['read:emails', 'write:emails', 'manage:folders']
    });

    const emailCredential = await delegationManager.createDelegationCredential(
      executiveAssistant.did,
      executiveAssistant.keyPair,
      emailSpecialist.did,
      emailSpecialist.name,
      {
        serviceDID: 'email-service',
        scopes: ['read:emails', 'write:emails'],
        expiresAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14 days
      }
    );

    agentManager.addDelegationCredential(emailSpecialist.did, emailCredential);

    // Calendar specialist
    const calendarSpecialist = await agentManager.createSubAgent(executiveAssistant.did, {
      name: 'Calendar Management Specialist',
      description: 'Specialized agent for calendar operations',
      parentAgentDID: executiveAssistant.did,
      requestedScopes: ['read:calendar', 'write:calendar', 'manage:invites']
    });

    const calendarCredential = await delegationManager.createDelegationCredential(
      executiveAssistant.did,
      executiveAssistant.keyPair,
      calendarSpecialist.did,
      calendarSpecialist.name,
      {
        serviceDID: 'calendar-service',
        scopes: ['read:calendar', 'write:calendar'],
        expiresAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14 days
      }
    );

    agentManager.addDelegationCredential(calendarSpecialist.did, calendarCredential);

    console.log(`📧 ${emailSpecialist.name}: email-service access`);
    console.log(`📅 ${calendarSpecialist.name}: calendar-service access`);

    // 4. Create a cross-service coordinator
    console.log('\n4️⃣  Creating cross-service coordinator...\n');

    const crossServiceCoordinator = await agentManager.createSubAgent(executiveAssistant.did, {
      name: 'Cross-Service Coordinator',
      description: 'Agent that coordinates across multiple services',
      parentAgentDID: executiveAssistant.did,
      requestedScopes: ['read:emails', 'read:calendar', 'read:files']
    });

    // Grant limited access to multiple services
    for (const serviceId of ['email-service', 'calendar-service', 'file-service']) {
      const readCredential = await delegationManager.createDelegationCredential(
        executiveAssistant.did,
        executiveAssistant.keyPair,
        crossServiceCoordinator.did,
        crossServiceCoordinator.name,
        {
          serviceDID: serviceId,
          scopes: [`read:${serviceId.split('-')[0]}`],
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
        }
      );

      agentManager.addDelegationCredential(crossServiceCoordinator.did, readCredential);
    }

    console.log(`🔄 ${crossServiceCoordinator.name}: multi-service read access`);

    // 5. Create temporary project agent
    console.log('\n5️⃣  Creating temporary project agent...\n');

    const projectAgent = await agentManager.createSubAgent(emailSpecialist.did, {
      name: 'Q1 Project Coordinator',
      description: 'Temporary agent for Q1 project coordination',
      parentAgentDID: emailSpecialist.did,
      requestedScopes: ['read:emails']
    });

    const projectCredential = await delegationManager.createDelegationCredential(
      emailSpecialist.did,
      emailSpecialist.keyPair,
      projectAgent.did,
      projectAgent.name,
      {
        serviceDID: 'email-service',
        scopes: ['read:emails'],
        expiresAt: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000) // 3 days
      }
    );

    agentManager.addDelegationCredential(projectAgent.did, projectCredential);
    console.log(`📊 ${projectAgent.name}: temporary email read access`);

    // 6. Test service provider verification across services
    console.log('\n6️⃣  Testing service provider verification...\n');

    const agentsToTest = [
      { name: 'Executive Assistant', agent: executiveAssistant, services: ['email-service', 'calendar-service', 'file-service'] },
      { name: 'Email Specialist', agent: emailSpecialist, services: ['email-service'] },
      { name: 'Calendar Specialist', agent: calendarSpecialist, services: ['calendar-service'] },
      { name: 'Cross-Service Coordinator', agent: crossServiceCoordinator, services: ['email-service', 'calendar-service', 'file-service'] },
      { name: 'Project Agent', agent: projectAgent, services: ['email-service'] }
    ];

    for (const { name, agent, services: agentServices } of agentsToTest) {
      console.log(`\n🔍 Testing ${name}:`);
      
      for (const serviceId of agentServices) {
        try {
          const provider = serviceProviders.get(serviceId);
          const credentials = agentManager.getDelegationCredentials(agent.did)
            .filter(c => c.credentialSubject.serviceDID === serviceId);
          
          if (credentials.length === 0) {
            console.log(`   ${serviceId}: ❌ No credentials`);
            continue;
          }

          const scopes = credentials.flatMap(c => c.credentialSubject.scopes);
          const presentation = await delegationManager.createPresentation(
            agent.did,
            agent.keyPair,
            serviceId,
            scopes.slice(0, 1), // Test with first scope
            { challenge: `${serviceId}-challenge` }
          );

          const verification = await provider.verifyPresentation(presentation);
          console.log(`   ${serviceId}: ${verification.verified ? '✅ VERIFIED' : '❌ FAILED'}`);
          if (verification.verified) {
            console.log(`     Granted scopes: ${verification.grantedScopes?.join(', ')}`);
          } else {
            console.log(`     Error: ${verification.error}`);
          }
          
        } catch (error) {
          console.log(`   ${serviceId}: ❌ ERROR - ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }
    }

    // 7. Cross-service delegation chain validation
    console.log('\n7️⃣  Validating cross-service delegation chains...\n');

    for (const { name, agent, services: agentServices } of agentsToTest) {
      console.log(`${name}:`);
      
      for (const serviceId of agentServices) {
        const result = await chainValidator.validateChain(agent.did, serviceId);
        console.log(`  ${serviceId}: ${result.valid ? '✅ VALID' : '❌ INVALID'}`);
        if (!result.valid) {
          console.log(`    Errors: ${result.errors.join(', ')}`);
        }
      }
    }

    // 8. Demonstrate service-specific revocation
    console.log('\n8️⃣  Testing service-specific revocation...\n');

    // Revoke cross-service coordinator's access to file-service only
    const revocationResult = await revocationManager.revokeAgent({
      targetAgentDID: crossServiceCoordinator.did,
      reason: 'Temporary security review',
      revokedBy: userDID,
      timestamp: new Date(),
      cascading: false,
      serviceDID: 'file-service'
    });

    console.log(`Revocation result: ${revocationResult.success ? '✅ SUCCESS' : '❌ FAILED'}`);
    console.log(`Revoked agents: ${revocationResult.revokedAgents.length}`);
    console.log(`Failed revocations: ${revocationResult.failedRevocations.length}`);

    // Test access after partial revocation
    console.log('\n📋 Access status after service-specific revocation:');
    for (const serviceId of ['email-service', 'calendar-service', 'file-service']) {
      const isRevoked = revocationManager.isAgentRevoked(crossServiceCoordinator.did, serviceId);
      console.log(`  ${serviceId}: ${isRevoked ? '❌ REVOKED' : '✅ ACTIVE'}`);
    }

    // 9. Service dependency analysis
    console.log('\n9️⃣  Service dependency analysis...\n');

    const allAgents = agentManager.getAllAgents();
    const serviceUsage = new Map<string, { agents: string[], scopes: Set<string> }>();

    for (const agent of allAgents) {
      const credentials = agentManager.getDelegationCredentials(agent.did);
      
      for (const credential of credentials) {
        const serviceId = credential.credentialSubject.serviceDID || 'unknown';
        
        if (!serviceUsage.has(serviceId)) {
          serviceUsage.set(serviceId, { agents: [], scopes: new Set() });
        }
        
        const usage = serviceUsage.get(serviceId)!;
        if (!usage.agents.includes(agent.did)) {
          usage.agents.push(agent.did);
        }
        
        credential.credentialSubject.scopes.forEach(scope => usage.scopes.add(scope));
      }
    }

    console.log('Service usage analysis:');
    for (const [serviceId, usage] of serviceUsage.entries()) {
      const service = services.find(s => s.id === serviceId);
      console.log(`\n📊 ${service?.name || serviceId}:`);
      console.log(`   Active agents: ${usage.agents.length}`);
      console.log(`   Scopes in use: ${Array.from(usage.scopes).join(', ')}`);
      console.log(`   Coverage: ${Math.round((usage.scopes.size / (service?.scopes.length || 1)) * 100)}%`);
    }

    // 10. Cross-service workflow simulation
    console.log('\n🔟 Cross-service workflow simulation...\n');

    // Simulate a workflow that requires multiple services
    console.log('Simulating "Schedule meeting with file sharing" workflow:');
    
    const workflowSteps = [
      { service: 'calendar-service', action: 'create meeting', scope: 'write:calendar' },
      { service: 'email-service', action: 'send invites', scope: 'write:emails' },
      { service: 'file-service', action: 'share documents', scope: 'share:files' }
    ];

    let workflowAgent = crossServiceCoordinator;
    console.log(`Using agent: ${workflowAgent.name}`);

    for (const step of workflowSteps) {
      const credentials = agentManager.getDelegationCredentials(workflowAgent.did)
        .filter(c => c.credentialSubject.serviceDID === step.service);
      
      const hasScope = credentials.some(c => c.credentialSubject.scopes.includes(step.scope));
      const isRevoked = revocationManager.isAgentRevoked(workflowAgent.did, step.service);
      
      const canExecute = hasScope && !isRevoked;
      
      console.log(`  ${step.action} (${step.service}): ${canExecute ? '✅ CAN EXECUTE' : '❌ INSUFFICIENT ACCESS'}`);
      if (!canExecute) {
        if (isRevoked) {
          console.log(`    Reason: Service access revoked`);
        } else if (!hasScope) {
          console.log(`    Reason: Missing scope ${step.scope}`);
        }
      }
    }

    // 11. Generate comprehensive report
    console.log('\n1️⃣1️⃣ Comprehensive Cross-Service Report:\n');

    const totalAgents = allAgents.length;
    const multiServiceAgents = allAgents.filter(agent => {
      const credentials = agentManager.getDelegationCredentials(agent.did);
      const services = new Set(credentials.map(c => c.credentialSubject.serviceDID));
      return services.size > 1;
    }).length;

    console.log(`📈 Summary Statistics:`);
    console.log(`  Total agents: ${totalAgents}`);
    console.log(`  Multi-service agents: ${multiServiceAgents}`);
    console.log(`  Single-service agents: ${totalAgents - multiServiceAgents}`);
    console.log(`  Services in use: ${serviceUsage.size}`);
    console.log(`  Average services per agent: ${(Array.from(serviceUsage.values()).reduce((sum, usage) => sum + usage.agents.length, 0) / totalAgents).toFixed(2)}`);

    // Service coverage matrix
    console.log(`\n🎯 Service Coverage Matrix:`);
    const matrix = new Map<string, Map<string, boolean>>();
    
    for (const agent of allAgents) {
      const agentName = agent.name.substring(0, 20);
      matrix.set(agentName, new Map());
      
      const credentials = agentManager.getDelegationCredentials(agent.did);
      const agentServices = new Set(credentials.map(c => c.credentialSubject.serviceDID));
      
      for (const service of services) {
        matrix.get(agentName)!.set(service.id, agentServices.has(service.id));
      }
    }

    // Print matrix header
    console.log('Agent'.padEnd(22) + services.map(s => s.id.substring(0, 8).padEnd(10)).join(''));
    console.log('-'.repeat(22 + services.length * 10));
    
    for (const [agentName, serviceAccess] of matrix.entries()) {
      let row = agentName.padEnd(22);
      for (const service of services) {
        const hasAccess = serviceAccess.get(service.id);
        row += (hasAccess ? '✅' : '❌').padEnd(10);
      }
      console.log(row);
    }

    console.log('\n✅ Cross-service delegation example completed successfully!');

  } catch (error) {
    console.error('❌ Example failed:', error);
    throw error;
  }
}

// Run the example
if (require.main === module) {
  crossServiceDelegationExample()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('Example failed:', error);
      process.exit(1);
    });
}

export { crossServiceDelegationExample };