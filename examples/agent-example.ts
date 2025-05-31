import { 
  UserWallet, 
  IdentityProvider, 
  AgentEnabledServiceProvider,
  ServiceManifestBuilder,
  ScopeRegistry
} from '../src';

async function main() {
  console.log('=== Agent Sub-Identity Example ===\n');

  // 1. Create a user wallet
  console.log('1. Creating user wallet...');
  const userWallet = await UserWallet.create();
  const userDID = userWallet.getDID();
  console.log(`User DID: ${userDID}\n`);

  // 2. Create an identity provider and issue a credential to the user
  console.log('2. Issuing credential to user...');
  const idp = await IdentityProvider.create('Example IDP');
  const userCredential = await idp.issueCredential(userDID, {
    name: 'Alice Smith',
    email: 'alice@example.com',
    dateOfBirth: '1990-01-01'
  }, 'PersonalInfo');
  await userWallet.storeCredential(userCredential);
  console.log('User credential issued and stored\n');

  // 3. Create an agent for the user
  console.log('3. Creating agent identity...');
  const agent = await userWallet.createAgent({
    name: 'Shopping Assistant',
    description: 'AI agent that helps with online shopping'
  });
  console.log(`Agent DID: ${agent.did}`);
  console.log(`Agent Name: ${agent.name}\n`);

  // 4. Set up a service provider with agent support
  console.log('4. Setting up service provider...');
  const serviceDID = 'did:key:shopping-service-123';
  
  // Create a custom service manifest for an e-commerce service
  const serviceManifest = new ServiceManifestBuilder(
    serviceDID,
    'E-Commerce Service',
    'Online shopping platform with agent support'
  )
    .addRequiredScope('read:profile:basic')
    .addRequiredScope('read:products:all')
    .addOptionalScope('write:cart:add')
    .addOptionalScope('execute:payments:limit:100')
    .build();

  const serviceProvider = new AgentEnabledServiceProvider(
    'E-Commerce Service',
    serviceDID,
    [idp.getDID()], // Trust the IDP
    { serviceManifest }
  );

  console.log('Service manifest:');
  console.log('Required scopes:');
  serviceManifest.requiredScopes.forEach(scope => {
    console.log(`  - ${scope.name} (${scope.id})`);
  });
  console.log('Optional scopes:');
  serviceManifest.optionalScopes?.forEach(scope => {
    console.log(`  - ${scope.name} (${scope.id})`);
  });
  console.log();

  // 5. User grants agent access to the service
  console.log('5. Granting agent access to service...');
  const delegationCredential = await userWallet.grantAgentAccess(agent.did, {
    serviceDID: serviceDID,
    scopes: [
      'read:profile:basic',
      'read:products:all',
      'write:cart:add',
      'execute:payments:limit:100'
    ],
    constraints: {
      maxPurchaseAmount: 100,
      requireApprovalAbove: 50
    },
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
  });
  console.log('Agent granted access with scopes:', delegationCredential.credentialSubject.scopes);
  console.log();

  // 6. Agent creates a presentation for the service
  console.log('6. Agent presenting credentials to service...');
  const agentManager = userWallet.getAgentManager();
  const presentation = await agentManager.createPresentation(agent.did, {
    serviceDID: serviceDID,
    challenge: 'service-challenge-123'
  });

  if (!presentation) {
    console.error('Failed to create agent presentation');
    return;
  }

  // 7. Service provider verifies the agent presentation
  console.log('7. Service verifying agent presentation...');
  const verificationResult = await serviceProvider.verifyPresentation(presentation);

  console.log(`Verification result: ${verificationResult.valid ? 'VALID' : 'INVALID'}`);
  if (verificationResult.valid) {
    console.log(`Agent DID: ${verificationResult.holder}`);
    console.log('Agent details:', verificationResult.credentials?.[0].attributes);
    
    // Check agent permissions
    const agentDID = verificationResult.holder!;
    console.log('\nAgent permissions:');
    console.log(`  Can read products: ${serviceProvider.hasScope(agentDID, 'read:products:all')}`);
    console.log(`  Can add to cart: ${serviceProvider.hasScope(agentDID, 'write:cart:add')}`);
    console.log(`  Can make payments: ${serviceProvider.hasScope(agentDID, 'execute:payments:limit:100')}`);
    console.log(`  Can delete account: ${serviceProvider.hasScope(agentDID, 'admin:account:delete')}`);
  } else {
    console.log('Verification errors:', verificationResult.errors);
  }
  console.log();

  // 8. List all agents and their access
  console.log('8. Listing user agents...');
  const allAgents = userWallet.listAgents();
  allAgents.forEach(ag => {
    console.log(`\nAgent: ${ag.name}`);
    console.log(`  DID: ${ag.did}`);
    console.log(`  Created: ${ag.createdAt.toLocaleString()}`);
    
    const access = userWallet.getAgentAccess(ag.did);
    if (access.length > 0) {
      console.log('  Access grants:');
      access.forEach(grant => {
        console.log(`    - Service: ${grant.serviceDID}`);
        console.log(`      Scopes: ${grant.scopes.join(', ')}`);
        console.log(`      Expires: ${grant.expiresAt.toLocaleString()}`);
      });
    }
  });
  console.log();

  // 9. Demonstrate scope registry
  console.log('9. Available scope definitions:');
  const scopeRegistry = ScopeRegistry.getInstance();
  const categories = scopeRegistry.getCategories();
  
  categories.forEach(category => {
    console.log(`\n${category.toUpperCase()} Scopes:`);
    const scopes = scopeRegistry.getScopesByCategory(category);
    scopes.slice(0, 3).forEach(scope => {
      console.log(`  - ${scope.name} (${scope.id})`);
      console.log(`    ${scope.description}`);
      console.log(`    Risk: ${scope.riskLevel}`);
    });
    if (scopes.length > 3) {
      console.log(`  ... and ${scopes.length - 3} more`);
    }
  });
  console.log();

  // 10. Revoke agent access to a specific service
  console.log('10. Revoking agent access to service...');
  await userWallet.revokeAgentAccess(agent.did, serviceDID);
  console.log('Agent access revoked');

  // Verify agent no longer has access
  const updatedAccess = userWallet.getAgentAccess(agent.did);
  console.log(`Agent remaining access grants: ${updatedAccess.length}`);
}

main().catch(console.error);