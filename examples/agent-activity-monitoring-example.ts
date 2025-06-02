import {
  UserWallet,
  IdentityProvider,
  AgentEnabledServiceProvider,
  ServiceManifestBuilder,
  ActivityType,
  ActivityStatus
} from '../src';

async function main() {
  console.log('=== Agent Activity Monitoring Example ===\n');

  // 1. Setup identity provider and user wallet
  const idp = await IdentityProvider.create('Example IDP');
  const userWallet = await UserWallet.create();
  
  // Issue credential to user
  const userCredential = await idp.issueCredential(userWallet.getDID(), {
    name: 'Alice Johnson',
    email: 'alice@example.com'
  }, 'UserProfile');
  
  await userWallet.storeCredential(userCredential);

  // 2. Create an agent with specific purpose
  console.log('Creating data processing agent...');
  const agent = await userWallet.createAgent({
    name: 'Data Processor Bot',
    description: 'Processes and analyzes user data'
  });
  console.log(`Agent created: ${agent.did}\n`);

  // 3. Setup service provider with activity monitoring
  console.log('Setting up service provider with activity monitoring...');
  const serviceManifest = new ServiceManifestBuilder(
    'did:key:data-service',
    'Data Analytics Service',
    'Service for processing and analyzing data'
  )
    .addRequiredScope('read:data:all')
    .addOptionalScope('write:data:create')
    .addOptionalScope('execute:analysis:basic')
    .build();

  const serviceProvider = new AgentEnabledServiceProvider(
    'Data Analytics Service',
    'did:key:data-service',
    [idp.getDID()],
    { serviceManifest }
  );

  // 4. Subscribe to real-time activity updates
  console.log('Subscribing to agent activities...\n');
  const activityLogger = serviceProvider.getActivityLogger();
  
  const subscription = activityLogger.subscribe(
    { agentDID: agent.did },
    (activity) => {
      console.log(`[ACTIVITY] ${new Date(activity.timestamp).toISOString()}`);
      console.log(`  Type: ${activity.type}`);
      console.log(`  Status: ${activity.status}`);
      console.log(`  Service: ${activity.serviceDID}`);
      if (activity.scopes.length > 0) {
        console.log(`  Scopes: ${activity.scopes.join(', ')}`);
      }
      if (activity.details.message) {
        console.log(`  Message: ${activity.details.message}`);
      }
      if (activity.sessionId) {
        console.log(`  Session: ${activity.sessionId}`);
      }
      console.log('');
    }
  );

  // 5. Grant agent access to the service
  console.log('Granting agent access to service...');
  await userWallet.grantAgentAccess(agent.did, {
    serviceDID: 'did:key:data-service',
    scopes: ['read:data:all', 'write:data:create'],
    expiresAt: new Date(Date.now() + 3600000) // 1 hour
  });

  // 6. Agent authenticates with the service
  console.log('\n--- Agent Authentication Flow ---\n');
  const agentManager = userWallet.getAgentManager();
  const presentation = await agentManager.createPresentation(agent.did, {
    serviceDID: 'did:key:data-service',
    challenge: 'auth-challenge-123'
  });

  if (!presentation) {
    console.error('Failed to create presentation');
    return;
  }

  // Mock the JWT verification for demo
  jest.spyOn(serviceProvider as any, 'verifyJWT').mockResolvedValue({ valid: true });

  const verificationResult = await serviceProvider.verifyPresentation(presentation);
  console.log(`Authentication result: ${verificationResult.valid ? 'SUCCESS' : 'FAILED'}\n`);

  // 7. Simulate agent using different scopes
  console.log('--- Agent Scope Usage ---\n');
  
  if (verificationResult.valid && verificationResult.holder) {
    // Read data operation
    try {
      await serviceProvider.logScopeUsage(verificationResult.holder, 'read:data:all', {
        resourceType: 'user_analytics',
        resourceId: 'dataset-2024-01',
        operation: 'read',
        success: true
      });
      console.log('✓ Successfully read analytics data\n');
    } catch (error) {
      console.error('Failed to read data:', error);
    }

    // Write data operation
    try {
      await serviceProvider.logScopeUsage(verificationResult.holder, 'write:data:create', {
        resourceType: 'processed_results',
        resourceId: 'result-batch-001',
        operation: 'create',
        success: true
      });
      console.log('✓ Successfully created processed results\n');
    } catch (error) {
      console.error('Failed to write data:', error);
    }

    // Attempt to use unauthorized scope
    console.log('Attempting to use unauthorized scope...');
    try {
      await serviceProvider.logScopeUsage(verificationResult.holder, 'execute:analysis:advanced', {
        resourceType: 'ml_model',
        operation: 'execute'
      });
    } catch (error) {
      console.log('✗ Correctly denied access to unauthorized scope\n');
    }
  }

  // 8. Display activity summary
  console.log('--- Activity Summary ---\n');
  
  // In a real implementation, this would query from IPFS
  // For now, we'll show the buffer status
  console.log(`Activities in buffer: ${activityLogger.getBufferSize()}`);
  console.log(`Active subscriptions: ${activityLogger.getSubscriptionCount()}`);

  // 9. Revoke agent session
  console.log('\nRevoking agent session...');
  if (verificationResult.holder) {
    await serviceProvider.revokeAgentSession(verificationResult.holder);
    console.log('Agent session revoked\n');
  }

  // 10. Cleanup
  subscription.unsubscribe();
  await activityLogger.cleanup();
  
  console.log('=== Example Complete ===');
  console.log('\nIn Phase 2, all activities would be stored in IPFS with:');
  console.log('- Encrypted storage for privacy');
  console.log('- Content addressing for integrity');
  console.log('- Distributed availability');
  console.log('- Query capabilities through local index');
}

// Note: This example uses mock JWT verification for demonstration
// In production, real cryptographic verification would be used
main().catch(console.error);