/**
 * Enhanced Service Provider Example
 * 
 * This example demonstrates the new features added to the anon-identity package:
 * - Session Management
 * - Enhanced Error Handling
 * - Presentation Request Protocol
 * - Batch Operations
 */

import {
  CryptoService,
  DIDService,
  SecureStorage,
  IdentityProvider,
  UserWallet,
  ServiceProvider,
  SessionManager,
  VerificationError,
  VerificationErrorCode,
  BatchOperations,
  PresentationRequest,
  MemoryStorageProvider
} from '../src';

async function enhancedServiceProviderDemo() {
  console.log('=== Enhanced Service Provider Demo ===\n');

  // 1. Setup - Create Identity Provider, User Wallet, and Enhanced Service Provider
  const storage = new SecureStorage('demo-password');
  const storageProvider = new MemoryStorageProvider();

  // Create Identity Provider
  const idpKeys = await CryptoService.generateKeyPair();
  const idpDID = DIDService.createDIDKey(idpKeys.publicKey);
  const identityProvider = new IdentityProvider(idpKeys, storageProvider);

  // Create User Wallet
  const userKeys = await CryptoService.generateKeyPair();
  const userDID = DIDService.createDIDKey(userKeys.publicKey);
  const userWallet = new UserWallet(userKeys, storageProvider);

  // Create Enhanced Service Provider with new options
  const serviceProvider = new ServiceProvider('Enhanced Employer Inc', [identityProvider.getDID()], {
    checkRevocation: true,
    storageProvider,
    sessionManager: {
      defaultSessionDuration: 3600000, // 1 hour
      maxSessionDuration: 86400000,    // 24 hours
      cleanupInterval: 300000          // 5 minutes
    },
    batchOperations: {
      maxConcurrency: 5,
      timeout: 30000,
      continueOnError: true
    }
  });

  console.log('✅ Created enhanced service provider with session management and batch operations\n');

  // 2. Enhanced Error Handling Demo
  console.log('--- Enhanced Error Handling Demo ---');
  
  try {
    // Create a credential with the user
    const credential = await identityProvider.issueVerifiableCredential(userDID.id, {
      givenName: 'Alice Smith',
      dateOfBirth: '1995-06-15',
      degree: 'Computer Science',
      university: 'Enhanced University'
    });

    await userWallet.storeCredential(credential);

    // Create presentation
    const presentation = await userWallet.createVerifiablePresentation([credential.id]);

    // Verify with enhanced error details
    const result = await serviceProvider.verifyPresentation(presentation);
    
    if (result.valid) {
      console.log('✅ Verification successful');
      console.log(`   Holder: ${result.holder}`);
      console.log(`   Credentials: ${result.credentials?.length}`);
    } else {
      console.log('❌ Verification failed');
      result.errors?.forEach(error => {
        if (error instanceof VerificationError) {
          console.log(`   Error: [${error.code}] ${error.message}`);
          console.log(`   Details:`, error.details);
        }
      });
    }
  } catch (error) {
    console.log('Error in verification demo:', error);
  }

  console.log();

  // 3. Session Management Demo
  console.log('--- Session Management Demo ---');
  
  try {
    // Create a credential
    const credential = await identityProvider.issueVerifiableCredential(userDID.id, {
      givenName: 'Bob Johnson',
      dateOfBirth: '1990-03-15'
    });

    await userWallet.storeCredential(credential);
    const presentation = await userWallet.createVerifiablePresentation([credential.id]);

    // Verify and create session automatically
    const { verification, session } = await serviceProvider.verifyPresentationWithSession(
      presentation,
      true,
      { loginMethod: 'credential', userAgent: 'demo-client' }
    );

    if (verification.valid && session) {
      console.log('✅ Session created successfully');
      console.log(`   Session ID: ${session.id}`);
      console.log(`   Holder: ${session.holderDID}`);
      console.log(`   Expires: ${session.expiresAt.toISOString()}`);
      console.log(`   Attributes:`, Object.keys(session.attributes));

      // Validate session
      const validation = await serviceProvider.validateSession(session.id);
      console.log(`   Session valid: ${validation.valid}`);

      // Extend session
      await serviceProvider.setSessionExpiry(session.id, 7200000); // 2 hours
      console.log('✅ Session extended to 2 hours');

      // Get session info
      const sessionInfo = serviceProvider.getSession(session.id);
      console.log(`   New expiry: ${sessionInfo?.expiresAt.toISOString()}`);
    }
  } catch (error) {
    console.log('Error in session demo:', error);
  }

  console.log();

  // 4. Presentation Request Protocol Demo
  console.log('--- Presentation Request Protocol Demo ---');
  
  try {
    // Create a presentation request
    const presentationRequest = await serviceProvider.createPresentationRequest({
      credentialRequirements: [
        {
          type: ['VerifiableCredential', 'EducationCredential'],
          attributes: [
            { name: 'givenName', required: true },
            { name: 'degree', required: true },
            { name: 'university', required: false }
          ],
          trustedIssuers: [identityProvider.getDID()]
        }
      ],
      purpose: 'Employment verification',
      allowPartialMatch: false
    });

    console.log('✅ Created presentation request');
    console.log(`   Request ID: ${presentationRequest.id}`);
    console.log(`   Purpose: ${presentationRequest.purpose}`);
    console.log(`   Challenge: ${presentationRequest.challenge}`);

    // Create a simple request
    const simpleRequest = await serviceProvider.createSimplePresentationRequest(
      ['EducationCredential'],
      'Quick verification',
      ['givenName', 'degree'],
      ['university']
    );

    console.log('✅ Created simple presentation request');
    console.log(`   Requirements: ${simpleRequest.credentialRequirements.length}`);
  } catch (error) {
    console.log('Error in presentation request demo:', error);
  }

  console.log();

  // 5. Batch Operations Demo
  console.log('--- Batch Operations Demo ---');
  
  try {
    // Create multiple credentials and presentations
    const presentations = [];
    for (let i = 0; i < 3; i++) {
      const credential = await identityProvider.issueVerifiableCredential(userDID.id, {
        givenName: `User ${i + 1}`,
        dateOfBirth: '1990-01-01'
      });

      await userWallet.storeCredential(credential);
      const presentation = await userWallet.createVerifiablePresentation([credential.id]);
      presentations.push(presentation);
    }

    // Batch verify presentations
    console.log(`Batch verifying ${presentations.length} presentations...`);
    const batchResults = await serviceProvider.batchVerifyPresentations(presentations);

    console.log('✅ Batch verification completed');
    batchResults.forEach((result, index) => {
      console.log(`   Presentation ${index + 1}: ${result.result.valid ? 'Valid' : 'Invalid'} (${result.processingTime}ms)`);
      if (result.result.credentials) {
        const attributes = result.result.credentials[0]?.attributes;
        console.log(`     User: ${attributes?.givenName}, Role: ${attributes?.role}`);
      }
    });

    // Batch revocation check
    const credentialIds = batchResults
      .filter(r => r.result.valid && r.result.credentials)
      .flatMap(r => r.result.credentials!.map(c => c.id));

    if (credentialIds.length > 0) {
      console.log(`\nChecking revocation status for ${credentialIds.length} credentials...`);
      const revocationResults = await serviceProvider.batchCheckRevocations(credentialIds);

      console.log('✅ Batch revocation check completed');
      revocationResults.forEach((result, credentialId) => {
        console.log(`   ${credentialId}: ${result.isRevoked ? 'Revoked' : 'Not revoked'} (${result.processingTime}ms)`);
      });
    }

  } catch (error) {
    console.log('Error in batch operations demo:', error);
  }

  console.log();

  // 6. Error Recovery Demo
  console.log('--- Error Recovery Demo ---');
  
  try {
    // Simulate various error conditions
    const errorCases = [
      () => serviceProvider.validateSession('invalid-session-id'),
      () => serviceProvider.verifyPresentation({} as any), // Invalid presentation
    ];

    for (const errorCase of errorCases) {
      try {
        const result = await errorCase();
        if ('valid' in result && !result.valid) {
          console.log('❌ Expected error caught:');
          if ('errors' in result && result.errors) {
            result.errors.forEach(error => {
              if (error instanceof VerificationError) {
                console.log(`   [${error.code}] ${error.message}`);
              }
            });
          }
          if ('reason' in result && result.reason) {
            console.log(`   Reason: ${result.reason}`);
          }
        }
      } catch (error) {
        console.log(`❌ Exception caught: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  } catch (error) {
    console.log('Error in error recovery demo:', error);
  }

  console.log();

  // 7. Cleanup
  console.log('--- Cleanup ---');
  serviceProvider.destroy();
  console.log('✅ Service provider resources cleaned up');

  console.log('\n=== Enhanced Service Provider Demo Complete ===');
}

// Run the demo
if (require.main === module) {
  enhancedServiceProviderDemo().catch(console.error);
}

export { enhancedServiceProviderDemo };