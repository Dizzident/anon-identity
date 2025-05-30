import { IdentityProviderV2 } from '../src/idp/identity-provider-v2';
import { UserWallet } from '../src/wallet/user-wallet';
import { ServiceProviderV2 } from '../src/sp/service-provider-v2';
import { CredentialStatusType } from '../src/types/vc2';

async function demonstrateVC2Features() {
  console.log('=== W3C VC 2.0 Features Demo ===\n');
  
  // 1. Create Identity Provider with V2 support
  const idp = await IdentityProviderV2.create();
  console.log('Identity Provider DID:', idp.getDID());
  
  // 2. Create User Wallet
  const wallet = await UserWallet.create();
  console.log('User DID:', wallet.getDID());
  
  // 3. Issue a VC 2.0 credential with advanced features
  console.log('\n--- Issuing VC 2.0 Credential ---');
  
  const credential = await idp.issueVerifiableCredentialV2(
    wallet.getDID(),
    {
      givenName: 'Alice',
      dateOfBirth: '1990-01-15',
      emailAddresses: [{
        email: 'alice@example.com',
        type: 'personal',
        isPrimary: true,
        verified: true,
        verifiedAt: new Date().toISOString()
      }],
      phoneNumbers: [{
        number: '+1-555-123-4567',
        type: 'mobile',
        isPrimary: true,
        verified: true,
        canReceiveSMS: true,
        canReceiveCalls: true
      }]
    },
    {
      // Credential validity period
      validFrom: new Date().toISOString(),
      validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
      
      // Credential status
      credentialStatus: {
        type: CredentialStatusType.STATUS_LIST_2021,
        statusListIndex: 42
      },
      
      // Terms of use
      termsOfUse: {
        type: 'IssuerPolicy',
        id: 'https://example.com/policies/credential-tos',
        profile: 'https://example.com/profiles/v1',
        prohibition: [{
          assigner: idp.getDID(),
          assignee: 'AllVerifiers',
          target: 'https://example.com/credentials/personal-data',
          action: ['Archival', 'ThirdPartySharing']
        }],
        obligation: [{
          assigner: idp.getDID(),
          assignee: 'AllVerifiers',
          target: 'https://example.com/credentials/personal-data',
          action: ['SecureStorage', 'DeleteAfterUse']
        }]
      },
      
      // Evidence
      evidence: {
        type: ['DocumentVerification', 'BiometricVerification'],
        verifier: 'did:example:verifier123',
        evidenceDocument: 'DriversLicense',
        subjectPresence: 'Physical',
        documentPresence: 'Physical',
        licenseNumber: 'DL-123456789',
        biometricType: 'FaceMatch',
        biometricScore: 0.98
      }
    }
  );
  
  console.log('\nCredential issued with:');
  console.log('- ID:', credential.id);
  console.log('- Valid from:', credential.validFrom);
  console.log('- Valid until:', credential.validUntil);
  console.log('- Status type:', credential.credentialStatus?.type);
  console.log('- Terms of use:', credential.termsOfUse ? 'Yes' : 'No');
  console.log('- Evidence:', credential.evidence ? 'Yes' : 'No');
  
  // 4. Store credential in wallet
  await wallet.storeCredential(credential as any);
  
  // 5. Create and publish status list
  console.log('\n--- Publishing Status List ---');
  const statusListUrl = await idp.publishStatusList();
  console.log('Status list published at:', statusListUrl);
  
  // 6. Create Service Provider with V2 support
  const sp = new ServiceProviderV2('VerifierService', [idp.getDID()], {
    checkCredentialStatus: true
  });
  
  // 7. Create presentation
  console.log('\n--- Creating Presentation ---');
  const presentation = await wallet.createPresentation([credential.id!]);
  
  // 8. Verify presentation (should pass)
  console.log('\n--- Verifying Presentation (Valid) ---');
  let result = await sp.verifyPresentationV2(presentation);
  console.log('Verification result:', result.valid);
  console.log('Credentials verified:', result.credentials?.length);
  
  // 9. Revoke credential
  console.log('\n--- Revoking Credential ---');
  await idp.revokeCredentialV2(credential.id!, 42);
  
  // Load updated status list into service provider
  const statusList = await idp.publishStatusList();
  // In real scenario, SP would fetch this from the URL
  
  // 10. Verify presentation again (should fail due to revocation)
  console.log('\n--- Verifying Presentation (After Revocation) ---');
  result = await sp.verifyPresentationV2(presentation);
  console.log('Verification result:', result.valid);
  if (!result.valid && result.errors) {
    console.log('Errors:', result.errors.map(e => e.message));
  }
  
  // 11. Display credential details
  console.log('\n--- Credential Details ---');
  console.log('Contexts:', JSON.stringify(credential['@context'], null, 2));
  console.log('\nTerms of Use:', JSON.stringify(credential.termsOfUse, null, 2));
  console.log('\nEvidence:', JSON.stringify(credential.evidence, null, 2));
  console.log('\nCredential Status:', JSON.stringify(credential.credentialStatus, null, 2));
}

// Run the demo
demonstrateVC2Features().catch(console.error);