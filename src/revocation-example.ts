import { IdentityProvider } from './idp/identity-provider';
import { UserWallet } from './wallet/user-wallet';
import { ServiceProvider } from './sp/service-provider';
import { RevocationService } from './revocation/revocation-service';
import { UserAttributes } from './types';

async function demonstrateRevocation() {
  console.log('=== Credential Revocation Demo ===\n');
  
  // 1. Setup participants
  console.log('1. Setting up participants...');
  const idp = await IdentityProvider.create();
  const userWallet = await UserWallet.create();
  const serviceProvider = new ServiceProvider('Verification Service', [idp.getDID()]);
  
  console.log(`   IDP: ${idp.getDID()}`);
  console.log(`   User: ${userWallet.getDID()}\n`);
  
  // 2. Issue a credential
  console.log('2. Issuing credential to user...');
  const userAttributes: UserAttributes = {
    givenName: 'John Doe',
    dateOfBirth: '1990-01-01'
  };
  
  const credential = await idp.issueVerifiableCredential(
    userWallet.getDID(),
    userAttributes
  );
  
  userWallet.storeCredential(credential);
  console.log(`   Credential issued: ${credential.id}\n`);
  
  // 3. Create and verify presentation (should succeed)
  console.log('3. Creating presentation and verifying (before revocation)...');
  const presentation1 = await userWallet.createVerifiablePresentation([credential.id]);
  const result1 = await serviceProvider.verifyPresentation(presentation1);
  
  console.log(`   Verification result: ${result1.valid ? '✓ VALID' : '✗ INVALID'}`);
  if (!result1.valid) {
    console.log(`   Errors: ${result1.errors?.join(', ')}`);
  }
  console.log();
  
  // 4. IDP revokes the credential
  console.log('4. IDP revoking credential...');
  idp.revokeCredential(credential.id);
  console.log(`   Credential ${credential.id} added to revocation list`);
  
  // Publish revocation list
  const revocationUrl = await idp.publishRevocationList();
  console.log(`   Revocation list published at: ${revocationUrl}`);
  
  // Show revocation list contents
  const revocationList = await idp.getRevocationList();
  console.log(`   Revoked credentials: ${revocationList.revokedCredentials.length}`);
  console.log(`   List: [${revocationList.revokedCredentials.join(', ')}]\n`);
  
  // 5. Try to verify the same presentation again (should fail)
  console.log('5. Verifying presentation again (after revocation)...');
  const result2 = await serviceProvider.verifyPresentation(presentation1);
  
  console.log(`   Verification result: ${result2.valid ? '✓ VALID' : '✗ INVALID'}`);
  if (!result2.valid) {
    console.log(`   Errors: ${result2.errors?.join(', ')}`);
  }
  console.log();
  
  // 6. Demonstrate unrevocation
  console.log('6. Unrevoking credential...');
  idp.unrevokeCredential(credential.id);
  await idp.publishRevocationList();
  
  const result3 = await serviceProvider.verifyPresentation(presentation1);
  console.log(`   Verification after unrevoke: ${result3.valid ? '✓ VALID' : '✗ INVALID'}\n`);
  
  console.log('=== Revocation Demo Complete ===');
}

async function demonstrateRevocationWithMultipleCredentials() {
  console.log('\n\n=== Multiple Credentials Revocation Demo ===\n');
  
  const idp = await IdentityProvider.create();
  const wallet1 = await UserWallet.create();
  const wallet2 = await UserWallet.create();
  const sp = new ServiceProvider('Multi-Check Service', [idp.getDID()]);
  
  // Issue multiple credentials
  console.log('1. Issuing multiple credentials...');
  const cred1 = await idp.issueVerifiableCredential(wallet1.getDID(), {
    givenName: 'Alice',
    dateOfBirth: '1985-05-15'
  });
  const cred2 = await idp.issueVerifiableCredential(wallet2.getDID(), {
    givenName: 'Bob',
    dateOfBirth: '1992-08-20'
  });
  const cred3 = await idp.issueVerifiableCredential(wallet1.getDID(), {
    givenName: 'Alice',
    dateOfBirth: '1985-05-15'
  });
  
  wallet1.storeCredential(cred1);
  wallet1.storeCredential(cred3);
  wallet2.storeCredential(cred2);
  
  console.log(`   Issued 3 credentials`);
  console.log(`   - ${cred1.id} to Alice`);
  console.log(`   - ${cred2.id} to Bob`);
  console.log(`   - ${cred3.id} to Alice\n`);
  
  // Revoke only Bob's credential
  console.log('2. Revoking only Bob\'s credential...');
  idp.revokeCredential(cred2.id);
  await idp.publishRevocationList();
  console.log(`   Revoked: ${cred2.id}\n`);
  
  // Test all credentials
  console.log('3. Testing all credentials...');
  
  // Alice's first credential - should be valid
  const pres1 = await wallet1.createVerifiablePresentation([cred1.id]);
  const res1 = await sp.verifyPresentation(pres1);
  console.log(`   Alice's credential 1: ${res1.valid ? '✓ VALID' : '✗ INVALID'}`);
  
  // Bob's credential - should be revoked
  const pres2 = await wallet2.createVerifiablePresentation([cred2.id]);
  const res2 = await sp.verifyPresentation(pres2);
  console.log(`   Bob's credential: ${res2.valid ? '✓ VALID' : '✗ INVALID (REVOKED)'}`);
  
  // Alice's second credential - should be valid
  const pres3 = await wallet1.createVerifiablePresentation([cred3.id]);
  const res3 = await sp.verifyPresentation(pres3);
  console.log(`   Alice's credential 2: ${res3.valid ? '✓ VALID' : '✗ INVALID'}`);
  
  console.log('\n=== Multiple Credentials Demo Complete ===');
}

async function demonstrateRevocationToggle() {
  console.log('\n\n=== Revocation Check Toggle Demo ===\n');
  
  const idp = await IdentityProvider.create();
  const wallet = await UserWallet.create();
  const sp = new ServiceProvider('Toggle Service', [idp.getDID()]);
  
  // Issue and immediately revoke a credential
  const credential = await idp.issueVerifiableCredential(wallet.getDID(), {
    givenName: 'Charlie',
    dateOfBirth: '2000-01-01'
  });
  wallet.storeCredential(credential);
  
  idp.revokeCredential(credential.id);
  await idp.publishRevocationList();
  
  const presentation = await wallet.createVerifiablePresentation([credential.id]);
  
  console.log('1. With revocation checking enabled (default):');
  const result1 = await sp.verifyPresentation(presentation);
  console.log(`   Result: ${result1.valid ? '✓ VALID' : '✗ INVALID'}`);
  if (!result1.valid) console.log(`   Reason: ${result1.errors?.[0]}`);
  
  console.log('\n2. Disabling revocation checking:');
  sp.setRevocationCheck(false);
  const result2 = await sp.verifyPresentation(presentation);
  console.log(`   Result: ${result2.valid ? '✓ VALID' : '✗ INVALID'}`);
  console.log('   (Revoked credential accepted when check is disabled)');
  
  console.log('\n=== Toggle Demo Complete ===');
}

// Run all demonstrations
async function main() {
  try {
    // Clear any previous revocation data
    RevocationService.clearRegistry();
    
    await demonstrateRevocation();
    await demonstrateRevocationWithMultipleCredentials();
    await demonstrateRevocationToggle();
  } catch (error) {
    console.error('Error:', error);
  }
}

main();