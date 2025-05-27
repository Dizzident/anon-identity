import { IdentityProvider } from './idp/identity-provider';
import { UserWallet } from './wallet/user-wallet';
import { ServiceProvider } from './sp/service-provider';
import { UserAttributes, SelectiveDisclosureRequest } from './types';

async function demonstrateSelectiveDisclosure() {
  console.log('=== Selective Disclosure (ZKP) Demo ===\n');
  
  // 1. Setup participants
  console.log('1. Setting up participants...');
  const idp = await IdentityProvider.create();
  const userWallet = await UserWallet.create();
  const ageVerificationService = new ServiceProvider('Age Verification Service', [idp.getDID()]);
  
  console.log(`   IDP: ${idp.getDID()}`);
  console.log(`   User: ${userWallet.getDID()}`);
  console.log(`   Service: ${ageVerificationService.getName()}\n`);
  
  // 2. Issue credential with sensitive data
  console.log('2. Issuing credential with personal data...');
  const userAttributes: UserAttributes = {
    givenName: 'Alice Smith',
    dateOfBirth: '1995-06-15',
    // isOver18 will be auto-calculated as true
  };
  
  const credential = await idp.issueVerifiableCredential(
    userWallet.getDID(),
    userAttributes
  );
  
  userWallet.storeCredential(credential);
  console.log('   Full credential contains:');
  console.log(`   - givenName: ${credential.credentialSubject.givenName}`);
  console.log(`   - dateOfBirth: ${credential.credentialSubject.dateOfBirth}`);
  console.log(`   - isOver18: ${credential.credentialSubject.isOver18}`);
  console.log();
  
  // 3. Create presentation revealing ONLY isOver18 (not dateOfBirth)
  console.log('3. Creating selective disclosure presentation...');
  console.log('   User wants to prove they are over 18 WITHOUT revealing birth date');
  
  const disclosureRequest: SelectiveDisclosureRequest = {
    credentialId: credential.id,
    attributesToDisclose: ['isOver18'] // Only disclose this attribute
  };
  
  const presentation = await userWallet.createSelectiveDisclosurePresentation([disclosureRequest]);
  
  console.log('   Presentation created with selective disclosure');
  const disclosedCred = presentation.verifiableCredential[0];
  console.log('   Disclosed attributes:', Object.keys(disclosedCred.credentialSubject).filter(k => k !== 'id'));
  console.log();
  
  // 4. Service provider verifies the selective disclosure
  console.log('4. Service Provider verifying selective disclosure...');
  const verificationResult = await ageVerificationService.verifyPresentation(presentation);
  
  if (verificationResult.valid) {
    console.log('   ✓ Verification successful!');
    console.log(`   Holder: ${verificationResult.holder}`);
    
    const verifiedCred = verificationResult.credentials![0];
    console.log('   Verified attributes:');
    console.log(`     - isOver18: ${verifiedCred.attributes.isOver18}`);
    console.log(`     - Selectively disclosed: ${verifiedCred.selectivelyDisclosed || false}`);
    console.log(`     - Disclosed fields: ${verifiedCred.disclosedAttributes?.join(', ') || 'N/A'}`);
    
    // Confirm that dateOfBirth is NOT revealed
    if (!verifiedCred.attributes.dateOfBirth) {
      console.log('   ✓ Birth date was NOT revealed (Zero-Knowledge Proof success!)');
    }
  } else {
    console.log('   ✗ Verification failed:');
    verificationResult.errors?.forEach(error => {
      console.log(`     - ${error}`);
    });
  }
  
  console.log('\n=== Privacy-Preserving Age Verification Complete ===');
  console.log('The service verified the user is over 18 without learning their birth date!');
}

// Comparison example showing full disclosure vs selective disclosure
async function compareDisclosureMethods() {
  console.log('\n\n=== Comparing Full vs Selective Disclosure ===\n');
  
  const idp = await IdentityProvider.create();
  const userWallet = await UserWallet.create();
  const sp = new ServiceProvider('Comparison Service', [idp.getDID()]);
  
  // Issue credential
  const credential = await idp.issueVerifiableCredential(
    userWallet.getDID(),
    {
      givenName: 'Bob Johnson',
      dateOfBirth: '1990-03-20',
    }
  );
  userWallet.storeCredential(credential);
  
  // Full disclosure
  console.log('1. FULL DISCLOSURE (Traditional Method):');
  const fullPresentation = await userWallet.createVerifiablePresentation([credential.id]);
  const fullResult = await sp.verifyPresentation(fullPresentation);
  console.log('   Revealed attributes:', fullResult.credentials![0].attributes);
  
  // Selective disclosure
  console.log('\n2. SELECTIVE DISCLOSURE (Privacy-Preserving):');
  const selectivePresentation = await userWallet.createSelectiveDisclosurePresentation([{
    credentialId: credential.id,
    attributesToDisclose: ['isOver18']
  }]);
  const selectiveResult = await sp.verifyPresentation(selectivePresentation);
  console.log('   Revealed attributes:', selectiveResult.credentials![0].attributes);
  
  console.log('\n✓ Selective disclosure protects user privacy!');
}

// Run the demonstrations
async function main() {
  try {
    await demonstrateSelectiveDisclosure();
    await compareDisclosureMethods();
  } catch (error) {
    console.error('Error:', error);
  }
}

main();