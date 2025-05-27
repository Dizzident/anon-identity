import { IdentityProvider } from '../src/idp/identity-provider';
import { UserWallet } from '../src/wallet/user-wallet';
import { ServiceProvider } from '../src/sp/service-provider';
import { UserAttributes } from '../src/types';

async function demonstrateIdentityFlow() {
  console.log('=== Anonymous Identity Framework Demo ===\n');
  
  // 1. Create Identity Provider (IDP)
  console.log('1. Setting up Identity Provider...');
  const idp = await IdentityProvider.create();
  console.log(`   IDP DID: ${idp.getDID()}\n`);
  
  // 2. Create User Wallet
  console.log('2. Creating User Wallet...');
  const userWallet = await UserWallet.create();
  console.log(`   User DID: ${userWallet.getDID()}\n`);
  
  // 3. User requests credential from IDP
  console.log('3. Issuing Verifiable Credential...');
  const userAttributes: UserAttributes = {
    givenName: 'Alice',
    dateOfBirth: '1990-01-15',
    // isOver18 will be auto-calculated
  };
  
  const credential = await idp.issueVerifiableCredential(
    userWallet.getDID(),
    userAttributes
  );
  
  console.log('   Credential issued:');
  console.log(`   - ID: ${credential.id}`);
  console.log(`   - Type: ${credential.type.join(', ')}`);
  console.log(`   - Subject:`, credential.credentialSubject);
  console.log();
  
  // 4. User stores credential in wallet
  console.log('4. Storing credential in wallet...');
  userWallet.storeCredential(credential);
  console.log(`   Credentials in wallet: ${userWallet.getAllCredentials().length}\n`);
  
  // 5. Save wallet with passphrase
  console.log('5. Saving wallet with passphrase...');
  await userWallet.save('my-secure-passphrase', 'alice-wallet');
  console.log('   Wallet saved successfully\n');
  
  // 6. Create Service Provider
  console.log('6. Setting up Service Provider...');
  const serviceProvider = new ServiceProvider('Online Age Verification Service', [
    idp.getDID() // Trust this IDP
  ]);
  console.log(`   Service: ${serviceProvider.getName()}`);
  console.log(`   Trusted Issuers: ${serviceProvider.getTrustedIssuers().join(', ')}\n`);
  
  // 7. User creates Verifiable Presentation
  console.log('7. Creating Verifiable Presentation...');
  const presentation = await userWallet.createVerifiablePresentation([credential.id]);
  console.log('   Presentation created with credentials:', 
    presentation.verifiableCredential.map(vc => vc.id));
  console.log();
  
  // 8. Service Provider verifies presentation
  console.log('8. Verifying Presentation...');
  const verificationResult = await serviceProvider.verifyPresentation(presentation);
  
  if (verificationResult.valid) {
    console.log('   ✓ Presentation verified successfully!');
    console.log(`   Holder: ${verificationResult.holder}`);
    console.log('   Verified credentials:');
    verificationResult.credentials?.forEach(cred => {
      console.log(`     - ${cred.type.join(', ')}`);
      console.log(`       Issuer: ${cred.issuer}`);
      console.log('       Attributes:', cred.attributes);
    });
  } else {
    console.log('   ✗ Verification failed:');
    verificationResult.errors?.forEach(error => {
      console.log(`     - ${error}`);
    });
  }
  
  console.log('\n=== Demo Complete ===');
}

// Run the demo
demonstrateIdentityFlow().catch(console.error);