import { 
  IdentityProvider, 
  UserWallet, 
  ServiceProvider,
  FileStorageProvider,
  StorageFactory
} from '../src';
import * as path from 'path';

async function main() {
  console.log('Storage Abstraction Example\n');
  
  // Create file storage provider
  const fileStorage = new FileStorageProvider(
    path.join(__dirname, 'identity-data.json'),
    true, // encryption enabled
    'my-secure-passphrase'
  );
  
  console.log('1. Creating Identity Provider with File Storage...');
  const idp = await IdentityProvider.create(fileStorage);
  console.log(`   IDP DID: ${idp.getDID()}`);
  
  console.log('\n2. Creating User Wallet with File Storage...');
  const wallet = await UserWallet.create(fileStorage);
  console.log(`   Wallet DID: ${wallet.getDID()}`);
  
  console.log('\n3. Issuing Credential...');
  const credential = await idp.issueVerifiableCredential(
    wallet.getDID(),
    {
      givenName: 'Alice',
      familyName: 'Smith',
      dateOfBirth: '1995-06-15',
      email: 'alice@example.com'
    }
  );
  console.log(`   Credential ID: ${credential.id}`);
  console.log(`   Credential stored in file system`);
  
  console.log('\n4. Storing Credential in Wallet...');
  await wallet.storeCredential(credential);
  console.log('   Credential stored in wallet');
  
  console.log('\n5. Creating New Wallet Instance...');
  // Create a new wallet instance to test persistence
  const wallet2 = await UserWallet.create(fileStorage);
  
  console.log('\n6. Retrieving Credentials from Storage...');
  const credentials = await fileStorage.listCredentials(wallet.getDID());
  console.log(`   Found ${credentials.length} credential(s) for ${wallet.getDID()}`);
  
  if (credentials.length > 0) {
    console.log(`   Credential ID: ${credentials[0].id}`);
    console.log(`   Subject: ${JSON.stringify(credentials[0].credentialSubject, null, 2)}`);
  }
  
  console.log('\n7. Testing DID Resolution...');
  const didDoc = await fileStorage.resolveDID(wallet.getDID());
  if (didDoc) {
    console.log(`   DID Document found for ${wallet.getDID()}`);
    console.log(`   Created: ${didDoc.created}`);
  }
  
  console.log('\n8. Testing Revocation...');
  // Revoke the credential
  idp.revokeCredential(credential.id);
  await idp.publishRevocationList();
  console.log(`   Credential ${credential.id} revoked`);
  
  // Check revocation
  const isRevoked = await fileStorage.checkRevocation(idp.getDID(), credential.id);
  console.log(`   Revocation check: ${isRevoked ? 'REVOKED' : 'VALID'}`);
  
  console.log('\n9. Service Provider Verification with Storage...');
  const sp = new ServiceProvider('Test Service', [idp.getDID()], true, fileStorage);
  
  // Create presentation
  const presentation = await wallet.createVerifiablePresentation([credential.id]);
  
  // Verify presentation (should detect revocation)
  const result = await sp.verifyPresentation(presentation);
  console.log(`   Verification result: ${result.valid ? 'VALID' : 'INVALID'}`);
  if (result.errors) {
    console.log(`   Errors: ${result.errors.join(', ')}`);
  }
  
  console.log('\n10. Storage Statistics...');
  const allDIDs = await fileStorage.listDIDs();
  const allSchemas = await fileStorage.listSchemas();
  console.log(`   Total DIDs stored: ${allDIDs.length}`);
  console.log(`   Total Schemas stored: ${allSchemas.length}`);
  
  console.log('\nFile storage example completed!');
  console.log(`Data persisted to: ${path.join(__dirname, 'identity-data.json')}`);
}

main().catch(console.error);