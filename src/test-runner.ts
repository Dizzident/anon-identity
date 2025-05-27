import { CryptoService } from './core/crypto';
import { DIDService } from './core/did';
import { IdentityProvider } from './idp/identity-provider';
import { UserWallet } from './wallet/user-wallet';
import { ServiceProvider } from './sp/service-provider';
import { UserAttributes } from './types';

async function runTests() {
  console.log('Running tests...\n');
  
  let passed = 0;
  let failed = 0;
  
  async function test(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      console.log(`✓ ${name}`);
      passed++;
    } catch (error) {
      console.log(`✗ ${name}`);
      console.log(`  Error: ${error instanceof Error ? error.message : error}`);
      failed++;
    }
  }
  
  // Test CryptoService
  console.log('CryptoService Tests:');
  await test('should generate Ed25519 key pair', async () => {
    const keyPair = await CryptoService.generateKeyPair();
    if (keyPair.publicKey.length !== 32) throw new Error('Invalid public key length');
    if (keyPair.privateKey.length !== 32) throw new Error('Invalid private key length');
  });
  
  await test('should sign and verify correctly', async () => {
    const keyPair = await CryptoService.generateKeyPair();
    const message = new TextEncoder().encode('Hello, World!');
    const signature = await CryptoService.sign(message, keyPair.privateKey);
    const isValid = await CryptoService.verify(signature, message, keyPair.publicKey);
    if (!isValid) throw new Error('Signature verification failed');
  });
  
  // Test DIDService
  console.log('\nDIDService Tests:');
  await test('should create valid did:key', async () => {
    const keyPair = await CryptoService.generateKeyPair();
    const did = DIDService.createDIDKey(keyPair.publicKey);
    if (!did.id.startsWith('did:key:z')) throw new Error('Invalid DID format');
  });
  
  await test('should extract public key from DID', async () => {
    const keyPair = await CryptoService.generateKeyPair();
    const did = DIDService.createDIDKey(keyPair.publicKey);
    const extractedKey = DIDService.getPublicKeyFromDID(did.id);
    if (!extractedKey.every((v, i) => v === keyPair.publicKey[i])) {
      throw new Error('Extracted key does not match original');
    }
  });
  
  // Test Identity Provider
  console.log('\nIdentityProvider Tests:');
  await test('should issue verifiable credential', async () => {
    const idp = await IdentityProvider.create();
    const wallet = await UserWallet.create();
    const attributes: UserAttributes = {
      givenName: 'Alice',
      dateOfBirth: '1990-01-15'
    };
    const credential = await idp.issueVerifiableCredential(wallet.getDID(), attributes);
    if (!credential.proof?.jws) throw new Error('Credential missing proof');
    if (credential.credentialSubject.givenName !== 'Alice') throw new Error('Invalid subject');
  });
  
  // Test End-to-End Flow
  console.log('\nIntegration Tests:');
  await test('should complete full identity flow', async () => {
    const idp = await IdentityProvider.create();
    const wallet = await UserWallet.create();
    const sp = new ServiceProvider('Test SP', [idp.getDID()]);
    
    const credential = await idp.issueVerifiableCredential(wallet.getDID(), {
      givenName: 'Bob',
      dateOfBirth: '1990-01-01'
    });
    
    wallet.storeCredential(credential);
    const presentation = await wallet.createVerifiablePresentation([credential.id]);
    const result = await sp.verifyPresentation(presentation);
    
    if (!result.valid) throw new Error('Verification failed');
    if (result.credentials![0].attributes.givenName !== 'Bob') {
      throw new Error('Invalid credential data');
    }
  });
  
  console.log(`\nTests completed: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(console.error);