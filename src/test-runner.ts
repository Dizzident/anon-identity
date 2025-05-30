import { CryptoService } from './core/crypto';
import { DIDService } from './core/did';
import { IdentityProvider } from './idp/identity-provider';
import { UserWallet } from './wallet/user-wallet';
import { ServiceProvider } from './sp/service-provider';
import { SelectiveDisclosure } from './zkp/selective-disclosure';
import { RevocationService } from './revocation/revocation-service';
import { UserAttributes, SelectiveDisclosureRequest } from './types';
import { MemoryStorageProvider, FileStorageProvider } from './storage';
import * as fs from 'fs';
import * as path from 'path';

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
  
  // Test Selective Disclosure
  console.log('\nSelective Disclosure Tests:');
  await test('should create and verify selective disclosure', async () => {
    const idp = await IdentityProvider.create();
    const wallet = await UserWallet.create();
    const sp = new ServiceProvider('Test SP', [idp.getDID()]);
    
    // Issue credential with multiple attributes
    const credential = await idp.issueVerifiableCredential(wallet.getDID(), {
      givenName: 'Charlie',
      dateOfBirth: '1985-12-25'
    });
    
    wallet.storeCredential(credential);
    
    // Create selective disclosure presentation showing only isOver18
    const disclosureRequest: SelectiveDisclosureRequest = {
      credentialId: credential.id,
      attributesToDisclose: ['isOver18']
    };
    
    const presentation = await wallet.createSelectiveDisclosurePresentation([disclosureRequest]);
    const result = await sp.verifyPresentation(presentation);
    
    if (!result.valid) throw new Error('Selective disclosure verification failed');
    
    const verifiedAttrs = result.credentials![0].attributes;
    if (verifiedAttrs.dateOfBirth !== undefined) {
      throw new Error('Birth date should not be revealed');
    }
    if (verifiedAttrs.isOver18 !== true) {
      throw new Error('isOver18 should be true');
    }
  });
  
  await test('should handle multiple attributes in selective disclosure', async () => {
    const idp = await IdentityProvider.create();
    const wallet = await UserWallet.create();
    
    const credential = await idp.issueVerifiableCredential(wallet.getDID(), {
      givenName: 'David',
      dateOfBirth: '2000-01-01'
    });
    
    wallet.storeCredential(credential);
    
    // Disclose both givenName and isOver18, but not dateOfBirth
    const presentation = await wallet.createSelectiveDisclosurePresentation([{
      credentialId: credential.id,
      attributesToDisclose: ['givenName', 'isOver18']
    }]);
    
    const disclosedCred = presentation.verifiableCredential[0];
    const attrs = disclosedCred.credentialSubject;
    
    if (attrs.givenName !== 'David') throw new Error('givenName not disclosed');
    if (attrs.isOver18 !== true) throw new Error('isOver18 not disclosed');
    if (attrs.dateOfBirth !== undefined) throw new Error('dateOfBirth should not be disclosed');
  });
  
  // Test Revocation
  console.log('\nRevocation Tests:');
  await test('should revoke and detect revoked credentials', async () => {
    // Clear any previous revocation data
    RevocationService.clearRegistry();
    
    const idp = await IdentityProvider.create();
    const wallet = await UserWallet.create();
    const sp = new ServiceProvider('Test SP', [idp.getDID()]);
    
    // Issue credential
    const credential = await idp.issueVerifiableCredential(wallet.getDID(), {
      givenName: 'Eve',
      dateOfBirth: '1995-07-10'
    });
    wallet.storeCredential(credential);
    
    // Verify before revocation
    const presentation1 = await wallet.createVerifiablePresentation([credential.id]);
    const result1 = await sp.verifyPresentation(presentation1);
    if (!result1.valid) throw new Error('Credential should be valid before revocation');
    
    // Revoke and publish
    idp.revokeCredential(credential.id);
    await idp.publishRevocationList();
    
    // Verify after revocation
    const result2 = await sp.verifyPresentation(presentation1);
    if (result2.valid) throw new Error('Credential should be invalid after revocation');
    if (!result2.errors?.some(e => e.message.includes('revoked'))) {
      throw new Error('Error should mention revocation');
    }
  });
  
  await test('should handle multiple revocations correctly', async () => {
    RevocationService.clearRegistry();
    
    const idp = await IdentityProvider.create();
    const wallet = await UserWallet.create();
    
    // Issue multiple credentials
    const cred1 = await idp.issueVerifiableCredential(wallet.getDID(), {
      givenName: 'Frank',
      dateOfBirth: '1990-01-01'
    });
    const cred2 = await idp.issueVerifiableCredential(wallet.getDID(), {
      givenName: 'Frank',
      dateOfBirth: '1990-01-01'
    });
    
    // Revoke only the first one
    idp.revokeCredential(cred1.id);
    // Small delay to ensure async operation completes
    await new Promise(resolve => setTimeout(resolve, 100));
    const revList = await idp.getRevocationList();
    
    if (revList.revokedCredentials.length !== 1) {
      throw new Error('Should have exactly one revoked credential');
    }
    if (!revList.revokedCredentials.includes(cred1.id)) {
      throw new Error('Wrong credential revoked');
    }
    if (revList.revokedCredentials.includes(cred2.id)) {
      throw new Error('Second credential should not be revoked');
    }
  });
  
  // Storage Provider Tests
  console.log('\nStorage Provider Tests:');
  
  await test('should store and retrieve DIDs', async () => {
    const provider = new MemoryStorageProvider();
    const testDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    const didDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: testDID,
      verificationMethod: [{
        id: `${testDID}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: testDID,
        publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      }],
      created: new Date().toISOString()
    };
    
    await provider.storeDID(testDID, didDocument);
    const retrieved = await provider.resolveDID(testDID);
    
    if (!retrieved || retrieved.id !== testDID) {
      throw new Error('DID storage/retrieval failed');
    }
  });
  
  await test('should persist data to file', async () => {
    const testFile = path.join(__dirname, 'test-storage.json');
    
    // Clean up any existing test file
    try {
      await fs.promises.unlink(testFile);
    } catch (e) {
      // File doesn't exist, which is fine
    }
    
    const provider1 = new FileStorageProvider(testFile, true, 'test-pass');
    const testDID = 'did:key:z6Mktest123';
    const didDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: testDID,
      verificationMethod: [{
        id: `${testDID}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: testDID,
        publicKeyMultibase: 'z6Mktest123'
      }],
      created: new Date().toISOString()
    };
    
    await provider1.storeDID(testDID, didDocument);
    
    // Create new instance to test persistence
    const provider2 = new FileStorageProvider(testFile, true, 'test-pass');
    const retrieved = await provider2.resolveDID(testDID);
    
    if (!retrieved || retrieved.id !== testDID) {
      throw new Error('File persistence failed');
    }
    
    // Clean up
    try {
      await fs.promises.unlink(testFile);
    } catch (e) {
      // Ignore cleanup errors
    }
  });
  
  console.log(`\nTests completed: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(console.error);