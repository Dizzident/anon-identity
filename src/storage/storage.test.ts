import { MemoryStorageProvider } from './providers/memory-storage-provider';
import { FileStorageProvider } from './providers/file-storage-provider';
import { IStorageProvider, CredentialSchema } from './types';
import { VerifiableCredential } from '../types';
import { DIDDocument } from '../types/did';
import * as fs from 'fs';
import * as path from 'path';

const testStorageProvider = async (provider: IStorageProvider, name: string) => {
  console.log(`\n${name} Tests:`);
  
  // Test DID operations
  const testDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const didDocument: DIDDocument = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: testDID,
    verificationMethod: [{
      id: `${testDID}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: testDID,
      publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    }],
    authentication: [`${testDID}#key-1`],
    created: new Date().toISOString()
  };
  
  await provider.storeDID(testDID, didDocument);
  const retrievedDID = await provider.resolveDID(testDID);
  
  if (!retrievedDID || retrievedDID.id !== testDID) {
    throw new Error('DID storage/retrieval failed');
  }
  console.log('✓ DID storage and retrieval');
  
  // Test credential operations
  const credential: VerifiableCredential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: 'urn:uuid:test-credential',
    type: ['VerifiableCredential'],
    issuer: testDID,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: 'did:key:holder123',
      name: 'Test User'
    }
  };
  
  await provider.storeCredential(credential);
  const retrievedCred = await provider.getCredential(credential.id);
  
  if (!retrievedCred || retrievedCred.id !== credential.id) {
    throw new Error('Credential storage/retrieval failed');
  }
  console.log('✓ Credential storage and retrieval');
  
  // Test revocation operations
  await provider.publishRevocation(testDID, {
    issuerDID: testDID,
    revokedCredentialIds: [credential.id],
    timestamp: Date.now(),
    signature: 'test-signature'
  });
  
  const isRevoked = await provider.checkRevocation(testDID, credential.id);
  if (!isRevoked) {
    throw new Error('Revocation check failed');
  }
  console.log('✓ Revocation operations');
  
  // Test schema operations
  const schema: CredentialSchema = {
    name: 'TestSchema',
    description: 'Test credential schema',
    properties: {
      name: { type: 'string', required: true }
    },
    issuerDID: testDID,
    version: '1.0.0',
    active: true
  };
  
  const schemaId = await provider.registerSchema(schema);
  const retrievedSchema = await provider.getSchema(schemaId);
  
  if (!retrievedSchema || retrievedSchema.name !== schema.name) {
    throw new Error('Schema storage/retrieval failed');
  }
  console.log('✓ Schema operations');
  
  // Clean up
  await provider.clear();
  const afterClear = await provider.listDIDs();
  if (afterClear.length !== 0) {
    throw new Error('Clear operation failed');
  }
  console.log('✓ Clear operation');
};

export const runStorageTests = async () => {
  console.log('Storage Provider Tests:');
  
  // Test MemoryStorageProvider
  const memoryProvider = new MemoryStorageProvider();
  await testStorageProvider(memoryProvider, 'MemoryStorageProvider');
  
  // Test FileStorageProvider
  const testFilePath = path.join(__dirname, 'test-storage.json');
  
  // Clean up any existing test file
  try {
    await fs.promises.unlink(testFilePath);
  } catch (e) {
    // File doesn't exist, which is fine
  }
  
  const fileProvider = new FileStorageProvider(testFilePath, true, 'test-passphrase');
  await testStorageProvider(fileProvider, 'FileStorageProvider');
  
  // Test persistence
  console.log('\nTesting FileStorageProvider persistence:');
  const testDID = 'did:key:z6MkpersistenceTest';
  const didDoc: DIDDocument = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: testDID,
    verificationMethod: [{
      id: `${testDID}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: testDID,
      publicKeyMultibase: 'z6MkpersistenceTest'
    }],
    created: new Date().toISOString()
  };
  
  await fileProvider.storeDID(testDID, didDoc);
  
  // Create new instance to test persistence
  const fileProvider2 = new FileStorageProvider(testFilePath, true, 'test-passphrase');
  const persistedDID = await fileProvider2.resolveDID(testDID);
  
  if (!persistedDID || persistedDID.id !== testDID) {
    throw new Error('File persistence failed');
  }
  console.log('✓ File persistence across instances');
  
  // Clean up test file
  try {
    await fs.promises.unlink(testFilePath);
  } catch (e) {
    console.error('Failed to clean up test file:', e);
  }
};