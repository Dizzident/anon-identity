import { StorageFactory } from '../src/storage';
import { v4 as uuidv4 } from 'uuid';

// Test script to verify IPFS provider works with kubo-rpc-client
async function testIPFSProvider() {
  console.log('Testing IPFS Storage Provider with kubo-rpc-client...\n');

  try {
    // Note: This requires a running IPFS node (Kubo) at localhost:5001
    const ipfsProvider = StorageFactory.createProvider({
      provider: 'ipfs',
      ipfs: {
        host: 'localhost',
        port: 5001,
        protocol: 'http'
      }
    });

    console.log('✓ IPFS provider created successfully');

    // Test credential storage
    const testCredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: `urn:uuid:${uuidv4()}`,
      type: ['VerifiableCredential'],
      issuer: 'did:key:test-issuer',
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: 'did:key:test-subject',
        name: 'Test User'
      },
      proof: {
        type: 'JsonWebSignature2020',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: 'did:key:test-issuer#key-1',
        jws: 'test-signature'
      }
    };

    await ipfsProvider.storeCredential(testCredential);
    console.log('✓ Credential stored to IPFS');

    const retrieved = await ipfsProvider.getCredential(testCredential.id);
    console.log('✓ Credential retrieved from IPFS');

    if (JSON.stringify(retrieved) === JSON.stringify(testCredential)) {
      console.log('✓ Retrieved credential matches original');
    } else {
      console.log('✗ Retrieved credential does not match original');
    }

    console.log('\n✅ IPFS provider test completed successfully!');
  } catch (error) {
    console.error('\n❌ IPFS provider test failed:');
    console.error(error);
    console.error('\nNote: This test requires a running IPFS (Kubo) node at localhost:5001');
    console.error('You can start one with: ipfs daemon');
  }
}

// Run the test if this file is executed directly
if (require.main === module) {
  testIPFSProvider().catch(console.error);
}