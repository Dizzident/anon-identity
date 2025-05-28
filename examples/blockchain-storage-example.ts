/**
 * Example: Using Blockchain Storage Provider
 * 
 * This example demonstrates how to use the BlockchainStorageProvider
 * for decentralized identity management with on-chain storage.
 */

import { 
  DIDManager, 
  CredentialIssuer, 
  CredentialVerifier,
  StorageFactory,
  StorageConfig
} from '../src';
import { ethers } from 'ethers';

async function main() {
  console.log('=== Blockchain Storage Provider Example ===\n');

  // Configure blockchain storage
  const storageConfig: StorageConfig = {
    provider: 'blockchain',
    blockchain: {
      network: 'ethereum',
      rpcUrl: process.env.RPC_URL || 'http://localhost:8545',
      privateKey: process.env.PRIVATE_KEY || '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
      contracts: {
        didRegistry: process.env.DID_REGISTRY || '0x5FbDB2315678afecb367f032d93F642f64180aa3',
        revocationRegistry: process.env.REVOCATION_REGISTRY || '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
        schemaRegistry: process.env.SCHEMA_REGISTRY || '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0',
      },
    },
    cache: {
      enabled: true,
      ttl: 300, // 5 minutes
      maxSize: 50, // 50MB
    },
  };

  // Create storage provider
  const storageProvider = StorageFactory.createProvider(storageConfig);

  // Initialize managers with blockchain storage
  const didManager = new DIDManager(storageProvider);
  const issuer = new CredentialIssuer(storageProvider);
  const verifier = new CredentialVerifier(storageProvider);

  try {
    // Step 1: Create DIDs
    console.log('1. Creating DIDs on blockchain...');
    const aliceDID = await didManager.createDID();
    const bobDID = await didManager.createDID();
    const issuerDID = await didManager.createDID();
    
    console.log('Alice DID:', aliceDID.id);
    console.log('Bob DID:', bobDID.id);
    console.log('Issuer DID:', issuerDID.id);

    // Step 2: Register a credential schema
    console.log('\n2. Registering credential schema on blockchain...');
    const schemaId = await storageProvider.registerSchema({
      name: 'IdentityCredential',
      description: 'Basic identity credential schema',
      properties: {
        name: { type: 'string', required: true },
        dateOfBirth: { type: 'string', format: 'date' },
        nationalId: { type: 'string' },
      },
      issuerDID: issuerDID.id,
      version: '1.0',
      active: true,
    });
    console.log('Schema registered with ID:', schemaId);

    // Step 3: Issue credentials
    console.log('\n3. Issuing credentials (storing on blockchain)...');
    const aliceCredential = await issuer.issueCredential(
      issuerDID,
      aliceDID.id,
      {
        name: 'Alice Johnson',
        dateOfBirth: '1990-01-15',
        nationalId: 'ID123456',
      },
      ['IdentityCredential']
    );

    const bobCredential = await issuer.issueCredential(
      issuerDID,
      bobDID.id,
      {
        name: 'Bob Smith',
        dateOfBirth: '1985-06-20',
        nationalId: 'ID789012',
      },
      ['IdentityCredential']
    );

    console.log('Issued credential for Alice:', aliceCredential.id);
    console.log('Issued credential for Bob:', bobCredential.id);

    // Step 4: Verify credentials
    console.log('\n4. Verifying credentials from blockchain...');
    const aliceVerified = await verifier.verifyCredential(aliceCredential);
    const bobVerified = await verifier.verifyCredential(bobCredential);
    
    console.log('Alice credential valid:', aliceVerified);
    console.log('Bob credential valid:', bobVerified);

    // Step 5: Demonstrate revocation
    console.log('\n5. Revoking Bob\'s credential on blockchain...');
    await issuer.revokeCredential(issuerDID.id, bobCredential.id);
    
    // Check revocation status
    const isBobRevoked = await storageProvider.checkRevocation(issuerDID.id, bobCredential.id);
    console.log('Bob credential revoked:', isBobRevoked);

    // Verify again after revocation
    const bobVerifiedAfterRevocation = await verifier.verifyCredential(bobCredential);
    console.log('Bob credential valid after revocation:', bobVerifiedAfterRevocation);

    // Step 6: Demonstrate gas optimization with merkle trees
    console.log('\n6. Demonstrating gas-optimized batch revocation...');
    
    // Create multiple credentials for batch revocation
    const batchCredentials = [];
    for (let i = 0; i < 5; i++) {
      const credential = await issuer.issueCredential(
        issuerDID,
        aliceDID.id,
        { id: `batch-${i}`, data: `Test data ${i}` },
        ['TestCredential']
      );
      batchCredentials.push(credential);
    }

    // Batch revoke using merkle tree
    const revocationList = {
      issuerDID: issuerDID.id,
      revokedCredentialIds: batchCredentials.map(c => c.id),
      timestamp: Date.now(),
      signature: 'batch-signature', // In production, this would be a real signature
    };

    await storageProvider.publishRevocation(issuerDID.id, revocationList);
    console.log(`Batch revoked ${batchCredentials.length} credentials with single merkle root`);

    // Step 7: Query blockchain events
    console.log('\n7. Querying blockchain events...');
    
    // List all DIDs from events
    const allDIDs = await storageProvider.listDIDs();
    console.log('Total DIDs on blockchain:', allDIDs.length);

    // List schemas by issuer
    const issuerSchemas = await storageProvider.listSchemas(issuerDID.id);
    console.log('Schemas registered by issuer:', issuerSchemas.length);

    // Step 8: Demonstrate caching
    console.log('\n8. Demonstrating cache performance...');
    
    // First call - hits blockchain
    const start1 = Date.now();
    await storageProvider.resolveDID(aliceDID.id);
    const time1 = Date.now() - start1;
    console.log(`First DID resolution (blockchain): ${time1}ms`);
    
    // Second call - hits cache
    const start2 = Date.now();
    await storageProvider.resolveDID(aliceDID.id);
    const time2 = Date.now() - start2;
    console.log(`Second DID resolution (cache): ${time2}ms`);
    console.log(`Cache speedup: ${(time1 / time2).toFixed(1)}x`);

    // Step 9: Gas estimation
    console.log('\n9. Gas usage information...');
    console.log('Note: Actual gas usage depends on network and current gas prices');
    console.log('Tips for gas optimization:');
    console.log('- Use batch operations when possible');
    console.log('- Store only essential data on-chain');
    console.log('- Use IPFS for large data (coming in Phase 4)');
    console.log('- Enable caching to reduce blockchain reads');

  } catch (error) {
    console.error('Error:', error);
    console.log('\nNote: This example requires a running blockchain with deployed contracts.');
    console.log('Please ensure:');
    console.log('1. Hardhat node is running: npx hardhat node');
    console.log('2. Contracts are deployed: npm run deploy:local');
    console.log('3. Contract addresses are set in environment variables');
  }
}

// Run the example
main().catch(console.error);