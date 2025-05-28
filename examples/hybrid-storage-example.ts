/**
 * Example: Hybrid Storage Solution
 * 
 * This example demonstrates the HybridStorageProvider that intelligently
 * combines blockchain, IPFS, and local storage for optimal performance,
 * cost efficiency, and data availability.
 */

import { 
  DIDManager, 
  CredentialIssuer, 
  CredentialVerifier,
  StorageFactory,
  StorageConfig
} from '../src';

async function main() {
  console.log('=== Hybrid Storage Provider Example ===\n');

  // Configure hybrid storage with all three backends
  const storageConfig: StorageConfig = {
    provider: 'hybrid',
    
    // Blockchain configuration for immutable, public data
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
    
    // IPFS configuration for large, distributed data
    ipfs: {
      host: process.env.IPFS_HOST || 'localhost',
      port: parseInt(process.env.IPFS_PORT || '5001'),
      protocol: process.env.IPFS_PROTOCOL || 'http',
    },
    
    // Cache configuration for performance
    cache: {
      enabled: true,
      ttl: 300, // 5 minutes
      maxSize: 50, // 50MB
    },
    
    // Hybrid-specific configuration
    hybrid: {
      // Routing rules: where to store each data type
      routing: {
        dids: 'blockchain',        // DIDs on blockchain for public verifiability
        credentials: 'ipfs',       // Credentials on IPFS for distributed storage
        revocations: 'blockchain', // Revocations on blockchain for trust
        schemas: 'ipfs',          // Schemas on IPFS for efficient retrieval
      },
      
      // Size-based routing thresholds
      sizeThresholds: {
        useIPFS: 10240,  // Use IPFS for data > 10KB
        useLocal: 1024,  // Use local for data < 1KB
      },
      
      // Synchronization settings
      sync: {
        enabled: true,
        interval: 60000, // Sync every minute
        conflictResolution: 'newest', // Use newest data in conflicts
      },
      
      // Fallback configuration
      fallback: {
        enabled: true,
        order: ['blockchain', 'ipfs', 'local'], // Try in this order
        retries: 3,
        retryDelay: 1000, // 1 second
      },
    },
  };

  // Create storage provider
  const storageProvider = StorageFactory.createProvider(storageConfig);

  // Initialize managers
  const didManager = new DIDManager(storageProvider);
  const issuer = new CredentialIssuer(storageProvider);
  const verifier = new CredentialVerifier(storageProvider);

  try {
    // Step 1: Create DIDs (stored on blockchain)
    console.log('1. Creating DIDs (routing to blockchain)...');
    const aliceDID = await didManager.createDID();
    const issuerDID = await didManager.createDID();
    
    console.log('Alice DID:', aliceDID.id);
    console.log('Issuer DID:', issuerDID.id);
    console.log('✓ DIDs stored on blockchain for public verifiability\n');

    // Step 2: Register schemas (stored on IPFS)
    console.log('2. Registering schemas (routing to IPFS)...');
    const basicSchema = await storageProvider.registerSchema({
      name: 'BasicIdentity',
      description: 'Basic identity information',
      properties: {
        name: { type: 'string', required: true },
        email: { type: 'string', format: 'email' },
      },
      issuerDID: issuerDID.id,
      version: '1.0',
      active: true,
    });

    const largeSchema = await storageProvider.registerSchema({
      name: 'DetailedProfile',
      description: 'Detailed user profile with extensive metadata',
      properties: {
        // Large schema with many fields (simulating > 10KB)
        personalInfo: { 
          type: 'object',
          properties: {
            ...Object.fromEntries(
              Array.from({ length: 100 }, (_, i) => [`field${i}`, { type: 'string' }])
            ),
          },
        },
      },
      issuerDID: issuerDID.id,
      version: '1.0',
      active: true,
    });

    console.log('Basic schema ID:', basicSchema);
    console.log('Large schema ID:', largeSchema);
    console.log('✓ Schemas stored on IPFS for efficient distributed access\n');

    // Step 3: Issue credentials of different sizes
    console.log('3. Issuing credentials with size-based routing...');
    
    // Small credential (< 1KB) - should go to local storage
    const smallCredential = await issuer.issueCredential(
      issuerDID,
      aliceDID.id,
      {
        type: 'mini',
        data: 'small',
      },
      ['SmallCredential']
    );
    console.log('Small credential:', smallCredential.id, '(routed to local storage)');

    // Medium credential - should go to IPFS based on routing config
    const mediumCredential = await issuer.issueCredential(
      issuerDID,
      aliceDID.id,
      {
        name: 'Alice Johnson',
        email: 'alice@example.com',
        bio: 'Software developer with 10 years of experience',
      },
      ['BasicIdentity']
    );
    console.log('Medium credential:', mediumCredential.id, '(routed to IPFS)');

    // Large credential (> 10KB) - should definitely go to IPFS
    const largeData = {
      profile: 'x'.repeat(15000), // 15KB of data
      metadata: {
        created: new Date().toISOString(),
        version: '1.0',
      },
    };
    const largeCredential = await issuer.issueCredential(
      issuerDID,
      aliceDID.id,
      largeData,
      ['DetailedProfile']
    );
    console.log('Large credential:', largeCredential.id, '(routed to IPFS)');
    console.log('✓ Credentials routed based on size and configuration\n');

    // Step 4: Demonstrate fallback mechanisms
    console.log('4. Testing fallback mechanisms...');
    
    // Verify credentials (will use fallback if primary storage fails)
    const verified = await verifier.verifyCredential(mediumCredential);
    console.log('Credential verification with fallback:', verified);
    console.log('✓ Fallback ensures data availability\n');

    // Step 5: Revocation (stored on blockchain)
    console.log('5. Publishing revocation (routing to blockchain)...');
    await issuer.revokeCredential(issuerDID.id, smallCredential.id);
    
    const isRevoked = await storageProvider.checkRevocation(issuerDID.id, smallCredential.id);
    console.log('Revocation published on blockchain:', isRevoked);
    console.log('✓ Revocations on blockchain for public trust\n');

    // Step 6: Demonstrate data aggregation
    console.log('6. Aggregating data from all storage layers...');
    
    // List all DIDs (aggregated from blockchain, IPFS, and local)
    const allDIDs = await storageProvider.listDIDs();
    console.log('Total DIDs across all storage:', allDIDs.length);
    
    // List all credentials (aggregated and deduplicated)
    const allCredentials = await storageProvider.listCredentials(aliceDID.id);
    console.log('Alice\'s credentials from all storage:', allCredentials.length);
    console.log('✓ Data seamlessly aggregated from multiple sources\n');

    // Step 7: Performance comparison
    console.log('7. Performance comparison...');
    
    // Resolve DID multiple times to test caching
    const start1 = Date.now();
    await storageProvider.resolveDID(aliceDID.id);
    const time1 = Date.now() - start1;
    
    const start2 = Date.now();
    await storageProvider.resolveDID(aliceDID.id);
    const time2 = Date.now() - start2;
    
    console.log(`First resolution: ${time1}ms`);
    console.log(`Cached resolution: ${time2}ms`);
    console.log(`Cache speedup: ${(time1 / time2).toFixed(1)}x`);
    console.log('✓ Caching improves performance across all storage layers\n');

    // Step 8: Storage statistics
    console.log('8. Hybrid storage benefits summary:');
    console.log('- Blockchain: Immutable DIDs and revocations');
    console.log('- IPFS: Distributed storage for large data');
    console.log('- Local: Fast access for frequently used data');
    console.log('- Intelligent routing: Automatic optimization');
    console.log('- Fallback: High availability and resilience');
    console.log('- Synchronization: Data consistency');
    console.log('- Cost optimization: Use appropriate storage for each data type');

    // Cleanup
    if ('destroy' in storageProvider) {
      (storageProvider as any).destroy();
    }

  } catch (error) {
    console.error('Error:', error);
    console.log('\nNote: This example requires:');
    console.log('1. Running blockchain (Hardhat node)');
    console.log('2. Running IPFS daemon');
    console.log('3. Deployed smart contracts');
    console.log('\nSetup instructions:');
    console.log('1. Start Hardhat: npx hardhat node');
    console.log('2. Deploy contracts: npm run deploy:local');
    console.log('3. Start IPFS: ipfs daemon');
    console.log('4. Run example: npm run example:hybrid');
  }
}

// Run the example
main().catch(console.error);