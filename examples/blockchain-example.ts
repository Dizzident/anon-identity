import { ethers } from 'ethers';
import { ContractClient } from '../src/blockchain/contract-client';
import { BlockchainConfig } from '../src/blockchain/types';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Comprehensive example demonstrating blockchain integration
 */
async function main() {
  console.log('🚀 Blockchain Integration Example\n');

  // Load deployment configuration
  const deploymentPath = path.join(__dirname, '..', 'deployments', 'latest-localhost.json');
  if (!fs.existsSync(deploymentPath)) {
    console.error('❌ No deployment found. Please run: npx hardhat run scripts/deploy.ts --network localhost');
    return;
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, 'utf8'));
  
  const config: BlockchainConfig = {
    network: 'localhost',
    rpcUrl: 'http://127.0.0.1:8545',
    privateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', // First Hardhat account
    contracts: deployment.contracts
  };

  console.log('📋 Configuration:');
  console.log(`Network: ${config.network}`);
  console.log(`RPC URL: ${config.rpcUrl}`);
  console.log(`DID Registry: ${config.contracts.didRegistry}`);
  console.log(`Revocation Registry: ${config.contracts.revocationRegistry}`);
  console.log(`Schema Registry: ${config.contracts.schemaRegistry}`);

  // Create client
  const client = new ContractClient(config);
  console.log(`\n👤 Client Address: ${client.getAddress()}`);

  try {
    // 1. DID Registry Example
    console.log('\n🆔 === DID Registry Example ===');
    
    const sampleDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    const publicKey = '0x' + 'a'.repeat(64); // 32 bytes
    const documentHash = 'QmSampleIPFSHash123';

    console.log('📝 Registering DID...');
    const registerTx = await client.registerDID(sampleDID, publicKey, documentHash);
    console.log(`Transaction hash: ${registerTx.hash}`);
    
    // Wait for confirmation
    const receipt = await registerTx.wait();
    console.log(`✅ DID registered in block ${receipt?.blockNumber}`);

    // Resolve DID
    console.log('\n🔍 Resolving DID...');
    const didDoc = await client.resolveDID(sampleDID);
    console.log('DID Document:', {
      publicKey: didDoc.publicKey,
      owner: didDoc.owner,
      active: didDoc.active,
      created: Number(didDoc.created),
      documentHash: didDoc.documentHash
    });

    // Check if DID exists
    const exists = await client.didExists(sampleDID);
    console.log(`DID exists: ${exists}`);

    // 2. Schema Registry Example
    console.log('\n📋 === Schema Registry Example ===');
    
    console.log('📝 Registering schema...');
    const schemaRegisterTx = await client.registerSchema(
      'BasicProfile',
      'Basic user profile schema for identity verification',
      'QmSchemaHash456',
      sampleDID,
      '1.0.0',
      0, // BasicProfile type
      [] // No dependencies
    );
    
    await schemaRegisterTx.wait();
    console.log(`✅ Schema registered: ${schemaRegisterTx.hash}`);

    // Get schema by ID
    const schema = await client.getSchema(1);
    console.log('Schema details:', {
      name: schema.name,
      description: schema.description,
      version: schema.version,
      issuer: schema.issuerDID,
      active: schema.active
    });

    // 3. Revocation Registry Example
    console.log('\n🚫 === Revocation Registry Example ===');
    
    // First, authorize the issuer (this would typically be done by contract owner)
    console.log('🔐 Authorizing issuer...');
    const authTx = await client.authorizeIssuer(sampleDID);
    await authTx.wait();
    console.log(`✅ Issuer authorized: ${authTx.hash}`);

    // Create some credential hashes to revoke
    const credentialId1 = 'urn:uuid:credential-123';
    const credentialId2 = 'urn:uuid:credential-456';
    const credentialHash1 = ethers.keccak256(ethers.toUtf8Bytes(credentialId1));
    const credentialHash2 = ethers.keccak256(ethers.toUtf8Bytes(credentialId2));

    console.log('\n📝 Publishing revocation list...');
    const mockSignature = '0x' + 'a'.repeat(128); // Mock signature
    const revocationTx = await client.publishRevocationList(
      sampleDID,
      [credentialHash1, credentialHash2],
      mockSignature
    );
    
    await revocationTx.wait();
    console.log(`✅ Revocation list published: ${revocationTx.hash}`);

    // Check revocation status
    console.log('\n🔍 Checking revocation status...');
    const isRevoked1 = await client.isCredentialRevoked(sampleDID, credentialId1);
    const isRevoked2 = await client.isCredentialRevoked(sampleDID, credentialId2);
    const isRevoked3 = await client.isCredentialRevoked(sampleDID, 'urn:uuid:credential-999');

    console.log(`Credential 1 revoked: ${isRevoked1}`);
    console.log(`Credential 2 revoked: ${isRevoked2}`);
    console.log(`Credential 3 revoked: ${isRevoked3}`);

    // Get revocation list
    const revocationList = await client.getRevocationList(sampleDID);
    console.log('Revocation list:', {
      revokedCount: revocationList.revokedCredentialIds.length,
      version: Number(revocationList.version),
      timestamp: Number(revocationList.timestamp)
    });

    // 4. Event Listening Example
    console.log('\n📡 === Event Listening Example ===');
    
    console.log('🎧 Setting up event listeners...');
    
    client.onDIDRegistered((did, owner, publicKey, timestamp) => {
      console.log(`📢 DID Registered Event: ${did} by ${owner}`);
    });

    client.onCredentialRevoked((issuerHash, credentialHash, issuerDID, timestamp) => {
      console.log(`📢 Credential Revoked Event: ${credentialHash} by ${issuerDID}`);
    });

    client.onSchemaRegistered((schemaId, issuerDID, name, version, schemaType, timestamp) => {
      console.log(`📢 Schema Registered Event: ${name} v${version} by ${issuerDID}`);
    });

    // Test another operation to trigger events
    console.log('\n📝 Testing additional operations...');
    const anotherDID = 'did:key:z6MkpqCcLGrqpDjDHU8hqQQQP9ZGGd4VrMjGVTKGrqpDjDHU';
    const anotherRegisterTx = await client.registerDID(anotherDID, publicKey, 'QmAnotherHash');
    await anotherRegisterTx.wait();

    // Give events time to process
    await new Promise(resolve => setTimeout(resolve, 1000));

    // 5. Gas Estimation and Utilities
    console.log('\n⛽ === Gas and Utilities ===');
    
    const gasPrice = await client.getGasPrice();
    console.log(`Current gas price: ${ethers.formatUnits(gasPrice, 'gwei')} gwei`);

    const balance = await client.getBalance();
    console.log(`Account balance: ${ethers.formatEther(balance)} ETH`);

    // Clean up event listeners
    client.removeAllListeners();
    console.log('🧹 Event listeners cleaned up');

    console.log('\n🎉 Blockchain integration example completed successfully!');
    
    console.log('\n📊 Summary:');
    console.log('✅ DID Registry: Registered and resolved DIDs');
    console.log('✅ Schema Registry: Registered and retrieved schemas');
    console.log('✅ Revocation Registry: Published revocation lists and checked status');
    console.log('✅ Event Listening: Set up and tested event handlers');
    console.log('✅ Utilities: Checked gas prices and balances');

  } catch (error) {
    console.error('❌ Error during blockchain operations:', error);
    throw error;
  }
}

// Run the example
if (require.main === module) {
  main()
    .then(() => {
      console.log('\n✨ Example completed successfully!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Example failed:', error);
      process.exit(1);
    });
}

export { main as runBlockchainExample };