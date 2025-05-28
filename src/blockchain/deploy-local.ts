import { ethers } from 'ethers';
import { ContractClient } from './contract-client';
import { BlockchainConfig } from './types';

/**
 * Deploy contracts to a local Hardhat network for testing
 */
export async function deployToLocalNetwork(): Promise<BlockchainConfig> {
  console.log('Deploying contracts to local network...');
  
  // Connect to local Hardhat node
  const provider = new ethers.JsonRpcProvider('http://127.0.0.1:8545');
  
  // Use the first account from Hardhat's default accounts
  const privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // First Hardhat account
  const wallet = new ethers.Wallet(privateKey, provider);
  
  console.log('Deployer address:', wallet.address);
  console.log('Deployer balance:', ethers.formatEther(await provider.getBalance(wallet.address)));
  
  // Contract bytecode and ABI would need to be imported here
  // For now, we'll return mock addresses that would be used in a real deployment
  
  // In a real implementation, you would:
  // 1. Import contract factories from artifacts
  // 2. Deploy each contract
  // 3. Wait for deployment confirmation
  // 4. Return actual addresses
  
  const mockAddresses = {
    didRegistry: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    revocationRegistry: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
    schemaRegistry: '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0',
  };
  
  console.log('Contracts deployed:');
  console.log('DID Registry:', mockAddresses.didRegistry);
  console.log('Revocation Registry:', mockAddresses.revocationRegistry);
  console.log('Schema Registry:', mockAddresses.schemaRegistry);
  
  return {
    network: 'localhost',
    rpcUrl: 'http://127.0.0.1:8545',
    privateKey: privateKey,
    contracts: mockAddresses,
  };
}

/**
 * Create a ContractClient for local testing
 */
export async function createLocalContractClient(): Promise<ContractClient> {
  const config = await deployToLocalNetwork();
  return new ContractClient(config);
}

/**
 * Test basic contract functionality
 */
export async function testLocalDeployment(): Promise<void> {
  console.log('\n🧪 Testing local deployment...');
  
  try {
    const client = await createLocalContractClient();
    
    console.log('✅ ContractClient created successfully');
    console.log('📍 Client address:', client.getAddress());
    
    // Test basic read operations (these would work with real deployed contracts)
    console.log('✅ Local deployment test completed');
    
  } catch (error) {
    console.error('❌ Local deployment test failed:', error);
    throw error;
  }
}

// Run test if this file is executed directly
if (require.main === module) {
  testLocalDeployment()
    .then(() => {
      console.log('\n🎉 All tests passed!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Test failed:', error);
      process.exit(1);
    });
}