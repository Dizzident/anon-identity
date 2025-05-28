export interface BlockchainConfig {
  network: 'ethereum' | 'polygon' | 'arbitrum' | 'localhost';
  rpcUrl: string;
  privateKey?: string; // For write operations
  contracts: {
    didRegistry: string;
    revocationRegistry: string;
    schemaRegistry: string;
  };
}

export interface ContractAddresses {
  didRegistry: string;
  revocationRegistry: string;
  schemaRegistry: string;
}

export interface NetworkConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  blockExplorerUrl?: string;
  gasPrice?: string;
  gasLimit?: number;
}

export const SUPPORTED_NETWORKS: Record<string, NetworkConfig> = {
  localhost: {
    chainId: 1337,
    name: 'Localhost',
    rpcUrl: 'http://127.0.0.1:8545',
  },
  sepolia: {
    chainId: 11155111,
    name: 'Sepolia Testnet',
    rpcUrl: 'https://sepolia.infura.io/v3/',
    blockExplorerUrl: 'https://sepolia.etherscan.io',
  },
  polygon: {
    chainId: 137,
    name: 'Polygon Mainnet',
    rpcUrl: 'https://polygon-rpc.com',
    blockExplorerUrl: 'https://polygonscan.com',
  },
  arbitrum: {
    chainId: 42161,
    name: 'Arbitrum One',
    rpcUrl: 'https://arb1.arbitrum.io/rpc',
    blockExplorerUrl: 'https://arbiscan.io',
  },
};