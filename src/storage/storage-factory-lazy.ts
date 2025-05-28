import { IStorageProvider, StorageConfig } from './types';
import { MemoryStorageProvider } from './providers/memory-storage-provider';

export class StorageFactory {
  private static instances: Map<string, IStorageProvider> = new Map();

  static async createProvider(config: StorageConfig): Promise<IStorageProvider> {
    const key = JSON.stringify(config);
    
    // Return existing instance if available
    if (this.instances.has(key)) {
      return this.instances.get(key)!;
    }

    let provider: IStorageProvider;

    switch (config.provider) {
      case 'memory':
        provider = new MemoryStorageProvider();
        break;
        
      case 'file':
        if (!config.file) {
          throw new Error('File storage configuration required');
        }
        // Dynamic import for Node.js environments
        const { FileStorageProvider } = await import('./providers/file-storage-provider-lazy');
        provider = new FileStorageProvider(
          config.file.path,
          config.file.encryption || false
        );
        break;
        
      case 'ipfs':
        if (!config.ipfs) {
          throw new Error('IPFS storage configuration required');
        }
        // Dynamic import for IPFS
        const { IPFSStorageProvider } = await import('./providers/ipfs-storage-provider');
        provider = new IPFSStorageProvider(config);
        break;
        
      case 'blockchain':
        if (!config.blockchain) {
          throw new Error('Blockchain storage configuration required');
        }
        // Dynamic import for blockchain
        const { BlockchainStorageProvider } = await import('./providers/blockchain-storage-provider-lazy');
        provider = new BlockchainStorageProvider(config);
        break;
        
      case 'hybrid':
        // Dynamic import for hybrid storage
        const { HybridStorageProvider } = await import('./providers/hybrid-storage-provider');
        provider = new HybridStorageProvider(config);
        break;
        
      default:
        throw new Error(`Unknown storage provider: ${config.provider}`);
    }

    this.instances.set(key, provider);
    return provider;
  }

  static async getDefaultProvider(): Promise<IStorageProvider> {
    return this.createProvider({ provider: 'memory' });
  }

  static clearInstances(): void {
    this.instances.clear();
  }
}