import { IStorageProvider, StorageConfig } from './types';
import { MemoryStorageProvider } from './providers/memory-storage-provider';
import { FileStorageProvider } from './providers/file-storage-provider';
import { BlockchainStorageProvider } from './providers/blockchain-storage-provider';
// import { IPFSStorageProvider } from './providers/ipfs-storage-provider'; // Commented out due to IPFS import issues
import { HybridStorageProvider } from './providers/hybrid-storage-provider';

export class StorageFactory {
  private static instances: Map<string, IStorageProvider> = new Map();

  static createProvider(config: StorageConfig): IStorageProvider {
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
        provider = new FileStorageProvider(
          config.file.path,
          config.file.encryption
        );
        break;
        
      case 'ipfs':
        throw new Error('IPFS storage provider is currently disabled due to dependency issues');
        // if (!config.ipfs) {
        //   throw new Error('IPFS storage configuration required');
        // }
        // provider = new IPFSStorageProvider(config);
        // break;
        
      case 'blockchain':
        if (!config.blockchain) {
          throw new Error('Blockchain storage configuration required');
        }
        provider = new BlockchainStorageProvider(config);
        break;
        
      case 'hybrid':
        provider = new HybridStorageProvider(config);
        break;
        
      default:
        throw new Error(`Unknown storage provider: ${config.provider}`);
    }

    this.instances.set(key, provider);
    return provider;
  }

  static getDefaultProvider(): IStorageProvider {
    return this.createProvider({ provider: 'memory' });
  }

  static clearInstances(): void {
    this.instances.clear();
  }
}