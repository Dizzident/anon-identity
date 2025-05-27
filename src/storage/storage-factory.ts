import { IStorageProvider, StorageConfig } from './types';
import { MemoryStorageProvider } from './providers/memory-storage-provider';
import { FileStorageProvider } from './providers/file-storage-provider';

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
        // TODO: Implement IPFSStorageProvider
        throw new Error('IPFS storage provider not yet implemented');
        
      case 'blockchain':
        // TODO: Implement BlockchainStorageProvider
        throw new Error('Blockchain storage provider not yet implemented');
        
      case 'hybrid':
        // TODO: Implement HybridStorageProvider
        throw new Error('Hybrid storage provider not yet implemented');
        
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