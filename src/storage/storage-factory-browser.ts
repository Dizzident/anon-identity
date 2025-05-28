import { IStorageProvider, StorageConfig } from './types';
import { MemoryStorageProvider } from './providers/memory-storage-provider';

/**
 * Browser-compatible storage factory
 * Only supports memory storage in the browser
 */
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
        throw new Error('File storage is not available in browser environment. Use memory storage instead.');
        
      case 'ipfs':
        throw new Error('IPFS storage requires a server-side proxy in browser environment.');
        
      case 'blockchain':
        throw new Error('Blockchain storage requires a server-side proxy in browser environment.');
        
      case 'hybrid':
        throw new Error('Hybrid storage is not available in browser environment. Use memory storage instead.');
        
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