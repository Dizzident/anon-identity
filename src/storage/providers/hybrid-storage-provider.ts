import { IStorageProvider, RevocationList, CredentialSchema, StorageConfig } from '../types';
import { VerifiableCredential } from '../../types';
import { DIDDocument } from '../../types/did';
import { StorageFactory } from '../storage-factory';
import { v4 as uuidv4 } from 'uuid';

interface HybridStorageConfig extends StorageConfig {
  hybrid?: {
    // Routing configuration
    routing?: {
      dids?: 'blockchain' | 'ipfs' | 'local';
      credentials?: 'blockchain' | 'ipfs' | 'local';
      revocations?: 'blockchain' | 'ipfs' | 'local';
      schemas?: 'blockchain' | 'ipfs' | 'local';
    };
    // Size thresholds for automatic routing
    sizeThresholds?: {
      useIPFS?: number; // Bytes - data larger than this goes to IPFS
      useLocal?: number; // Bytes - data smaller than this stays local
    };
    // Synchronization settings
    sync?: {
      enabled: boolean;
      interval?: number; // milliseconds
      conflictResolution?: 'newest' | 'blockchain' | 'local';
    };
    // Fallback configuration
    fallback?: {
      enabled: boolean;
      order?: ('blockchain' | 'ipfs' | 'local')[];
      retries?: number;
      retryDelay?: number; // milliseconds
    };
  };
}

export class HybridStorageProvider implements IStorageProvider {
  private providers: {
    blockchain?: IStorageProvider;
    ipfs?: IStorageProvider;
    local: IStorageProvider;
  };
  
  private config: HybridStorageConfig;
  private syncInterval?: NodeJS.Timeout;
  private dataIndex: Map<string, Set<'blockchain' | 'ipfs' | 'local'>> = new Map();

  constructor(config: HybridStorageConfig) {
    this.config = config;
    
    // Initialize providers based on configuration
    this.providers = {
      local: StorageFactory.createProvider({ provider: 'memory' }), // Always have local
    };

    if (config.blockchain) {
      this.providers.blockchain = StorageFactory.createProvider({
        provider: 'blockchain',
        blockchain: config.blockchain,
        cache: config.cache,
      });
    }

    if (config.ipfs) {
      try {
        this.providers.ipfs = StorageFactory.createProvider({
          provider: 'ipfs',
          ipfs: config.ipfs,
        });
      } catch (error) {
        console.warn('IPFS provider initialization failed:', error);
        // Continue without IPFS provider
      }
    }

    // Start synchronization if enabled
    if (config.hybrid?.sync?.enabled) {
      this.startSync();
    }
  }

  // Routing logic
  private getProviderForDataType(
    dataType: 'did' | 'credential' | 'revocation' | 'schema',
    dataSize?: number
  ): ('blockchain' | 'ipfs' | 'local')[] {
    const routing = this.config.hybrid?.routing;
    const thresholds = this.config.hybrid?.sizeThresholds;
    const providers: ('blockchain' | 'ipfs' | 'local')[] = [];

    // Check explicit routing configuration
    if (routing) {
      const explicitRoute = routing[`${dataType}s` as keyof typeof routing];
      if (explicitRoute && this.providers[explicitRoute]) {
        providers.push(explicitRoute);
      }
    }

    // If no explicit routing, use intelligent routing based on data characteristics
    if (providers.length === 0) {
      switch (dataType) {
        case 'did':
          // DIDs are small and need high availability - blockchain + local
          if (this.providers.blockchain) providers.push('blockchain');
          providers.push('local');
          break;
          
        case 'revocation':
          // Revocations must be publicly verifiable - blockchain
          if (this.providers.blockchain) {
            providers.push('blockchain');
          } else if (this.providers.ipfs) {
            providers.push('ipfs');
          }
          providers.push('local');
          break;
          
        case 'schema':
          // Schemas are public and rarely change - IPFS + blockchain
          if (this.providers.ipfs) providers.push('ipfs');
          if (this.providers.blockchain) providers.push('blockchain');
          providers.push('local');
          break;
          
        case 'credential':
          // Route based on size if available
          if (dataSize && thresholds) {
            if (dataSize > (thresholds.useIPFS || 10240) && this.providers.ipfs) {
              providers.push('ipfs');
            } else if (dataSize < (thresholds.useLocal || 1024)) {
              providers.push('local');
            } else if (this.providers.blockchain) {
              providers.push('blockchain');
            }
          } else {
            // Default: IPFS for full data, blockchain for hash
            if (this.providers.ipfs) providers.push('ipfs');
            if (this.providers.blockchain) providers.push('blockchain');
            providers.push('local');
          }
          break;
      }
    }

    // Always ensure at least local storage
    if (!providers.includes('local')) {
      providers.push('local');
    }

    return providers;
  }

  // Execute operation with fallback support
  private async executeWithFallback<T>(
    operation: (provider: IStorageProvider) => Promise<T>,
    providers: ('blockchain' | 'ipfs' | 'local')[],
    fallbackOperation?: (provider: IStorageProvider) => Promise<T>
  ): Promise<T> {
    const fallbackConfig = this.config.hybrid?.fallback;
    const maxRetries = fallbackConfig?.retries || 3;
    const retryDelay = fallbackConfig?.retryDelay || 1000;

    let lastError: Error | null = null;
    
    for (const providerType of providers) {
      const provider = this.providers[providerType];
      if (!provider) continue;

      for (let retry = 0; retry < maxRetries; retry++) {
        try {
          return await operation(provider);
        } catch (error) {
          lastError = error as Error;
          console.warn(`Provider ${providerType} failed (retry ${retry + 1}/${maxRetries}):`, error);
          
          if (retry < maxRetries - 1) {
            await new Promise(resolve => setTimeout(resolve, retryDelay * (retry + 1)));
          }
        }
      }

      // Try fallback operation if main operation failed
      if (fallbackOperation && fallbackConfig?.enabled) {
        try {
          return await fallbackOperation(provider);
        } catch (fallbackError) {
          console.warn(`Fallback operation also failed for ${providerType}:`, fallbackError);
        }
      }
    }

    throw lastError || new Error('All storage providers failed');
  }

  // Track where data is stored
  private trackDataLocation(key: string, providers: ('blockchain' | 'ipfs' | 'local')[]) {
    if (!this.dataIndex.has(key)) {
      this.dataIndex.set(key, new Set());
    }
    providers.forEach(p => this.dataIndex.get(key)!.add(p));
  }

  // DID Operations
  async storeDID(did: string, document: DIDDocument): Promise<void> {
    const providers = this.getProviderForDataType('did');
    const key = `did:${did}`;
    
    // Store in all designated providers
    const storePromises = providers.map(providerType => {
      const provider = this.providers[providerType];
      if (provider) {
        return provider.storeDID(did, document)
          .then(() => this.trackDataLocation(key, [providerType]))
          .catch(err => console.error(`Failed to store DID in ${providerType}:`, err));
      }
      return Promise.resolve();
    });

    await Promise.all(storePromises);
  }

  async resolveDID(did: string): Promise<DIDDocument | null> {
    const key = `did:${did}`;
    const locations = this.dataIndex.get(key) || new Set(this.getProviderForDataType('did'));
    
    return this.executeWithFallback(
      async (provider) => provider.resolveDID(did),
      Array.from(locations)
    );
  }

  async listDIDs(owner?: string): Promise<string[]> {
    // Aggregate from all providers
    const allDIDs = new Set<string>();
    
    for (const [providerType, provider] of Object.entries(this.providers)) {
      if (provider) {
        try {
          const dids = await provider.listDIDs(owner);
          dids.forEach(did => allDIDs.add(did));
        } catch (error) {
          console.warn(`Failed to list DIDs from ${providerType}:`, error);
        }
      }
    }
    
    return Array.from(allDIDs);
  }

  // Credential Operations
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    const dataSize = JSON.stringify(credential).length;
    const providers = this.getProviderForDataType('credential', dataSize);
    const key = `credential:${credential.id}`;
    
    // For hybrid storage, we might store full data in IPFS and hash on blockchain
    if (providers.includes('blockchain') && providers.includes('ipfs')) {
      // Store full credential in IPFS
      if (this.providers.ipfs) {
        await this.providers.ipfs.storeCredential(credential);
      }
      
      // Store only hash/reference on blockchain
      if (this.providers.blockchain) {
        // The blockchain provider already handles this by storing hashes
        await this.providers.blockchain.storeCredential(credential);
      }
      
      this.trackDataLocation(key, ['blockchain', 'ipfs']);
    } else {
      // Store in all designated providers
      const storePromises = providers.map(providerType => {
        const provider = this.providers[providerType];
        if (provider) {
          return provider.storeCredential(credential)
            .then(() => this.trackDataLocation(key, [providerType]))
            .catch(err => console.error(`Failed to store credential in ${providerType}:`, err));
        }
        return Promise.resolve();
      });

      await Promise.all(storePromises);
    }
  }

  async getCredential(id: string): Promise<VerifiableCredential | null> {
    const key = `credential:${id}`;
    const locations = this.dataIndex.get(key) || new Set(this.getProviderForDataType('credential'));
    
    // Prefer IPFS for full credential data
    const orderedLocations = Array.from(locations).sort((a, b) => {
      if (a === 'ipfs') return -1;
      if (b === 'ipfs') return 1;
      return 0;
    });
    
    return this.executeWithFallback(
      async (provider) => provider.getCredential(id),
      orderedLocations
    );
  }

  async listCredentials(holder: string): Promise<VerifiableCredential[]> {
    // Aggregate from all providers, removing duplicates
    const credentialsMap = new Map<string, VerifiableCredential>();
    
    for (const [providerType, provider] of Object.entries(this.providers)) {
      if (provider) {
        try {
          const credentials = await provider.listCredentials(holder);
          credentials.forEach(cred => credentialsMap.set(cred.id, cred));
        } catch (error) {
          console.warn(`Failed to list credentials from ${providerType}:`, error);
        }
      }
    }
    
    return Array.from(credentialsMap.values());
  }

  async deleteCredential(id: string): Promise<void> {
    const key = `credential:${id}`;
    const locations = this.dataIndex.get(key) || new Set(['local']);
    
    // Delete from all locations
    const deletePromises = Array.from(locations).map(providerType => {
      const provider = this.providers[providerType];
      if (provider && providerType !== 'blockchain') { // Can't delete from blockchain
        return provider.deleteCredential(id)
          .catch(err => console.error(`Failed to delete credential from ${providerType}:`, err));
      }
      return Promise.resolve();
    });

    await Promise.all(deletePromises);
    this.dataIndex.delete(key);
  }

  // Revocation Operations
  async publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void> {
    const providers = this.getProviderForDataType('revocation');
    const key = `revocation:${issuerDID}`;
    
    // Revocations should be on blockchain for public verifiability
    const storePromises = providers.map(providerType => {
      const provider = this.providers[providerType];
      if (provider) {
        return provider.publishRevocation(issuerDID, revocationList)
          .then(() => this.trackDataLocation(key, [providerType]))
          .catch(err => console.error(`Failed to publish revocation in ${providerType}:`, err));
      }
      return Promise.resolve();
    });

    await Promise.all(storePromises);
  }

  async checkRevocation(issuerDID: string, credentialId: string): Promise<boolean> {
    const key = `revocation:${issuerDID}`;
    const locations = this.dataIndex.get(key) || new Set(this.getProviderForDataType('revocation'));
    
    // Check blockchain first for most authoritative answer
    const orderedLocations = Array.from(locations).sort((a, b) => {
      if (a === 'blockchain') return -1;
      if (b === 'blockchain') return 1;
      return 0;
    });
    
    try {
      return await this.executeWithFallback(
        async (provider) => provider.checkRevocation(issuerDID, credentialId),
        orderedLocations
      );
    } catch {
      return false; // Default to not revoked if check fails
    }
  }

  async getRevocationList(issuerDID: string): Promise<RevocationList | null> {
    const key = `revocation:${issuerDID}`;
    const locations = this.dataIndex.get(key) || new Set(this.getProviderForDataType('revocation'));
    
    return this.executeWithFallback(
      async (provider) => provider.getRevocationList(issuerDID),
      Array.from(locations)
    );
  }

  // Key Management (always local)
  async storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void> {
    return this.providers.local.storeKeyPair(identifier, encryptedKeyPair);
  }

  async retrieveKeyPair(identifier: string): Promise<string | null> {
    return this.providers.local.retrieveKeyPair(identifier);
  }

  async deleteKeyPair(identifier: string): Promise<void> {
    return this.providers.local.deleteKeyPair(identifier);
  }

  // Schema Operations
  async registerSchema(schema: CredentialSchema): Promise<string> {
    const providers = this.getProviderForDataType('schema');
    const schemaId = schema.id || `schema:${uuidv4()}`;
    const key = `schema:${schemaId}`;
    
    // Store in all designated providers
    let resultId = schemaId;
    for (const providerType of providers) {
      const provider = this.providers[providerType];
      if (provider) {
        try {
          const id = await provider.registerSchema({ ...schema, id: schemaId });
          resultId = id;
          this.trackDataLocation(key, [providerType]);
        } catch (err) {
          console.error(`Failed to register schema in ${providerType}:`, err);
        }
      }
    }
    
    return resultId;
  }

  async getSchema(schemaId: string): Promise<CredentialSchema | null> {
    const key = `schema:${schemaId}`;
    const locations = this.dataIndex.get(key) || new Set(this.getProviderForDataType('schema'));
    
    return this.executeWithFallback(
      async (provider) => provider.getSchema(schemaId),
      Array.from(locations)
    );
  }

  async listSchemas(issuerDID?: string): Promise<CredentialSchema[]> {
    // Aggregate from all providers, removing duplicates
    const schemasMap = new Map<string, CredentialSchema>();
    
    for (const [providerType, provider] of Object.entries(this.providers)) {
      if (provider) {
        try {
          const schemas = await provider.listSchemas(issuerDID);
          schemas.forEach(schema => {
            if (schema.id) {
              schemasMap.set(schema.id, schema);
            }
          });
        } catch (error) {
          console.warn(`Failed to list schemas from ${providerType}:`, error);
        }
      }
    }
    
    return Array.from(schemasMap.values());
  }

  // General operations
  async clear(): Promise<void> {
    // Clear all providers
    const clearPromises = Object.values(this.providers).map(provider => 
      provider?.clear().catch(err => console.error('Failed to clear provider:', err))
    );
    
    await Promise.all(clearPromises);
    this.dataIndex.clear();
  }

  // Synchronization
  private startSync(): void {
    const interval = this.config.hybrid?.sync?.interval || 60000; // Default 1 minute
    
    this.syncInterval = setInterval(() => {
      this.performSync().catch(err => 
        console.error('Synchronization failed:', err)
      );
    }, interval);
  }

  private async performSync(): Promise<void> {
    console.log('Starting hybrid storage synchronization...');
    
    // Sync DIDs
    const allDIDs = await this.listDIDs();
    for (const did of allDIDs) {
      await this.syncData('did', did);
    }
    
    // Additional sync operations can be added here
    
    console.log('Synchronization completed');
  }

  private async syncData(dataType: string, id: string): Promise<void> {
    const key = `${dataType}:${id}`;
    const locations = this.dataIndex.get(key);
    
    if (!locations || locations.size <= 1) {
      return; // No need to sync if data is in only one location
    }
    
    // Implement conflict resolution based on configuration
    const conflictResolution = this.config.hybrid?.sync?.conflictResolution || 'newest';
    
    // This is a simplified sync - in production, you'd implement
    // proper conflict resolution and data comparison
    console.log(`Syncing ${key} across ${locations.size} locations`);
  }

  // Cleanup
  destroy(): void {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
    }
  }
}