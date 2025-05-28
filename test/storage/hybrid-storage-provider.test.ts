import { HybridStorageProvider } from '../../src/storage/providers/hybrid-storage-provider';
import { StorageConfig } from '../../src/storage/types';
import { DIDDocument } from '../../src/types/did';
import { VerifiableCredential } from '../../src/types';
import { RevocationList, CredentialSchema } from '../../src/storage/types';

// Mock the storage factory
jest.mock('../../src/storage/storage-factory', () => {
  const mockMemoryProvider = {
    storeDID: jest.fn().mockResolvedValue(undefined),
    resolveDID: jest.fn().mockResolvedValue(null),
    listDIDs: jest.fn().mockResolvedValue([]),
    storeCredential: jest.fn().mockResolvedValue(undefined),
    getCredential: jest.fn().mockResolvedValue(null),
    listCredentials: jest.fn().mockResolvedValue([]),
    deleteCredential: jest.fn().mockResolvedValue(undefined),
    publishRevocation: jest.fn().mockResolvedValue(undefined),
    checkRevocation: jest.fn().mockResolvedValue(false),
    getRevocationList: jest.fn().mockResolvedValue(null),
    storeKeyPair: jest.fn().mockResolvedValue(undefined),
    retrieveKeyPair: jest.fn().mockResolvedValue(null),
    deleteKeyPair: jest.fn().mockResolvedValue(undefined),
    registerSchema: jest.fn().mockResolvedValue('schema:123'),
    getSchema: jest.fn().mockResolvedValue(null),
    listSchemas: jest.fn().mockResolvedValue([]),
    clear: jest.fn().mockResolvedValue(undefined),
  };

  const mockBlockchainProvider = {
    storeDID: jest.fn().mockResolvedValue(undefined),
    resolveDID: jest.fn().mockResolvedValue(null),
    listDIDs: jest.fn().mockResolvedValue([]),
    storeCredential: jest.fn().mockResolvedValue(undefined),
    getCredential: jest.fn().mockResolvedValue(null),
    listCredentials: jest.fn().mockResolvedValue([]),
    deleteCredential: jest.fn().mockResolvedValue(undefined),
    publishRevocation: jest.fn().mockResolvedValue(undefined),
    checkRevocation: jest.fn().mockResolvedValue(false),
    getRevocationList: jest.fn().mockResolvedValue(null),
    storeKeyPair: jest.fn().mockResolvedValue(undefined),
    retrieveKeyPair: jest.fn().mockResolvedValue(null),
    deleteKeyPair: jest.fn().mockResolvedValue(undefined),
    registerSchema: jest.fn().mockResolvedValue('schema:123'),
    getSchema: jest.fn().mockResolvedValue(null),
    listSchemas: jest.fn().mockResolvedValue([]),
    clear: jest.fn().mockResolvedValue(undefined),
  };
  
  const mockIPFSProvider = {
    storeDID: jest.fn().mockResolvedValue(undefined),
    resolveDID: jest.fn().mockResolvedValue(null),
    listDIDs: jest.fn().mockResolvedValue([]),
    storeCredential: jest.fn().mockResolvedValue(undefined),
    getCredential: jest.fn().mockResolvedValue(null),
    listCredentials: jest.fn().mockResolvedValue([]),
    deleteCredential: jest.fn().mockResolvedValue(undefined),
    publishRevocation: jest.fn().mockResolvedValue(undefined),
    checkRevocation: jest.fn().mockResolvedValue(false),
    getRevocationList: jest.fn().mockResolvedValue(null),
    storeKeyPair: jest.fn().mockResolvedValue(undefined),
    retrieveKeyPair: jest.fn().mockResolvedValue(null),
    deleteKeyPair: jest.fn().mockResolvedValue(undefined),
    registerSchema: jest.fn().mockResolvedValue('schema:123'),
    getSchema: jest.fn().mockResolvedValue(null),
    listSchemas: jest.fn().mockResolvedValue([]),
    clear: jest.fn().mockResolvedValue(undefined),
  };

  return {
    StorageFactory: {
      createProvider: jest.fn((config: StorageConfig) => {
        if (config.provider === 'memory') return mockMemoryProvider;
        if (config.provider === 'blockchain') return mockBlockchainProvider;
        if (config.provider === 'ipfs') return mockIPFSProvider;
        throw new Error('Unknown provider');
      }),
    },
  };
});

describe('HybridStorageProvider', () => {
  let provider: HybridStorageProvider;
  let config: StorageConfig;

  beforeEach(() => {
    jest.clearAllMocks();
    
    config = {
      provider: 'hybrid',
      blockchain: {
        network: 'ethereum',
        rpcUrl: 'http://localhost:8545',
        contracts: {
          didRegistry: '0x123',
          revocationRegistry: '0x456',
          schemaRegistry: '0x789',
        },
      },
      ipfs: {
        host: 'localhost',
        port: 5001,
        protocol: 'http',
      },
      hybrid: {
        routing: {
          dids: 'blockchain',
          credentials: 'ipfs',
          revocations: 'blockchain',
          schemas: 'ipfs',
        },
        sizeThresholds: {
          useIPFS: 10240, // 10KB
          useLocal: 1024,  // 1KB
        },
        sync: {
          enabled: false, // Disable for tests
        },
        fallback: {
          enabled: true,
          retries: 2,
          retryDelay: 100,
        },
      },
    };

    provider = new HybridStorageProvider(config);
  });

  afterEach(() => {
    provider.destroy();
  });

  describe('Routing Logic', () => {
    const mockDIDDocument: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:anon:test123',
      verificationMethod: [{
        id: 'did:anon:test123#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:anon:test123',
        publicKeyMultibase: 'mocked-public-key',
      }],
      authentication: ['did:anon:test123#key-1'],
    };

    test('should route DIDs to blockchain based on configuration', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const blockchainProvider = StorageFactory.createProvider({ provider: 'blockchain' });
      
      await provider.storeDID('did:anon:test123', mockDIDDocument);
      
      expect(blockchainProvider.storeDID).toHaveBeenCalledWith('did:anon:test123', mockDIDDocument);
    });

    test('should route credentials to IPFS based on configuration', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const ipfsProvider = StorageFactory.createProvider({ provider: 'ipfs' });
      
      const credential: VerifiableCredential = {
        '@context': ['https://www.w3.org/ns/credentials/v1'],
        id: 'credential:123',
        type: ['VerifiableCredential'],
        issuer: 'did:anon:issuer',
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:anon:holder',
          name: 'Test User',
        },
      };
      
      await provider.storeCredential(credential);
      
      expect(ipfsProvider.storeCredential).toHaveBeenCalledWith(credential);
    });
  });

  describe('Fallback Mechanisms', () => {
    test('should retry failed operations', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const blockchainProvider = StorageFactory.createProvider({ provider: 'blockchain' });
      
      // Mock failure then success
      blockchainProvider.resolveDID
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:anon:test123',
        });
      
      const result = await provider.resolveDID('did:anon:test123');
      
      expect(result).toBeTruthy();
      expect(blockchainProvider.resolveDID).toHaveBeenCalledTimes(2);
    });

    test('should fall back to local storage on complete failure', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const blockchainProvider = StorageFactory.createProvider({ provider: 'blockchain' });
      const localProvider = StorageFactory.createProvider({ provider: 'memory' });
      
      // Mock blockchain failure
      blockchainProvider.resolveDID.mockRejectedValue(new Error('Network error'));
      
      // Mock local success
      localProvider.resolveDID.mockResolvedValue({
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:anon:test123',
      });
      
      const result = await provider.resolveDID('did:anon:test123');
      
      expect(result).toBeTruthy();
      expect(localProvider.resolveDID).toHaveBeenCalled();
    });
  });

  describe('Data Aggregation', () => {
    test('should aggregate DIDs from all providers', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const blockchainProvider = StorageFactory.createProvider({ provider: 'blockchain' });
      const ipfsProvider = StorageFactory.createProvider({ provider: 'ipfs' });
      const localProvider = StorageFactory.createProvider({ provider: 'memory' });
      
      blockchainProvider.listDIDs.mockResolvedValue(['did:anon:blockchain1']);
      ipfsProvider.listDIDs.mockResolvedValue(['did:anon:ipfs1']);
      localProvider.listDIDs.mockResolvedValue(['did:anon:local1']);
      
      const dids = await provider.listDIDs();
      
      expect(dids).toContain('did:anon:blockchain1');
      expect(dids).toContain('did:anon:ipfs1');
      expect(dids).toContain('did:anon:local1');
    });

    test('should remove duplicate credentials when aggregating', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const blockchainProvider = StorageFactory.createProvider({ provider: 'blockchain' });
      const ipfsProvider = StorageFactory.createProvider({ provider: 'ipfs' });
      
      const credential: VerifiableCredential = {
        '@context': ['https://www.w3.org/ns/credentials/v1'],
        id: 'credential:123',
        type: ['VerifiableCredential'],
        issuer: 'did:anon:issuer',
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:anon:holder',
        },
      };
      
      blockchainProvider.listCredentials.mockResolvedValue([credential]);
      ipfsProvider.listCredentials.mockResolvedValue([credential]);
      
      const credentials = await provider.listCredentials('did:anon:holder');
      
      expect(credentials).toHaveLength(1);
      expect(credentials[0].id).toBe('credential:123');
    });
  });

  describe('Size-based Routing', () => {
    test('should route large data to IPFS', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const ipfsProvider = StorageFactory.createProvider({ provider: 'ipfs' });
      
      // Create large credential (> 10KB)
      const largeCredential: VerifiableCredential = {
        '@context': ['https://www.w3.org/ns/credentials/v1'],
        id: 'credential:large',
        type: ['VerifiableCredential'],
        issuer: 'did:anon:issuer',
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:anon:holder',
          largeData: 'x'.repeat(11000), // > 10KB
        },
      };
      
      // Remove explicit routing to test size-based routing
      const configWithoutRouting = {
        ...config,
        hybrid: {
          ...config.hybrid,
          routing: undefined,
        },
      };
      
      const sizeBasedProvider = new HybridStorageProvider(configWithoutRouting);
      await sizeBasedProvider.storeCredential(largeCredential);
      
      expect(ipfsProvider.storeCredential).toHaveBeenCalled();
      sizeBasedProvider.destroy();
    });

    test('should route small data to local storage', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const localProvider = StorageFactory.createProvider({ provider: 'memory' });
      
      // Create small credential (< 1KB)
      const smallCredential: VerifiableCredential = {
        '@context': ['https://www.w3.org/ns/credentials/v1'],
        id: 'credential:small',
        type: ['VerifiableCredential'],
        issuer: 'did:anon:issuer',
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:anon:holder',
          data: 'small',
        },
      };
      
      // Remove explicit routing to test size-based routing
      const configWithoutRouting = {
        ...config,
        hybrid: {
          ...config.hybrid,
          routing: undefined,
        },
      };
      
      const sizeBasedProvider = new HybridStorageProvider(configWithoutRouting);
      await sizeBasedProvider.storeCredential(smallCredential);
      
      expect(localProvider.storeCredential).toHaveBeenCalled();
      sizeBasedProvider.destroy();
    });
  });

  describe('Key Management', () => {
    test('should always store keys locally', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const localProvider = StorageFactory.createProvider({ provider: 'memory' });
      
      await provider.storeKeyPair('key-123', 'encrypted-key');
      
      expect(localProvider.storeKeyPair).toHaveBeenCalledWith('key-123', 'encrypted-key');
    });
  });

  describe('Revocation Operations', () => {
    test('should prefer blockchain for revocation checks', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const blockchainProvider = StorageFactory.createProvider({ provider: 'blockchain' });
      const ipfsProvider = StorageFactory.createProvider({ provider: 'ipfs' });
      
      blockchainProvider.checkRevocation.mockResolvedValue(true);
      ipfsProvider.checkRevocation.mockResolvedValue(false);
      
      const isRevoked = await provider.checkRevocation('did:anon:issuer', 'cred-123');
      
      expect(isRevoked).toBe(true);
      expect(blockchainProvider.checkRevocation).toHaveBeenCalled();
    });
  });

  describe('Schema Operations', () => {
    test('should register schemas in multiple providers', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const ipfsProvider = StorageFactory.createProvider({ provider: 'ipfs' });
      const localProvider = StorageFactory.createProvider({ provider: 'memory' });
      
      const schema: CredentialSchema = {
        name: 'TestSchema',
        description: 'Test',
        properties: {},
        issuerDID: 'did:anon:issuer',
        version: '1.0',
        active: true,
      };
      
      await provider.registerSchema(schema);
      
      expect(ipfsProvider.registerSchema).toHaveBeenCalled();
      expect(localProvider.registerSchema).toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    test('should handle provider initialization failures gracefully', () => {
      const invalidConfig: StorageConfig = {
        provider: 'hybrid',
        // No blockchain or IPFS config
      };
      
      // Should not throw, just use local storage
      expect(() => new HybridStorageProvider(invalidConfig)).not.toThrow();
    });

    test('should continue operation if one provider fails during aggregate operations', async () => {
      const { StorageFactory } = require('../../src/storage/storage-factory');
      const blockchainProvider = StorageFactory.createProvider({ provider: 'blockchain' });
      const ipfsProvider = StorageFactory.createProvider({ provider: 'ipfs' });
      const localProvider = StorageFactory.createProvider({ provider: 'memory' });
      
      blockchainProvider.listDIDs.mockRejectedValue(new Error('Network error'));
      ipfsProvider.listDIDs.mockResolvedValue(['did:anon:ipfs1']); 
      localProvider.listDIDs.mockResolvedValue(['did:anon:local1']);
      
      const dids = await provider.listDIDs();
      
      expect(dids).toContain('did:anon:local1');
      expect(dids).toContain('did:anon:ipfs1');
      expect(dids).toHaveLength(2);
    });
  });

  describe('Synchronization', () => {
    test('should start sync when enabled', (done) => {
      const syncConfig: StorageConfig = {
        ...config,
        hybrid: {
          ...config.hybrid,
          sync: {
            enabled: true,
            interval: 100, // 100ms for testing
          },
        },
      };
      
      const syncProvider = new HybridStorageProvider(syncConfig);
      
      // Wait for sync to trigger
      setTimeout(() => {
        syncProvider.destroy();
        done();
      }, 150);
    });
  });
});