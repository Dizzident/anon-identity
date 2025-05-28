import { BlockchainStorageProvider } from '../../src/storage/providers/blockchain-storage-provider';
import { StorageConfig } from '../../src/storage/types';
import { DIDDocument } from '../../src/types/did';
import { VerifiableCredential } from '../../src/types';
import { RevocationList, CredentialSchema } from '../../src/storage/types';
import { ethers } from 'ethers';
import { RevocationMerkleTree } from '../../src/storage/providers/blockchain-batch-operations';

// Mock the contract client
jest.mock('../../src/blockchain/contract-client', () => {
  return {
    ContractClient: jest.fn().mockImplementation(() => {
      return {
        registerDID: jest.fn().mockResolvedValue({}),
        resolveDID: jest.fn().mockResolvedValue({
          did: 'did:anon:test123',
          owner: '0x1234567890123456789012345678901234567890',
          publicKey: 'mocked-public-key',
          documentHash: 'mocked-hash',
          createdAt: 1000000,
          updatedAt: 1000000,
          active: true,
        }),
        queryDIDEvents: jest.fn().mockResolvedValue([
          {
            eventName: 'DIDRegistered',
            args: { did: 'did:anon:test123' },
          },
        ]),
        publishRevocationList: jest.fn().mockResolvedValue({}),
        checkRevocation: jest.fn().mockResolvedValue(false),
        getRevocationList: jest.fn().mockResolvedValue({
          timestamp: 1000000,
          signature: 'mocked-signature',
        }),
        registerSchema: jest.fn().mockResolvedValue({}),
        getSchema: jest.fn().mockResolvedValue({
          name: 'TestSchema',
          description: 'Test schema description',
          issuerDID: 'did:anon:issuer',
          version: '1.0',
          active: true,
        }),
        querySchemaEvents: jest.fn().mockResolvedValue([
          {
            eventName: 'SchemaRegistered',
            args: { schemaId: 1 },
          },
        ]),
        queryRevocationEvents: jest.fn().mockResolvedValue([]),
      };
    }),
  };
});

describe('BlockchainStorageProvider', () => {
  let provider: BlockchainStorageProvider;
  let config: StorageConfig;

  beforeEach(() => {
    config = {
      provider: 'blockchain',
      blockchain: {
        network: 'ethereum',
        rpcUrl: 'http://localhost:8545',
        privateKey: '0x' + '0'.repeat(64),
        contracts: {
          didRegistry: '0x' + '1'.repeat(40),
          revocationRegistry: '0x' + '2'.repeat(40),
          schemaRegistry: '0x' + '3'.repeat(40),
        },
      },
      cache: {
        enabled: true,
        ttl: 60,
        maxSize: 10,
      },
    };

    provider = new BlockchainStorageProvider(config);
  });

  describe('DID Operations', () => {
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
      assertionMethod: ['did:anon:test123#key-1'],
    };

    test('should store a DID', async () => {
      await expect(provider.storeDID('did:anon:test123', mockDIDDocument))
        .resolves.not.toThrow();
    });

    test('should resolve a DID', async () => {
      const result = await provider.resolveDID('did:anon:test123');
      expect(result).toBeTruthy();
      expect(result?.id).toBe('did:anon:test123');
      expect(result?.verificationMethod).toHaveLength(1);
    });

    test('should list DIDs', async () => {
      const dids = await provider.listDIDs();
      expect(Array.isArray(dids)).toBe(true);
      expect(dids).toContain('did:anon:test123');
    });

    test('should use cache for DID resolution', async () => {
      // First call - should hit blockchain
      const result1 = await provider.resolveDID('did:anon:test123');
      
      // Second call - should hit cache
      const result2 = await provider.resolveDID('did:anon:test123');
      
      expect(result1).toEqual(result2);
    });
  });

  describe('Credential Operations', () => {
    const mockCredential: VerifiableCredential = {
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

    test('should store a credential', async () => {
      await expect(provider.storeCredential(mockCredential))
        .resolves.not.toThrow();
    });

    test('should warn when deleting credentials', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      await provider.deleteCredential('credential:123');
      expect(consoleSpy).toHaveBeenCalledWith(
        'Credential deletion not supported on blockchain. Use revocation instead.'
      );
      consoleSpy.mockRestore();
    });
  });

  describe('Revocation Operations', () => {
    const mockRevocationList: RevocationList = {
      issuerDID: 'did:anon:issuer',
      revokedCredentialIds: ['cred1', 'cred2', 'cred3'],
      timestamp: Date.now(),
      signature: 'mock-signature',
    };

    test('should publish revocation list with merkle root', async () => {
      await expect(provider.publishRevocation('did:anon:issuer', mockRevocationList))
        .resolves.not.toThrow();
    });

    test('should check revocation status', async () => {
      const isRevoked = await provider.checkRevocation('did:anon:issuer', 'cred1');
      expect(typeof isRevoked).toBe('boolean');
    });

    test('should get revocation list', async () => {
      const revocationList = await provider.getRevocationList('did:anon:issuer');
      expect(revocationList).toBeTruthy();
      expect(revocationList?.issuerDID).toBe('did:anon:issuer');
    });
  });

  describe('Schema Operations', () => {
    const mockSchema: CredentialSchema = {
      name: 'TestSchema',
      description: 'Test schema description',
      properties: { field1: 'string', field2: 'number' },
      issuerDID: 'did:anon:issuer',
      version: '1.0',
      active: true,
    };

    test('should register a schema', async () => {
      const schemaId = await provider.registerSchema(mockSchema);
      expect(schemaId).toBeTruthy();
      expect(schemaId.startsWith('schema:')).toBe(true);
    });

    test('should get a schema', async () => {
      const schema = await provider.getSchema('schema:123');
      expect(schema).toBeTruthy();
      expect(schema?.name).toBe('TestSchema');
    });

    test('should list schemas', async () => {
      const schemas = await provider.listSchemas('did:anon:issuer');
      expect(Array.isArray(schemas)).toBe(true);
    });
  });

  describe('Key Management', () => {
    test('should store key pair locally', async () => {
      const encryptedKey = 'encrypted-key-data';
      await provider.storeKeyPair('key-123', encryptedKey);
      
      const retrieved = await provider.retrieveKeyPair('key-123');
      expect(retrieved).toBe(encryptedKey);
    });

    test('should delete key pair', async () => {
      await provider.storeKeyPair('key-123', 'encrypted-key');
      await provider.deleteKeyPair('key-123');
      
      const retrieved = await provider.retrieveKeyPair('key-123');
      expect(retrieved).toBeNull();
    });
  });

  describe('Merkle Tree Operations', () => {
    test('should calculate merkle root correctly', () => {
      const hashes = [
        ethers.keccak256(ethers.toUtf8Bytes('cred1')),
        ethers.keccak256(ethers.toUtf8Bytes('cred2')),
        ethers.keccak256(ethers.toUtf8Bytes('cred3')),
        ethers.keccak256(ethers.toUtf8Bytes('cred4')),
      ];

      const merkleTree = new RevocationMerkleTree(hashes);
      const root = merkleTree.getRoot();
      
      expect(root).toBeTruthy();
      expect(root).not.toBe(ethers.ZeroHash);
    });

    test('should generate and verify merkle proofs', () => {
      const credentialIds = ['cred1', 'cred2', 'cred3', 'cred4'];
      const hashes = credentialIds.map(id => ethers.keccak256(ethers.toUtf8Bytes(id)));
      
      const merkleTree = new RevocationMerkleTree(hashes);
      const root = merkleTree.getRoot();
      
      // Generate proof for cred2
      const targetHash = ethers.keccak256(ethers.toUtf8Bytes('cred2'));
      const proof = merkleTree.getProof(targetHash);
      
      // Verify proof
      const isValid = merkleTree.verify(targetHash, proof, root);
      expect(isValid).toBe(true);
      
      // Verify invalid proof
      const invalidHash = ethers.keccak256(ethers.toUtf8Bytes('cred5'));
      const isInvalid = merkleTree.verify(invalidHash, proof, root);
      expect(isInvalid).toBe(false);
    });
  });

  describe('Error Handling', () => {
    test('should throw error if blockchain config is missing', () => {
      const invalidConfig: StorageConfig = {
        provider: 'blockchain',
      };
      
      expect(() => new BlockchainStorageProvider(invalidConfig))
        .toThrow('Blockchain configuration is required');
    });

    test('should handle errors gracefully', async () => {
      // Mock a failing contract call
      const mockContractClient = (provider as any).contractClient;
      mockContractClient.resolveDID.mockRejectedValueOnce(new Error('Network error'));
      
      const result = await provider.resolveDID('did:anon:test123');
      expect(result).toBeNull();
    });
  });

  describe('General Operations', () => {
    test('should warn when clearing blockchain storage', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      await provider.clear();
      expect(consoleSpy).toHaveBeenCalledWith(
        'Clear operation not supported for blockchain storage'
      );
      consoleSpy.mockRestore();
    });
  });
});