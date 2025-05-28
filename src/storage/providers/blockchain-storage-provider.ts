import { IStorageProvider, RevocationList, CredentialSchema, StorageConfig } from '../types';
import { VerifiableCredential } from '../../types';
import { DIDDocument } from '../../types/did';
import { ethers, Contract, Wallet, Provider } from 'ethers';
import { v4 as uuidv4 } from 'uuid';
import { LRUCache } from 'lru-cache';
import * as crypto from 'crypto';

// Import contract ABIs and client
import { ContractClient } from '../../blockchain/contract-client';
import { BatchOperationsManager, RevocationMerkleTree } from './blockchain-batch-operations';

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

export class BlockchainStorageProvider implements IStorageProvider {
  private contractClient: ContractClient;
  private cache?: LRUCache<string, CacheEntry<any>>;
  private ipfsClient?: any; // Will be implemented later
  private localKeyStore: Map<string, string> = new Map(); // Keys are always stored locally
  private config: StorageConfig;
  private batchManager: BatchOperationsManager;

  constructor(config: StorageConfig) {
    if (!config.blockchain) {
      throw new Error('Blockchain configuration is required');
    }

    this.config = config;
    
    // Initialize contract client
    this.contractClient = new ContractClient(
      config.blockchain.rpcUrl,
      config.blockchain.privateKey,
      config.blockchain.contracts
    );

    // Initialize cache if enabled
    if (config.cache?.enabled) {
      this.cache = new LRUCache<string, CacheEntry<any>>({
        maxSize: config.cache.maxSize * 1024 * 1024, // Convert MB to bytes
        ttl: config.cache.ttl * 1000, // Convert seconds to milliseconds
        sizeCalculation: (value) => JSON.stringify(value).length,
      });
    }

    // Initialize batch manager for gas optimization
    this.batchManager = new BatchOperationsManager(10, 5000);
  }

  // Cache helper methods
  private getCached<T>(key: string): T | null {
    if (!this.cache) return null;
    
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    const now = Date.now();
    if (now - entry.timestamp > (this.config.cache?.ttl || 0) * 1000) {
      this.cache.delete(key);
      return null;
    }
    
    return entry.data as T;
  }

  private setCached<T>(key: string, data: T): void {
    if (!this.cache) return;
    
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
    });
  }

  // DID Operations
  async storeDID(did: string, document: DIDDocument): Promise<void> {
    // Convert DIDDocument to blockchain format
    const publicKey = document.verificationMethod?.[0]?.publicKeyMultibase || '';
    const documentHash = this.hashDocument(document);
    
    await this.contractClient.registerDID(did, publicKey, documentHash);
    
    // Store full document in IPFS if available
    if (this.ipfsClient && document) {
      // TODO: Implement IPFS storage
    }
    
    // Clear cache for this DID
    this.cache?.delete(`did:${did}`);
  }

  async resolveDID(did: string): Promise<DIDDocument | null> {
    // Check cache first
    const cached = this.getCached<DIDDocument>(`did:${did}`);
    if (cached) return cached;
    
    try {
      const didInfo = await this.contractClient.resolveDID(did);
      if (!didInfo || !didInfo.active) return null;
      
      // Reconstruct DIDDocument from blockchain data
      const document: DIDDocument = {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [{
          id: `${did}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyMultibase: didInfo.publicKey,
        }],
        authentication: [`${did}#key-1`],
        assertionMethod: [`${did}#key-1`],
        created: new Date(didInfo.createdAt * 1000).toISOString(),
        updated: new Date(didInfo.updatedAt * 1000).toISOString(),
      };
      
      // Cache the result
      this.setCached(`did:${did}`, document);
      
      return document;
    } catch (error) {
      console.error('Error resolving DID from blockchain:', error);
      return null;
    }
  }

  async listDIDs(owner?: string): Promise<string[]> {
    // This operation is expensive on blockchain, use events
    try {
      const events = await this.contractClient.queryDIDEvents({
        owner,
        fromBlock: 0,
        toBlock: 'latest',
      });
      
      const dids = events
        .filter(event => event.eventName === 'DIDRegistered')
        .map(event => event.args?.did as string)
        .filter(did => did !== undefined);
      
      return [...new Set(dids)]; // Remove duplicates
    } catch (error) {
      console.error('Error listing DIDs from blockchain:', error);
      return [];
    }
  }

  // Credential Operations
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    // Store credential hash on blockchain for integrity
    const credentialHash = this.hashCredential(credential);
    const issuerDID = credential.issuer;
    
    // For now, we store credential metadata in the schema registry
    // In a production system, you might want a separate credential registry
    const schemaTypeEnum = 1; // Using 1 for credential records
    
    await this.contractClient.registerSchema(
      `credential:${credential.id}`,
      'VerifiableCredential',
      credentialHash,
      issuerDID,
      '1.0',
      schemaTypeEnum,
      [] // dependencies
    );
    
    // Store full credential in IPFS if available
    if (this.ipfsClient) {
      // TODO: Implement IPFS storage
    }
    
    // Clear cache
    this.cache?.delete(`credential:${credential.id}`);
  }

  async getCredential(id: string): Promise<VerifiableCredential | null> {
    // Check cache first
    const cached = this.getCached<VerifiableCredential>(`credential:${id}`);
    if (cached) return cached;
    
    // For now, credentials are not fully stored on-chain
    // In a full implementation, we would retrieve from IPFS
    // using the hash stored on-chain
    console.warn('Full credential retrieval from blockchain not yet implemented');
    return null;
  }

  async listCredentials(holder: string): Promise<VerifiableCredential[]> {
    // This would require an index of credentials by holder
    // For now, return empty array
    console.warn('Listing credentials by holder not yet implemented for blockchain storage');
    return [];
  }

  async deleteCredential(id: string): Promise<void> {
    // Credentials on blockchain are immutable, but we can revoke them
    console.warn('Credential deletion not supported on blockchain. Use revocation instead.');
  }

  // Revocation Operations
  async publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void> {
    // Convert credential IDs to hashes
    const credentialHashes = revocationList.revokedCredentialIds.map(id => 
      ethers.keccak256(ethers.toUtf8Bytes(id))
    );
    
    // Calculate merkle root for gas efficiency
    const merkleRoot = this.calculateMerkleRoot(credentialHashes);
    
    await this.contractClient.publishRevocationList(
      issuerDID,
      credentialHashes,
      revocationList.signature,
      merkleRoot
    );
    
    // Clear cache
    this.cache?.delete(`revocation:${issuerDID}`);
  }

  async checkRevocation(issuerDID: string, credentialId: string): Promise<boolean> {
    // Check cache first
    const cacheKey = `revocation:${issuerDID}:${credentialId}`;
    const cached = this.getCached<boolean>(cacheKey);
    if (cached !== null) return cached;
    
    try {
      const credentialHash = ethers.keccak256(ethers.toUtf8Bytes(credentialId));
      const isRevoked = await this.contractClient.checkRevocation(issuerDID, credentialHash);
      
      // Cache the result
      this.setCached(cacheKey, isRevoked);
      
      return isRevoked;
    } catch (error) {
      console.error('Error checking revocation:', error);
      return false;
    }
  }

  async getRevocationList(issuerDID: string): Promise<RevocationList | null> {
    // Check cache first
    const cached = this.getCached<RevocationList>(`revocation:${issuerDID}`);
    if (cached) return cached;
    
    try {
      const revocationInfo = await this.contractClient.getRevocationList(issuerDID);
      if (!revocationInfo) return null;
      
      // Convert back to RevocationList format
      const revocationList: RevocationList = {
        issuerDID,
        revokedCredentialIds: [], // Would need to be retrieved from events or IPFS
        timestamp: revocationInfo.timestamp,
        signature: revocationInfo.signature,
      };
      
      // Cache the result
      this.setCached(`revocation:${issuerDID}`, revocationList);
      
      return revocationList;
    } catch (error) {
      console.error('Error getting revocation list:', error);
      return null;
    }
  }

  // Key Management (always local)
  async storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void> {
    // Keys are never stored on blockchain for security
    this.localKeyStore.set(identifier, encryptedKeyPair);
  }

  async retrieveKeyPair(identifier: string): Promise<string | null> {
    return this.localKeyStore.get(identifier) || null;
  }

  async deleteKeyPair(identifier: string): Promise<void> {
    this.localKeyStore.delete(identifier);
  }

  // Schema Operations
  async registerSchema(schema: CredentialSchema): Promise<string> {
    const schemaId = schema.id || `schema:${uuidv4()}`;
    const schemaHash = this.hashSchema(schema);
    
    // Convert schema type to enum value (0 = VerifiableCredential)
    const schemaTypeEnum = 0; // SchemaType.VerifiableCredential
    
    await this.contractClient.registerSchema(
      schema.name,
      schema.description,
      schemaHash,
      schema.issuerDID,
      schema.version,
      schemaTypeEnum,
      [] // dependencies
    );
    
    // Store full schema in IPFS if available
    if (this.ipfsClient) {
      // TODO: Implement IPFS storage
    }
    
    // Clear cache
    this.cache?.delete(`schema:${schemaId}`);
    
    return schemaId;
  }

  async getSchema(schemaId: string): Promise<CredentialSchema | null> {
    // Check cache first
    const cached = this.getCached<CredentialSchema>(`schema:${schemaId}`);
    if (cached) return cached;
    
    try {
      // Schema ID on blockchain might be different, try to map it
      const schemaInfo = await this.contractClient.getSchema(schemaId);
      if (!schemaInfo) return null;
      
      // Reconstruct CredentialSchema from blockchain data
      const schema: CredentialSchema = {
        id: schemaId,
        name: schemaInfo.name,
        description: schemaInfo.description,
        properties: {}, // Would need to be retrieved from IPFS
        issuerDID: schemaInfo.issuerDID,
        version: schemaInfo.version,
        active: schemaInfo.active,
      };
      
      // Cache the result
      this.setCached(`schema:${schemaId}`, schema);
      
      return schema;
    } catch (error) {
      console.error('Error getting schema from blockchain:', error);
      return null;
    }
  }

  async listSchemas(issuerDID?: string): Promise<CredentialSchema[]> {
    try {
      const events = await this.contractClient.querySchemaEvents({
        issuerDID,
        fromBlock: 0,
        toBlock: 'latest',
      });
      
      const schemas: CredentialSchema[] = [];
      for (const event of events) {
        if (event.eventName === 'SchemaRegistered') {
          const schemaId = event.args?.schemaId;
          if (schemaId) {
            const schema = await this.getSchema(schemaId.toString());
            if (schema) {
              schemas.push(schema);
            }
          }
        }
      }
      
      return schemas;
    } catch (error) {
      console.error('Error listing schemas from blockchain:', error);
      return [];
    }
  }

  // General operations
  async clear(): Promise<void> {
    // Cannot clear blockchain data
    console.warn('Clear operation not supported for blockchain storage');
    // Clear local data only
    this.localKeyStore.clear();
    this.cache?.clear();
  }

  // Helper methods
  private hashDocument(document: DIDDocument): string {
    const canonicalDoc = JSON.stringify(document, Object.keys(document).sort());
    return ethers.keccak256(ethers.toUtf8Bytes(canonicalDoc));
  }

  private hashCredential(credential: VerifiableCredential): string {
    const canonicalCred = JSON.stringify(credential, Object.keys(credential).sort());
    return ethers.keccak256(ethers.toUtf8Bytes(canonicalCred));
  }

  private hashSchema(schema: CredentialSchema): string {
    const canonicalSchema = JSON.stringify(schema, Object.keys(schema).sort());
    return ethers.keccak256(ethers.toUtf8Bytes(canonicalSchema));
  }

  private calculateMerkleRoot(hashes: string[]): string {
    const merkleTree = new RevocationMerkleTree(hashes);
    return merkleTree.getRoot();
  }
}