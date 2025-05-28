import { IStorageProvider, RevocationList, CredentialSchema, StorageConfig } from '../types';
import { VerifiableCredential } from '../../types';
import { DIDDocument } from '../../types/did';
import { v4 as uuidv4 } from 'uuid';
import { LRUCache } from 'lru-cache';

// Lazy-loaded dependencies
let ethersModule: any;
let cryptoModule: any;
let ContractClient: any;
let BatchOperationsManager: any;
let RevocationMerkleTree: any;

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

export class BlockchainStorageProvider implements IStorageProvider {
  private contractClient: any;
  private cache?: LRUCache<string, CacheEntry<any>>;
  private ipfsClient?: any;
  private localKeyStore: Map<string, string> = new Map();
  private config: StorageConfig;
  private batchManager: any;
  private initialized = false;
  private initPromise: Promise<void> | null = null;

  constructor(config: StorageConfig) {
    if (!config.blockchain) {
      throw new Error('Blockchain configuration is required');
    }
    this.config = config;
  }

  private async initialize(): Promise<void> {
    if (this.initialized) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = this.doInitialize();
    await this.initPromise;
    this.initialized = true;
  }

  private async doInitialize(): Promise<void> {
    try {
      // Dynamic imports
      [ethersModule, cryptoModule] = await Promise.all([
        import('ethers'),
        import('crypto'),
      ]);

      // Import blockchain components
      const [contractClientModule, batchOpsModule] = await Promise.all([
        import('../../blockchain/contract-client-lazy'),
        import('./blockchain-batch-operations'),
      ]);

      ContractClient = contractClientModule.ContractClient;
      BatchOperationsManager = batchOpsModule.BatchOperationsManager;
      RevocationMerkleTree = batchOpsModule.RevocationMerkleTree;

      // Initialize contract client
      this.contractClient = new ContractClient(
        this.config.blockchain!.rpcUrl,
        this.config.blockchain!.privateKey,
        this.config.blockchain!.contracts
      );

      // Initialize cache if enabled
      if (this.config.cache?.enabled) {
        this.cache = new LRUCache<string, CacheEntry<any>>({
          maxSize: this.config.cache.maxSize * 1024 * 1024,
          ttl: this.config.cache.ttl * 1000,
          sizeCalculation: (value) => JSON.stringify(value).length,
        });
      }

      // Initialize batch manager
      this.batchManager = new BatchOperationsManager(10, 5000);
    } catch (error) {
      throw new Error(`Failed to initialize blockchain storage: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Cache helpers
  private getCached<T>(key: string): T | null {
    if (!this.cache) return null;
    
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    // Check if entry is still valid within TTL
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

  // Encryption helpers for sensitive data
  private encrypt(data: string, key: string): string {
    if (!cryptoModule) throw new Error('Crypto module not loaded');
    
    const algorithm = 'aes-256-gcm';
    const salt = cryptoModule.randomBytes(16);
    const derivedKey = cryptoModule.pbkdf2Sync(key, salt, 100000, 32, 'sha256');
    const iv = cryptoModule.randomBytes(16);
    const cipher = cryptoModule.createCipheriv(algorithm, derivedKey, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return JSON.stringify({
      encrypted,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    });
  }

  private decrypt(encryptedData: string, key: string): string {
    if (!cryptoModule) throw new Error('Crypto module not loaded');
    
    const { encrypted, salt, iv, authTag } = JSON.parse(encryptedData);
    const algorithm = 'aes-256-gcm';
    const derivedKey = cryptoModule.pbkdf2Sync(key, Buffer.from(salt, 'hex'), 100000, 32, 'sha256');
    
    const decipher = cryptoModule.createDecipheriv(
      algorithm,
      derivedKey,
      Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // DID Operations
  async storeDID(did: string, document: DIDDocument): Promise<void> {
    await this.initialize();
    
    // Check cache first
    const cacheKey = `did:${did}`;
    
    try {
      // Store on blockchain
      const tx = await this.contractClient.registerDID(did, JSON.stringify(document));
      await tx.wait();
      
      // Cache the result
      this.setCached(cacheKey, document);
    } catch (error) {
      // Check if DID already exists and try to update instead
      if (error instanceof Error && error.message.includes('DID already exists')) {
        const updateTx = await this.contractClient.updateDID(did, JSON.stringify(document));
        await updateTx.wait();
        this.setCached(cacheKey, document);
      } else {
        throw error;
      }
    }
  }

  async resolveDID(did: string): Promise<DIDDocument | null> {
    await this.initialize();
    
    // Check cache first
    const cacheKey = `did:${did}`;
    const cached = this.getCached<DIDDocument>(cacheKey);
    if (cached) return cached;
    
    try {
      const documentJson = await this.contractClient.resolveDID(did);
      if (!documentJson || documentJson === '') return null;
      
      const document = JSON.parse(documentJson);
      
      // Cache the result
      this.setCached(cacheKey, document);
      
      return document;
    } catch (error) {
      console.error('Error resolving DID:', error);
      return null;
    }
  }

  async listDIDs(owner?: string): Promise<string[]> {
    await this.initialize();
    
    // Note: This is a limitation of the current blockchain implementation
    // In a real implementation, we would need to emit events when DIDs are created
    // and index them off-chain, or implement an enumerable mapping in the contract
    console.warn('listDIDs is not fully implemented for blockchain storage');
    return [];
  }

  // Credential Operations
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    await this.initialize();
    
    // For credentials, we store a hash on-chain and the full data off-chain (IPFS or encrypted local)
    const credentialHash = ethersModule.keccak256(
      ethersModule.toUtf8Bytes(JSON.stringify(credential))
    );
    
    // Store hash on blockchain for verification
    const holder = credential.credentialSubject.id;
    const issuer = credential.issuer;
    
    // Store credential data locally (encrypted)
    const encryptionKey = 'default-encryption-key';
    const encryptedCredential = this.encrypt(JSON.stringify(credential), encryptionKey);
    
    // Use a simple key-value store approach
    const storageKey = `credential:${credential.id}`;
    this.localKeyStore.set(storageKey, encryptedCredential);
    
    // Also index by holder
    const holderKey = `holder:${holder}:credentials`;
    const existingCreds = this.localKeyStore.get(holderKey) || '[]';
    const credIds = JSON.parse(existingCreds);
    if (!credIds.includes(credential.id)) {
      credIds.push(credential.id);
      this.localKeyStore.set(holderKey, JSON.stringify(credIds));
    }
    
    // Cache the credential
    this.setCached(`credential:${credential.id}`, credential);
  }

  async getCredential(id: string): Promise<VerifiableCredential | null> {
    await this.initialize();
    
    // Check cache first
    const cacheKey = `credential:${id}`;
    const cached = this.getCached<VerifiableCredential>(cacheKey);
    if (cached) return cached;
    
    // Retrieve from local encrypted storage
    const storageKey = `credential:${id}`;
    const encryptedData = this.localKeyStore.get(storageKey);
    if (!encryptedData) return null;
    
    try {
      const encryptionKey = 'default-encryption-key';
      const decryptedData = this.decrypt(encryptedData, encryptionKey);
      const credential = JSON.parse(decryptedData);
      
      // Cache the result
      this.setCached(cacheKey, credential);
      
      return credential;
    } catch (error) {
      console.error('Error retrieving credential:', error);
      return null;
    }
  }

  async listCredentials(holder: string): Promise<VerifiableCredential[]> {
    await this.initialize();
    
    const holderKey = `holder:${holder}:credentials`;
    const credIdsJson = this.localKeyStore.get(holderKey);
    if (!credIdsJson) return [];
    
    const credIds = JSON.parse(credIdsJson);
    const credentials: VerifiableCredential[] = [];
    
    for (const credId of credIds) {
      const credential = await this.getCredential(credId);
      if (credential) {
        credentials.push(credential);
      }
    }
    
    return credentials;
  }

  async deleteCredential(id: string): Promise<void> {
    await this.initialize();
    
    const credential = await this.getCredential(id);
    if (credential) {
      // Remove from holder index
      const holder = credential.credentialSubject.id;
      const holderKey = `holder:${holder}:credentials`;
      const credIdsJson = this.localKeyStore.get(holderKey);
      if (credIdsJson) {
        const credIds = JSON.parse(credIdsJson);
        const updatedIds = credIds.filter((cid: string) => cid !== id);
        this.localKeyStore.set(holderKey, JSON.stringify(updatedIds));
      }
      
      // Remove credential
      this.localKeyStore.delete(`credential:${id}`);
      
      // Remove from cache
      if (this.cache) {
        this.cache.delete(`credential:${id}`);
      }
    }
  }

  // Revocation Operations
  async publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void> {
    await this.initialize();
    
    // Generate a list ID based on timestamp
    const listId = `revocation-${Date.now()}`;
    
    // Use batch manager for efficient revocation updates
    await this.batchManager.addRevocation(
      issuerDID,
      listId,
      revocationList.revokedCredentialIds,
      async (issuer: string, listId: string, credIds: string[]) => {
        const tx = await this.contractClient.publishRevocationList(issuer, listId, credIds);
        await tx.wait();
      }
    );
    
    // Cache the revocation list
    this.setCached(`revocation:${issuerDID}:${listId}`, revocationList);
  }

  async checkRevocation(issuerDID: string, credentialId: string): Promise<boolean> {
    await this.initialize();
    
    // Check cache first
    const lists = await this.getRevocationListsForIssuer(issuerDID);
    for (const list of lists) {
      if (list.revokedCredentialIds.includes(credentialId)) {
        return true;
      }
    }
    
    // Check on-chain
    return await this.contractClient.isCredentialRevoked(issuerDID, credentialId);
  }

  async getRevocationList(issuerDID: string): Promise<RevocationList | null> {
    await this.initialize();
    
    // Get the latest revocation list for the issuer
    const lists = await this.getRevocationListsForIssuer(issuerDID);
    return lists.length > 0 ? lists[0] : null;
  }

  private async getRevocationListsForIssuer(issuerDID: string): Promise<RevocationList[]> {
    // In a real implementation, we would query events or maintain an index
    // For now, return cached lists
    const lists: RevocationList[] = [];
    
    if (this.cache) {
      for (const [key, entry] of this.cache.entries()) {
        if (key.startsWith(`revocation:${issuerDID}:`)) {
          lists.push(entry.data as RevocationList);
        }
      }
    }
    
    return lists;
  }

  // Key Management
  async storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void> {
    await this.initialize();
    
    // Keys are always stored locally, never on-chain
    this.localKeyStore.set(`keypair:${identifier}`, encryptedKeyPair);
  }

  async retrieveKeyPair(identifier: string): Promise<string | null> {
    await this.initialize();
    
    return this.localKeyStore.get(`keypair:${identifier}`) || null;
  }

  async deleteKeyPair(identifier: string): Promise<void> {
    await this.initialize();
    
    this.localKeyStore.delete(`keypair:${identifier}`);
  }

  // Schema Operations
  async registerSchema(schema: CredentialSchema): Promise<string> {
    await this.initialize();
    
    const schemaId = schema.id || `schema:${uuidv4()}`;
    const schemaWithId = { ...schema, id: schemaId };
    
    // Store schema on blockchain
    const tx = await this.contractClient.registerSchema(schemaId, JSON.stringify(schemaWithId));
    await tx.wait();
    
    // Cache the schema
    this.setCached(`schema:${schemaId}`, schemaWithId);
    
    return schemaId;
  }

  async getSchema(schemaId: string): Promise<CredentialSchema | null> {
    await this.initialize();
    
    // Check cache first
    const cacheKey = `schema:${schemaId}`;
    const cached = this.getCached<CredentialSchema>(cacheKey);
    if (cached) return cached;
    
    try {
      const schemaJson = await this.contractClient.getSchema(schemaId);
      if (!schemaJson || schemaJson === '') return null;
      
      const schema = JSON.parse(schemaJson);
      
      // Cache the result
      this.setCached(cacheKey, schema);
      
      return schema;
    } catch (error) {
      console.error('Error retrieving schema:', error);
      return null;
    }
  }

  async listSchemas(issuerDID?: string): Promise<CredentialSchema[]> {
    await this.initialize();
    
    // This would require event indexing in a real implementation
    console.warn('listSchemas is not fully implemented for blockchain storage');
    return [];
  }

  // General operations
  async clear(): Promise<void> {
    await this.initialize();
    
    // Clear local storage and cache
    this.localKeyStore.clear();
    if (this.cache) {
      this.cache.clear();
    }
    
    // Note: We cannot clear blockchain data
    console.warn('Blockchain data cannot be cleared');
  }

  // Utility methods
  async getStorageStats(): Promise<{
    localItems: number;
    cacheSize: number;
    blockNumber: number;
  }> {
    await this.initialize();
    
    const blockNumber = await this.contractClient.getBlockNumber();
    
    return {
      localItems: this.localKeyStore.size,
      cacheSize: this.cache ? this.cache.size : 0,
      blockNumber,
    };
  }
}