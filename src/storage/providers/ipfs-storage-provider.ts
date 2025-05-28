import { IStorageProvider, RevocationList, CredentialSchema, StorageConfig } from '../types';
import { VerifiableCredential, PhoneNumber, Address, EmailAddress } from '../../types';
import { DIDDocument } from '../../types/did';
import { v4 as uuidv4 } from 'uuid';

// Type for the dynamically imported Kubo client
type KuboRPCClient = any;

interface IPFSStoredData<T> {
  type: 'did' | 'credential' | 'revocation' | 'schema';
  data: T;
  metadata: {
    created: string;
    updated: string;
    version: string;
  };
}

export class IPFSStorageProvider implements IStorageProvider {
  private ipfsClient: KuboRPCClient | null = null;
  private localIndex: Map<string, string> = new Map(); // Maps IDs to IPFS CIDs
  private localKeyStore: Map<string, string> = new Map(); // Keys are always stored locally

  constructor(config: StorageConfig) {
    if (!config.ipfs) {
      throw new Error('IPFS configuration is required');
    }

    // Initialize IPFS client lazily to avoid import issues
    this.initializeIPFSClient(config.ipfs);
  }

  private async initializeIPFSClient(ipfsConfig: { host: string; port: number; protocol: string }) {
    try {
      // Dynamic import to avoid ESM issues
      const { create } = await import('kubo-rpc-client');
      this.ipfsClient = create({
        host: ipfsConfig.host,
        port: ipfsConfig.port,
        protocol: ipfsConfig.protocol,
      });
    } catch (error) {
      console.error('Failed to initialize Kubo RPC client:', error);
      throw new Error('Kubo RPC client initialization failed');
    }
  }

  // Helper methods for IPFS operations
  private async storeToIPFS<T>(data: IPFSStoredData<T>): Promise<string> {
    if (!this.ipfsClient) {
      throw new Error('IPFS client not initialized');
    }
    const jsonData = JSON.stringify(data);
    const result = await this.ipfsClient.add(jsonData);
    return result.cid.toString(); // Returns the IPFS CID
  }

  private async retrieveFromIPFS<T>(cid: string): Promise<IPFSStoredData<T> | null> {
    try {
      if (!this.ipfsClient) {
        throw new Error('IPFS client not initialized');
      }
      const chunks: Uint8Array[] = [];
      for await (const chunk of this.ipfsClient.cat(cid)) {
        chunks.push(chunk);
      }
      
      const data = Buffer.concat(chunks).toString('utf8');
      return JSON.parse(data) as IPFSStoredData<T>;
    } catch (error) {
      console.error('Error retrieving from IPFS:', error);
      return null;
    }
  }

  // DID Operations
  async storeDID(did: string, document: DIDDocument): Promise<void> {
    const storedData: IPFSStoredData<DIDDocument> = {
      type: 'did',
      data: document,
      metadata: {
        created: new Date().toISOString(),
        updated: new Date().toISOString(),
        version: '1.0',
      },
    };

    const cid = await this.storeToIPFS(storedData);
    this.localIndex.set(`did:${did}`, cid);
  }

  async resolveDID(did: string): Promise<DIDDocument | null> {
    const cid = this.localIndex.get(`did:${did}`);
    if (!cid) return null;

    const storedData = await this.retrieveFromIPFS<DIDDocument>(cid);
    return storedData?.data || null;
  }

  async listDIDs(owner?: string): Promise<string[]> {
    // Filter DIDs from local index
    const dids: string[] = [];
    for (const [key, _] of this.localIndex) {
      if (key.startsWith('did:')) {
        const did = key.substring(4);
        if (!owner) {
          dids.push(did);
        } else {
          // Need to retrieve and check ownership
          const document = await this.resolveDID(did);
          if (document?.verificationMethod?.some(vm => vm.controller === owner)) {
            dids.push(did);
          }
        }
      }
    }
    return dids;
  }

  // Credential Operations
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    const storedData: IPFSStoredData<VerifiableCredential> = {
      type: 'credential',
      data: credential,
      metadata: {
        created: new Date().toISOString(),
        updated: new Date().toISOString(),
        version: '1.0',
      },
    };

    const cid = await this.storeToIPFS(storedData);
    this.localIndex.set(`credential:${credential.id}`, cid);
    
    // Also index by holder
    const holder = credential.credentialSubject.id;
    const holderKey = `holder:${holder}:credentials`;
    const holderCreds = this.localIndex.get(holderKey) || '';
    const credIds = holderCreds ? holderCreds.split(',') : [];
    if (!credIds.includes(credential.id)) {
      credIds.push(credential.id);
      this.localIndex.set(holderKey, credIds.join(','));
    }
  }

  async getCredential(id: string): Promise<VerifiableCredential | null> {
    const cid = this.localIndex.get(`credential:${id}`);
    if (!cid) return null;

    const storedData = await this.retrieveFromIPFS<VerifiableCredential>(cid);
    return storedData?.data || null;
  }

  async listCredentials(holder: string): Promise<VerifiableCredential[]> {
    const holderKey = `holder:${holder}:credentials`;
    const credIds = this.localIndex.get(holderKey)?.split(',') || [];
    
    const credentials: VerifiableCredential[] = [];
    for (const credId of credIds) {
      if (credId) {
        const credential = await this.getCredential(credId);
        if (credential) {
          credentials.push(credential);
        }
      }
    }
    return credentials;
  }

  async deleteCredential(id: string): Promise<void> {
    const credential = await this.getCredential(id);
    if (credential) {
      // Remove from holder index
      const holder = credential.credentialSubject.id;
      const holderKey = `holder:${holder}:credentials`;
      const credIds = this.localIndex.get(holderKey)?.split(',') || [];
      const updatedIds = credIds.filter(cid => cid !== id);
      if (updatedIds.length > 0) {
        this.localIndex.set(holderKey, updatedIds.join(','));
      } else {
        this.localIndex.delete(holderKey);
      }
      
      // Remove credential index
      this.localIndex.delete(`credential:${id}`);
    }
  }

  // Revocation Operations
  async publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void> {
    const storedData: IPFSStoredData<RevocationList> = {
      type: 'revocation',
      data: revocationList,
      metadata: {
        created: new Date().toISOString(),
        updated: new Date().toISOString(),
        version: '1.0',
      },
    };

    const cid = await this.storeToIPFS(storedData);
    this.localIndex.set(`revocation:${issuerDID}`, cid);
  }

  async checkRevocation(issuerDID: string, credentialId: string): Promise<boolean> {
    const revocationList = await this.getRevocationList(issuerDID);
    if (!revocationList) return false;
    return revocationList.revokedCredentialIds.includes(credentialId);
  }

  async getRevocationList(issuerDID: string): Promise<RevocationList | null> {
    const cid = this.localIndex.get(`revocation:${issuerDID}`);
    if (!cid) return null;

    const storedData = await this.retrieveFromIPFS<RevocationList>(cid);
    return storedData?.data || null;
  }

  // Key Management (always local)
  async storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void> {
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
    const schemaWithId = { ...schema, id: schemaId };
    
    const storedData: IPFSStoredData<CredentialSchema> = {
      type: 'schema',
      data: schemaWithId,
      metadata: {
        created: new Date().toISOString(),
        updated: new Date().toISOString(),
        version: '1.0',
      },
    };

    const cid = await this.storeToIPFS(storedData);
    this.localIndex.set(`schema:${schemaId}`, cid);
    
    // Index by issuer
    const issuerKey = `issuer:${schema.issuerDID}:schemas`;
    const issuerSchemas = this.localIndex.get(issuerKey) || '';
    const schemaIds = issuerSchemas ? issuerSchemas.split(',') : [];
    if (!schemaIds.includes(schemaId)) {
      schemaIds.push(schemaId);
      this.localIndex.set(issuerKey, schemaIds.join(','));
    }
    
    return schemaId;
  }

  async getSchema(schemaId: string): Promise<CredentialSchema | null> {
    const cid = this.localIndex.get(`schema:${schemaId}`);
    if (!cid) return null;

    const storedData = await this.retrieveFromIPFS<CredentialSchema>(cid);
    return storedData?.data || null;
  }

  async listSchemas(issuerDID?: string): Promise<CredentialSchema[]> {
    if (!issuerDID) {
      // List all schemas
      const schemas: CredentialSchema[] = [];
      for (const [key, cid] of this.localIndex) {
        if (key.startsWith('schema:')) {
          const storedData = await this.retrieveFromIPFS<CredentialSchema>(cid);
          if (storedData?.data) {
            schemas.push(storedData.data);
          }
        }
      }
      return schemas;
    }
    
    // List schemas by issuer
    const issuerKey = `issuer:${issuerDID}:schemas`;
    const schemaIds = this.localIndex.get(issuerKey)?.split(',') || [];
    
    const schemas: CredentialSchema[] = [];
    for (const schemaId of schemaIds) {
      if (schemaId) {
        const schema = await this.getSchema(schemaId);
        if (schema) {
          schemas.push(schema);
        }
      }
    }
    return schemas;
  }

  // General operations
  async clear(): Promise<void> {
    // Note: This doesn't remove data from IPFS (which is immutable)
    // It only clears the local index
    this.localIndex.clear();
    this.localKeyStore.clear();
  }

  // IPFS-specific methods
  async pin(cid: string): Promise<void> {
    if (!this.ipfsClient) {
      throw new Error('IPFS client not initialized');
    }
    await this.ipfsClient.pin.add(cid);
  }

  async unpin(cid: string): Promise<void> {
    if (!this.ipfsClient) {
      throw new Error('IPFS client not initialized');
    }
    await this.ipfsClient.pin.rm(cid);
  }

  async getStorageStats(): Promise<{
    totalItems: number;
    indexSize: number;
    ipfsNodeInfo: any;
  }> {
    if (!this.ipfsClient) {
      throw new Error('IPFS client not initialized');
    }
    const nodeInfo = await this.ipfsClient.id();
    return {
      totalItems: this.localIndex.size,
      indexSize: JSON.stringify([...this.localIndex.entries()]).length,
      ipfsNodeInfo: nodeInfo,
    };
  }

  // Phone Number Operations (not implemented for IPFS)
  async storePhoneNumber(userDID: string, phoneNumber: PhoneNumber): Promise<string> {
    throw new Error('Phone number storage not implemented for IPFS provider');
  }

  async getPhoneNumber(userDID: string, phoneId: string): Promise<PhoneNumber | null> {
    throw new Error('Phone number storage not implemented for IPFS provider');
  }

  async listPhoneNumbers(userDID: string): Promise<PhoneNumber[]> {
    throw new Error('Phone number storage not implemented for IPFS provider');
  }

  async updatePhoneNumber(userDID: string, phoneId: string, phoneNumber: Partial<PhoneNumber>): Promise<void> {
    throw new Error('Phone number storage not implemented for IPFS provider');
  }

  async deletePhoneNumber(userDID: string, phoneId: string): Promise<void> {
    throw new Error('Phone number storage not implemented for IPFS provider');
  }

  // Address Operations (not implemented for IPFS)
  async storeAddress(userDID: string, address: Address): Promise<string> {
    throw new Error('Address storage not implemented for IPFS provider');
  }

  async getAddress(userDID: string, addressId: string): Promise<Address | null> {
    throw new Error('Address storage not implemented for IPFS provider');
  }

  async listAddresses(userDID: string): Promise<Address[]> {
    throw new Error('Address storage not implemented for IPFS provider');
  }

  async updateAddress(userDID: string, addressId: string, address: Partial<Address>): Promise<void> {
    throw new Error('Address storage not implemented for IPFS provider');
  }

  async deleteAddress(userDID: string, addressId: string): Promise<void> {
    throw new Error('Address storage not implemented for IPFS provider');
  }

  // Email Address Operations (not implemented for IPFS)
  async storeEmailAddress(userDID: string, emailAddress: EmailAddress): Promise<string> {
    throw new Error('Email address storage not implemented for IPFS provider');
  }

  async getEmailAddress(userDID: string, emailId: string): Promise<EmailAddress | null> {
    throw new Error('Email address storage not implemented for IPFS provider');
  }

  async listEmailAddresses(userDID: string): Promise<EmailAddress[]> {
    throw new Error('Email address storage not implemented for IPFS provider');
  }

  async updateEmailAddress(userDID: string, emailId: string, emailAddress: Partial<EmailAddress>): Promise<void> {
    throw new Error('Email address storage not implemented for IPFS provider');
  }

  async deleteEmailAddress(userDID: string, emailId: string): Promise<void> {
    throw new Error('Email address storage not implemented for IPFS provider');
  }
}