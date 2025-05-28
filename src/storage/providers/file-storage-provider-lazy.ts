import { IStorageProvider, RevocationList, CredentialSchema, StorageConfig } from '../types';
import { VerifiableCredential } from '../../types';
import { DIDDocument } from '../../types/did';
import { v4 as uuidv4 } from 'uuid';

// Lazy-loaded Node.js dependencies
let fsModule: any;
let pathModule: any;
let cryptoModule: any;

export class FileStorageProvider implements IStorageProvider {
  private filePath: string;
  private encryptionKey?: string;
  private data: {
    dids: Map<string, DIDDocument>;
    credentials: Map<string, VerifiableCredential>;
    revocations: Map<string, RevocationList>;
    keyPairs: Map<string, string>;
    schemas: Map<string, CredentialSchema>;
  } = {
    dids: new Map(),
    credentials: new Map(),
    revocations: new Map(),
    keyPairs: new Map(),
    schemas: new Map(),
  };
  private initialized = false;
  private initPromise: Promise<void> | null = null;

  constructor(filePath: string, private encryption: boolean = true, private passphrase?: string) {
    this.filePath = filePath;
    if (encryption && passphrase) {
      this.encryptionKey = passphrase;
    }
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
      // Dynamic import of Node.js modules
      [fsModule, pathModule, cryptoModule] = await Promise.all([
        import('fs').then(m => m.promises),
        import('path'),
        import('crypto'),
      ]);

      await this.load();
    } catch (error) {
      throw new Error(`Failed to initialize file storage: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async ensureDirectoryExists(filePath: string): Promise<void> {
    const dir = pathModule.dirname(filePath);
    try {
      await fsModule.access(dir);
    } catch {
      await fsModule.mkdir(dir, { recursive: true });
    }
  }

  private encrypt(data: string): string {
    if (!this.encryptionKey) return data;
    
    const algorithm = 'aes-256-gcm';
    const salt = cryptoModule.randomBytes(16);
    const key = cryptoModule.pbkdf2Sync(this.encryptionKey, salt, 100000, 32, 'sha256');
    const iv = cryptoModule.randomBytes(16);
    const cipher = cryptoModule.createCipheriv(algorithm, key, iv);
    
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

  private decrypt(encryptedData: string): string {
    if (!this.encryptionKey) return encryptedData;
    
    try {
      const { encrypted, salt, iv, authTag } = JSON.parse(encryptedData);
      const algorithm = 'aes-256-gcm';
      const key = cryptoModule.pbkdf2Sync(this.encryptionKey, Buffer.from(salt, 'hex'), 100000, 32, 'sha256');
      
      const decipher = cryptoModule.createDecipheriv(
        algorithm,
        key,
        Buffer.from(iv, 'hex')
      );
      
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      // If decryption fails, assume data is not encrypted
      return encryptedData;
    }
  }

  private async save(): Promise<void> {
    await this.ensureDirectoryExists(this.filePath);
    
    const dataToSave = {
      dids: Array.from(this.data.dids.entries()),
      credentials: Array.from(this.data.credentials.entries()),
      revocations: Array.from(this.data.revocations.entries()),
      keyPairs: Array.from(this.data.keyPairs.entries()),
      schemas: Array.from(this.data.schemas.entries()),
    };
    
    const jsonData = JSON.stringify(dataToSave, null, 2);
    const dataToWrite = this.encrypt(jsonData);
    
    await fsModule.writeFile(this.filePath, dataToWrite, 'utf8');
  }

  private async load(): Promise<void> {
    try {
      await this.ensureDirectoryExists(this.filePath);
      const encryptedData = await fsModule.readFile(this.filePath, 'utf8');
      const jsonData = this.decrypt(encryptedData);
      const loadedData = JSON.parse(jsonData);
      
      this.data.dids = new Map(loadedData.dids || []);
      this.data.credentials = new Map(loadedData.credentials || []);
      this.data.revocations = new Map(loadedData.revocations || []);
      this.data.keyPairs = new Map(loadedData.keyPairs || []);
      this.data.schemas = new Map(loadedData.schemas || []);
    } catch (error) {
      // File doesn't exist or is corrupt, start fresh
      this.data = {
        dids: new Map(),
        credentials: new Map(),
        revocations: new Map(),
        keyPairs: new Map(),
        schemas: new Map(),
      };
    }
  }

  // DID Operations
  async storeDID(did: string, document: DIDDocument): Promise<void> {
    await this.initialize();
    this.data.dids.set(did, document);
    await this.save();
  }

  async resolveDID(did: string): Promise<DIDDocument | null> {
    await this.initialize();
    return this.data.dids.get(did) || null;
  }

  async listDIDs(owner?: string): Promise<string[]> {
    await this.initialize();
    if (!owner) {
      return Array.from(this.data.dids.keys());
    }
    
    const dids: string[] = [];
    for (const [did, document] of this.data.dids) {
      if (document.verificationMethod?.some(vm => vm.controller === owner)) {
        dids.push(did);
      }
    }
    return dids;
  }

  // Credential Operations
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    await this.initialize();
    this.data.credentials.set(credential.id, credential);
    await this.save();
  }

  async getCredential(id: string): Promise<VerifiableCredential | null> {
    await this.initialize();
    return this.data.credentials.get(id) || null;
  }

  async listCredentials(holder: string): Promise<VerifiableCredential[]> {
    await this.initialize();
    const credentials: VerifiableCredential[] = [];
    for (const credential of this.data.credentials.values()) {
      if (credential.credentialSubject.id === holder) {
        credentials.push(credential);
      }
    }
    return credentials;
  }

  async deleteCredential(id: string): Promise<void> {
    await this.initialize();
    this.data.credentials.delete(id);
    await this.save();
  }

  // Revocation Operations
  async publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void> {
    await this.initialize();
    this.data.revocations.set(issuerDID, revocationList);
    await this.save();
  }

  async checkRevocation(issuerDID: string, credentialId: string): Promise<boolean> {
    await this.initialize();
    const revocationList = this.data.revocations.get(issuerDID);
    if (!revocationList) return false;
    return revocationList.revokedCredentialIds.includes(credentialId);
  }

  async getRevocationList(issuerDID: string): Promise<RevocationList | null> {
    await this.initialize();
    return this.data.revocations.get(issuerDID) || null;
  }

  // Key Management
  async storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void> {
    await this.initialize();
    this.data.keyPairs.set(identifier, encryptedKeyPair);
    await this.save();
  }

  async retrieveKeyPair(identifier: string): Promise<string | null> {
    await this.initialize();
    return this.data.keyPairs.get(identifier) || null;
  }

  async deleteKeyPair(identifier: string): Promise<void> {
    await this.initialize();
    this.data.keyPairs.delete(identifier);
    await this.save();
  }

  // Schema Operations
  async registerSchema(schema: CredentialSchema): Promise<string> {
    await this.initialize();
    const schemaId = schema.id || `schema:${uuidv4()}`;
    const schemaWithId = { ...schema, id: schemaId };
    this.data.schemas.set(schemaId, schemaWithId);
    await this.save();
    return schemaId;
  }

  async getSchema(schemaId: string): Promise<CredentialSchema | null> {
    await this.initialize();
    return this.data.schemas.get(schemaId) || null;
  }

  async listSchemas(issuerDID?: string): Promise<CredentialSchema[]> {
    await this.initialize();
    if (!issuerDID) {
      return Array.from(this.data.schemas.values());
    }
    
    return Array.from(this.data.schemas.values()).filter(
      schema => schema.issuerDID === issuerDID
    );
  }

  // General operations
  async clear(): Promise<void> {
    await this.initialize();
    this.data = {
      dids: new Map(),
      credentials: new Map(),
      revocations: new Map(),
      keyPairs: new Map(),
      schemas: new Map(),
    };
    await this.save();
  }
}