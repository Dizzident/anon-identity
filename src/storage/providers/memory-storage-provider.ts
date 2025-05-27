import { IStorageProvider, RevocationList, CredentialSchema } from '../types';
import { VerifiableCredential } from '../../types';
import { DIDDocument } from '../../types/did';
import { v4 as uuidv4 } from 'uuid';

export class MemoryStorageProvider implements IStorageProvider {
  private dids: Map<string, DIDDocument> = new Map();
  private credentials: Map<string, VerifiableCredential> = new Map();
  private credentialsByHolder: Map<string, Set<string>> = new Map();
  private keyPairs: Map<string, string> = new Map();
  private revocationLists: Map<string, RevocationList> = new Map();
  private schemas: Map<string, CredentialSchema> = new Map();
  private schemasByIssuer: Map<string, Set<string>> = new Map();

  // DID Operations
  async storeDID(did: string, document: DIDDocument): Promise<void> {
    this.dids.set(did, document);
  }

  async resolveDID(did: string): Promise<DIDDocument | null> {
    return this.dids.get(did) || null;
  }

  async listDIDs(owner?: string): Promise<string[]> {
    if (!owner) {
      return Array.from(this.dids.keys());
    }
    // Filter by owner - check if any verification method has this owner as controller
    return Array.from(this.dids.keys()).filter(did => {
      const doc = this.dids.get(did);
      if (!doc || !doc.verificationMethod) return false;
      return doc.verificationMethod.some(vm => vm.controller === owner);
    });
  }

  // Credential Operations
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    this.credentials.set(credential.id, credential);
    
    // Update holder index
    const holder = credential.credentialSubject.id;
    if (!this.credentialsByHolder.has(holder)) {
      this.credentialsByHolder.set(holder, new Set());
    }
    this.credentialsByHolder.get(holder)!.add(credential.id);
  }

  async getCredential(id: string): Promise<VerifiableCredential | null> {
    return this.credentials.get(id) || null;
  }

  async listCredentials(holder: string): Promise<VerifiableCredential[]> {
    const credentialIds = this.credentialsByHolder.get(holder);
    if (!credentialIds) return [];
    
    const credentials: VerifiableCredential[] = [];
    for (const id of credentialIds) {
      const credential = this.credentials.get(id);
      if (credential) {
        credentials.push(credential);
      }
    }
    return credentials;
  }

  async deleteCredential(id: string): Promise<void> {
    const credential = this.credentials.get(id);
    if (credential) {
      const holder = credential.credentialSubject.id;
      const holderCreds = this.credentialsByHolder.get(holder);
      if (holderCreds) {
        holderCreds.delete(id);
        if (holderCreds.size === 0) {
          this.credentialsByHolder.delete(holder);
        }
      }
      this.credentials.delete(id);
    }
  }

  // Revocation Operations
  async publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void> {
    this.revocationLists.set(issuerDID, revocationList);
  }

  async checkRevocation(issuerDID: string, credentialId: string): Promise<boolean> {
    const revocationList = this.revocationLists.get(issuerDID);
    if (!revocationList) return false;
    return revocationList.revokedCredentialIds.includes(credentialId);
  }

  async getRevocationList(issuerDID: string): Promise<RevocationList | null> {
    return this.revocationLists.get(issuerDID) || null;
  }

  // Key Management
  async storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void> {
    this.keyPairs.set(identifier, encryptedKeyPair);
  }

  async retrieveKeyPair(identifier: string): Promise<string | null> {
    return this.keyPairs.get(identifier) || null;
  }

  async deleteKeyPair(identifier: string): Promise<void> {
    this.keyPairs.delete(identifier);
  }

  // Schema Operations
  async registerSchema(schema: CredentialSchema): Promise<string> {
    const schemaId = schema.id || `schema:${uuidv4()}`;
    const schemaWithId = { ...schema, id: schemaId };
    this.schemas.set(schemaId, schemaWithId);
    
    // Update issuer index
    if (!this.schemasByIssuer.has(schema.issuerDID)) {
      this.schemasByIssuer.set(schema.issuerDID, new Set());
    }
    this.schemasByIssuer.get(schema.issuerDID)!.add(schemaId);
    
    return schemaId;
  }

  async getSchema(schemaId: string): Promise<CredentialSchema | null> {
    return this.schemas.get(schemaId) || null;
  }

  async listSchemas(issuerDID?: string): Promise<CredentialSchema[]> {
    if (!issuerDID) {
      return Array.from(this.schemas.values());
    }
    
    const schemaIds = this.schemasByIssuer.get(issuerDID);
    if (!schemaIds) return [];
    
    const schemas: CredentialSchema[] = [];
    for (const id of schemaIds) {
      const schema = this.schemas.get(id);
      if (schema) {
        schemas.push(schema);
      }
    }
    return schemas;
  }

  // General operations
  async clear(): Promise<void> {
    this.dids.clear();
    this.credentials.clear();
    this.credentialsByHolder.clear();
    this.keyPairs.clear();
    this.revocationLists.clear();
    this.schemas.clear();
    this.schemasByIssuer.clear();
  }
}