import { VerifiableCredential, PhoneNumber, EmailAddress, Address } from '../types';
import { DIDDocument } from '../types/did';

export interface RevocationList {
  issuerDID: string;
  revokedCredentialIds: string[];
  timestamp: number;
  signature: string;
}

export interface CredentialSchema {
  id?: string;
  name: string;
  description: string;
  properties: Record<string, any>;
  issuerDID: string;
  version: string;
  active: boolean;
}

export interface StorageConfig {
  provider: 'memory' | 'file' | 'blockchain' | 'hybrid' | 'ipfs';
  
  // File storage specific
  file?: {
    path: string;
    encryption: boolean;
  };
  
  // Blockchain specific
  blockchain?: {
    network: 'ethereum' | 'polygon' | 'arbitrum';
    rpcUrl: string;
    privateKey?: string;
    contracts: {
      didRegistry: string;
      revocationRegistry: string;
      schemaRegistry: string;
    };
  };
  
  // IPFS specific
  ipfs?: {
    host: string;
    port: number;
    protocol: string;
  };
  
  // Caching
  cache?: {
    enabled: boolean;
    ttl: number; // seconds
    maxSize: number; // MB
  };
  
  // Hybrid storage specific
  hybrid?: {
    routing?: {
      dids?: 'blockchain' | 'ipfs' | 'local';
      credentials?: 'blockchain' | 'ipfs' | 'local';
      revocations?: 'blockchain' | 'ipfs' | 'local';
      schemas?: 'blockchain' | 'ipfs' | 'local';
    };
    sizeThresholds?: {
      useIPFS?: number;
      useLocal?: number;
    };
    sync?: {
      enabled: boolean;
      interval?: number;
      conflictResolution?: 'newest' | 'blockchain' | 'local';
    };
    fallback?: {
      enabled: boolean;
      order?: ('blockchain' | 'ipfs' | 'local')[];
      retries?: number;
      retryDelay?: number;
    };
  };
}

export interface IStorageProvider {
  // DID Operations
  storeDID(did: string, document: DIDDocument): Promise<void>;
  resolveDID(did: string): Promise<DIDDocument | null>;
  listDIDs(owner?: string): Promise<string[]>;
  
  // Credential Operations  
  storeCredential(credential: VerifiableCredential): Promise<void>;
  getCredential(id: string): Promise<VerifiableCredential | null>;
  listCredentials(holder: string): Promise<VerifiableCredential[]>;
  deleteCredential(id: string): Promise<void>;
  
  // Revocation Operations
  publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void>;
  checkRevocation(issuerDID: string, credentialId: string): Promise<boolean>;
  getRevocationList(issuerDID: string): Promise<RevocationList | null>;
  
  // Key Management (always local)
  storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void>;
  retrieveKeyPair(identifier: string): Promise<string | null>;
  deleteKeyPair(identifier: string): Promise<void>;
  
  // Schema Operations
  registerSchema(schema: CredentialSchema): Promise<string>;
  getSchema(schemaId: string): Promise<CredentialSchema | null>;
  listSchemas(issuerDID?: string): Promise<CredentialSchema[]>;
  
  // Phone Number Operations
  storePhoneNumber(userDID: string, phoneNumber: PhoneNumber): Promise<string>;
  getPhoneNumber(userDID: string, phoneId: string): Promise<PhoneNumber | null>;
  listPhoneNumbers(userDID: string): Promise<PhoneNumber[]>;
  updatePhoneNumber(userDID: string, phoneId: string, phoneNumber: Partial<PhoneNumber>): Promise<void>;
  deletePhoneNumber(userDID: string, phoneId: string): Promise<void>;
  
  // Email Address Operations
  storeEmailAddress(userDID: string, emailAddress: EmailAddress): Promise<string>;
  getEmailAddress(userDID: string, emailId: string): Promise<EmailAddress | null>;
  listEmailAddresses(userDID: string): Promise<EmailAddress[]>;
  updateEmailAddress(userDID: string, emailId: string, emailAddress: Partial<EmailAddress>): Promise<void>;
  deleteEmailAddress(userDID: string, emailId: string): Promise<void>;
  
  // Address Operations
  storeAddress(userDID: string, address: Address): Promise<string>;
  getAddress(userDID: string, addressId: string): Promise<Address | null>;
  listAddresses(userDID: string): Promise<Address[]>;
  updateAddress(userDID: string, addressId: string, address: Partial<Address>): Promise<void>;
  deleteAddress(userDID: string, addressId: string): Promise<void>;
  
  // General operations
  clear(): Promise<void>;
}