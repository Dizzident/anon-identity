# Storage Abstraction Layer

The anon-identity framework now includes a flexible storage abstraction layer that supports multiple storage backends for identity data. This enables persistence, distribution, and prepares for blockchain integration.

## Overview

The storage abstraction provides a unified interface (`IStorageProvider`) for storing and retrieving:
- DIDs and DID Documents
- Verifiable Credentials
- Revocation Lists
- Credential Schemas
- Encrypted Key Pairs

## Available Storage Providers

### 1. MemoryStorageProvider

In-memory storage for development and testing.

```typescript
import { MemoryStorageProvider } from 'anon-identity';

const provider = new MemoryStorageProvider();
```

**Use cases:**
- Development and testing
- Temporary sessions
- Performance-critical applications

### 2. FileStorageProvider

Persistent file-based storage with optional encryption.

```typescript
import { FileStorageProvider } from 'anon-identity';

const provider = new FileStorageProvider(
  './identity-data.json',  // File path
  true,                    // Enable encryption
  'secure-passphrase'      // Encryption passphrase
);
```

**Features:**
- AES-256-GCM encryption
- JSON-based storage
- Atomic write operations
- Cross-instance persistence

**Use cases:**
- Desktop applications
- Local development
- Offline-first applications

### 3. IPFSStorageProvider (Coming Soon)

Distributed storage using IPFS.

### 4. BlockchainStorageProvider (Coming Soon)

On-chain storage for public data (DIDs, revocations).

## Using Storage Providers

### With Identity Provider

```typescript
import { IdentityProvider, FileStorageProvider } from 'anon-identity';

// Create storage provider
const storage = new FileStorageProvider('./idp-data.json', true, 'passphrase');

// Create IDP with custom storage
const idp = await IdentityProvider.create(storage);

// Issue credentials - automatically stored
const credential = await idp.issueVerifiableCredential(userDID, attributes);
```

### With User Wallet

```typescript
import { UserWallet, FileStorageProvider } from 'anon-identity';

// Create storage provider
const storage = new FileStorageProvider('./wallet-data.json', true, 'passphrase');

// Create wallet with custom storage
const wallet = await UserWallet.create(storage);

// Store credentials - persisted to file
await wallet.storeCredential(credential);

// Credentials persist across sessions
const wallet2 = await UserWallet.create(storage);
const creds = await storage.listCredentials(wallet.getDID());
```

### With Service Provider

```typescript
import { ServiceProvider, FileStorageProvider } from 'anon-identity';

// Create storage provider
const storage = new FileStorageProvider('./sp-data.json', true, 'passphrase');

// Create SP with custom storage
const sp = new ServiceProvider('My Service', [trustedIssuer], true, storage);

// Verification automatically checks storage for revocations
const result = await sp.verifyPresentation(presentation);
```

## Storage Provider Interface

```typescript
interface IStorageProvider {
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
  
  // General operations
  clear(): Promise<void>;
}
```

## Creating Custom Storage Providers

To create a custom storage provider, implement the `IStorageProvider` interface:

```typescript
import { IStorageProvider } from 'anon-identity';

export class CustomStorageProvider implements IStorageProvider {
  async storeDID(did: string, document: DIDDocument): Promise<void> {
    // Your implementation
  }
  
  // Implement all other methods...
}
```

## Storage Configuration

```typescript
interface StorageConfig {
  provider: 'memory' | 'file' | 'blockchain' | 'hybrid' | 'ipfs';
  
  // File storage specific
  file?: {
    path: string;
    encryption: boolean;
  };
  
  // Future: Blockchain specific
  blockchain?: {
    network: 'ethereum' | 'polygon' | 'arbitrum';
    rpcUrl: string;
    contracts: {
      didRegistry: string;
      revocationRegistry: string;
      schemaRegistry: string;
    };
  };
}
```

## Security Considerations

### Encryption
- FileStorageProvider uses AES-256-GCM encryption
- Key derivation uses PBKDF2 with 100,000 iterations
- Each write generates a new IV
- Authentication tags prevent tampering

### Key Storage
- Private keys are always encrypted before storage
- Keys are never stored in plaintext
- Passphrase-based encryption for key material

### Best Practices
1. Use strong passphrases for encrypted storage
2. Implement proper access controls
3. Regularly backup encrypted storage files
4. Use different storage providers for different data types
5. Never store private keys on-chain

## Migration from In-Memory Storage

To migrate existing code:

```typescript
// Before
const idp = await IdentityProvider.create();

// After
import { FileStorageProvider } from 'anon-identity';
const storage = new FileStorageProvider('./data.json', true, 'passphrase');
const idp = await IdentityProvider.create(storage);
```

The default behavior remains in-memory storage for backward compatibility.

## Future Roadmap

1. **IPFS Integration** - Distributed storage for credentials and schemas
2. **Blockchain Integration** - On-chain storage for DIDs and revocations
3. **Hybrid Storage** - Automatic routing based on data type
4. **Cloud Storage** - AWS S3, Google Cloud Storage adapters
5. **Database Adapters** - PostgreSQL, MongoDB storage providers

## Examples

See the [storage example](../examples/storage-example.ts) for a complete demonstration of the storage abstraction features.