# Browser Usage Guide

The anon-identity library now supports browser environments with a dedicated browser-safe entry point.

## Installation

```bash
npm install anon-identity
```

## Browser Import

For browser environments (React, Vue, Angular, etc.), import from the browser-specific entry point:

```typescript
// Browser-safe imports
import { 
  CryptoService, 
  DIDService, 
  IdentityProvider,
  UserWallet,
  ServiceProvider,
  MemoryStorageProvider 
} from 'anon-identity/browser';
```

## Node.js Import

For Node.js environments with full features:

```typescript
// Full Node.js features
import { 
  CryptoService,
  DIDService,
  FileStorageProvider,
  BlockchainStorageProvider,
  ContractClient 
} from 'anon-identity/node';
```

## Feature Availability

### Browser-Safe Features ✅
- Core crypto operations (Ed25519 signatures)
- DID creation and resolution
- Verifiable Credentials issuance and verification
- Selective disclosure / Zero-knowledge proofs
- Memory storage
- Browser-based encrypted storage

### Node.js-Only Features ⚠️
- File storage provider
- Blockchain storage provider (requires ethers.js)
- IPFS storage provider (requires kubo-rpc-client)
- Direct smart contract interaction

## Browser Example

```typescript
import { 
  CryptoService, 
  DIDService, 
  IdentityProvider,
  UserWallet,
  ServiceProvider,
  MemoryStorageProvider,
  StorageFactory
} from 'anon-identity/browser';

// Create storage provider (only memory storage in browser)
const storage = StorageFactory.getDefaultProvider();

// Generate key pair
const keyPair = await CryptoService.generateKeyPair();

// Create DID
const did = DIDService.createDID(keyPair.publicKey);

// Create wallet
const wallet = new UserWallet(storage);
await wallet.initialize('user-password');

// Issue credential
const idp = new IdentityProvider('did:key:issuer', keyPair, storage);
const credential = await idp.issueCredential(
  did,
  { name: 'Alice', age: 25 },
  'BasicProfile'
);

// Store and present credential
await wallet.addCredential(credential);
const presentation = await wallet.createPresentation(
  [credential.id],
  'did:key:verifier'
);
```

## Storage in Browser

In browser environments, you have two storage options:

1. **MemoryStorageProvider** - Data stored in memory (lost on page refresh)
2. **EncryptedStorageService** - Data encrypted and stored in localStorage

```typescript
import { EncryptedStorageService } from 'anon-identity/browser';

const storage = new EncryptedStorageService();

// Save encrypted data
await storage.saveEncryptedData('my-wallet', walletData, 'password123');

// Load encrypted data
const data = await storage.loadEncryptedData('my-wallet', 'password123');
```

## Blockchain Integration in Browser

For blockchain features in browser apps, you'll need a server-side proxy or use a wallet like MetaMask:

```typescript
// Browser app with MetaMask
import { ethers } from 'ethers';

// Get provider from MetaMask
const provider = new ethers.BrowserProvider(window.ethereum);
const signer = await provider.getSigner();

// Use the signer with your app logic
// Note: ContractClient is not available in browser bundle
```

## Build Configuration

### Webpack

```javascript
module.exports = {
  resolve: {
    alias: {
      'anon-identity': 'anon-identity/browser'
    }
  }
};
```

### Vite

```javascript
export default {
  resolve: {
    alias: {
      'anon-identity': 'anon-identity/browser'
    }
  }
};
```

### TypeScript

For proper TypeScript support, the library automatically provides the correct types based on the import path:

```typescript
// Browser types
import type { CryptoService } from 'anon-identity/browser';

// Node.js types  
import type { FileStorageProvider } from 'anon-identity/node';
```

## Migration Guide

If you're migrating from an older version:

1. Update imports to use `/browser` for browser environments
2. Replace any file or blockchain storage with memory storage
3. Implement server-side proxies for blockchain/IPFS operations if needed

## Common Issues

### "Module not found" errors
Make sure you're importing from `anon-identity/browser` not just `anon-identity`.

### "crypto is not defined" errors
Use the browser entry point which includes browser-compatible crypto.

### Storage persistence
Memory storage doesn't persist. Use `EncryptedStorageService` for persistence.

### Blockchain features
Blockchain features require a server-side proxy or wallet integration in browsers.