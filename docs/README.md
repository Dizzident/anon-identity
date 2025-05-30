# anon-identity Documentation

This documentation is optimized for coding agents integrating the anon-identity library.

## Quick Navigation

### Core Integration Guides
- [**Quick Start**](./quick-start.md) - Get up and running in 5 minutes
- [**API Reference**](./api-reference.md) - Complete method documentation
- [**TypeScript Types**](./types.md) - All interfaces and types
- [**Error Handling**](./error-handling.md) - Error codes and recovery strategies

### Implementation Guides
- [**Identity Provider Setup**](./identity-provider.md) - Issuing credentials
- [**Service Provider Setup**](./service-provider.md) - Verifying presentations
- [**User Wallet Integration**](./user-wallet.md) - Managing user credentials
- [**Session Management**](./session-management.md) - Managing user sessions
- [**Batch Operations**](./batch-operations.md) - High-performance verification

### Advanced Features
- [**Selective Disclosure**](./selective-disclosure.md) - Privacy-preserving credentials
- [**Revocation Management**](./revocation.md) - Credential revocation
- [**Presentation Requests**](./presentation-requests.md) - Structured credential requests
- [**Storage Providers**](./storage-providers.md) - Data persistence options

### Platform-Specific
- [**Browser Integration**](./browser-integration.md) - Web application setup
- [**Node.js Integration**](./nodejs-integration.md) - Server-side implementation
- [**Blockchain Features**](./blockchain.md) - Decentralized storage options

### Operational
- [**Security Considerations**](./security.md) - Production security guidelines
- [**Performance Optimization**](./performance.md) - Scaling and optimization
- [**Migration Guide**](./migration.md) - Upgrading from previous versions
- [**Limitations**](./limitations.md) - Current constraints and workarounds
- [**Future Roadmap**](./roadmap.md) - Planned improvements

## Library Overview

The anon-identity library provides a complete implementation of W3C Verifiable Credentials and Decentralized Identifiers (DIDs) with enhanced features for production use:

### Core Components
- **Identity Provider (IDP)**: Issues verifiable credentials
- **User Wallet**: Stores and manages credentials
- **Service Provider (SP)**: Verifies presentations with session management
- **Storage Providers**: Multiple backend options (memory, file, IPFS, blockchain)

### Key Features
- ✅ W3C VC/DID compliance
- ✅ Ed25519 cryptographic signatures
- ✅ Selective disclosure (privacy-preserving)
- ✅ Credential revocation
- ✅ Session management
- ✅ Batch operations
- ✅ Enhanced error handling
- ✅ Browser and Node.js support
- ✅ TypeScript support

### Architecture Pattern
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Identity        │    │ User            │    │ Service         │
│ Provider        │───▶│ Wallet          │───▶│ Provider        │
│ (Issues VCs)    │    │ (Stores VCs)    │    │ (Verifies VPs)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Storage Layer                                │
│  Memory │ File │ IPFS │ Blockchain │ Hybrid                    │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
npm install anon-identity
```

## Basic Usage

```typescript
import {
  IdentityProvider,
  UserWallet,
  ServiceProvider,
  MemoryStorageProvider
} from 'anon-identity';

// Setup
const storage = new MemoryStorageProvider();
const idp = await IdentityProvider.create(storage);
const wallet = await UserWallet.create(storage);
const sp = new ServiceProvider('MyService', [idp.getDID()], { storageProvider: storage });

// Issue credential
const credential = await idp.issueVerifiableCredential(wallet.getDID(), {
  givenName: 'Alice',
  dateOfBirth: '1990-01-01'
});

// Store and present
await wallet.storeCredential(credential);
const presentation = await wallet.createVerifiablePresentation([credential.id]);

// Verify with session
const { verification, session } = await sp.verifyPresentationWithSession(presentation);
```

## Support

- GitHub Issues: Report bugs and feature requests
- Examples: See `/examples` directory for working code
- Tests: See `/src/**/*.test.ts` for usage patterns