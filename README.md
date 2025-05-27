# Anonymous Identity Framework

[![CI](https://github.com/Dizzident/anon-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/Dizzident/anon-identity/actions/workflows/ci.yml)
[![Node.js Version](https://img.shields.io/node/v/anon-identity)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A TypeScript implementation of a decentralized identity framework using DIDs (Decentralized Identifiers) and VCs (Verifiable Credentials), with preparation for future ZKP (Zero-Knowledge Proof) integration.

## Features

- **DID Management**: Generate and manage decentralized identifiers using the did:key method
- **Verifiable Credentials**: Issue and verify W3C-compliant verifiable credentials
- **Secure Key Storage**: Encrypted local storage for private keys
- **Verifiable Presentations**: Create and verify presentations containing multiple credentials
- **Selective Disclosure (ZKP)**: Privacy-preserving attribute disclosure without revealing unnecessary information
- **Credential Revocation**: Issuers can revoke credentials with signed revocation lists
- **Ed25519 Cryptography**: Strong elliptic curve cryptography for signatures

## Installation

```bash
npm install anon-identity
```

## Usage

### Basic Example

```typescript
import { IdentityProvider, UserWallet, ServiceProvider } from './src';

// Create an Identity Provider
const idp = await IdentityProvider.create();

// Create a User Wallet
const userWallet = await UserWallet.create();

// Issue a Verifiable Credential
const credential = await idp.issueVerifiableCredential(
  userWallet.getDID(),
  {
    givenName: 'Alice',
    dateOfBirth: '1990-01-15'
  }
);

// Store credential in wallet
userWallet.storeCredential(credential);

// Create a Verifiable Presentation
const presentation = await userWallet.createVerifiablePresentation([credential.id]);

// Verify the presentation
const sp = new ServiceProvider('My Service', [idp.getDID()]);
const result = await sp.verifyPresentation(presentation);
```

### Quick Start

```typescript
import { IdentityProvider, UserWallet, ServiceProvider } from 'anon-identity';

// See examples directory for complete usage examples
```

### Selective Disclosure Example

```typescript
// Create a presentation revealing only specific attributes
const disclosureRequest: SelectiveDisclosureRequest = {
  credentialId: credential.id,
  attributesToDisclose: ['isOver18'] // Only reveal age verification, not birth date
};

const presentation = await userWallet.createSelectiveDisclosurePresentation([disclosureRequest]);
```

### Revocation Example

```typescript
// Revoke a credential
idp.revokeCredential(credential.id);
const revocationUrl = await idp.publishRevocationList();

// Service provider automatically checks revocation during verification
const result = await sp.verifyPresentation(presentation);
// Result will be invalid if credential is revoked
```

## Development

### Build
```bash
npm run build
```

### Test
```bash
npm run test
```

### Test with Watch Mode
```bash
npm run test:watch
```

## Architecture

The framework is organized into four main modules:

1. **Core**: Cryptographic operations, DID management, and secure storage
2. **Identity Provider (IDP)**: Issues and signs verifiable credentials
3. **User Wallet**: Manages credentials and creates presentations
4. **Service Provider (SP)**: Verifies presentations and credentials

## Architecture Overview

### Phase 1: Core Identity Framework ✓
- DID generation and management (did:key)
- Verifiable Credential issuance and storage
- Verifiable Presentation creation and verification
- Secure encrypted key storage

### Phase 2: Basic Zero-Knowledge Proofs ✓
- Selective disclosure of credential attributes
- Privacy-preserving age verification (prove over 18 without revealing birth date)
- Cryptographic commitments for future ZKP enhancements

### Phase 3: Basic Revocation ✓
- Credential revocation by issuers
- Signed revocation lists
- Automatic revocation checking during verification
- Mock revocation registry for testing

## Future Enhancements

- Advanced Zero-Knowledge Proofs (Circom/SnarkJS integration)
- Support for additional DID methods (did:ethr, did:ion)
- Persistent storage backends
- Credential revocation
- Advanced credential schemas
- Homomorphic encryption for computation on encrypted data

## Demo Application

For a complete demo application with UI, see [anon-identity-demo](https://github.com/Dizzident/anon-identity-demo).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT