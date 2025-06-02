# Anonymous Identity Framework

[![CI](https://github.com/Dizzident/anon-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/Dizzident/anon-identity/actions/workflows/ci.yml)
[![Node.js Version](https://img.shields.io/node/v/anon-identity)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A TypeScript implementation of a decentralized identity framework using DIDs (Decentralized Identifiers) and VCs (Verifiable Credentials), with preparation for future ZKP (Zero-Knowledge Proof) integration.

## Features

- 🔐 **Decentralized Identity (DID)**: Create and manage DID:key identifiers
- 📜 **W3C VC 2.0 Support**: Full Verifiable Credentials 2.0 specification compliance
- 🎭 **Enhanced Privacy**: BBS+ signatures for zero-knowledge selective disclosure
- 🔑 **Secure Key Management**: Ed25519 key generation and encrypted storage
- 📝 **JSON-LD Processing**: Full validation, expansion, and canonicalization
- 🖊️ **Linked Data Proofs**: Extensible signature suites (Ed25519, BBS+)
- 📊 **Credential Status**: StatusList2021 and RevocationList2020 support
- 🔒 **Multiple Proofs**: Multi-party attestations and endorsements
- 💼 **Enterprise Ready**: Session management, batch operations, error handling
- 🌐 **Multi-Storage**: Memory, File, IPFS, and Blockchain backends
- 🎯 **TypeScript First**: Full type safety and IntelliSense support

## Installation

```bash
npm install anon-identity
```

### Browser Support 🌐

The library now supports browser environments! Use the browser-specific entry point for web applications:

```typescript
// For browsers (React, Vue, Angular, etc.)
import { CryptoService, DIDService } from 'anon-identity/browser';

// For Node.js (full features)
import { CryptoService, DIDService } from 'anon-identity/node';
```

See [BROWSER_USAGE.md](./BROWSER_USAGE.md) for detailed browser usage instructions.

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

### Agent-to-Agent Delegation Example

```typescript
import { AgentIdentityManager, DelegationManager } from 'anon-identity';

// Create agent manager
const agentManager = new AgentIdentityManager();

// Create primary agent
const primaryAgent = await agentManager.createAgent(userDID, {
  name: 'Assistant Agent',
  description: 'Main AI assistant',
  canDelegate: true,
  maxDelegationDepth: 3
});

// Create specialized sub-agent
const calendarAgent = await agentManager.createSubAgent(primaryAgent.did, {
  name: 'Calendar Agent',
  description: 'Calendar management specialist',
  parentAgentDID: primaryAgent.did,
  requestedScopes: ['read:calendar', 'write:calendar']
});
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

### Advanced Features (NEW!)

#### W3C VC 2.0 Support

```typescript
import { IdentityProviderV2, ServiceProviderV2 } from 'anon-identity';

// Issue VC 2.0 credential with advanced features
const credential = await idp.issueVerifiableCredentialV2(userDID, attributes, {
  credentialStatus: { type: 'StatusList2021', statusListIndex: 42 },
  termsOfUse: { type: 'IssuerPolicy', prohibition: [...] },
  evidence: { type: 'DocumentVerification', verifier: 'did:example:123' }
});
```

#### BBS+ Selective Disclosure

```typescript
import { BbsSelectiveDisclosure } from 'anon-identity';

// Create privacy-preserving derived credential
const bbsDisclosure = new BbsSelectiveDisclosure();
const result = await bbsDisclosure.deriveCredential(credential, {
  attributesToReveal: ['name', 'age'], // Only reveal selected attributes
  nonce: 'unique-nonce'
});
```

#### Agent Communication and Revocation

```typescript
import { CascadingRevocationManager, CommunicationManager } from 'anon-identity';

// Inter-agent communication
const commManager = new CommunicationManager(agentIdentity, agentManager, delegationManager);
await commManager.requestDelegation(targetAgentDID, ['read:data'], { purpose: 'Data analysis' });

// Cascading revocation
const revocationManager = new CascadingRevocationManager(agentManager, chainValidator, commManager);
await revocationManager.revokeAgent({
  targetAgentDID: compromisedAgent.did,
  reason: 'Security breach',
  cascading: true // Revoke all sub-agents
});
```

#### JSON-LD Processing

```typescript
import { JsonLdProcessor } from 'anon-identity';

// Validate and process credentials
const processor = new JsonLdProcessor();
const validation = await processor.validateCredential(credential);
const canonical = await processor.canonicalize(credential);
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

### Phase 4: Storage Abstraction ✓
- Abstract storage interface for all identity data
- Memory storage provider (default)
- File storage provider with encryption
- Prepared for blockchain and IPFS integration
- Persistent credential and DID storage

### Phase 5: Smart Contract Infrastructure ✓
- DID Registry contract for on-chain DID management
- Revocation Registry contract for credential revocation
- Schema Registry contract for credential schemas
- Comprehensive TypeScript integration library
- 71 passing smart contract tests
- Local deployment and testing environment

## Future Enhancements

- Advanced Zero-Knowledge Proofs (Circom/SnarkJS integration)
- Support for additional DID methods (did:ethr, did:ion)
- Persistent storage backends
- Credential revocation
- Advanced credential schemas
- Homomorphic encryption for computation on encrypted data

## Demo Application

For a complete demo application with UI, see [anon-identity-demo](https://github.com/Dizzident/anon-identity-demo).

## Publishing

This package is automatically published to npm when a new release is created on GitHub.

### Setup (One-time)

1. Create an npm account at https://www.npmjs.com
2. Generate an npm access token:
   - Go to https://www.npmjs.com/settings/YOUR_USERNAME/tokens
   - Click "Generate New Token" → "Classic Token"
   - Select "Automation" type
   - Copy the token
3. Add the token to GitHub:
   - Go to https://github.com/Dizzident/anon-identity/settings/secrets/actions
   - Click "New repository secret"
   - Name: `NPM_TOKEN`
   - Value: Your npm token

### Publishing a New Version

1. Update version in package.json:
   ```bash
   npm version patch  # or minor/major
   ```
2. Push the tag:
   ```bash
   git push origin main --tags
   ```
3. Create a GitHub release:
   - Go to https://github.com/Dizzident/anon-identity/releases
   - Click "Draft a new release"
   - Choose the tag you just created
   - Add release notes
   - Click "Publish release"
4. The package will automatically be published to npm!

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT