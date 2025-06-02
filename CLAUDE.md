# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Anonymous Identity Framework implementing DIDs (Decentralized Identifiers), VCs (Verifiable Credentials), and preparation for ZKPs (Zero-Knowledge Proofs).

## Project Management

### Planning Documents
All project plans are stored in `docs/plans/`. When working on features:
1. Check `docs/plans/` for existing plans
2. Update plan documents with progress as you complete phases
3. Mark completed items with ✅ and add timestamps
4. Document any deviations or lessons learned

**Important Plan Files:**
- `docs/plans/README.md` - Overview of all plans and tracking conventions
- `docs/plans/AGENT_SUB_IDENTITY_PLAN.md` - Completed agent feature plan (good example)
- `docs/plans/ROADMAP_UPDATE_2025.md` - Current development roadmap
- `docs/plans/NEXT_FEATURES_PRIORITY.md` - Prioritized feature list

Example progress update:
```markdown
### Phase 1: Core Infrastructure ✅ COMPLETED (2024-01-15)
- ✅ Task completed
**Note:** Added extra validation that wasn't in original plan
```

When starting new features:
1. Create a plan in `docs/plans/FEATURE_NAME_PLAN.md`
2. Break down into phases with clear deliverables
3. Update progress as you work
4. Move completed plans to a "Completed" section in the README

## Commands

- `npm run build` - Compile TypeScript to JavaScript
- `npm run test` - Run all tests
- `npm run test:watch` - Run tests in watch mode
- `npm run dev` - Run the basic example
- `npm run dev:zkp` - Run the selective disclosure example
- `npm run dev:revocation` - Run the revocation example
- `npm start` - Run the compiled example

## Architecture

### Core Components

1. **Core Module** (`src/core/`)
   - `crypto.ts` - Ed25519 key generation and signature operations
   - `did.ts` - DID:key creation and resolution
   - `storage.ts` - Secure encrypted storage for private keys

2. **Identity Provider** (`src/idp/`)
   - Issues Verifiable Credentials
   - Signs credentials with Ed25519
   - Validates attributes against schemas
   - Auto-calculates derived attributes (e.g., isOver18 from dateOfBirth)

3. **User Wallet** (`src/wallet/`)
   - Stores credentials
   - Creates Verifiable Presentations
   - Supports selective disclosure presentations
   - Manages key pairs with encrypted storage

4. **Service Provider** (`src/sp/`)
   - Verifies Verifiable Presentations
   - Validates credential signatures
   - Verifies selective disclosure proofs
   - Manages trusted issuer list

5. **ZKP Module** (`src/zkp/`)
   - `selective-disclosure.ts` - Implements privacy-preserving attribute disclosure
   - Creates and verifies disclosure proofs
   - Supports cryptographic commitments

6. **Revocation Module** (`src/revocation/`)
   - `revocation-service.ts` - Manages credential revocation
   - Creates and signs revocation lists
   - Mock registry for testing revocation flows
   - Verification of revocation list signatures

### Key Design Patterns

- W3C Verifiable Credentials standard compliance
- JWT-based proof mechanism using Ed25519 signatures
- DID:key method for simplicity (easily extensible to other DID methods)
- In-memory storage with encryption for private keys
- Modular architecture for easy extension with ZKPs

## Development Workflow

1. The main entry point exports all public APIs from `src/index.ts`
2. Example usage is in `src/example.ts`
3. Tests are co-located with source files (*.test.ts)
4. Integration tests demonstrate full flows in `src/integration.test.ts`

## CI/CD

GitHub Actions workflows:
- **CI** (`.github/workflows/ci.yml`): Runs on push/PR, tests on Node 18.x and 20.x
- **Release** (`.github/workflows/release.yml`): Creates releases on version tags
- **Dependabot** configured for npm and GitHub Actions updates

PR checks include:
- Build verification
- Test execution
- Type checking
- Optional linting