# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Anonymous Identity Framework implementing DIDs (Decentralized Identifiers), VCs (Verifiable Credentials), and preparation for ZKPs (Zero-Knowledge Proofs).

## Commands

- `npm run build` - Compile TypeScript to JavaScript
- `npm run test` - Run all tests
- `npm run test:watch` - Run tests in watch mode
- `npm run dev` - Run the example in development mode
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

3. **User Wallet** (`src/wallet/`)
   - Stores credentials
   - Creates Verifiable Presentations
   - Manages key pairs with encrypted storage

4. **Service Provider** (`src/sp/`)
   - Verifies Verifiable Presentations
   - Validates credential signatures
   - Manages trusted issuer list

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