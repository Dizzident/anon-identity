# Blockchain Storage Integration Plan

## Executive Summary

This document outlines the plan to integrate blockchain storage into the anon-identity framework, enabling decentralized storage of public identity data while maintaining privacy for sensitive information.

## Current State Analysis

### Storage Components
- **In-Memory Storage**: All data currently stored in memory
- **SecureStorage**: Basic key-value store with encryption for private keys
- **No Persistence**: Data lost on application restart
- **No Distribution**: Single node storage only

### Data Types
1. **Public Data** (suitable for blockchain):
   - DIDs and DID Documents
   - Revocation Lists
   - Credential Schemas

2. **Private Data** (must remain off-chain):
   - Private Keys
   - Full Verifiable Credentials (contain PII)
   - Personal Identity Attributes

## Proposed Architecture

### Multi-Layer Storage System

```
┌─────────────────────────────────────────┐
│         Application Layer               │
│  (IDP, Wallet, Service Provider)        │
└────────────────┬────────────────────────┘
                 │
┌────────────────┴────────────────────────┐
│        Storage Abstraction Layer        │
│         (IStorageProvider)              │
└────────────────┬────────────────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
┌───┴──────────┐    ┌────────┴────────────┐
│  Blockchain  │    │   Off-Chain         │
│   Storage    │    │   Storage           │
│              │    │                     │
│ • DIDs       │    │ • Private Keys     │
│ • Revocations│    │ • Credentials      │
│ • Schemas    │    │ • Personal Data    │
└──────────────┘    └────────────────────┘
        │                    │
        │                    ├── Local Encrypted
        │                    ├── IPFS
        │                    └── Cloud Storage
        │
        ├── Ethereum L2
        ├── Polygon
        └── Arbitrum
```

### Smart Contract Design

#### 1. DID Registry Contract
```solidity
contract DIDRegistry {
    struct DIDDocument {
        bytes publicKey;
        uint256 created;
        uint256 updated;
        bool active;
    }
    
    mapping(string => DIDDocument) public dids;
    mapping(address => string[]) public ownerDIDs;
    
    event DIDRegistered(string indexed did, address indexed owner);
    event DIDUpdated(string indexed did);
    event DIDDeactivated(string indexed did);
    
    function registerDID(string memory did, bytes memory publicKey) external;
    function updateDID(string memory did, bytes memory publicKey) external;
    function resolveDID(string memory did) external view returns (DIDDocument memory);
    function deactivateDID(string memory did) external;
}
```

#### 2. Revocation Registry Contract
```solidity
contract RevocationRegistry {
    struct RevocationList {
        uint256[] revokedCredentialIds;
        uint256 timestamp;
        bytes signature;
    }
    
    mapping(string => RevocationList) public revocationLists;
    mapping(address => bool) public authorizedIssuers;
    
    event RevocationPublished(string indexed issuerDID, uint256 timestamp);
    
    function publishRevocationList(
        string memory issuerDID, 
        uint256[] memory revokedIds,
        bytes memory signature
    ) external;
    
    function checkRevocation(
        string memory issuerDID, 
        uint256 credentialId
    ) external view returns (bool);
}
```

#### 3. Schema Registry Contract
```solidity
contract SchemaRegistry {
    struct CredentialSchema {
        string schemaHash;  // IPFS hash
        string issuerDID;
        uint256 version;
        bool active;
    }
    
    mapping(uint256 => CredentialSchema) public schemas;
    uint256 public nextSchemaId;
    
    event SchemaRegistered(uint256 indexed schemaId, string issuerDID);
    
    function registerSchema(
        string memory schemaHash, 
        string memory issuerDID
    ) external returns (uint256);
    
    function getSchema(uint256 schemaId) external view returns (CredentialSchema memory);
}
```

## Implementation Roadmap

### Phase 1: Storage Abstraction Layer (Weeks 1-2)

**Objective**: Create flexible storage architecture supporting multiple backends

**Tasks**:
1. Define `IStorageProvider` interface
2. Implement storage providers:
   - `MemoryStorageProvider` (refactor existing)
   - `FileStorageProvider` (local persistence)
   - `IPFSStorageProvider` (distributed storage)
3. Update all components to use storage abstraction
4. Create storage configuration system

**Deliverables**:
- Storage provider interface and implementations
- Updated components with configurable storage
- Unit tests for each provider

### Phase 2: Smart Contract Development (Weeks 3-5)

**Objective**: Deploy core identity contracts on blockchain

**Tasks**:
1. Set up development environment (Hardhat/Foundry)
2. Implement smart contracts:
   - DID Registry
   - Revocation Registry
   - Schema Registry
3. Write comprehensive contract tests
4. Deploy to testnet
5. Create contract interaction library

**Deliverables**:
- Deployed contracts on testnet
- Contract interaction TypeScript library
- Contract documentation and tests

### Phase 3: Blockchain Storage Provider (Weeks 6-7)

**Objective**: Integrate blockchain with storage abstraction

**Tasks**:
1. Implement `BlockchainStorageProvider`
2. Add Web3 integration (ethers.js/viem)
3. Implement gas optimization strategies:
   - Batch operations
   - Merkle tree for revocations
   - IPFS for large data
4. Create caching layer for blockchain reads

**Deliverables**:
- Working blockchain storage provider
- Gas optimization implementation
- Performance benchmarks

### Phase 4: Hybrid Storage Solution (Week 8)

**Objective**: Combine on-chain and off-chain storage optimally

**Tasks**:
1. Implement `HybridStorageProvider`
2. Create routing logic:
   - Public data → Blockchain
   - Large data → IPFS
   - Private data → Local encrypted
3. Implement data synchronization
4. Add fallback mechanisms

**Deliverables**:
- Hybrid storage implementation
- Configuration documentation
- Integration examples

### Phase 5: Testing & Migration (Week 9)

**Objective**: Ensure production readiness

**Tasks**:
1. Create migration tools
2. Comprehensive integration testing
3. Performance testing and optimization
4. Security audit preparation
5. Documentation updates

**Deliverables**:
- Migration tools and guides
- Test reports
- Performance benchmarks
- Updated documentation

## Technical Specifications

### Storage Provider Interface

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
  
  // Revocation Operations
  publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void>;
  checkRevocation(issuerDID: string, credentialId: string): Promise<boolean>;
  getRevocationList(issuerDID: string): Promise<RevocationList | null>;
  
  // Key Management (always local)
  storeKeyPair(identifier: string, keyPair: CryptoKeyPair, passphrase: string): Promise<void>;
  retrieveKeyPair(identifier: string, passphrase: string): Promise<CryptoKeyPair | null>;
  
  // Schema Operations
  registerSchema(schema: CredentialSchema): Promise<string>;
  getSchema(schemaId: string): Promise<CredentialSchema | null>;
}
```

### Configuration Options

```typescript
interface StorageConfig {
  provider: 'memory' | 'file' | 'blockchain' | 'hybrid';
  
  // Blockchain specific
  blockchain?: {
    network: 'ethereum' | 'polygon' | 'arbitrum';
    rpcUrl: string;
    privateKey?: string; // For write operations
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
  
  // Local storage specific
  local?: {
    path: string;
    encryption: boolean;
  };
  
  // Caching
  cache?: {
    enabled: boolean;
    ttl: number; // seconds
    maxSize: number; // MB
  };
}
```

## Security Considerations

### On-Chain Security
1. **Access Control**: Only DID owners can update their documents
2. **Signature Verification**: All updates require valid signatures
3. **Rate Limiting**: Prevent spam through gas costs
4. **Upgradability**: Use proxy patterns for contract updates

### Off-Chain Security
1. **Encryption**: All private data encrypted at rest
2. **Key Derivation**: Use PBKDF2/Argon2 for key derivation
3. **Access Control**: Implement fine-grained permissions
4. **Audit Logging**: Track all data access

### Privacy Considerations
1. **Minimal On-Chain Data**: Store only necessary public data
2. **Zero-Knowledge Proofs**: Already implemented for selective disclosure
3. **Data Minimization**: Use hashes and references where possible
4. **GDPR Compliance**: Ensure right to erasure for off-chain data

## Performance Optimization

### Blockchain Optimization
1. **Batch Operations**: Group multiple updates
2. **Event Indexing**: Use events for efficient querying
3. **IPFS for Large Data**: Store only hashes on-chain
4. **Layer 2 Solutions**: Use rollups for scalability

### Caching Strategy
1. **Multi-Level Cache**: Memory → Redis → Blockchain
2. **TTL Configuration**: Based on data type
3. **Invalidation**: Event-based cache invalidation
4. **Preloading**: Anticipate common queries

## Cost Analysis

### Estimated Gas Costs (Ethereum L2)
- DID Registration: ~50,000 gas
- DID Update: ~30,000 gas
- Revocation List Update: ~40,000 gas
- Schema Registration: ~45,000 gas

### Cost Optimization Strategies
1. **Batch Transactions**: Reduce per-operation cost
2. **Merkle Trees**: Store root hash only
3. **IPFS Integration**: Offload storage
4. **Subsidized Gas**: IDP pays for user operations

## Migration Strategy

### Data Migration
1. Export existing in-memory data
2. Deploy contracts and storage infrastructure
3. Migrate DIDs to blockchain
4. Update revocation lists
5. Transition users gradually

### Backward Compatibility
1. Maintain storage abstraction interface
2. Support multiple storage providers
3. Gradual feature rollout
4. Fallback mechanisms

## Future Enhancements

### Short Term (3-6 months)
1. **Multi-Chain Support**: Deploy on multiple blockchains
2. **Advanced Caching**: Redis integration
3. **Monitoring**: Blockchain event monitoring
4. **Analytics**: Usage statistics

### Long Term (6-12 months)
1. **Cross-Chain Bridge**: Interoperability between chains
2. **Decentralized Governance**: DAO for protocol updates
3. **Economic Incentives**: Token rewards for participants
4. **Advanced Privacy**: Integration with privacy chains

## Conclusion

This blockchain integration plan provides a path to transform the anon-identity framework from a centralized in-memory system to a decentralized, persistent, and scalable identity solution. The phased approach ensures minimal disruption while maximizing the benefits of blockchain technology for digital identity management.