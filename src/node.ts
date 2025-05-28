/**
 * Node.js entry point with full features
 * Uses lazy loading for heavy dependencies
 */

// Core components
export { CryptoService } from './core/crypto';
export { DIDService } from './core/did';
export { SecureStorage } from './core/storage';

// Types
export * from './types';
export * from './types/did';

// Identity components
export { IdentityProvider } from './idp/identity-provider';
export { UserWallet } from './wallet/user-wallet';
export { ServiceProvider, VerificationResult } from './sp/service-provider';

// Schemas
export * from './idp/schemas';

// ZKP
export { SelectiveDisclosure } from './zkp/selective-disclosure';

// Revocation
export { RevocationService, MockRevocationRegistry } from './revocation/revocation-service';

// Storage providers
export { MemoryStorageProvider } from './storage/providers/memory-storage-provider';

// Lazy-loaded storage providers
export { FileStorageProvider } from './storage/providers/file-storage-provider-lazy';
export { IPFSStorageProvider } from './storage/providers/ipfs-storage-provider';
export { BlockchainStorageProvider } from './storage/providers/blockchain-storage-provider-lazy';
export { HybridStorageProvider } from './storage/providers/hybrid-storage-provider';

// Storage factory
export { StorageFactory } from './storage/storage-factory-lazy';

// Storage types (excluding RevocationList to avoid conflict)
export { 
  IStorageProvider, 
  StorageConfig, 
  CredentialSchema,
  RevocationList as StorageRevocationList 
} from './storage/types';

// Blockchain components (lazy-loaded)
export { ContractClient } from './blockchain/contract-client-lazy';
export * from './blockchain/types';