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
export { IdentityProviderV2 } from './idp/identity-provider-v2';
export { UserWallet } from './wallet/user-wallet';
export { ServiceProvider, VerificationResult, ServiceProviderOptions } from './sp/service-provider';
export { ServiceProviderV2, ServiceProviderV2Options } from './sp/service-provider-v2';

// Enhanced Service Provider components
export { SessionManager, Session, SessionValidation, SessionManagerOptions } from './sp/session-manager';
export { VerificationError, VerificationErrorCode, isVerificationError } from './sp/verification-errors';
export { BatchOperations, BatchVerificationResult, BatchRevocationResult, BatchOperationOptions } from './sp/batch-operations';
export { PresentationRequest, PresentationRequestOptions, ValidationResult, AttributeConstraint, CredentialRequirement } from './sp/presentation-request';

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

// Enhanced standards compliance
export { ProofManager } from './core/proof-manager';
export { 
  CompositeStatusChecker, 
  StatusList2021, 
  StatusList2021StatusChecker,
  RevocationList2020StatusChecker,
  CredentialStatusChecker,
  StatusCheckResult
} from './status/credential-status';
export { migrateCredentialToV2, migratePresentationToV2, createV2Context } from './utils/vc-migration';

// JSON-LD and Linked Data Proofs
export * from './ld';

// BBS+ Selective Disclosure
export { BbsSelectiveDisclosure, BbsSelectiveDisclosureOptions, BbsSelectiveDisclosureResult } from './zkp/bbs-selective-disclosure';