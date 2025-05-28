/**
 * Browser-compatible exports for anon-identity
 * 
 * This entry point excludes Node.js-specific features like:
 * - File storage
 * - Direct blockchain access (requires server-side proxy)
 * - IPFS storage (requires server-side proxy)
 */

// Core browser-compatible components
export { CryptoService } from './core/crypto-browser';
export { DIDService } from './core/did';
export { EncryptedStorageService, EncryptedStorageService as SecureStorage } from './core/storage-browser';

// Types (all browser-safe)
export * from './types';
export * from './types/did';

// Identity components (browser-safe)
export { IdentityProvider } from './idp/identity-provider';
export { UserWallet } from './wallet/user-wallet';
export { ServiceProvider, VerificationResult } from './sp/service-provider';

// Schemas (browser-safe)
export * from './idp/schemas';

// ZKP (browser-safe)
export { SelectiveDisclosure } from './zkp/selective-disclosure';

// Revocation (browser-safe)
export { RevocationService, MockRevocationRegistry } from './revocation/revocation-service';

// Memory storage provider (browser-safe)
export { MemoryStorageProvider } from './storage/providers/memory-storage-provider';
export { StorageFactory } from './storage/storage-factory-browser';

// Storage types
export type { IStorageProvider, StorageConfig } from './storage/types';