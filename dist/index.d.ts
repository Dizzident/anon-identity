export { CryptoService } from './core/crypto';
export { DIDService } from './core/did';
export { SecureStorage } from './core/storage';
export { IdentityProvider } from './idp/identity-provider';
export { UserWallet } from './wallet/user-wallet';
export { ServiceProvider, VerificationResult } from './sp/service-provider';
export { SelectiveDisclosure } from './zkp/selective-disclosure';
export { RevocationService, MockRevocationRegistry } from './revocation/revocation-service';
export * from './types';
export { BASIC_PROFILE_SCHEMA, CREDENTIAL_CONTEXTS, CREDENTIAL_TYPES, validateAttributes } from './idp/schemas';
export { IStorageProvider, StorageConfig, RevocationList as StorageRevocationList, CredentialSchema, StorageFactory, MemoryStorageProvider, FileStorageProvider } from './storage';
export { DIDDocument, VerificationMethod } from './types/did';
//# sourceMappingURL=index.d.ts.map