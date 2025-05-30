# TypeScript Types Reference

Complete type definitions for coding agents implementing anon-identity.

## Core Interfaces

### KeyPair
Cryptographic key pair for signing operations.

```typescript
interface KeyPair {
  publicKey: Uint8Array;   // Ed25519 public key (32 bytes)
  privateKey: Uint8Array;  // Ed25519 private key (64 bytes)
}
```

### DID
Decentralized Identifier with associated public key.

```typescript
interface DID {
  id: string;              // DID string (e.g., "did:key:z6Mk...")
  publicKey: Uint8Array;   // Associated public key
}
```

## Credential and Presentation Types

### VerifiableCredential
W3C Verifiable Credential structure.

```typescript
interface VerifiableCredential {
  "@context": string[];              // JSON-LD contexts
  id: string;                        // Unique credential ID
  type: string[];                    // Credential types
  issuer: string;                    // Issuer DID
  issuanceDate: string;              // ISO 8601 date string
  credentialSubject: {               // Subject attributes
    id: string;                      // Subject DID
    [key: string]: any;              // Dynamic attributes
  };
  proof?: {                          // Cryptographic proof
    type: string;                    // Proof type
    created: string;                 // Proof creation time
    proofPurpose: string;            // Proof purpose
    verificationMethod: string;      // Verification method reference
    jws: string;                     // JSON Web Signature
  };
}
```

### VerifiablePresentation
W3C Verifiable Presentation containing credentials.

```typescript
interface VerifiablePresentation {
  "@context": string[];              // JSON-LD contexts
  type: string[];                    // Presentation types
  verifiableCredential: (           // Array of credentials
    VerifiableCredential | 
    SelectivelyDisclosedCredential
  )[];
  proof?: {                          // Presentation proof
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    jws: string;
  };
}
```

### SelectivelyDisclosedCredential
Privacy-preserving credential with selective attribute disclosure.

```typescript
interface SelectivelyDisclosedCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    id: string;
    [key: string]: any;              // Only disclosed attributes
  };
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    jws: string;
  };
  disclosureProof?: {                // Selective disclosure proof
    type: string;
    originalCredentialId: string;
    disclosedAttributes: string[];   // List of disclosed attribute names
    nonce: string;                   // Cryptographic nonce
    proofValue: string;              // Proof data
  };
}
```

### UserAttributes
User attribute schema for credential subjects.

```typescript
interface UserAttributes {
  // Basic identity
  givenName?: string;
  familyName?: string;
  dateOfBirth?: string;              // YYYY-MM-DD format
  isOver18?: boolean;                // Auto-calculated from dateOfBirth
  
  // Contact information
  phoneNumbers?: PhoneNumber[];
  emailAddresses?: EmailAddress[];
  addresses?: Address[];
  
  // Extensible for additional attributes
  [key: string]: any;
}

interface PhoneNumber {
  id?: string;
  number: string;
  type: 'mobile' | 'home' | 'work' | 'other';
  countryCode?: string;
  isPrimary?: boolean;
  verified?: boolean;
  verifiedAt?: string;
  canReceiveSMS?: boolean;
  canReceiveCalls?: boolean;
  preferredFor2FA?: boolean;
}

interface EmailAddress {
  id?: string;
  email: string;
  type: 'personal' | 'work' | 'school' | 'other';
  isPrimary?: boolean;
  verified?: boolean;
  verifiedAt?: string;
  canReceive2FA?: boolean;
  preferredFor2FA?: boolean;
}

interface Address {
  id?: string;
  street: string;
  city: string;
  state?: string;
  postalCode?: string;
  country: string;
  type: 'home' | 'work' | 'mailing' | 'other';
  isPrimary?: boolean;
  verified?: boolean;
  verifiedAt?: string;
}
```

## Service Provider Types

### VerificationResult
Result of credential/presentation verification.

```typescript
interface VerificationResult {
  valid: boolean;                    // Overall verification result
  holder?: string;                   // Holder DID if verification successful
  credentials?: Array<{              // Verified credentials
    id: string;                      // Credential ID
    issuer: string;                  // Issuer DID
    type: string[];                  // Credential types
    attributes: Record<string, any>; // Verified attributes
    selectivelyDisclosed?: boolean;  // Whether selective disclosure was used
    disclosedAttributes?: string[];  // List of disclosed attributes
  }>;
  errors?: VerificationError[];      // Verification errors
  timestamp?: Date;                  // Verification timestamp
}
```

### ServiceProviderOptions
Configuration options for ServiceProvider.

```typescript
interface ServiceProviderOptions {
  sessionManager?: SessionManagerOptions;     // Session management config
  checkRevocation?: boolean;                  // Enable revocation checking
  storageProvider?: IStorageProvider;         // Storage backend
  batchOperations?: BatchOperationOptions;    // Batch processing config
}
```

## Session Management Types

### Session
Active user session data.

```typescript
interface Session {
  id: string;                        // Unique session identifier
  holderDID: string;                 // Session holder's DID
  credentialIds: string[];           // Associated credential IDs
  attributes: Record<string, any>;   // Aggregated user attributes
  createdAt: Date;                   // Session creation time
  expiresAt: Date;                   // Session expiration time
  lastAccessedAt: Date;              // Last access time
  metadata?: Record<string, any>;    // Additional session metadata
}
```

### SessionValidation
Result of session validation.

```typescript
interface SessionValidation {
  valid: boolean;                    // Whether session is valid
  session?: Session;                 // Session data if valid
  reason?: string;                   // Reason if invalid
}
```

### SessionManagerOptions
Session manager configuration.

```typescript
interface SessionManagerOptions {
  defaultSessionDuration?: number;  // Default duration in milliseconds
  maxSessionDuration?: number;      // Maximum allowed duration
  cleanupInterval?: number;         // Cleanup timer interval
}
```

## Error Types

### VerificationError
Enhanced error with specific error codes and details.

```typescript
class VerificationError extends Error {
  readonly code: VerificationErrorCode;
  readonly details: VerificationErrorDetails;
  
  constructor(
    code: VerificationErrorCode,
    message: string,
    details?: VerificationErrorDetails
  );
  
  // Factory methods
  static expiredCredential(credentialId: string, issuer: string): VerificationError;
  static revokedCredential(credentialId: string, issuer: string): VerificationError;
  static untrustedIssuer(issuer: string, credentialId: string): VerificationError;
  static invalidSignature(credentialId: string, reason?: string): VerificationError;
  static missingRequiredAttribute(attribute: string, credentialId?: string): VerificationError;
  static invalidDisclosureProof(credentialId: string): VerificationError;
  // ... other factory methods
}
```

### VerificationErrorCode
Enumeration of specific error codes.

```typescript
enum VerificationErrorCode {
  EXPIRED_CREDENTIAL = 'EXPIRED_CREDENTIAL',
  REVOKED_CREDENTIAL = 'REVOKED_CREDENTIAL',
  UNTRUSTED_ISSUER = 'UNTRUSTED_ISSUER',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  MISSING_REQUIRED_ATTRIBUTE = 'MISSING_REQUIRED_ATTRIBUTE',
  INVALID_DISCLOSURE_PROOF = 'INVALID_DISCLOSURE_PROOF',
  MISSING_PROOF = 'MISSING_PROOF',
  INVALID_PRESENTATION_SIGNATURE = 'INVALID_PRESENTATION_SIGNATURE',
  INVALID_CREDENTIAL_FORMAT = 'INVALID_CREDENTIAL_FORMAT',
  NETWORK_ERROR = 'NETWORK_ERROR',
  STORAGE_ERROR = 'STORAGE_ERROR'
}
```

### VerificationErrorDetails
Additional error context information.

```typescript
interface VerificationErrorDetails {
  credentialId?: string;             // Related credential ID
  issuer?: string;                   // Related issuer DID
  attribute?: string;                // Related attribute name
  expectedValue?: any;               // Expected attribute value
  actualValue?: any;                 // Actual attribute value
  timestamp?: Date;                  // Error occurrence time
  [key: string]: any;                // Additional context
}
```

## Batch Operation Types

### BatchVerificationResult
Result of batch verification operation.

```typescript
interface BatchVerificationResult {
  presentationIndex: number;         // Index in original batch
  presentationId?: string;           // Presentation identifier
  result: VerificationResult;        // Verification result
  processingTime: number;            // Processing time in milliseconds
}
```

### BatchRevocationResult
Result of batch revocation check.

```typescript
interface BatchRevocationResult {
  credentialId: string;              // Credential identifier
  isRevoked: boolean;                // Revocation status
  error?: VerificationError;         // Error if check failed
  processingTime: number;            // Processing time in milliseconds
}
```

### BatchOperationOptions
Configuration for batch operations.

```typescript
interface BatchOperationOptions {
  maxConcurrency?: number;           // Maximum concurrent operations
  timeout?: number;                  // Timeout per operation (ms)
  continueOnError?: boolean;         // Whether to continue on individual failures
}
```

## Presentation Request Types

### PresentationRequestObject
Structured presentation request.

```typescript
interface PresentationRequestObject {
  id: string;                        // Unique request identifier
  type: ['PresentationRequest'];     // Request type
  from: string;                      // Requesting service DID
  purpose: string;                   // Request purpose description
  challenge: string;                 // Cryptographic challenge
  domain?: string;                   // Request domain
  credentialRequirements: CredentialRequirement[];
  createdAt: Date;                   // Request creation time
  expiresAt?: Date;                  // Request expiration
  allowPartialMatch: boolean;        // Accept partial fulfillment
}
```

### CredentialRequirement
Requirements for a specific credential type.

```typescript
interface CredentialRequirement {
  type: string[];                    // Required credential types
  issuer?: string;                   // Specific required issuer
  trustedIssuers?: string[];         // List of acceptable issuers
  attributes: AttributeConstraint[];  // Attribute requirements
  maxAge?: number;                   // Maximum credential age (ms)
}
```

### AttributeConstraint
Constraints for credential attributes.

```typescript
interface AttributeConstraint {
  name: string;                      // Attribute name
  required: boolean;                 // Whether attribute is required
  expectedValue?: any;               // Exact expected value
  allowedValues?: any[];             // List of acceptable values
  minValue?: number;                 // Minimum value (for numbers)
  maxValue?: number;                 // Maximum value (for numbers)
  pattern?: string;                  // Regex pattern (for strings)
}
```

### ValidationResult
Result of presentation validation against request.

```typescript
interface ValidationResult {
  valid: boolean;                    // Whether presentation satisfies request
  matchedRequirements: CredentialRequirement[];
  unmatchedRequirements: CredentialRequirement[];
  errors: VerificationError[];       // Validation errors
  score: number;                     // Fulfillment score (0-1)
}
```

### PresentationRequestOptions
Options for creating presentation requests.

```typescript
interface PresentationRequestOptions {
  credentialRequirements: CredentialRequirement[];
  purpose: string;                   // Human-readable purpose
  challenge?: string;                // Custom challenge
  domain?: string;                   // Request domain
  expiresAt?: Date;                  // Request expiration
  allowPartialMatch?: boolean;       // Accept partial matches
}
```

## Storage Provider Types

### IStorageProvider
Interface for storage providers.

```typescript
interface IStorageProvider {
  // DID operations
  storeDID(did: string, didDocument: DIDDocument): Promise<void>;
  resolveDID(did: string): Promise<DIDDocument | null>;
  
  // Credential operations
  storeCredential(credential: VerifiableCredential): Promise<void>;
  getCredential(credentialId: string): Promise<VerifiableCredential | null>;
  listCredentials(holderDID?: string): Promise<VerifiableCredential[]>;
  deleteCredential(credentialId: string): Promise<void>;
  
  // Revocation operations
  publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void>;
  checkRevocation(issuerDID: string, credentialId: string): Promise<boolean>;
  getRevocationList(issuerDID: string): Promise<RevocationList | null>;
  
  // Key management
  storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void>;
  retrieveKeyPair(identifier: string): Promise<string | null>;
}
```

### StorageConfig
Configuration for storage providers.

```typescript
interface StorageConfig {
  // File storage
  dataDirectory?: string;            // Data directory path
  encryption?: boolean;              // Enable file encryption
  
  // IPFS storage
  ipfsNode?: string;                 // IPFS node URL
  pinningService?: string;           // Pinning service URL
  
  // Blockchain storage
  provider?: any;                    // Web3 provider
  contractAddress?: string;          // Contract address
  gasLimit?: number;                 // Gas limit for transactions
  
  // Hybrid storage
  primaryProvider?: IStorageProvider;
  backupProvider?: IStorageProvider;
  syncInterval?: number;             // Sync interval (ms)
}
```

### DIDDocument
W3C DID Document structure.

```typescript
interface DIDDocument {
  '@context': string[];              // JSON-LD contexts
  id: string;                        // DID identifier
  verificationMethod: VerificationMethod[];
  authentication?: string[];         // Authentication methods
  assertionMethod?: string[];        // Assertion methods
  created: string;                   // Creation timestamp
}

interface VerificationMethod {
  id: string;                        // Method identifier
  type: string;                      // Method type
  controller: string;                // Controller DID
  publicKeyMultibase?: string;       // Public key (multibase)
  publicKeyJwk?: any;               // Public key (JWK)
}
```

## Revocation Types

### RevocationList
W3C-style revocation list.

```typescript
interface RevocationList {
  "@context": string[];              // JSON-LD contexts
  id: string;                        // Revocation list identifier
  type: string[];                    // Revocation list types
  issuer: string;                    // Issuer DID
  issuanceDate: string;              // List creation date
  revokedCredentials: string[];      // Revoked credential IDs
  proof?: {                          // List signature
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    jws: string;
  };
}
```

### Storage RevocationList
Internal revocation list format for storage.

```typescript
interface StorageRevocationList {
  issuerDID: string;                 // Issuer identifier
  revokedCredentialIds: string[];    // Revoked credential IDs
  timestamp: number;                 // Last update timestamp
  signature: string;                 // List signature (JWT)
}
```

## Schema Types

### AttributeSchema
Schema definition for credential attributes.

```typescript
interface AttributeSchema {
  name: string;                      // Attribute name
  type: "string" | "date" | "boolean" | "number" | "object";
  required?: boolean;                // Whether attribute is required
  description?: string;              // Human-readable description
  format?: string;                   // Format specification
  pattern?: string;                  // Validation pattern
  minimum?: number;                  // Minimum value
  maximum?: number;                  // Maximum value
  enum?: any[];                      // Enumerated values
}
```

### CredentialSchema
Complete schema for credential types.

```typescript
interface CredentialSchema {
  id: string;                        // Schema identifier
  type: string;                      // Schema type
  name: string;                      // Human-readable name
  description: string;               // Schema description
  version: string;                   // Schema version
  attributes: AttributeSchema[];     // Attribute definitions
  contexts: string[];                // Required JSON-LD contexts
  credentialTypes: string[];         // Associated credential types
}
```

## Selective Disclosure Types

### SelectiveDisclosureRequest
Request for selective attribute disclosure.

```typescript
interface SelectiveDisclosureRequest {
  credentialId: string;              // Source credential ID
  attributesToDisclose: string[];    // Attributes to reveal
  purpose?: string;                  // Disclosure purpose
  nonce?: string;                    // Cryptographic nonce
}
```

## Utility Types

### Constructor Parameters
Helper types for constructor parameters.

```typescript
// Service Provider constructor parameters
type ServiceProviderParams = [
  name: string,
  trustedIssuers?: string[],
  options?: ServiceProviderOptions
];

// Identity Provider constructor parameters
type IdentityProviderParams = [
  keyPair: KeyPair,
  storageProvider?: IStorageProvider
];

// User Wallet constructor parameters
type UserWalletParams = [
  keyPair: KeyPair,
  storageProvider?: IStorageProvider
];
```

### Error Type Guards
Type guard functions for error handling.

```typescript
// Check if error is a VerificationError
function isVerificationError(error: unknown): error is VerificationError;

// Get error code from any error
function getErrorCode(error: unknown): VerificationErrorCode | null;
```

### Generic Response Types
Common response patterns.

```typescript
interface SuccessResponse<T> {
  success: true;
  data: T;
  timestamp: Date;
}

interface ErrorResponse {
  success: false;
  error: string;
  code?: string;
  details?: any;
  timestamp: Date;
}

type ApiResponse<T> = SuccessResponse<T> | ErrorResponse;
```

## Type Usage Examples

### Basic Implementation
```typescript
// Type-safe service provider setup
const serviceProvider: ServiceProvider = new ServiceProvider(
  'My Service',
  ['did:key:z6Mk...'],
  {
    checkRevocation: true,
    storageProvider: new MemoryStorageProvider(),
    sessionManager: {
      defaultSessionDuration: 3600000
    }
  }
);

// Type-safe verification
const result: VerificationResult = await serviceProvider.verifyPresentation(presentation);

if (result.valid && result.credentials) {
  // TypeScript knows credentials is defined here
  const attributes: Record<string, any> = result.credentials[0].attributes;
}
```

### Error Handling with Types
```typescript
try {
  const result = await serviceProvider.verifyPresentation(presentation);
} catch (error: unknown) {
  if (isVerificationError(error)) {
    // TypeScript knows this is a VerificationError
    const code: VerificationErrorCode = error.code;
    const details: VerificationErrorDetails = error.details;
    
    switch (code) {
      case VerificationErrorCode.REVOKED_CREDENTIAL:
        handleRevokedCredential(details.credentialId!, details.issuer!);
        break;
      case VerificationErrorCode.EXPIRED_CREDENTIAL:
        handleExpiredCredential(details.credentialId!, details.issuer!);
        break;
    }
  }
}
```

### Session Management with Types
```typescript
// Type-safe session creation
const sessionResult: { verification: VerificationResult; session?: Session } = 
  await serviceProvider.verifyPresentationWithSession(presentation);

if (sessionResult.session) {
  // TypeScript knows session is defined
  const sessionId: string = sessionResult.session.id;
  const attributes: Record<string, any> = sessionResult.session.attributes;
  
  // Type-safe session validation
  const validation: SessionValidation = await serviceProvider.validateSession(sessionId);
  
  if (validation.valid && validation.session) {
    // TypeScript knows session is defined in this branch
    console.log('Session expires at:', validation.session.expiresAt);
  }
}
```

All types are exported from the main package and can be imported for use in your TypeScript applications.