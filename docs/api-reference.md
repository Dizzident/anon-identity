# API Reference

Complete method documentation for coding agents.

## Core Classes

### IdentityProvider

Issues verifiable credentials and manages revocation.

#### Constructor
```typescript
new IdentityProvider(keyPair: KeyPair, storageProvider?: IStorageProvider)
```

#### Static Methods
```typescript
static async create(storageProvider?: IStorageProvider): Promise<IdentityProvider>
```

#### Instance Methods

##### `issueVerifiableCredential(userDID: string, attributes: UserAttributes): Promise<VerifiableCredential>`
Issues a W3C-compliant verifiable credential.

**Parameters:**
- `userDID`: Target user's DID
- `attributes`: Credential attributes (must include `dateOfBirth` for age calculation)

**Returns:** Signed verifiable credential

**Example:**
```typescript
const credential = await idp.issueVerifiableCredential('did:key:z6Mk...', {
  givenName: 'Alice',
  dateOfBirth: '1990-01-01',
  degree: 'Computer Science'
});
```

##### `revokeCredential(credentialId: string): void`
Marks a credential as revoked.

##### `publishRevocationList(): Promise<string>`
Publishes current revocation list and returns URL.

##### `getDID(): string`
Returns the identity provider's DID.

##### `getRevocationList(): Promise<RevocationList>`
Returns current revocation list.

---

### UserWallet

Manages user credentials and creates presentations.

#### Constructor
```typescript
new UserWallet(keyPair: KeyPair, storageProvider?: IStorageProvider)
```

#### Static Methods
```typescript
static async create(storageProvider?: IStorageProvider): Promise<UserWallet>
```

#### Instance Methods

##### `storeCredential(credential: VerifiableCredential): Promise<void>`
Stores a credential in the wallet.

##### `getCredential(credentialId: string): Promise<VerifiableCredential | null>`
Retrieves a stored credential.

##### `listCredentials(): Promise<VerifiableCredential[]>`
Lists all stored credentials.

##### `createVerifiablePresentation(credentialIds: string[]): Promise<VerifiablePresentation>`
Creates a presentation containing specified credentials.

**Parameters:**
- `credentialIds`: Array of credential IDs to include

**Returns:** Signed verifiable presentation

##### `createSelectiveDisclosurePresentation(credentialId: string, attributesToDisclose: string[], purpose: string): Promise<VerifiablePresentation>`
Creates a privacy-preserving presentation revealing only selected attributes.

**Parameters:**
- `credentialId`: Source credential ID
- `attributesToDisclose`: Array of attribute names to reveal
- `purpose`: Proof purpose for the presentation

##### `getDID(): string`
Returns the wallet owner's DID.

---

### ServiceProvider

Verifies presentations with enhanced features.

#### Constructor
```typescript
new ServiceProvider(
  name: string, 
  trustedIssuers: string[] = [], 
  options: ServiceProviderOptions = {}
)
```

**Options Interface:**
```typescript
interface ServiceProviderOptions {
  sessionManager?: SessionManagerOptions;
  checkRevocation?: boolean;
  storageProvider?: IStorageProvider;
  batchOperations?: BatchOperationOptions;
}
```

#### Verification Methods

##### `verifyPresentation(presentation: VerifiablePresentation): Promise<VerificationResult>`
Core verification method with enhanced error reporting.

**Returns:**
```typescript
interface VerificationResult {
  valid: boolean;
  holder?: string;
  credentials?: Array<{
    id: string;
    issuer: string;
    type: string[];
    attributes: Record<string, any>;
    selectivelyDisclosed?: boolean;
    disclosedAttributes?: string[];
  }>;
  errors?: VerificationError[];
  timestamp?: Date;
}
```

##### `verifyPresentationWithSession(presentation: VerifiablePresentation, createSession?: boolean, sessionMetadata?: Record<string, any>): Promise<{ verification: VerificationResult; session?: Session }>`
Verifies presentation and optionally creates a session.

##### `verifyPresentationWithRequest(presentation: VerifiablePresentation, request: PresentationRequestObject): Promise<{ verification: VerificationResult; requestValidation: ValidationResult }>`
Verifies presentation against a specific request.

#### Session Management

##### `createSession(verificationResult: VerificationResult, metadata?: Record<string, any>): Promise<Session>`
Creates a new session from successful verification.

##### `validateSession(sessionId: string): Promise<SessionValidation>`
Validates an existing session.

##### `setSessionExpiry(sessionId: string, duration: number): Promise<void>`
Updates session expiration time.

##### `getSession(sessionId: string): Session | undefined`
Retrieves session by ID.

##### `getAllSessions(): Session[]`
Returns all active sessions.

##### `getSessionsByHolder(holderDID: string): Session[]`
Returns sessions for a specific holder.

##### `removeSession(sessionId: string): void`
Manually removes a session.

##### `clearAllSessions(): void`
Removes all sessions.

#### Batch Operations

##### `batchVerifyPresentations(presentations: VerifiablePresentation[]): Promise<BatchVerificationResult[]>`
Verifies multiple presentations concurrently.

##### `batchCheckRevocations(credentialIds: string[]): Promise<Map<string, BatchRevocationResult>>`
Checks revocation status for multiple credentials.

##### `batchVerifyWithRevocationCheck(presentations: VerifiablePresentation[]): Promise<BatchVerificationResult[]>`
Combined batch verification and revocation checking.

#### Presentation Requests

##### `createPresentationRequest(options: PresentationRequestOptions): Promise<PresentationRequestObject>`
Creates a structured presentation request.

##### `createSimplePresentationRequest(credentialTypes: string[], purpose: string, requiredAttributes?: string[], optionalAttributes?: string[]): Promise<PresentationRequestObject>`
Creates a simple presentation request.

##### `validatePresentationAgainstRequest(presentation: VerifiablePresentation, request: PresentationRequestObject): Promise<ValidationResult>`
Validates presentation against request requirements.

#### Trust Management

##### `addTrustedIssuer(issuerDID: string): void`
Adds an issuer to the trusted list.

##### `removeTrustedIssuer(issuerDID: string): void`
Removes an issuer from the trusted list.

##### `getTrustedIssuers(): string[]`
Returns array of trusted issuer DIDs.

#### Configuration

##### `setRevocationCheck(enabled: boolean): void`
Enables/disables revocation checking.

##### `setStorageProvider(provider: IStorageProvider): void`
Updates the storage provider.

##### `destroy(): void`
Cleanup method - stops timers and releases resources.

---

### Storage Providers

#### MemoryStorageProvider
In-memory storage for testing and development.

```typescript
const storage = new MemoryStorageProvider();
```

#### FileStorageProvider (Node.js only)
File-based persistence.

```typescript
const storage = new FileStorageProvider('./data');
```

#### IPFSStorageProvider
IPFS distributed storage.

```typescript
const storage = new IPFSStorageProvider('http://localhost:5001');
```

#### BlockchainStorageProvider
Ethereum/Polygon blockchain storage.

```typescript
const storage = new BlockchainStorageProvider(provider, contractAddress);
```

#### HybridStorageProvider
Combines multiple storage backends.

```typescript
const storage = new HybridStorageProvider(
  primaryProvider,
  backupProvider,
  { syncInterval: 60000 }
);
```

---

### Utility Classes

#### SessionManager
Direct session management (used internally by ServiceProvider).

```typescript
const sessionManager = new SessionManager({
  defaultSessionDuration: 3600000, // 1 hour
  maxSessionDuration: 86400000,    // 24 hours
  cleanupInterval: 300000          // 5 minutes
});
```

#### BatchOperations
Direct batch operation management.

```typescript
const batchOps = new BatchOperations({
  maxConcurrency: 10,
  timeout: 30000,
  continueOnError: true
});
```

#### PresentationRequest
Direct presentation request management.

```typescript
const requestManager = new PresentationRequest(serviceProviderDID);
```

---

### Error Classes

#### VerificationError
Enhanced error with specific error codes.

```typescript
class VerificationError extends Error {
  code: VerificationErrorCode;
  details: VerificationErrorDetails;
  
  // Factory methods
  static expiredCredential(credentialId: string, issuer: string): VerificationError
  static revokedCredential(credentialId: string, issuer: string): VerificationError
  static untrustedIssuer(issuer: string, credentialId: string): VerificationError
  static invalidSignature(credentialId: string, reason?: string): VerificationError
  static missingRequiredAttribute(attribute: string, credentialId?: string): VerificationError
  static invalidDisclosureProof(credentialId: string): VerificationError
}
```

#### Error Codes
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

---

### Cryptographic Services

#### CryptoService
Ed25519 key generation and signing.

```typescript
// Generate key pair
const keyPair = await CryptoService.generateKeyPair();

// Sign data
const signature = await CryptoService.sign(data, privateKey);

// Verify signature
const isValid = await CryptoService.verify(data, signature, publicKey);
```

#### DIDService
DID creation and resolution.

```typescript
// Create DID from public key
const did = DIDService.createDIDKey(publicKey);

// Extract public key from DID
const publicKey = DIDService.getPublicKeyFromDID(didString);
```

---

## Method Chaining Patterns

### Basic Flow
```typescript
const idp = await IdentityProvider.create(storage);
const wallet = await UserWallet.create(storage);
const sp = new ServiceProvider('Service', [idp.getDID()], { storageProvider: storage });

const credential = await idp.issueVerifiableCredential(wallet.getDID(), attributes);
await wallet.storeCredential(credential);
const presentation = await wallet.createVerifiablePresentation([credential.id]);
const result = await sp.verifyPresentation(presentation);
```

### With Session Management
```typescript
const { verification, session } = await sp.verifyPresentationWithSession(presentation);
if (verification.valid && session) {
  const validation = await sp.validateSession(session.id);
  await sp.setSessionExpiry(session.id, 7200000);
}
```

### With Batch Operations
```typescript
const results = await sp.batchVerifyPresentations(presentations);
const statistics = batchOps.generateBatchStatistics(results);
const validResults = batchOps.filterResults(results, { validOnly: true });
```

### Error Handling Pattern
```typescript
try {
  const result = await sp.verifyPresentation(presentation);
  if (!result.valid) {
    result.errors?.forEach(error => {
      if (error instanceof VerificationError) {
        console.log(`[${error.code}] ${error.message}`, error.details);
      }
    });
  }
} catch (error) {
  if (isVerificationError(error)) {
    // Handle specific verification error
  } else {
    // Handle general error
  }
}
```