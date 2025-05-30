# Current Limitations

Understanding the library's constraints for proper implementation planning.

## Cryptographic Limitations

### Signature Algorithm Support
**Current State:** Only Ed25519 signatures supported
**Impact:** Limited interoperability with systems using other signature algorithms
**Workaround:** Convert or bridge to Ed25519 where needed
**Future:** Planned support for secp256k1, RSA, and ECDSA

```typescript
// ❌ Not supported
const rsaCredential = await idp.issueWithRSA(userDID, attributes);

// ✅ Currently supported
const ed25519Credential = await idp.issueVerifiableCredential(userDID, attributes);
```

### Key Management
**Current State:** Private keys stored encrypted with user-provided passphrase
**Impact:** No hardware security module (HSM) support
**Workaround:** Use strong passphrases and secure storage
**Future:** HSM integration planned

## DID Method Support

### Limited DID Methods
**Current State:** Only `did:key` method supported
**Impact:** Cannot resolve `did:web`, `did:ethr`, or other DID methods
**Workaround:** Convert external DIDs or use bridging services
**Future:** Support for `did:web`, `did:ethr`, `did:ion` planned

```typescript
// ❌ Not supported
const webDID = DIDService.resolve('did:web:example.com');
const ethrDID = DIDService.resolve('did:ethr:0x123...');

// ✅ Currently supported
const keyDID = DIDService.createDIDKey(publicKey);
```

### DID Resolution
**Current State:** No external DID resolution
**Impact:** Cannot verify credentials from external DID systems
**Workaround:** Manual DID document management
**Future:** Universal resolver integration

## Storage Limitations

### Blockchain Performance
**Current State:** Ethereum transactions are slow and expensive
**Impact:** Real-time applications may experience delays
**Workaround:** Use hybrid storage with blockchain backup
**Future:** Layer 2 solutions and alternative blockchain support

```typescript
// ⚠️ Slow for real-time use
const blockchainStorage = new BlockchainStorageProvider(provider, address);

// ✅ Better for real-time
const hybridStorage = new HybridStorageProvider(
  new MemoryStorageProvider(),     // Fast primary
  blockchainStorage,               // Secure backup
  { syncInterval: 300000 }
);
```

### IPFS Dependencies
**Current State:** IPFS requires external node or service
**Impact:** Additional infrastructure complexity
**Workaround:** Use managed IPFS services (Pinata, Infura)
**Future:** Embedded IPFS node option

### File Storage Security
**Current State:** File storage uses basic filesystem permissions
**Impact:** Limited access control granularity
**Workaround:** Use OS-level security and encryption
**Future:** Enhanced file encryption and access controls

## Session Management Limitations

### Session Persistence
**Current State:** Sessions stored in memory only
**Impact:** Sessions lost on service restart
**Workaround:** Use persistent storage providers for session data
**Future:** Built-in session persistence

```typescript
// ⚠️ Sessions lost on restart
const sp = new ServiceProvider(name, issuers, {
  sessionManager: { /* memory only */ }
});

// ✅ Workaround - implement custom persistence
class PersistentSessionManager extends SessionManager {
  async createSession(verificationResult) {
    const session = await super.createSession(verificationResult);
    await this.saveToDatabase(session);
    return session;
  }
}
```

### Cross-Service Sessions
**Current State:** Sessions are service-specific
**Impact:** Cannot share sessions across services
**Workaround:** Use shared storage or session federation
**Future:** Cross-service session standards

### Session Clustering
**Current State:** No distributed session support
**Impact:** Sessions tied to specific service instances
**Workaround:** Use sticky sessions or shared storage
**Future:** Distributed session management

## Batch Operation Limitations

### Memory Usage
**Current State:** All batch items loaded into memory
**Impact:** Large batches may cause memory issues
**Workaround:** Process in smaller chunks
**Future:** Streaming batch processing

```typescript
// ⚠️ Memory intensive for large batches
const results = await sp.batchVerifyPresentations(tenThousandPresentations);

// ✅ Process in chunks
const chunks = chunkArray(presentations, 100);
const allResults = [];
for (const chunk of chunks) {
  const chunkResults = await sp.batchVerifyPresentations(chunk);
  allResults.push(...chunkResults);
}
```

### Error Recovery
**Current State:** Limited error recovery in batch operations
**Impact:** Partial batch failures may require full retry
**Workaround:** Use `continueOnError` option and manual retry
**Future:** Advanced retry mechanisms and partial recovery

## Revocation Limitations

### Real-time Revocation
**Current State:** Revocation lists updated periodically
**Impact:** Brief window where revoked credentials appear valid
**Workaround:** Frequent revocation list updates
**Future:** Real-time revocation notifications

### Revocation Privacy
**Current State:** Revocation lists expose revoked credential IDs
**Impact:** Privacy concerns for revoked credentials
**Workaround:** Use credential rotation strategies
**Future:** Privacy-preserving revocation methods

## Selective Disclosure Limitations

### Attribute Granularity
**Current State:** Disclosure at attribute level only
**Impact:** Cannot partially disclose complex attributes
**Workaround:** Structure credentials with granular attributes
**Future:** Sub-attribute disclosure support

```typescript
// ⚠️ All-or-nothing disclosure
const attributes = {
  address: '123 Main St, City, State, 12345' // Must reveal entire address
};

// ✅ Granular structure
const attributes = {
  streetAddress: '123 Main St',
  city: 'City',
  state: 'State',
  postalCode: '12345'
};
```

### Proof Verification Performance
**Current State:** Selective disclosure verification is CPU intensive
**Impact:** May impact performance for large-scale verification
**Workaround:** Use batch operations and caching
**Future:** Optimized cryptographic implementations

## Network and Performance Limitations

### Network Dependencies
**Current State:** External network calls for blockchain and IPFS
**Impact:** Network failures can affect functionality
**Workaround:** Implement proper timeout and retry logic
**Future:** Enhanced offline capabilities

### Concurrent Operations
**Current State:** Limited concurrent operation testing
**Impact:** Potential race conditions in high-concurrency scenarios
**Workaround:** Implement application-level locking
**Future:** Enhanced concurrency testing and safety

## Browser Limitations

### Crypto API Support
**Current State:** Depends on Web Crypto API availability
**Impact:** Older browsers may not be supported
**Workaround:** Use polyfills or fallback implementations
**Future:** Broader browser compatibility

### Storage Limitations
**Current State:** Browser storage quotas and persistence
**Impact:** Large credential stores may hit limits
**Workaround:** Use IndexedDB and periodic cleanup
**Future:** Better storage management

### IPFS Access
**Current State:** Browser IPFS requires gateway or proxy
**Impact:** Direct IPFS access not available in browser
**Workaround:** Use IPFS gateways or server-side proxy
**Future:** Browser IPFS improvements

## Integration Limitations

### Framework Support
**Current State:** Generic TypeScript/JavaScript only
**Impact:** No framework-specific integrations
**Workaround:** Create wrapper services for specific frameworks
**Future:** React, Vue, Angular integrations planned

### Mobile Support
**Current State:** No native mobile SDKs
**Impact:** Mobile integration requires JavaScript bridge
**Workaround:** Use React Native or similar frameworks
**Future:** Native iOS/Android SDKs

## Standards Compliance Limitations

### W3C VC Standards
**Current State:** Based on W3C VC 1.1 specification
**Impact:** May not support newer W3C VC features
**Workaround:** Manual implementation of newer features
**Future:** Continuous standards compliance updates

### JSON-LD Context
**Current State:** Limited JSON-LD context support
**Impact:** May not be compatible with all VC ecosystems
**Workaround:** Use supported contexts or manual mapping
**Future:** Enhanced JSON-LD support

## Development and Testing Limitations

### Testing Coverage
**Current State:** Core functionality tested, edge cases limited
**Impact:** Potential undiscovered issues in complex scenarios
**Workaround:** Thorough integration testing in applications
**Future:** Enhanced test coverage and edge case testing

### Documentation
**Current State:** Core documentation provided
**Impact:** Some advanced use cases may lack examples
**Workaround:** Community examples and issue discussions
**Future:** Comprehensive documentation and tutorials

### Debug Support
**Current State:** Limited debugging tools and logging
**Impact:** Troubleshooting complex issues may be difficult
**Workaround:** Add application-level logging
**Future:** Enhanced debugging and diagnostic tools

## Scalability Limitations

### Horizontal Scaling
**Current State:** No built-in horizontal scaling support
**Impact:** Scaling requires application-level design
**Workaround:** Use load balancers and shared storage
**Future:** Built-in scaling patterns and guides

### Performance Metrics
**Current State:** Limited built-in performance monitoring
**Impact:** Difficulty optimizing performance
**Workaround:** Implement custom metrics and monitoring
**Future:** Built-in performance monitoring and optimization

## Security Limitations

### Audit Status
**Current State:** No formal security audit completed
**Impact:** Potential security vulnerabilities unknown
**Workaround:** Careful security review and testing
**Future:** Professional security audit planned

### Side-Channel Attacks
**Current State:** Limited protection against timing attacks
**Impact:** Potential information leakage in verification
**Workaround:** Constant-time implementation where possible
**Future:** Enhanced side-channel protection

## Migration and Compatibility

### Breaking Changes
**Current State:** API may change in major versions
**Impact:** Migration effort required for upgrades
**Workaround:** Pin to specific versions, test upgrades
**Future:** Stable API with backward compatibility

### Data Migration
**Current State:** No built-in data migration tools
**Impact:** Manual migration required between versions
**Workaround:** Export/import data manually
**Future:** Automated migration tools

## Workaround Patterns

### Error Handling
```typescript
// Implement robust error handling
try {
  const result = await operation();
} catch (error) {
  if (isNetworkError(error)) {
    // Retry with exponential backoff
    await retryWithBackoff(operation);
  } else if (isVerificationError(error)) {
    // Handle verification failure
    logVerificationFailure(error);
  } else {
    // Handle unknown error
    throw error;
  }
}
```

### Performance Optimization
```typescript
// Cache frequently accessed data
const cache = new Map();
async function getCachedCredential(id: string) {
  if (cache.has(id)) {
    return cache.get(id);
  }
  const credential = await storage.getCredential(id);
  cache.set(id, credential);
  return credential;
}
```

### Resource Management
```typescript
// Proper cleanup
class ServiceWrapper {
  private sp: ServiceProvider;
  
  constructor() {
    this.sp = new ServiceProvider(/* ... */);
    
    // Cleanup on process exit
    process.on('SIGTERM', () => this.cleanup());
    process.on('SIGINT', () => this.cleanup());
  }
  
  cleanup() {
    this.sp.destroy();
  }
}
```