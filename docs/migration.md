# Migration Guide

Guide for upgrading between versions and migrating from other credential systems.

## Version Migration

### From v1.0.x to Enhanced v1.1.x

The enhanced version maintains full backward compatibility while adding new features.

#### No Breaking Changes
All existing code continues to work without modification:

```typescript
// ✅ Existing code works unchanged
const sp = new ServiceProvider('My Service', trustedIssuers, true, storageProvider);
const result = await sp.verifyPresentation(presentation);

if (result.valid) {
  // result.errors is still string[] for backward compatibility
  console.log('Verification successful');
}
```

#### Optional Enhancements
New features are opt-in through updated constructor options:

```typescript
// ✅ Enhanced features via new options
const sp = new ServiceProvider('My Service', trustedIssuers, {
  checkRevocation: true,
  storageProvider,
  sessionManager: {
    defaultSessionDuration: 3600000,
    maxSessionDuration: 86400000
  },
  batchOperations: {
    maxConcurrency: 10,
    timeout: 30000
  }
});
```

#### Error Handling Migration
Enhanced error handling is backward compatible but provides more detail:

```typescript
// Before (still works)
const result = await sp.verifyPresentation(presentation);
if (!result.valid) {
  console.log('Errors:', result.errors); // string[]
}

// Enhanced (optional upgrade)
import { VerificationError, VerificationErrorCode } from 'anon-identity';

const result = await sp.verifyPresentation(presentation);
if (!result.valid && result.errors) {
  result.errors.forEach(error => {
    if (error instanceof VerificationError) {
      console.log(`[${error.code}] ${error.message}`, error.details);
    } else {
      console.log('Legacy error:', error); // string
    }
  });
}
```

#### Session Management Migration
Sessions are a new feature - existing code unaffected:

```typescript
// Before - basic verification
const result = await sp.verifyPresentation(presentation);

// Enhanced - with sessions
const { verification, session } = await sp.verifyPresentationWithSession(presentation);
if (verification.valid && session) {
  // New session-based workflow
  const sessionId = session.id;
}
```

### From v0.x to v1.x (Historical)

#### Breaking Changes in v1.0

1. **Constructor Signatures Changed**
```typescript
// v0.x
const idp = new IdentityProvider(keyPair, did, metadata);
const wallet = new UserWallet(keyPair, did, storage);

// v1.x
const idp = new IdentityProvider(keyPair, storageProvider);
const wallet = new UserWallet(keyPair, storageProvider);

// DID is now auto-generated from keyPair
console.log(idp.getDID()); // Get the generated DID
```

2. **Storage Provider Required**
```typescript
// v0.x - no storage required
const idp = new IdentityProvider(keyPair, did);

// v1.x - storage provider required
const storage = new MemoryStorageProvider();
const idp = new IdentityProvider(keyPair, storage);
```

3. **Async Factory Methods Added**
```typescript
// v0.x - sync constructor
const idp = new IdentityProvider(keyPair, did);

// v1.x - async factory method preferred
const idp = await IdentityProvider.create(storageProvider);
```

#### Migration Script v0.x → v1.x

```typescript
// Migration helper function
async function migrateFromV0toV1(oldIdp, oldWallet, oldSp) {
  // Create storage provider
  const storage = new MemoryStorageProvider();
  
  // Migrate Identity Provider
  const newIdp = new IdentityProvider(oldIdp.keyPair, storage);
  
  // Migrate existing credentials if any
  if (oldIdp.issuedCredentials) {
    for (const credential of oldIdp.issuedCredentials) {
      await storage.storeCredential(credential);
    }
  }
  
  // Migrate User Wallet
  const newWallet = new UserWallet(oldWallet.keyPair, storage);
  
  // Migrate stored credentials
  if (oldWallet.credentials) {
    for (const credential of oldWallet.credentials) {
      await newWallet.storeCredential(credential);
    }
  }
  
  // Migrate Service Provider
  const newSp = new ServiceProvider(
    oldSp.name,
    oldSp.trustedIssuers,
    {
      checkRevocation: oldSp.checkRevocation,
      storageProvider: storage
    }
  );
  
  return { idp: newIdp, wallet: newWallet, sp: newSp };
}
```

## Migrating from Other Credential Systems

### From Hyperledger Aries/Indy

#### Credential Format Conversion
```typescript
// Convert Indy credential to W3C VC
function convertIndyToW3C(indyCredential) {
  return {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    id: `urn:uuid:${indyCredential.cred_def_id}`,
    type: ["VerifiableCredential"],
    issuer: convertIndyDidToKey(indyCredential.issuer_did),
    issuanceDate: new Date(indyCredential.created * 1000).toISOString(),
    credentialSubject: {
      id: convertIndyDidToKey(indyCredential.prover_did),
      ...indyCredential.values
    }
  };
}
```

#### DID Conversion
```typescript
// Convert Indy DID to did:key
async function convertIndyDidToKey(indyDid) {
  // Extract public key from Indy ledger
  const publicKey = await getPublicKeyFromIndyLedger(indyDid);
  
  // Create did:key from public key
  const did = DIDService.createDIDKey(publicKey);
  return did.id;
}
```

#### Schema Migration
```typescript
// Convert Indy schema to anon-identity schema
function convertIndySchema(indySchema) {
  const attributes = indySchema.attrNames.map(name => ({
    name,
    type: "string", // Indy schemas don't specify types
    required: true
  }));
  
  return {
    id: indySchema.id,
    type: "CredentialSchema",
    name: indySchema.name,
    description: `Migrated from Indy schema ${indySchema.id}`,
    version: indySchema.version,
    attributes,
    contexts: ["https://www.w3.org/2018/credentials/v1"],
    credentialTypes: ["VerifiableCredential"]
  };
}
```

### From Microsoft Verifiable Credentials

#### Credential Conversion
```typescript
// Convert Microsoft VC to anon-identity format
function convertMSVCToAnonIdentity(msvc) {
  return {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      ...(msvc.credentialSchema?.context || [])
    ],
    id: msvc.jti,
    type: ["VerifiableCredential", ...(msvc.vc?.type || [])],
    issuer: msvc.iss,
    issuanceDate: new Date(msvc.iat * 1000).toISOString(),
    credentialSubject: {
      id: msvc.sub,
      ...msvc.vc?.credentialSubject
    }
  };
}
```

#### Trust Registry Migration
```typescript
// Convert Microsoft trust registry to trusted issuers list
async function migrateMSTrustRegistry(msTrustRegistry) {
  const trustedIssuers = [];
  
  for (const issuer of msTrustRegistry.issuers) {
    // Convert Microsoft issuer DID format
    if (issuer.did.startsWith('did:ion:')) {
      // For now, add to pending migration list
      console.warn(`ION DID ${issuer.did} needs manual migration`);
    } else if (issuer.did.startsWith('did:web:')) {
      // did:web DIDs can be supported in future versions
      trustedIssuers.push(issuer.did);
    }
  }
  
  return trustedIssuers;
}
```

### From Custom JWT-based Systems

#### JWT Credential Migration
```typescript
// Convert custom JWT credentials to W3C VCs
function convertJWTCredentialToW3C(jwtCredential, issuerDID) {
  const payload = JSON.parse(atob(jwtCredential.split('.')[1]));
  
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    id: payload.jti || `urn:uuid:${generateUUID()}`,
    type: ["VerifiableCredential"],
    issuer: issuerDID,
    issuanceDate: new Date(payload.iat * 1000).toISOString(),
    credentialSubject: {
      id: payload.sub,
      ...payload.claims
    },
    proof: {
      type: "Ed25519Signature2020",
      created: new Date(payload.iat * 1000).toISOString(),
      proofPurpose: "assertionMethod",
      verificationMethod: `${issuerDID}#key-1`,
      jws: jwtCredential // Preserve original JWT
    }
  };
}
```

## Database Migration

### Credential Storage Migration

#### From File-based to Database
```typescript
// Migration script for moving from file storage to database
async function migrateFileToDatabase() {
  const fileStorage = new FileStorageProvider('./old-data');
  const dbStorage = new DatabaseStorageProvider(connectionString);
  
  // Migrate DIDs
  const didFiles = await fileStorage.listDIDFiles();
  for (const didFile of didFiles) {
    const didDocument = await fileStorage.resolveDID(didFile.did);
    await dbStorage.storeDID(didFile.did, didDocument);
  }
  
  // Migrate credentials
  const credentialFiles = await fileStorage.listCredentialFiles();
  for (const credFile of credentialFiles) {
    const credential = await fileStorage.getCredential(credFile.id);
    await dbStorage.storeCredential(credential);
  }
  
  // Migrate revocation lists
  const revocationFiles = await fileStorage.listRevocationFiles();
  for (const revFile of revocationFiles) {
    const revList = await fileStorage.getRevocationList(revFile.issuer);
    await dbStorage.publishRevocation(revFile.issuer, revList);
  }
  
  console.log('Migration completed successfully');
}
```

#### From Memory to Persistent Storage
```typescript
// Export data from memory storage before shutdown
async function exportMemoryStorage(memoryStorage) {
  const exportData = {
    dids: new Map(),
    credentials: new Map(),
    revocationLists: new Map(),
    keyPairs: new Map()
  };
  
  // Export each data type
  exportData.dids = await memoryStorage.exportDIDs();
  exportData.credentials = await memoryStorage.exportCredentials();
  exportData.revocationLists = await memoryStorage.exportRevocationLists();
  exportData.keyPairs = await memoryStorage.exportKeyPairs();
  
  return exportData;
}

// Import data to new persistent storage
async function importToPersistentStorage(exportData, persistentStorage) {
  // Import DIDs
  for (const [did, document] of exportData.dids) {
    await persistentStorage.storeDID(did, document);
  }
  
  // Import credentials
  for (const [id, credential] of exportData.credentials) {
    await persistentStorage.storeCredential(credential);
  }
  
  // Import revocation lists
  for (const [issuer, revList] of exportData.revocationLists) {
    await persistentStorage.publishRevocation(issuer, revList);
  }
  
  // Import key pairs
  for (const [identifier, keyPair] of exportData.keyPairs) {
    await persistentStorage.storeKeyPair(identifier, keyPair);
  }
}
```

## Configuration Migration

### Environment Variables Update
```bash
# Old configuration (v0.x)
CREDENTIAL_STORAGE_PATH=./data
ISSUER_DID=did:key:z6Mk...
REVOCATION_CHECK=true

# New configuration (v1.x+)
STORAGE_TYPE=file
STORAGE_PATH=./data
SESSION_DURATION=3600000
BATCH_CONCURRENCY=10
REVOCATION_CHECK=true
# Issuer DID now auto-generated
```

### Configuration File Migration
```typescript
// Old config format
const oldConfig = {
  issuer: {
    did: 'did:key:z6Mk...',
    keyPath: './keys/issuer.key'
  },
  storage: './data',
  revocation: true
};

// New config format
const newConfig = {
  storage: {
    type: 'file',
    path: './data',
    encryption: true
  },
  serviceProvider: {
    name: 'My Service',
    sessionManager: {
      defaultSessionDuration: 3600000,
      maxSessionDuration: 86400000
    },
    batchOperations: {
      maxConcurrency: 10,
      timeout: 30000
    }
  },
  security: {
    checkRevocation: true,
    enableSessions: true
  }
};
```

## Testing Migration

### Test Suite Updates
```typescript
// Update test suites for new API
describe('Migration Tests', () => {
  it('should maintain backward compatibility', async () => {
    // Test old constructor still works
    const sp = ServiceProvider.create(
      'Test Service',
      trustedIssuers,
      true,
      storageProvider
    );
    
    const result = await sp.verifyPresentation(presentation);
    expect(result.valid).toBe(true);
  });
  
  it('should support new enhanced features', async () => {
    // Test new constructor with options
    const sp = new ServiceProvider('Test Service', trustedIssuers, {
      sessionManager: { defaultSessionDuration: 1800000 }
    });
    
    const { verification, session } = await sp.verifyPresentationWithSession(presentation);
    expect(verification.valid).toBe(true);
    expect(session).toBeDefined();
  });
});
```

### Integration Test Migration
```typescript
// Update integration tests for new patterns
describe('Integration Migration', () => {
  let oldSystem: any;
  let newSystem: any;
  
  beforeEach(async () => {
    // Set up both old and new systems
    oldSystem = await createOldSystem();
    newSystem = await migrateToNewSystem(oldSystem);
  });
  
  it('should produce equivalent verification results', async () => {
    const presentation = await createTestPresentation();
    
    const oldResult = await oldSystem.verify(presentation);
    const newResult = await newSystem.verifyPresentation(presentation);
    
    expect(newResult.valid).toBe(oldResult.valid);
    expect(newResult.holder).toBe(oldResult.holder);
  });
});
```

## Deployment Migration

### Rolling Deployment Strategy
```typescript
// Blue-green deployment for migration
class DeploymentMigration {
  async performRollingMigration() {
    // Phase 1: Deploy new version alongside old
    await this.deployNewVersion();
    
    // Phase 2: Migrate data in background
    await this.migrateDataInBackground();
    
    // Phase 3: Switch traffic gradually
    await this.switchTrafficGradually();
    
    // Phase 4: Verify and cleanup
    await this.verifyMigration();
    await this.cleanupOldVersion();
  }
  
  async migrateDataInBackground() {
    const batchSize = 1000;
    let offset = 0;
    
    while (true) {
      const batch = await this.getCredentialBatch(offset, batchSize);
      if (batch.length === 0) break;
      
      await this.migrateBatch(batch);
      offset += batchSize;
      
      // Avoid overwhelming the system
      await this.sleep(1000);
    }
  }
}
```

### Monitoring During Migration
```typescript
// Monitor migration progress and health
class MigrationMonitor {
  async monitorMigration() {
    const metrics = {
      recordsMigrated: 0,
      errorsEncountered: 0,
      migrationRate: 0,
      estimatedCompletion: null
    };
    
    const startTime = Date.now();
    
    setInterval(async () => {
      const progress = await this.getMigrationProgress();
      metrics.recordsMigrated = progress.completed;
      metrics.errorsEncountered = progress.errors;
      
      const elapsed = Date.now() - startTime;
      metrics.migrationRate = metrics.recordsMigrated / (elapsed / 1000);
      
      if (progress.total > 0) {
        const remaining = progress.total - progress.completed;
        metrics.estimatedCompletion = new Date(
          Date.now() + (remaining / metrics.migrationRate * 1000)
        );
      }
      
      await this.reportMetrics(metrics);
    }, 5000);
  }
}
```

## Rollback Strategy

### Safe Rollback Plan
```typescript
// Implement safe rollback for failed migrations
class MigrationRollback {
  async prepareRollback() {
    // Create backup before migration
    await this.createBackup();
    
    // Document current state
    await this.documentCurrentState();
    
    // Prepare rollback scripts
    await this.prepareRollbackScripts();
  }
  
  async executeRollback() {
    console.log('Initiating rollback...');
    
    // Stop new system
    await this.stopNewSystem();
    
    // Restore data from backup
    await this.restoreFromBackup();
    
    // Restart old system
    await this.startOldSystem();
    
    // Verify rollback success
    await this.verifyRollback();
    
    console.log('Rollback completed successfully');
  }
  
  async verifyRollback() {
    // Run verification tests
    const testResults = await this.runVerificationTests();
    
    if (!testResults.allPassed) {
      throw new Error('Rollback verification failed');
    }
    
    // Check data integrity
    const integrityCheck = await this.checkDataIntegrity();
    
    if (!integrityCheck.valid) {
      throw new Error('Data integrity check failed after rollback');
    }
  }
}
```

## Best Practices for Migration

### 1. Always Test Migration Scripts
```typescript
// Test migration with subset of data first
async function testMigration() {
  const testData = await createTestDataset();
  const backupStorage = new MemoryStorageProvider();
  
  // Copy test data to backup
  await copyData(testData, backupStorage);
  
  // Run migration on test data
  const migrationResult = await runMigration(testData);
  
  // Verify migration results
  const verificationResult = await verifyMigration(testData, migrationResult);
  
  if (!verificationResult.success) {
    throw new Error('Migration test failed');
  }
  
  console.log('Migration test passed');
}
```

### 2. Implement Incremental Migration
```typescript
// Migrate data incrementally to reduce risk
async function incrementalMigration() {
  const batches = await splitDataIntoBatches();
  
  for (const [index, batch] of batches.entries()) {
    console.log(`Migrating batch ${index + 1}/${batches.length}`);
    
    try {
      await migrateBatch(batch);
      await verifyBatch(batch);
    } catch (error) {
      console.error(`Batch ${index + 1} failed:`, error);
      await rollbackBatch(batch);
      throw error;
    }
  }
}
```

### 3. Monitor Performance Impact
```typescript
// Monitor system performance during migration
class PerformanceMonitor {
  async monitorDuringMigration() {
    const baseline = await this.getBaselineMetrics();
    
    const monitor = setInterval(async () => {
      const current = await this.getCurrentMetrics();
      const impact = this.calculateImpact(baseline, current);
      
      if (impact.degradation > 0.5) { // 50% degradation threshold
        console.warn('High performance impact detected');
        await this.throttleMigration();
      }
      
      await this.logMetrics(current);
    }, 10000);
    
    return monitor;
  }
}
```

This migration guide ensures smooth transitions while maintaining system stability and data integrity.