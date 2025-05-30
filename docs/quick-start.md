# Quick Start Guide

Get the anon-identity library running in 5 minutes.

## Installation

```bash
npm install anon-identity
```

## Choose Your Import Style

### Node.js (Full Features)
```typescript
import { IdentityProvider, UserWallet, ServiceProvider } from 'anon-identity';
// or
import { IdentityProvider, UserWallet, ServiceProvider } from 'anon-identity/node';
```

### Browser (Web Compatible)
```typescript
import { IdentityProvider, UserWallet, ServiceProvider } from 'anon-identity/browser';
```

## 5-Minute Example

```typescript
import {
  IdentityProvider,
  UserWallet,
  ServiceProvider,
  MemoryStorageProvider
} from 'anon-identity';

async function quickDemo() {
  // 1. Setup storage
  const storage = new MemoryStorageProvider();
  
  // 2. Create actors
  const university = await IdentityProvider.create(storage);
  const student = await UserWallet.create(storage);
  const employer = new ServiceProvider('ACME Corp', [university.getDID()], {
    storageProvider: storage
  });
  
  // 3. Issue credential
  const degree = await university.issueVerifiableCredential(student.getDID(), {
    givenName: 'Alice Smith',
    dateOfBirth: '1995-06-15',
    degree: 'Computer Science',
    university: 'State University',
    graduationDate: '2023-05-15'
  });
  
  // 4. Store credential
  await student.storeCredential(degree);
  
  // 5. Create presentation
  const jobApplication = await student.createVerifiablePresentation([degree.id]);
  
  // 6. Verify with session management
  const { verification, session } = await employer.verifyPresentationWithSession(
    jobApplication,
    true, // create session
    { context: 'job-application', ip: '192.168.1.1' }
  );
  
  if (verification.valid && session) {
    console.log('✅ Verification successful!');
    console.log(`Session ID: ${session.id}`);
    console.log(`Verified attributes:`, session.attributes);
    
    // Session is now active for 1 hour by default
    const sessionCheck = await employer.validateSession(session.id);
    console.log(`Session still valid: ${sessionCheck.valid}`);
  } else {
    console.log('❌ Verification failed:', verification.errors);
  }
}

quickDemo().catch(console.error);
```

## Key Concepts

### Actors
- **Identity Provider (IDP)**: Issues credentials (university, government, employer)
- **User/Holder**: Owns and presents credentials via wallet
- **Service Provider (SP)**: Verifies presentations (employer, service)

### Credentials Flow
```
IDP Issues → User Stores → User Presents → SP Verifies
```

### Storage Options
```typescript
// In-memory (testing)
const storage = new MemoryStorageProvider();

// File-based (Node.js only)
const storage = new FileStorageProvider('./data');

// IPFS distributed
const storage = new IPFSStorageProvider('http://localhost:5001');

// Blockchain (Ethereum/Polygon)
const storage = new BlockchainStorageProvider(provider, contractAddress);
```

## Enhanced Features

### Session Management
```typescript
// Automatic session creation
const { verification, session } = await sp.verifyPresentationWithSession(presentation);

// Manual session management
const sessionId = session?.id;
const validation = await sp.validateSession(sessionId);
await sp.setSessionExpiry(sessionId, 7200000); // 2 hours
```

### Batch Operations
```typescript
// Verify multiple presentations
const results = await sp.batchVerifyPresentations([pres1, pres2, pres3]);

// Check multiple revocations
const revocations = await sp.batchCheckRevocations(['cred1', 'cred2']);
```

### Enhanced Error Handling
```typescript
import { VerificationError, VerificationErrorCode } from 'anon-identity';

const result = await sp.verifyPresentation(presentation);
if (!result.valid && result.errors) {
  for (const error of result.errors) {
    if (error instanceof VerificationError) {
      switch (error.code) {
        case VerificationErrorCode.REVOKED_CREDENTIAL:
          console.log('Credential was revoked:', error.details);
          break;
        case VerificationErrorCode.UNTRUSTED_ISSUER:
          console.log('Issuer not trusted:', error.details);
          break;
        default:
          console.log('Other error:', error.message);
      }
    }
  }
}
```

### Selective Disclosure (Privacy)
```typescript
// User selects which attributes to reveal
const presentation = await wallet.createSelectiveDisclosurePresentation(
  credentialId,
  ['givenName', 'isOver18'], // only reveal these
  'employer-verification'     // proof purpose
);
```

## Next Steps

1. **Production Setup**: See [Service Provider Setup](./service-provider.md) for production configuration
2. **Security**: Review [Security Considerations](./security.md) 
3. **Storage**: Choose appropriate [Storage Provider](./storage-providers.md)
4. **Error Handling**: Implement robust [Error Handling](./error-handling.md)
5. **Performance**: Optimize with [Batch Operations](./batch-operations.md)

## Common Patterns

### Credential Verification Service
```typescript
class CredentialVerificationService {
  constructor(private sp: ServiceProvider) {}
  
  async verifyCredential(presentation: VerifiablePresentation) {
    const result = await this.sp.verifyPresentation(presentation);
    
    if (!result.valid) {
      throw new Error(`Verification failed: ${result.errors?.map(e => e.message).join(', ')}`);
    }
    
    return result.credentials?.[0]?.attributes;
  }
}
```

### Session-Based Authentication
```typescript
class AuthService {
  constructor(private sp: ServiceProvider) {}
  
  async authenticate(presentation: VerifiablePresentation) {
    const { verification, session } = await this.sp.verifyPresentationWithSession(
      presentation,
      true,
      { loginTime: new Date() }
    );
    
    if (verification.valid && session) {
      return { 
        sessionId: session.id, 
        user: session.attributes,
        expiresAt: session.expiresAt 
      };
    }
    
    throw new Error('Authentication failed');
  }
  
  async validateUserSession(sessionId: string) {
    const validation = await this.sp.validateSession(sessionId);
    return validation.valid ? validation.session : null;
  }
}
```