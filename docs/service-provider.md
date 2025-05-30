# Service Provider Integration Guide

Complete guide for integrating verification and session management into your service.

## Basic Setup

### Simple Service Provider
```typescript
import { ServiceProvider, MemoryStorageProvider } from 'anon-identity';

const serviceProvider = new ServiceProvider(
  'ACME Corp',           // Service name
  [                      // Trusted issuer DIDs
    'did:key:z6Mk...',   // University
    'did:key:z6Ml...'    // Government
  ]
);
```

### Production Service Provider
```typescript
import { 
  ServiceProvider, 
  FileStorageProvider,
  VerificationErrorCode 
} from 'anon-identity';

const storage = new FileStorageProvider('./credentials');

const serviceProvider = new ServiceProvider('Production Service', trustedIssuers, {
  checkRevocation: true,
  storageProvider: storage,
  sessionManager: {
    defaultSessionDuration: 3600000,  // 1 hour
    maxSessionDuration: 86400000,     // 24 hours
    cleanupInterval: 300000           // 5 minutes
  },
  batchOperations: {
    maxConcurrency: 10,
    timeout: 30000,
    continueOnError: true
  }
});
```

## Basic Verification

### Simple Credential Verification
```typescript
async function verifyCredential(presentation) {
  const result = await serviceProvider.verifyPresentation(presentation);
  
  if (result.valid) {
    return {
      success: true,
      user: result.holder,
      attributes: result.credentials[0].attributes
    };
  } else {
    return {
      success: false,
      errors: result.errors.map(e => e.message)
    };
  }
}
```

### Enhanced Verification with Error Handling
```typescript
import { isVerificationError, VerificationErrorCode } from 'anon-identity';

async function verifyCredentialEnhanced(presentation) {
  try {
    const result = await serviceProvider.verifyPresentation(presentation);
    
    if (result.valid) {
      return {
        success: true,
        user: result.holder,
        attributes: result.credentials[0].attributes,
        timestamp: result.timestamp
      };
    }
    
    // Handle specific verification failures
    const errorAnalysis = analyzeErrors(result.errors);
    
    return {
      success: false,
      errors: errorAnalysis.userFriendlyErrors,
      canRetry: errorAnalysis.retryable,
      suggestions: errorAnalysis.suggestions
    };
    
  } catch (error) {
    console.error('Unexpected verification error:', error);
    return {
      success: false,
      errors: ['Verification service temporarily unavailable'],
      canRetry: true
    };
  }
}

function analyzeErrors(errors) {
  const retryableCodes = [
    VerificationErrorCode.NETWORK_ERROR,
    VerificationErrorCode.STORAGE_ERROR
  ];
  
  const criticalCodes = [
    VerificationErrorCode.REVOKED_CREDENTIAL,
    VerificationErrorCode.INVALID_SIGNATURE
  ];
  
  const userFriendlyErrors = [];
  const suggestions = [];
  let retryable = false;
  
  errors.forEach(error => {
    if (isVerificationError(error)) {
      switch (error.code) {
        case VerificationErrorCode.EXPIRED_CREDENTIAL:
          userFriendlyErrors.push('Your credential has expired');
          suggestions.push('Please obtain a renewed credential from your issuer');
          break;
        case VerificationErrorCode.REVOKED_CREDENTIAL:
          userFriendlyErrors.push('This credential is no longer valid');
          suggestions.push('Contact your issuer for assistance');
          break;
        case VerificationErrorCode.UNTRUSTED_ISSUER:
          userFriendlyErrors.push('Credential from unrecognized issuer');
          suggestions.push('Please use a credential from an approved issuer');
          break;
        case VerificationErrorCode.NETWORK_ERROR:
          userFriendlyErrors.push('Temporary verification issue');
          suggestions.push('Please try again in a moment');
          retryable = true;
          break;
        default:
          userFriendlyErrors.push('Credential verification failed');
      }
    }
  });
  
  return { userFriendlyErrors, retryable, suggestions };
}
```

## Session Management

### Authentication with Sessions
```typescript
class AuthenticationService {
  constructor(private serviceProvider: ServiceProvider) {}
  
  async authenticateUser(presentation) {
    const { verification, session } = await this.serviceProvider
      .verifyPresentationWithSession(presentation, true, {
        loginTime: new Date(),
        userAgent: 'web-app',
        ipAddress: '192.168.1.1'
      });
    
    if (verification.valid && session) {
      return {
        authenticated: true,
        sessionId: session.id,
        user: {
          did: session.holderDID,
          attributes: session.attributes,
          sessionExpiry: session.expiresAt
        }
      };
    }
    
    throw new Error('Authentication failed');
  }
  
  async validateUserSession(sessionId: string) {
    const validation = await this.serviceProvider.validateSession(sessionId);
    
    if (validation.valid && validation.session) {
      return {
        valid: true,
        user: validation.session.attributes,
        expiresAt: validation.session.expiresAt
      };
    }
    
    return { valid: false, reason: validation.reason };
  }
  
  async extendSession(sessionId: string, additionalTime: number) {
    await this.serviceProvider.setSessionExpiry(sessionId, additionalTime);
    
    const session = this.serviceProvider.getSession(sessionId);
    return {
      sessionId,
      newExpiry: session?.expiresAt
    };
  }
  
  async logoutUser(sessionId: string) {
    this.serviceProvider.removeSession(sessionId);
    return { success: true };
  }
}
```

### Express.js Middleware Example
```typescript
import express from 'express';

function createAuthMiddleware(serviceProvider: ServiceProvider) {
  return async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const sessionId = req.headers['x-session-id'] as string;
    
    if (!sessionId) {
      return res.status(401).json({ error: 'No session provided' });
    }
    
    try {
      const validation = await serviceProvider.validateSession(sessionId);
      
      if (validation.valid && validation.session) {
        // Add user info to request
        req.user = {
          did: validation.session.holderDID,
          attributes: validation.session.attributes,
          sessionId: sessionId
        };
        
        next();
      } else {
        res.status(401).json({ 
          error: 'Invalid session', 
          reason: validation.reason 
        });
      }
    } catch (error) {
      console.error('Session validation error:', error);
      res.status(500).json({ error: 'Session validation failed' });
    }
  };
}

// Usage
const app = express();
const authMiddleware = createAuthMiddleware(serviceProvider);

app.post('/login', async (req, res) => {
  try {
    const { presentation } = req.body;
    const authService = new AuthenticationService(serviceProvider);
    const result = await authService.authenticateUser(presentation);
    
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

app.get('/protected-resource', authMiddleware, (req, res) => {
  res.json({ 
    message: 'Access granted', 
    user: req.user 
  });
});
```

## Presentation Requests

### Creating Presentation Requests
```typescript
async function createEmploymentVerificationRequest() {
  return await serviceProvider.createPresentationRequest({
    credentialRequirements: [
      {
        type: ['VerifiableCredential', 'EducationCredential'],
        attributes: [
          { name: 'givenName', required: true },
          { name: 'degree', required: true },
          { name: 'graduationDate', required: true },
          { name: 'university', required: false }
        ],
        trustedIssuers: ['did:key:university123...'],
        maxAge: 31536000000 // 1 year in milliseconds
      },
      {
        type: ['VerifiableCredential', 'IDCredential'],
        attributes: [
          { name: 'dateOfBirth', required: true },
          { name: 'isOver18', required: true }
        ],
        trustedIssuers: ['did:key:government456...']
      }
    ],
    purpose: 'Employment verification for senior developer position',
    domain: 'acme-corp.com',
    expiresAt: new Date(Date.now() + 3600000) // 1 hour
  });
}

// Simple request for quick verification
async function createSimpleAgeVerification() {
  return await serviceProvider.createSimplePresentationRequest(
    ['IDCredential'],
    'Age verification for service access',
    ['isOver18'], // required
    ['givenName'] // optional
  );
}
```

### Validating Against Requests
```typescript
async function verifyAgainstRequest(presentation, request) {
  const { verification, requestValidation } = await serviceProvider
    .verifyPresentationWithRequest(presentation, request);
  
  if (verification.valid && requestValidation.valid) {
    return {
      success: true,
      fulfillmentScore: requestValidation.score,
      matchedRequirements: requestValidation.matchedRequirements.length,
      totalRequirements: request.credentialRequirements.length
    };
  }
  
  return {
    success: false,
    verificationErrors: verification.errors,
    requestErrors: requestValidation.errors,
    missingRequirements: requestValidation.unmatchedRequirements
  };
}
```

## Batch Operations

### High-Volume Verification
```typescript
class BatchVerificationService {
  constructor(private serviceProvider: ServiceProvider) {}
  
  async processBatch(presentations: Array<{ id: string, presentation: any }>) {
    const results = await this.serviceProvider.batchVerifyPresentations(
      presentations.map(p => p.presentation)
    );
    
    const processedResults = results.map((result, index) => ({
      id: presentations[index].id,
      valid: result.result.valid,
      processingTime: result.processingTime,
      errors: result.result.errors,
      attributes: result.result.credentials?.[0]?.attributes
    }));
    
    // Generate batch statistics
    const stats = this.generateStatistics(results);
    
    return {
      results: processedResults,
      statistics: stats,
      summary: {
        total: results.length,
        successful: stats.valid,
        failed: stats.invalid,
        averageTime: stats.averageProcessingTime
      }
    };
  }
  
  private generateStatistics(results) {
    const total = results.length;
    const valid = results.filter(r => r.result.valid).length;
    const invalid = total - valid;
    
    const processingTimes = results.map(r => r.processingTime);
    const averageProcessingTime = processingTimes.reduce((a, b) => a + b, 0) / total;
    const maxProcessingTime = Math.max(...processingTimes);
    
    const errorDistribution = {};
    results.forEach(result => {
      result.result.errors?.forEach(error => {
        const code = error.code || 'UNKNOWN';
        errorDistribution[code] = (errorDistribution[code] || 0) + 1;
      });
    });
    
    return {
      total,
      valid,
      invalid,
      averageProcessingTime,
      maxProcessingTime,
      errorDistribution
    };
  }
}
```

### Background Processing
```typescript
import Bull from 'bull';

class BackgroundVerificationService {
  private queue: Bull.Queue;
  
  constructor(private serviceProvider: ServiceProvider) {
    this.queue = new Bull('credential verification', {
      redis: { host: 'localhost', port: 6379 }
    });
    
    this.setupProcessor();
  }
  
  private setupProcessor() {
    this.queue.process('verify-batch', async (job) => {
      const { presentations, batchId } = job.data;
      
      try {
        const results = await this.serviceProvider
          .batchVerifyPresentations(presentations);
        
        // Store results
        await this.storeResults(batchId, results);
        
        // Notify completion
        await this.notifyBatchComplete(batchId, results);
        
        return { success: true, processed: results.length };
      } catch (error) {
        console.error('Batch processing failed:', error);
        throw error;
      }
    });
  }
  
  async submitBatch(presentations: any[], options = {}) {
    const batchId = generateBatchId();
    
    const job = await this.queue.add('verify-batch', {
      presentations,
      batchId,
      submittedAt: new Date()
    }, {
      attempts: 3,
      backoff: 'exponential',
      ...options
    });
    
    return {
      batchId,
      jobId: job.id,
      estimatedCompletion: new Date(Date.now() + presentations.length * 100)
    };
  }
  
  async getBatchStatus(batchId: string) {
    const job = await this.queue.getJob(batchId);
    
    if (!job) {
      return { status: 'not_found' };
    }
    
    return {
      status: await job.getState(),
      progress: job.progress(),
      result: job.returnvalue,
      error: job.failedReason
    };
  }
}
```

## Performance Optimization

### Caching Strategy
```typescript
class CachedServiceProvider {
  private verificationCache = new Map();
  private sessionCache = new Map();
  
  constructor(private serviceProvider: ServiceProvider) {}
  
  async verifyPresentationCached(presentation, cacheKey?: string) {
    const key = cacheKey || this.generateCacheKey(presentation);
    
    // Check cache first
    if (this.verificationCache.has(key)) {
      const cached = this.verificationCache.get(key);
      if (Date.now() - cached.timestamp < 300000) { // 5 minute cache
        return cached.result;
      }
    }
    
    // Perform verification
    const result = await this.serviceProvider.verifyPresentation(presentation);
    
    // Cache successful results only
    if (result.valid) {
      this.verificationCache.set(key, {
        result,
        timestamp: Date.now()
      });
    }
    
    return result;
  }
  
  private generateCacheKey(presentation) {
    // Create cache key from presentation hash
    const hash = require('crypto')
      .createHash('sha256')
      .update(JSON.stringify(presentation))
      .digest('hex');
    return `presentation:${hash}`;
  }
}
```

### Connection Pooling for Storage
```typescript
class OptimizedServiceProvider {
  private connectionPool: any;
  
  constructor() {
    // Initialize connection pool for database storage
    this.connectionPool = createConnectionPool({
      max: 10,
      min: 2,
      idle: 30000
    });
    
    const storage = new DatabaseStorageProvider(this.connectionPool);
    
    this.serviceProvider = new ServiceProvider('Service', trustedIssuers, {
      storageProvider: storage,
      batchOperations: {
        maxConcurrency: 20, // Higher concurrency with pool
        timeout: 10000      // Faster timeout with pooling
      }
    });
  }
}
```

## Security Best Practices

### Rate Limiting
```typescript
import rateLimit from 'express-rate-limit';

const verificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many verification requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

const sessionLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // limit session operations
  keyGenerator: (req) => req.headers['x-session-id'] || req.ip
});

app.use('/verify', verificationLimiter);
app.use('/session', sessionLimiter);
```

### Input Validation
```typescript
import Joi from 'joi';

const presentationSchema = Joi.object({
  '@context': Joi.array().items(Joi.string()).required(),
  type: Joi.array().items(Joi.string()).required(),
  verifiableCredential: Joi.array().items(Joi.object()).required(),
  proof: Joi.object().required()
});

async function validateAndVerify(presentationData) {
  // Validate structure first
  const { error, value } = presentationSchema.validate(presentationData);
  
  if (error) {
    throw new Error(`Invalid presentation format: ${error.message}`);
  }
  
  // Verify credential
  return await serviceProvider.verifyPresentation(value);
}
```

### Audit Logging
```typescript
class AuditLogger {
  static async logVerification(presentation, result, context) {
    const auditEntry = {
      timestamp: new Date(),
      action: 'credential_verification',
      holder: result.holder,
      issuer: result.credentials?.[0]?.issuer,
      success: result.valid,
      sessionId: context.sessionId,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      errors: result.errors?.map(e => e.code)
    };
    
    // Log to audit system
    await sendToAuditLog(auditEntry);
  }
  
  static async logSessionActivity(sessionId, action, details) {
    const auditEntry = {
      timestamp: new Date(),
      action: `session_${action}`,
      sessionId,
      details
    };
    
    await sendToAuditLog(auditEntry);
  }
}
```

## Testing Service Provider Integration

### Unit Testing
```typescript
describe('ServiceProvider Integration', () => {
  let serviceProvider: ServiceProvider;
  let mockStorage: any;
  
  beforeEach(() => {
    mockStorage = createMockStorageProvider();
    serviceProvider = new ServiceProvider('Test Service', trustedIssuers, {
      storageProvider: mockStorage
    });
  });
  
  it('should verify valid presentation', async () => {
    const presentation = createValidPresentation();
    const result = await serviceProvider.verifyPresentation(presentation);
    
    expect(result.valid).toBe(true);
    expect(result.credentials).toHaveLength(1);
  });
  
  it('should create session on successful verification', async () => {
    const presentation = createValidPresentation();
    const { verification, session } = await serviceProvider
      .verifyPresentationWithSession(presentation);
    
    expect(verification.valid).toBe(true);
    expect(session).toBeDefined();
    expect(session.id).toBeTruthy();
  });
});
```

### Integration Testing
```typescript
describe('End-to-End Verification Flow', () => {
  it('should complete full verification flow', async () => {
    // Setup
    const idp = await IdentityProvider.create();
    const wallet = await UserWallet.create();
    const sp = new ServiceProvider('Test', [idp.getDID()]);
    
    // Issue credential
    const credential = await idp.issueVerifiableCredential(wallet.getDID(), {
      givenName: 'Test User',
      dateOfBirth: '1990-01-01'
    });
    
    // Store and present
    await wallet.storeCredential(credential);
    const presentation = await wallet.createVerifiablePresentation([credential.id]);
    
    // Verify
    const result = await sp.verifyPresentation(presentation);
    
    expect(result.valid).toBe(true);
    expect(result.credentials[0].attributes.givenName).toBe('Test User');
  });
});
```

### Load Testing
```typescript
describe('Performance Testing', () => {
  it('should handle concurrent verifications', async () => {
    const presentations = Array(100).fill(null).map(() => createValidPresentation());
    
    const startTime = Date.now();
    const results = await serviceProvider.batchVerifyPresentations(presentations);
    const endTime = Date.now();
    
    const successfulResults = results.filter(r => r.result.valid);
    const averageTime = results.reduce((sum, r) => sum + r.processingTime, 0) / results.length;
    
    expect(successfulResults.length).toBe(100);
    expect(averageTime).toBeLessThan(500); // Less than 500ms average
    expect(endTime - startTime).toBeLessThan(10000); // Complete in under 10s
  });
});
```