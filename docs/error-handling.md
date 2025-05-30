# Error Handling Guide

Comprehensive error handling strategies for robust integrations.

## Error Types Overview

### VerificationError Class
The library uses a structured error system with specific error codes for precise error handling.

```typescript
import { VerificationError, VerificationErrorCode, isVerificationError } from 'anon-identity';

try {
  const result = await serviceProvider.verifyPresentation(presentation);
} catch (error) {
  if (isVerificationError(error)) {
    console.log(`Error Code: ${error.code}`);
    console.log(`Message: ${error.message}`);
    console.log(`Details:`, error.details);
  }
}
```

## Error Codes Reference

### Credential-Related Errors

#### `EXPIRED_CREDENTIAL`
Credential has passed its expiration date.

**Common Causes:**
- Credential issued with expiration date in the past
- System clock issues
- Long-lived credentials that weren't renewed

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.EXPIRED_CREDENTIAL) {
  // Request credential renewal
  const renewalRequest = {
    credentialId: error.details.credentialId,
    issuer: error.details.issuer,
    reason: 'expired'
  };
  
  await requestCredentialRenewal(renewalRequest);
}
```

#### `REVOKED_CREDENTIAL`
Credential has been revoked by the issuer.

**Common Causes:**
- Employee termination
- Credential compromise
- Data correction requirements
- Policy changes

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.REVOKED_CREDENTIAL) {
  // Log security event and deny access
  await logSecurityEvent({
    type: 'revoked_credential_used',
    credentialId: error.details.credentialId,
    issuer: error.details.issuer,
    timestamp: new Date()
  });
  
  // Optionally invalidate related sessions
  await serviceProvider.handleCredentialRevocation(error.details.credentialId);
  
  throw new Error('Access denied: Credential has been revoked');
}
```

#### `UNTRUSTED_ISSUER`
Credential issued by an untrusted issuer.

**Common Causes:**
- Issuer not in trusted issuer list
- Issuer DID format mismatch
- Configuration errors

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.UNTRUSTED_ISSUER) {
  // Check if issuer should be trusted
  const issuerVerification = await verifyIssuerLegitimacy(error.details.issuer);
  
  if (issuerVerification.legitimate) {
    // Add to trusted list
    serviceProvider.addTrustedIssuer(error.details.issuer);
    
    // Retry verification
    return await serviceProvider.verifyPresentation(presentation);
  } else {
    // Log potential fraud attempt
    await logSecurityEvent({
      type: 'untrusted_issuer_attempt',
      issuer: error.details.issuer,
      credentialId: error.details.credentialId
    });
  }
}
```

### Signature and Proof Errors

#### `INVALID_SIGNATURE`
Cryptographic signature verification failed.

**Common Causes:**
- Credential tampering
- Key rotation without proper migration
- Cryptographic implementation issues
- Data corruption

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.INVALID_SIGNATURE) {
  // Log security incident
  await logSecurityEvent({
    type: 'invalid_signature',
    credentialId: error.details.credentialId,
    severity: 'high'
  });
  
  // Check if this is a known issue
  const knownIssue = await checkKnownSignatureIssues(error.details.credentialId);
  
  if (knownIssue) {
    // Apply known fix or workaround
    await applySignatureFix(knownIssue);
  } else {
    // Treat as potential tampering
    throw new Error('Security violation: Invalid signature detected');
  }
}
```

#### `INVALID_DISCLOSURE_PROOF`
Selective disclosure proof verification failed.

**Common Causes:**
- Proof tampering
- Incorrect attribute selection
- Cryptographic errors

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.INVALID_DISCLOSURE_PROOF) {
  // Request full disclosure as fallback
  const fullPresentation = await requestFullDisclosure(error.details.credentialId);
  return await serviceProvider.verifyPresentation(fullPresentation);
}
```

### Format and Structure Errors

#### `MISSING_PROOF`
Required proof field is missing from credential or presentation.

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.MISSING_PROOF) {
  const fixedPresentation = await addMissingProof(presentation, error.details);
  return await serviceProvider.verifyPresentation(fixedPresentation);
}
```

#### `INVALID_CREDENTIAL_FORMAT`
Credential structure doesn't match expected format.

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.INVALID_CREDENTIAL_FORMAT) {
  // Attempt format migration
  const migratedCredential = await migrateCredentialFormat(
    presentation.verifiableCredential[0],
    error.details.reason
  );
  
  if (migratedCredential) {
    presentation.verifiableCredential[0] = migratedCredential;
    return await serviceProvider.verifyPresentation(presentation);
  }
}
```

#### `MISSING_REQUIRED_ATTRIBUTE`
Required attribute is missing from credential.

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.MISSING_REQUIRED_ATTRIBUTE) {
  // Request additional credentials with missing attribute
  const additionalCredRequest = {
    attributesNeeded: [error.details.attribute],
    purpose: 'complete_verification'
  };
  
  await requestAdditionalCredentials(additionalCredRequest);
}
```

### Network and System Errors

#### `NETWORK_ERROR`
Network-related operation failed.

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.NETWORK_ERROR) {
  // Implement exponential backoff retry
  const maxRetries = 3;
  let retryCount = 0;
  
  while (retryCount < maxRetries) {
    try {
      await delay(Math.pow(2, retryCount) * 1000); // Exponential backoff
      return await serviceProvider.verifyPresentation(presentation);
    } catch (retryError) {
      retryCount++;
      if (retryCount >= maxRetries) {
        throw new Error(`Network error after ${maxRetries} retries: ${error.message}`);
      }
    }
  }
}
```

#### `STORAGE_ERROR`
Storage operation failed.

**Recovery Strategy:**
```typescript
if (error.code === VerificationErrorCode.STORAGE_ERROR) {
  // Try alternative storage provider
  const backupStorage = getBackupStorageProvider();
  serviceProvider.setStorageProvider(backupStorage);
  
  // Retry operation
  return await serviceProvider.verifyPresentation(presentation);
}
```

## Comprehensive Error Handling Patterns

### Basic Error Handling Pattern
```typescript
async function verifyCredential(presentation: VerifiablePresentation) {
  try {
    const result = await serviceProvider.verifyPresentation(presentation);
    
    if (!result.valid) {
      // Handle verification failures
      return handleVerificationErrors(result.errors);
    }
    
    return result;
    
  } catch (error) {
    // Handle unexpected errors
    return handleUnexpectedError(error);
  }
}

function handleVerificationErrors(errors: VerificationError[]) {
  const errorsByCode = groupBy(errors, 'code');
  
  for (const [code, errorList] of Object.entries(errorsByCode)) {
    switch (code) {
      case VerificationErrorCode.REVOKED_CREDENTIAL:
        handleRevokedCredentials(errorList);
        break;
      case VerificationErrorCode.EXPIRED_CREDENTIAL:
        handleExpiredCredentials(errorList);
        break;
      case VerificationErrorCode.UNTRUSTED_ISSUER:
        handleUntrustedIssuers(errorList);
        break;
      default:
        handleGenericErrors(errorList);
    }
  }
}
```

### Retry Logic with Circuit Breaker
```typescript
class VerificationService {
  private circuitBreaker = new CircuitBreaker();
  
  async verifyWithRetry(presentation: VerifiablePresentation, maxRetries = 3) {
    return this.circuitBreaker.execute(async () => {
      let lastError: Error;
      
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          return await this.serviceProvider.verifyPresentation(presentation);
        } catch (error) {
          lastError = error;
          
          if (isVerificationError(error)) {
            // Don't retry certain errors
            if (this.isNonRetryableError(error)) {
              throw error;
            }
          }
          
          if (attempt < maxRetries) {
            await this.delay(Math.pow(2, attempt) * 1000);
          }
        }
      }
      
      throw lastError;
    });
  }
  
  private isNonRetryableError(error: VerificationError): boolean {
    return [
      VerificationErrorCode.REVOKED_CREDENTIAL,
      VerificationErrorCode.EXPIRED_CREDENTIAL,
      VerificationErrorCode.INVALID_SIGNATURE,
      VerificationErrorCode.UNTRUSTED_ISSUER
    ].includes(error.code);
  }
}
```

### Graceful Degradation
```typescript
async function verifyWithFallback(presentation: VerifiablePresentation) {
  try {
    // Try full verification first
    return await serviceProvider.verifyPresentation(presentation);
  } catch (error) {
    if (isVerificationError(error)) {
      // Try verification with reduced security for some errors
      if (error.code === VerificationErrorCode.NETWORK_ERROR) {
        return await verifyOffline(presentation);
      }
      
      if (error.code === VerificationErrorCode.STORAGE_ERROR) {
        return await verifyWithoutRevocationCheck(presentation);
      }
    }
    
    throw error;
  }
}

async function verifyOffline(presentation: VerifiablePresentation) {
  // Verify signatures without network calls
  const offlineProvider = new ServiceProvider(name, trustedIssuers, {
    checkRevocation: false, // Skip revocation check
    storageProvider: new MemoryStorageProvider() // Use local cache
  });
  
  return await offlineProvider.verifyPresentation(presentation);
}
```

### Error Aggregation for Batch Operations
```typescript
async function handleBatchErrors(results: BatchVerificationResult[]) {
  const errorSummary = {
    totalProcessed: results.length,
    successful: 0,
    failed: 0,
    errorsByType: new Map<VerificationErrorCode, number>(),
    criticalErrors: [],
    retryableErrors: []
  };
  
  for (const result of results) {
    if (result.result.valid) {
      errorSummary.successful++;
    } else {
      errorSummary.failed++;
      
      result.result.errors?.forEach(error => {
        if (error instanceof VerificationError) {
          // Count errors by type
          const count = errorSummary.errorsByType.get(error.code) || 0;
          errorSummary.errorsByType.set(error.code, count + 1);
          
          // Categorize errors
          if (this.isCriticalError(error)) {
            errorSummary.criticalErrors.push({
              presentationIndex: result.presentationIndex,
              error
            });
          } else if (this.isRetryableError(error)) {
            errorSummary.retryableErrors.push({
              presentationIndex: result.presentationIndex,
              error
            });
          }
        }
      });
    }
  }
  
  return errorSummary;
}
```

### Session Error Handling
```typescript
async function handleSessionErrors(sessionId: string) {
  try {
    const validation = await serviceProvider.validateSession(sessionId);
    
    if (!validation.valid) {
      switch (validation.reason) {
        case 'Session not found':
          // Session expired or never existed
          throw new SessionError('SESSION_NOT_FOUND', 'Please log in again');
          
        case 'Session expired':
          // Attempt to refresh if possible
          const refreshed = await attemptSessionRefresh(sessionId);
          if (refreshed) {
            return refreshed;
          }
          throw new SessionError('SESSION_EXPIRED', 'Session expired, please log in again');
          
        default:
          throw new SessionError('SESSION_INVALID', validation.reason);
      }
    }
    
    return validation.session;
    
  } catch (error) {
    if (error instanceof SessionError) {
      throw error;
    }
    
    // Handle unexpected session errors
    throw new SessionError('SESSION_ERROR', 'Unable to validate session');
  }
}
```

## Error Logging and Monitoring

### Structured Error Logging
```typescript
class ErrorLogger {
  static logVerificationError(error: VerificationError, context: any) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level: this.getErrorLevel(error.code),
      errorCode: error.code,
      message: error.message,
      details: error.details,
      context,
      stackTrace: error.stack
    };
    
    // Send to logging service
    this.sendToLogger(logEntry);
    
    // Send metrics
    this.incrementErrorMetric(error.code);
  }
  
  private static getErrorLevel(code: VerificationErrorCode): string {
    const criticalErrors = [
      VerificationErrorCode.INVALID_SIGNATURE,
      VerificationErrorCode.REVOKED_CREDENTIAL
    ];
    
    return criticalErrors.includes(code) ? 'error' : 'warning';
  }
}
```

### Error Metrics and Alerting
```typescript
class ErrorMetrics {
  private static metrics = new Map<string, number>();
  
  static recordError(error: VerificationError) {
    const key = `verification_error_${error.code}`;
    const count = this.metrics.get(key) || 0;
    this.metrics.set(key, count + 1);
    
    // Alert on critical error thresholds
    if (this.shouldAlert(error.code, count + 1)) {
      this.sendAlert(error.code, count + 1);
    }
  }
  
  private static shouldAlert(code: VerificationErrorCode, count: number): boolean {
    const thresholds = {
      [VerificationErrorCode.INVALID_SIGNATURE]: 5,
      [VerificationErrorCode.REVOKED_CREDENTIAL]: 10,
      [VerificationErrorCode.NETWORK_ERROR]: 50
    };
    
    return count >= (thresholds[code] || 100);
  }
}
```

## Testing Error Scenarios

### Unit Testing Error Conditions
```typescript
describe('Error Handling', () => {
  it('should handle revoked credential', async () => {
    // Setup revoked credential
    await identityProvider.revokeCredential(credentialId);
    await identityProvider.publishRevocationList();
    
    const result = await serviceProvider.verifyPresentation(presentation);
    
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toBeInstanceOf(VerificationError);
    expect(result.errors[0].code).toBe(VerificationErrorCode.REVOKED_CREDENTIAL);
  });
  
  it('should handle network errors with retry', async () => {
    // Mock network failure
    const mockStorageProvider = jest.fn()
      .mockRejectedValueOnce(new Error('Network timeout'))
      .mockRejectedValueOnce(new Error('Network timeout'))
      .mockResolvedValueOnce(true);
    
    const result = await verificationService.verifyWithRetry(presentation);
    
    expect(mockStorageProvider).toHaveBeenCalledTimes(3);
    expect(result.valid).toBe(true);
  });
});
```

### Integration Testing
```typescript
describe('Error Recovery Integration', () => {
  it('should recover from storage failure using backup', async () => {
    // Simulate primary storage failure
    await primaryStorage.simulateFailure();
    
    const result = await serviceProvider.verifyPresentation(presentation);
    
    // Should have switched to backup storage
    expect(result.valid).toBe(true);
    expect(backupStorage.wasCalled()).toBe(true);
  });
});
```

## Best Practices

### 1. Always Check Error Types
```typescript
// ✅ Good
if (isVerificationError(error)) {
  handleVerificationError(error);
} else {
  handleGenericError(error);
}

// ❌ Bad
handleGenericError(error);
```

### 2. Implement Proper Logging
```typescript
// ✅ Good
try {
  const result = await operation();
} catch (error) {
  logger.error('Operation failed', { error, context });
  throw error;
}

// ❌ Bad
try {
  const result = await operation();
} catch (error) {
  console.log('Something went wrong');
  throw error;
}
```

### 3. Use Appropriate Recovery Strategies
```typescript
// ✅ Good - Different strategies for different errors
if (error.code === VerificationErrorCode.NETWORK_ERROR) {
  return await retryWithBackoff();
} else if (error.code === VerificationErrorCode.REVOKED_CREDENTIAL) {
  return await denyAccess();
}

// ❌ Bad - Same strategy for all errors
return await retryOperation();
```

### 4. Provide User-Friendly Error Messages
```typescript
// ✅ Good
function getUserMessage(error: VerificationError): string {
  switch (error.code) {
    case VerificationErrorCode.EXPIRED_CREDENTIAL:
      return 'Your credential has expired. Please obtain a new one.';
    case VerificationErrorCode.REVOKED_CREDENTIAL:
      return 'This credential is no longer valid. Please contact your issuer.';
    default:
      return 'Verification failed. Please try again or contact support.';
  }
}

// ❌ Bad
function getUserMessage(error: VerificationError): string {
  return error.message; // Technical message not suitable for users
}
```