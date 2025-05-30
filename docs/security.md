# Security Considerations

Critical security guidelines for production deployment of the anon-identity library.

## Cryptographic Security

### Key Management

#### Secure Key Generation
```typescript
// ✅ Secure key generation
const keyPair = await CryptoService.generateKeyPair();

// ❌ Never use hardcoded keys
const badKeyPair = {
  publicKey: new Uint8Array([/* hardcoded bytes */]),
  privateKey: new Uint8Array([/* hardcoded bytes */])
};
```

#### Key Storage Security
```typescript
// ✅ Encrypted key storage
const storage = new SecureStorage(strongPassphrase);
await storage.storeKeyPair(keyPair, passphrase, identifier);

// ✅ Use strong passphrases
function generateStrongPassphrase(): string {
  return crypto.randomBytes(32).toString('base64');
}

// ❌ Weak passphrase
const weakPassphrase = "password123";
```

#### Key Rotation
```typescript
class KeyRotationManager {
  async rotateKeys(oldKeyPair: KeyPair, storageProvider: IStorageProvider) {
    // Generate new key pair
    const newKeyPair = await CryptoService.generateKeyPair();
    
    // Create new DID
    const newDID = DIDService.createDIDKey(newKeyPair.publicKey);
    
    // Update all references
    await this.updateDIDReferences(oldKeyPair, newKeyPair);
    
    // Revoke old credentials if necessary
    await this.revokeOldCredentials(oldKeyPair);
    
    // Securely dispose of old keys
    this.securelyDisposeKeys(oldKeyPair);
    
    return newKeyPair;
  }
  
  private securelyDisposeKeys(keyPair: KeyPair) {
    // Zero out memory
    keyPair.privateKey.fill(0);
    keyPair.publicKey.fill(0);
  }
}
```

### Signature Security

#### Signature Verification Best Practices
```typescript
// ✅ Always verify signatures
async function secureVerification(presentation: VerifiablePresentation) {
  const result = await serviceProvider.verifyPresentation(presentation);
  
  if (!result.valid) {
    // Log security event
    await logSecurityEvent({
      type: 'invalid_signature',
      details: result.errors,
      timestamp: new Date(),
      severity: 'high'
    });
    
    throw new Error('Signature verification failed');
  }
  
  return result;
}

// ❌ Skipping signature verification
async function insecureVerification(presentation: VerifiablePresentation) {
  // Never skip verification in production
  return { valid: true, credentials: presentation.verifiableCredential };
}
```

#### Prevent Signature Reuse
```typescript
// ✅ Check for replay attacks
class ReplayProtection {
  private usedNonces = new Set<string>();
  private nonceExpiry = new Map<string, number>();
  
  validateNonce(nonce: string): boolean {
    const now = Date.now();
    
    // Check if nonce was already used
    if (this.usedNonces.has(nonce)) {
      return false;
    }
    
    // Clean expired nonces
    this.cleanExpiredNonces(now);
    
    // Add nonce with expiry
    this.usedNonces.add(nonce);
    this.nonceExpiry.set(nonce, now + 300000); // 5 minute expiry
    
    return true;
  }
  
  private cleanExpiredNonces(now: number) {
    for (const [nonce, expiry] of this.nonceExpiry) {
      if (now > expiry) {
        this.usedNonces.delete(nonce);
        this.nonceExpiry.delete(nonce);
      }
    }
  }
}
```

## Input Validation and Sanitization

### Presentation Validation
```typescript
import Joi from 'joi';

const presentationSchema = Joi.object({
  '@context': Joi.array().items(Joi.string().uri()).required(),
  type: Joi.array().items(Joi.string()).required(),
  verifiableCredential: Joi.array().items(Joi.object()).min(1).required(),
  proof: Joi.object({
    type: Joi.string().required(),
    created: Joi.string().isoDate().required(),
    proofPurpose: Joi.string().required(),
    verificationMethod: Joi.string().uri().required(),
    jws: Joi.string().required()
  }).required()
});

async function validatePresentation(data: unknown): Promise<VerifiablePresentation> {
  const { error, value } = presentationSchema.validate(data, {
    stripUnknown: true,
    abortEarly: false
  });
  
  if (error) {
    throw new ValidationError('Invalid presentation format', error.details);
  }
  
  return value;
}
```

### DID Validation
```typescript
function validateDID(did: string): boolean {
  // Validate DID format
  const didRegex = /^did:key:z[1-9A-HJ-NP-Za-km-z]{44,}$/;
  
  if (!didRegex.test(did)) {
    return false;
  }
  
  try {
    // Verify the DID can be resolved
    const publicKey = DIDService.getPublicKeyFromDID(did);
    return publicKey.length === 32; // Ed25519 public key length
  } catch {
    return false;
  }
}
```

### Attribute Sanitization
```typescript
function sanitizeAttributes(attributes: Record<string, any>): Record<string, any> {
  const sanitized: Record<string, any> = {};
  
  for (const [key, value] of Object.entries(attributes)) {
    // Validate attribute name
    if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(key)) {
      continue; // Skip invalid attribute names
    }
    
    // Sanitize value based on type
    if (typeof value === 'string') {
      sanitized[key] = sanitizeString(value);
    } else if (typeof value === 'number') {
      sanitized[key] = sanitizeNumber(value);
    } else if (typeof value === 'boolean') {
      sanitized[key] = Boolean(value);
    } else if (value instanceof Date) {
      sanitized[key] = value.toISOString();
    }
    // Skip complex objects that aren't explicitly handled
  }
  
  return sanitized;
}

function sanitizeString(str: string): string {
  return str
    .trim()
    .substring(0, 1000) // Limit length
    .replace(/[\x00-\x1F\x7F]/g, ''); // Remove control characters
}

function sanitizeNumber(num: number): number {
  if (!Number.isFinite(num)) {
    throw new Error('Invalid number value');
  }
  return num;
}
```

## Access Control and Authorization

### Role-Based Access Control
```typescript
enum UserRole {
  ADMIN = 'admin',
  ISSUER = 'issuer',
  VERIFIER = 'verifier',
  USER = 'user'
}

class AccessControl {
  private permissions = new Map<UserRole, Set<string>>([
    [UserRole.ADMIN, new Set(['*'])],
    [UserRole.ISSUER, new Set(['issue_credential', 'revoke_credential'])],
    [UserRole.VERIFIER, new Set(['verify_presentation', 'manage_sessions'])],
    [UserRole.USER, new Set(['create_presentation', 'store_credential'])]
  ]);
  
  hasPermission(role: UserRole, action: string): boolean {
    const rolePermissions = this.permissions.get(role);
    return rolePermissions?.has('*') || rolePermissions?.has(action) || false;
  }
  
  enforcePermission(role: UserRole, action: string): void {
    if (!this.hasPermission(role, action)) {
      throw new Error(`Access denied: ${role} cannot perform ${action}`);
    }
  }
}

// Usage in middleware
function requirePermission(action: string) {
  return (req: any, res: any, next: any) => {
    const userRole = req.user?.role;
    
    try {
      accessControl.enforcePermission(userRole, action);
      next();
    } catch (error) {
      res.status(403).json({ error: error.message });
    }
  };
}
```

### Session Security
```typescript
class SecureSessionManager extends SessionManager {
  constructor(options: SessionManagerOptions & {
    secureOptions?: {
      enableIPValidation?: boolean;
      enableUserAgentValidation?: boolean;
      maxSessionsPerUser?: number;
    }
  }) {
    super(options);
    this.secureOptions = options.secureOptions || {};
  }
  
  async createSession(
    verificationResult: VerificationResult, 
    metadata?: Record<string, any>
  ): Promise<Session> {
    // Validate session limits
    if (this.secureOptions.maxSessionsPerUser) {
      const existingSessions = this.getSessionsByHolder(verificationResult.holder!);
      if (existingSessions.length >= this.secureOptions.maxSessionsPerUser) {
        throw new Error('Maximum sessions per user exceeded');
      }
    }
    
    // Create session with security metadata
    const secureMetadata = {
      ...metadata,
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
      createdAt: new Date(),
      securityFlags: {
        ipValidationEnabled: this.secureOptions.enableIPValidation,
        userAgentValidationEnabled: this.secureOptions.enableUserAgentValidation
      }
    };
    
    return super.createSession(verificationResult, secureMetadata);
  }
  
  async validateSession(sessionId: string, context?: {
    ipAddress?: string;
    userAgent?: string;
  }): Promise<SessionValidation> {
    const validation = await super.validateSession(sessionId);
    
    if (!validation.valid || !validation.session) {
      return validation;
    }
    
    // Additional security validations
    if (this.secureOptions.enableIPValidation && context?.ipAddress) {
      if (validation.session.metadata?.ipAddress !== context.ipAddress) {
        await this.logSecurityEvent({
          type: 'session_ip_mismatch',
          sessionId,
          expectedIP: validation.session.metadata?.ipAddress,
          actualIP: context.ipAddress
        });
        
        this.removeSession(sessionId);
        return { valid: false, reason: 'IP address mismatch' };
      }
    }
    
    if (this.secureOptions.enableUserAgentValidation && context?.userAgent) {
      if (validation.session.metadata?.userAgent !== context.userAgent) {
        await this.logSecurityEvent({
          type: 'session_user_agent_mismatch',
          sessionId,
          expectedUA: validation.session.metadata?.userAgent,
          actualUA: context.userAgent
        });
        
        this.removeSession(sessionId);
        return { valid: false, reason: 'User agent mismatch' };
      }
    }
    
    return validation;
  }
}
```

## Storage Security

### Encrypted Storage
```typescript
class EncryptedStorageProvider implements IStorageProvider {
  constructor(
    private baseProvider: IStorageProvider,
    private encryptionKey: Uint8Array
  ) {}
  
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    const encryptedCredential = await this.encrypt(JSON.stringify(credential));
    
    // Store encrypted data
    await this.baseProvider.storeCredential({
      ...credential,
      credentialSubject: { id: credential.credentialSubject.id },
      encryptedData: encryptedCredential
    } as any);
  }
  
  async getCredential(credentialId: string): Promise<VerifiableCredential | null> {
    const stored = await this.baseProvider.getCredential(credentialId);
    
    if (!stored || !(stored as any).encryptedData) {
      return stored;
    }
    
    try {
      const decryptedData = await this.decrypt((stored as any).encryptedData);
      return JSON.parse(decryptedData);
    } catch (error) {
      console.error('Failed to decrypt credential:', error);
      return null;
    }
  }
  
  private async encrypt(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    // Use Web Crypto API for encryption
    const key = await crypto.subtle.importKey(
      'raw',
      this.encryptionKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      dataBuffer
    );
    
    // Combine IV and encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    return btoa(String.fromCharCode(...combined));
  }
  
  private async decrypt(encryptedData: string): Promise<string> {
    const combined = new Uint8Array(
      atob(encryptedData).split('').map(char => char.charCodeAt(0))
    );
    
    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);
    
    const key = await crypto.subtle.importKey(
      'raw',
      this.encryptionKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }
}
```

### Database Security
```typescript
// Secure database configuration
const dbConfig = {
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME,
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    require: true,
    rejectUnauthorized: true,
    ca: fs.readFileSync('./certs/ca-cert.pem'),
    cert: fs.readFileSync('./certs/client-cert.pem'),
    key: fs.readFileSync('./certs/client-key.pem')
  },
  // Connection pooling
  pool: {
    min: 2,
    max: 10,
    idle: 30000
  }
};

// SQL injection prevention
class SecureQuery {
  static async executeQuery(query: string, params: any[]): Promise<any> {
    // Use parameterized queries only
    if (query.includes('${') || query.includes('$')) {
      throw new Error('Raw string interpolation not allowed');
    }
    
    return db.query(query, params);
  }
}
```

## Network Security

### TLS Configuration
```typescript
// Secure HTTPS server configuration
const httpsOptions = {
  key: fs.readFileSync('./certs/server-key.pem'),
  cert: fs.readFileSync('./certs/server-cert.pem'),
  ca: fs.readFileSync('./certs/ca-cert.pem'),
  
  // Security settings
  secureProtocol: 'TLSv1_2_method',
  ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256',
  honorCipherOrder: true,
  
  // Client certificate validation
  requestCert: true,
  rejectUnauthorized: true
};

const app = express();

// Security headers
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});
```

### Rate Limiting
```typescript
import rateLimit from 'express-rate-limit';

// Different limits for different endpoints
const verificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many verification requests',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    // Log suspicious activity
    logSecurityEvent({
      type: 'rate_limit_exceeded',
      ip: req.ip,
      endpoint: req.path,
      timestamp: new Date()
    });
    
    res.status(429).json({ error: 'Rate limit exceeded' });
  }
});

const sessionLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 session operations per minute
  keyGenerator: (req) => req.headers['x-session-id'] || req.ip
});
```

## Audit and Monitoring

### Security Event Logging
```typescript
interface SecurityEvent {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: Date;
  source: string;
  details: Record<string, any>;
}

class SecurityLogger {
  private static events: SecurityEvent[] = [];
  
  static async logEvent(event: Omit<SecurityEvent, 'timestamp'>): Promise<void> {
    const fullEvent: SecurityEvent = {
      ...event,
      timestamp: new Date()
    };
    
    this.events.push(fullEvent);
    
    // Send to monitoring system
    await this.sendToMonitoring(fullEvent);
    
    // Alert on critical events
    if (event.severity === 'critical') {
      await this.sendAlert(fullEvent);
    }
  }
  
  private static async sendToMonitoring(event: SecurityEvent): Promise<void> {
    // Implementation depends on monitoring system
    console.log('Security Event:', event);
  }
  
  private static async sendAlert(event: SecurityEvent): Promise<void> {
    // Send immediate alert for critical events
    console.error('CRITICAL SECURITY EVENT:', event);
  }
}

// Usage throughout the application
await SecurityLogger.logEvent({
  type: 'credential_verification_failed',
  severity: 'medium',
  source: 'service-provider',
  details: {
    credentialId: 'cred-123',
    error: 'Invalid signature',
    userIP: req.ip
  }
});
```

### Anomaly Detection
```typescript
class AnomalyDetector {
  private verificationCounts = new Map<string, number[]>();
  
  detectAnomalies(ip: string, action: string): boolean {
    const now = Date.now();
    const windowSize = 300000; // 5 minutes
    const threshold = 50; // suspicious if more than 50 requests in 5 minutes
    
    const key = `${ip}:${action}`;
    const timestamps = this.verificationCounts.get(key) || [];
    
    // Remove old timestamps
    const recent = timestamps.filter(ts => now - ts < windowSize);
    recent.push(now);
    
    this.verificationCounts.set(key, recent);
    
    if (recent.length > threshold) {
      SecurityLogger.logEvent({
        type: 'anomalous_activity_detected',
        severity: 'high',
        source: 'anomaly-detector',
        details: {
          ip,
          action,
          requestCount: recent.length,
          timeWindow: windowSize
        }
      });
      
      return true;
    }
    
    return false;
  }
}
```

## Production Deployment Security

### Environment Configuration
```bash
# Use environment variables for sensitive configuration
export NODE_ENV=production
export DB_PASSWORD="$(cat /run/secrets/db_password)"
export ENCRYPTION_KEY="$(cat /run/secrets/encryption_key)"
export JWT_SECRET="$(cat /run/secrets/jwt_secret)"

# Set secure defaults
export SESSION_SECURE=true
export COOKIE_SECURE=true
export TRUST_PROXY=true
```

### Container Security
```dockerfile
# Use non-root user
FROM node:18-alpine
RUN addgroup -g 1001 -S app && adduser -S app -u 1001
USER app

# Security updates
RUN apk update && apk upgrade

# Read-only filesystem
COPY --chown=app:app . /app
WORKDIR /app
RUN npm ci --only=production && npm cache clean --force

# Drop capabilities
USER 1001
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

### Secrets Management
```typescript
// Use a secrets management system
class SecretsManager {
  static async getSecret(name: string): Promise<string> {
    // In production, use AWS Secrets Manager, HashiCorp Vault, etc.
    if (process.env.NODE_ENV === 'production') {
      return await this.getFromSecretsManager(name);
    } else {
      return process.env[name] || '';
    }
  }
  
  private static async getFromSecretsManager(name: string): Promise<string> {
    // Implementation depends on secrets management system
    // This is a placeholder
    throw new Error('Secrets manager not configured');
  }
}

// Usage
const dbPassword = await SecretsManager.getSecret('DB_PASSWORD');
const encryptionKey = await SecretsManager.getSecret('ENCRYPTION_KEY');
```

## Security Testing

### Security Test Suite
```typescript
describe('Security Tests', () => {
  describe('Input Validation', () => {
    it('should reject malformed DIDs', () => {
      expect(() => validateDID('invalid-did')).toThrow();
      expect(() => validateDID('did:key:invalid')).toThrow();
    });
    
    it('should sanitize user input', () => {
      const malicious = {
        'valid_name': 'John',
        '../../etc/passwd': 'malicious',
        'script_injection': '<script>alert("xss")</script>'
      };
      
      const sanitized = sanitizeAttributes(malicious);
      expect(sanitized).toEqual({ valid_name: 'John' });
    });
  });
  
  describe('Cryptographic Security', () => {
    it('should use secure random for key generation', async () => {
      const key1 = await CryptoService.generateKeyPair();
      const key2 = await CryptoService.generateKeyPair();
      
      expect(key1.privateKey).not.toEqual(key2.privateKey);
      expect(key1.publicKey).not.toEqual(key2.publicKey);
    });
    
    it('should prevent signature reuse', async () => {
      const presentation = await createTestPresentation();
      
      // First verification should succeed
      const result1 = await serviceProvider.verifyPresentation(presentation);
      expect(result1.valid).toBe(true);
      
      // Replay should be detected (if nonce checking is enabled)
      // Implementation depends on specific replay protection
    });
  });
});
```

### Penetration Testing Checklist
- [ ] SQL injection testing
- [ ] XSS attack vectors
- [ ] Authentication bypass attempts
- [ ] Session hijacking tests
- [ ] Rate limiting validation
- [ ] Input validation fuzzing
- [ ] Cryptographic implementation review
- [ ] Access control verification
- [ ] Data exposure analysis
- [ ] Network security assessment

This security guide provides a comprehensive foundation for secure deployment and operation of the anon-identity library in production environments.