/**
 * Secure Credential Management for MCP
 * 
 * Handles secure storage, rotation, and access control for LLM provider credentials
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import {
  CredentialConfig,
  CredentialStorageType,
  CredentialRotationConfig,
  CredentialValidationConfig,
  MCPError,
  MCPErrorCode
} from '../types';
// Using MemoryStorageProvider directly for credential storage
import { MemoryStorageProvider } from '../../storage/providers/memory-storage-provider';

/**
 * Credential data structure
 */
export interface Credential {
  id: string;
  providerId: string;
  type: 'api_key' | 'oauth_token' | 'certificate' | 'custom';
  value: string;
  encryptedValue?: string;
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    expiresAt?: Date;
    rotatedAt?: Date;
    lastUsedAt?: Date;
    usageCount: number;
    description?: string;
    tags?: string[];
  };
  validation?: {
    validated: boolean;
    validatedAt?: Date;
    validationError?: string;
  };
}

/**
 * Credential validation result
 */
export interface CredentialValidationResult {
  valid: boolean;
  error?: string;
  details?: any;
}

/**
 * Credential rotation result
 */
export interface CredentialRotationResult {
  rotated: boolean;
  oldCredentialId: string;
  newCredentialId?: string;
  error?: string;
}

/**
 * Encryption configuration
 */
interface EncryptionConfig {
  algorithm: string;
  keyDerivationFunction: string;
  iterations: number;
  saltLength: number;
  ivLength: number;
  tagLength: number;
}

/**
 * Secure Credential Manager
 */
export class CredentialManager extends EventEmitter {
  private credentials: Map<string, Credential> = new Map();
  private encryptionKey: Buffer | null = null;
  private encryptionConfig: EncryptionConfig = {
    algorithm: 'aes-256-gcm',
    keyDerivationFunction: 'pbkdf2',
    iterations: 100000,
    saltLength: 32,
    ivLength: 16,
    tagLength: 16
  };
  private rotationTimers: Map<string, NodeJS.Timeout> = new Map();
  private validationCache: Map<string, CredentialValidationResult> = new Map();
  private storageProvider: MemoryStorageProvider;

  constructor(
    private config: CredentialConfig,
    storageProvider?: MemoryStorageProvider
  ) {
    super();
    this.storageProvider = storageProvider || new MemoryStorageProvider();
    this.initializeEncryption();
    this.loadCredentials();
  }

  /**
   * Initialize encryption
   */
  private async initializeEncryption(): Promise<void> {
    if (!this.config.encryption) {
      return;
    }

    // In production, this master key should come from a secure key management service
    // For now, we'll derive it from a passphrase
    const passphrase = process.env.MCP_CREDENTIAL_PASSPHRASE || 'default-passphrase-change-me';
    const salt = crypto.randomBytes(this.encryptionConfig.saltLength);
    
    this.encryptionKey = crypto.pbkdf2Sync(
      passphrase,
      salt,
      this.encryptionConfig.iterations,
      32,
      'sha256'
    );
  }

  /**
   * Load credentials from storage
   */
  private async loadCredentials(): Promise<void> {
    try {
      // Use internal storage for credentials
      const storedCredentials = (this.storageProvider as any)._storage?.get('mcp:credentials');
      if (storedCredentials) {
        const credentials = JSON.parse(storedCredentials);
        for (const cred of credentials) {
          // Decrypt if necessary
          if (cred.encryptedValue && this.config.encryption) {
            cred.value = await this.decrypt(cred.encryptedValue);
          }
          
          // Convert dates
          cred.metadata.createdAt = new Date(cred.metadata.createdAt);
          cred.metadata.updatedAt = new Date(cred.metadata.updatedAt);
          if (cred.metadata.expiresAt) {
            cred.metadata.expiresAt = new Date(cred.metadata.expiresAt);
          }
          if (cred.metadata.rotatedAt) {
            cred.metadata.rotatedAt = new Date(cred.metadata.rotatedAt);
          }
          if (cred.metadata.lastUsedAt) {
            cred.metadata.lastUsedAt = new Date(cred.metadata.lastUsedAt);
          }
          
          this.credentials.set(cred.id, cred);
          
          // Setup rotation if configured
          if (this.config.rotation?.enabled) {
            this.scheduleRotation(cred);
          }
        }
      }
    } catch (error) {
      this.emit('error', new MCPError({
        code: MCPErrorCode.INVALID_CONFIG,
        message: `Failed to load credentials: ${(error as Error).message}`,
        timestamp: new Date(),
        retryable: false
      }));
    }
  }

  /**
   * Save credentials to storage
   */
  private async saveCredentials(): Promise<void> {
    const credentialsToStore = Array.from(this.credentials.values()).map(cred => {
      const stored: any = { ...cred };
      
      // Encrypt if necessary
      if (this.config.encryption && this.encryptionKey) {
        stored.encryptedValue = this.encrypt(cred.value);
        delete stored.value; // Don't store plaintext
      }
      
      return stored;
    });

    // Use internal storage for credentials
    (this.storageProvider as any)._storage = (this.storageProvider as any)._storage || new Map();
    (this.storageProvider as any)._storage.set('mcp:credentials', JSON.stringify(credentialsToStore));
  }

  /**
   * Add credential
   */
  async addCredential(
    providerId: string,
    type: Credential['type'],
    value: string,
    metadata?: Partial<Credential['metadata']>
  ): Promise<Credential> {
    const id = `cred-${providerId}-${Date.now()}`;
    
    const credential: Credential = {
      id,
      providerId,
      type,
      value,
      metadata: {
        createdAt: new Date(),
        updatedAt: new Date(),
        usageCount: 0,
        ...metadata
      }
    };

    // Validate if configured
    if (this.config.validation?.validateOnLoad) {
      const validation = await this.validateCredential(credential);
      credential.validation = {
        validated: true,
        validatedAt: new Date(),
        validationError: validation.error
      };
      
      if (!validation.valid) {
        throw new MCPError({
          code: MCPErrorCode.INVALID_CREDENTIALS,
          message: `Invalid credential: ${validation.error}`,
          timestamp: new Date(),
          provider: providerId,
          retryable: false
        });
      }
    }

    this.credentials.set(id, credential);
    await this.saveCredentials();

    // Schedule rotation if configured
    if (this.config.rotation?.enabled) {
      this.scheduleRotation(credential);
    }

    this.emit('credential_added', credential);
    return credential;
  }

  /**
   * Get credential for provider
   */
  async getCredential(providerId: string): Promise<Credential | null> {
    // Find most recent valid credential for provider
    const providerCredentials = Array.from(this.credentials.values())
      .filter(cred => cred.providerId === providerId)
      .sort((a, b) => b.metadata.createdAt.getTime() - a.metadata.createdAt.getTime());

    for (const credential of providerCredentials) {
      // Check expiration
      if (credential.metadata.expiresAt && credential.metadata.expiresAt < new Date()) {
        continue;
      }

      // Validate on use if configured
      if (this.config.validation?.validateOnUse) {
        const validation = await this.validateCredential(credential);
        if (!validation.valid) {
          credential.validation = {
            validated: true,
            validatedAt: new Date(),
            validationError: validation.error
          };
          await this.saveCredentials();
          continue;
        }
      }

      // Update usage statistics
      credential.metadata.lastUsedAt = new Date();
      credential.metadata.usageCount++;
      await this.saveCredentials();

      return credential;
    }

    return null;
  }

  /**
   * Update credential
   */
  async updateCredential(
    credentialId: string,
    updates: Partial<Pick<Credential, 'value' | 'metadata'>>
  ): Promise<Credential> {
    const credential = this.credentials.get(credentialId);
    if (!credential) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_CREDENTIALS,
        message: `Credential not found: ${credentialId}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    if (updates.value) {
      credential.value = updates.value;
      credential.metadata.rotatedAt = new Date();
    }

    if (updates.metadata) {
      credential.metadata = { ...credential.metadata, ...updates.metadata };
    }

    credential.metadata.updatedAt = new Date();

    // Re-validate if value changed
    if (updates.value && this.config.validation?.validateOnLoad) {
      const validation = await this.validateCredential(credential);
      credential.validation = {
        validated: true,
        validatedAt: new Date(),
        validationError: validation.error
      };
    }

    await this.saveCredentials();
    this.emit('credential_updated', credential);
    
    return credential;
  }

  /**
   * Delete credential
   */
  async deleteCredential(credentialId: string): Promise<void> {
    const credential = this.credentials.get(credentialId);
    if (!credential) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_CREDENTIALS,
        message: `Credential not found: ${credentialId}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    // Cancel rotation timer
    const timer = this.rotationTimers.get(credentialId);
    if (timer) {
      clearTimeout(timer);
      this.rotationTimers.delete(credentialId);
    }

    this.credentials.delete(credentialId);
    this.validationCache.delete(credentialId);
    await this.saveCredentials();
    
    this.emit('credential_deleted', credential);
  }

  /**
   * Rotate credential
   */
  async rotateCredential(
    credentialId: string,
    newValue: string
  ): Promise<CredentialRotationResult> {
    const oldCredential = this.credentials.get(credentialId);
    if (!oldCredential) {
      return {
        rotated: false,
        oldCredentialId: credentialId,
        error: 'Credential not found'
      };
    }

    try {
      // Create new credential
      const newCredential = await this.addCredential(
        oldCredential.providerId,
        oldCredential.type,
        newValue,
        {
          ...oldCredential.metadata,
          description: `Rotated from ${credentialId}`
        }
      );

      // Mark old credential as rotated
      oldCredential.metadata.expiresAt = new Date();
      await this.saveCredentials();

      // Delete old credential after retention period
      if (this.config.rotation?.retentionCount) {
        // Keep only the configured number of old credentials
        const providerCredentials = Array.from(this.credentials.values())
          .filter(cred => cred.providerId === oldCredential.providerId)
          .sort((a, b) => b.metadata.createdAt.getTime() - a.metadata.createdAt.getTime());

        if (providerCredentials.length > this.config.rotation.retentionCount) {
          const toDelete = providerCredentials.slice(this.config.rotation.retentionCount);
          for (const cred of toDelete) {
            await this.deleteCredential(cred.id);
          }
        }
      }

      this.emit('credential_rotated', {
        oldCredential,
        newCredential
      });

      return {
        rotated: true,
        oldCredentialId: credentialId,
        newCredentialId: newCredential.id
      };

    } catch (error) {
      return {
        rotated: false,
        oldCredentialId: credentialId,
        error: (error as Error).message
      };
    }
  }

  /**
   * Validate credential
   */
  private async validateCredential(credential: Credential): Promise<CredentialValidationResult> {
    // Check cache first
    if (this.config.validation?.cacheValidation) {
      const cached = this.validationCache.get(credential.id);
      if (cached) {
        return cached;
      }
    }

    const result: CredentialValidationResult = { valid: true };

    try {
      // Basic validation
      if (!credential.value || credential.value.trim().length === 0) {
        result.valid = false;
        result.error = 'Credential value is empty';
      }

      // Type-specific validation
      switch (credential.type) {
        case 'api_key':
          if (credential.value.length < 32) {
            result.valid = false;
            result.error = 'API key too short';
          }
          break;
        case 'oauth_token':
          // Check token format
          if (!credential.value.startsWith('Bearer ') && !credential.value.includes('.')) {
            result.valid = false;
            result.error = 'Invalid OAuth token format';
          }
          break;
        case 'certificate':
          // Basic certificate validation
          if (!credential.value.includes('BEGIN CERTIFICATE')) {
            result.valid = false;
            result.error = 'Invalid certificate format';
          }
          break;
      }

      // Cache result
      if (this.config.validation?.cacheValidation) {
        this.validationCache.set(credential.id, result);
        
        // Clear cache after timeout
        setTimeout(() => {
          this.validationCache.delete(credential.id);
        }, this.config.validation?.validationTimeout || 300000); // 5 minutes default
      }

    } catch (error) {
      result.valid = false;
      result.error = (error as Error).message;
    }

    return result;
  }

  /**
   * Schedule credential rotation
   */
  private scheduleRotation(credential: Credential): void {
    if (!this.config.rotation?.enabled || !this.config.rotation.interval) {
      return;
    }

    // Clear existing timer
    const existingTimer = this.rotationTimers.get(credential.id);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Calculate next rotation time
    const lastRotation = credential.metadata.rotatedAt || credential.metadata.createdAt;
    const nextRotation = new Date(lastRotation.getTime() + this.config.rotation.interval);
    const timeUntilRotation = Math.max(0, nextRotation.getTime() - Date.now());

    // Notify before rotation if configured
    if (this.config.rotation.notifyBefore) {
      const notifyTime = timeUntilRotation - this.config.rotation.notifyBefore;
      if (notifyTime > 0) {
        setTimeout(() => {
          this.emit('rotation_due', {
            credential,
            dueIn: this.config.rotation!.notifyBefore
          });
        }, notifyTime);
      }
    }

    // Schedule rotation
    const timer = setTimeout(() => {
      this.emit('rotation_required', credential);
      this.rotationTimers.delete(credential.id);
    }, timeUntilRotation);

    this.rotationTimers.set(credential.id, timer);
  }

  /**
   * Encrypt value
   */
  private encrypt(value: string): string {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const iv = crypto.randomBytes(this.encryptionConfig.ivLength);
    const cipher = crypto.createCipheriv(
      this.encryptionConfig.algorithm,
      this.encryptionKey,
      iv
    );

    let encrypted = cipher.update(value, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    const tag = (cipher as any).getAuthTag();
    
    // Combine IV, tag, and encrypted data
    const combined = Buffer.concat([
      iv,
      tag,
      Buffer.from(encrypted, 'base64')
    ]);

    return combined.toString('base64');
  }

  /**
   * Decrypt value
   */
  private decrypt(encryptedValue: string): string {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const combined = Buffer.from(encryptedValue, 'base64');
    
    // Extract IV, tag, and encrypted data
    const iv = combined.slice(0, this.encryptionConfig.ivLength);
    const tag = combined.slice(
      this.encryptionConfig.ivLength,
      this.encryptionConfig.ivLength + this.encryptionConfig.tagLength
    );
    const encrypted = combined.slice(
      this.encryptionConfig.ivLength + this.encryptionConfig.tagLength
    );

    const decipher = crypto.createDecipheriv(
      this.encryptionConfig.algorithm,
      this.encryptionKey,
      iv
    );
    
    (decipher as any).setAuthTag(tag);

    let decrypted = decipher.update(encrypted.toString('base64'), 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Get credential statistics
   */
  getStatistics(): {
    total: number;
    byProvider: Record<string, number>;
    byType: Record<string, number>;
    expired: number;
    rotating: number;
    validated: number;
    failed: number;
  } {
    const stats = {
      total: this.credentials.size,
      byProvider: {} as Record<string, number>,
      byType: {} as Record<string, number>,
      expired: 0,
      rotating: 0,
      validated: 0,
      failed: 0
    };

    const now = new Date();

    for (const credential of this.credentials.values()) {
      // Count by provider
      stats.byProvider[credential.providerId] = (stats.byProvider[credential.providerId] || 0) + 1;

      // Count by type
      stats.byType[credential.type] = (stats.byType[credential.type] || 0) + 1;

      // Count expired
      if (credential.metadata.expiresAt && credential.metadata.expiresAt < now) {
        stats.expired++;
      }

      // Count rotating
      if (this.rotationTimers.has(credential.id)) {
        stats.rotating++;
      }

      // Count validated
      if (credential.validation?.validated) {
        stats.validated++;
        if (credential.validation.validationError) {
          stats.failed++;
        }
      }
    }

    return stats;
  }

  /**
   * Export credentials (for backup)
   */
  async exportCredentials(includeValues = false): Promise<string> {
    const credentials = Array.from(this.credentials.values()).map(cred => {
      const exported: any = {
        id: cred.id,
        providerId: cred.providerId,
        type: cred.type,
        metadata: cred.metadata,
        validation: cred.validation
      };

      if (includeValues) {
        exported.value = cred.value;
      }

      return exported;
    });

    return JSON.stringify(credentials, null, 2);
  }

  /**
   * Import credentials
   */
  async importCredentials(data: string, overwrite = false): Promise<number> {
    const credentials = JSON.parse(data);
    let imported = 0;

    for (const cred of credentials) {
      if (!overwrite && this.credentials.has(cred.id)) {
        continue;
      }

      await this.addCredential(
        cred.providerId,
        cred.type,
        cred.value,
        cred.metadata
      );
      imported++;
    }

    return imported;
  }

  /**
   * Shutdown credential manager
   */
  async shutdown(): Promise<void> {
    // Clear all rotation timers
    for (const timer of this.rotationTimers.values()) {
      clearTimeout(timer);
    }
    this.rotationTimers.clear();

    // Clear caches
    this.validationCache.clear();

    // Save final state
    await this.saveCredentials();

    // Clear sensitive data
    this.credentials.clear();
    this.encryptionKey = null;

    this.removeAllListeners();
  }
}

export default CredentialManager;