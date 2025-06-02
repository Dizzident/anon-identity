import * as crypto from 'crypto';
import { AgentActivity, ActivityBatch } from './types';

export interface EncryptedData {
  data: string; // Base64 encoded encrypted data
  iv: string; // Base64 encoded initialization vector
  tag: string; // Base64 encoded auth tag
  algorithm: string;
}

export class ActivityEncryption {
  private algorithm = 'aes-256-gcm';
  
  /**
   * Generate a new encryption key
   */
  static generateKey(): Uint8Array {
    return crypto.randomBytes(32);
  }

  /**
   * Encrypt an activity object
   */
  async encryptActivity(
    activity: AgentActivity, 
    key: Uint8Array
  ): Promise<EncryptedData> {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, key, iv) as crypto.CipherGCM;
    
    const activityString = JSON.stringify(activity);
    const encrypted = Buffer.concat([
      cipher.update(activityString, 'utf8'),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return {
      data: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      algorithm: this.algorithm
    };
  }

  /**
   * Decrypt an activity object
   */
  async decryptActivity(
    encrypted: EncryptedData, 
    key: Uint8Array
  ): Promise<AgentActivity> {
    const decipher = crypto.createDecipheriv(
      encrypted.algorithm || this.algorithm,
      key,
      Buffer.from(encrypted.iv, 'base64')
    ) as crypto.DecipherGCM;
    
    decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));
    
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted.data, 'base64')),
      decipher.final()
    ]);
    
    return JSON.parse(decrypted.toString('utf8'));
  }

  /**
   * Encrypt a batch of activities
   */
  async encryptBatch(
    batch: ActivityBatch,
    key: Uint8Array
  ): Promise<EncryptedData> {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, key, iv) as crypto.CipherGCM;
    
    const batchString = JSON.stringify(batch);
    const encrypted = Buffer.concat([
      cipher.update(batchString, 'utf8'),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return {
      data: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      algorithm: this.algorithm
    };
  }

  /**
   * Decrypt a batch of activities
   */
  async decryptBatch(
    encrypted: EncryptedData,
    key: Uint8Array
  ): Promise<ActivityBatch> {
    const decipher = crypto.createDecipheriv(
      encrypted.algorithm || this.algorithm,
      key,
      Buffer.from(encrypted.iv, 'base64')
    ) as crypto.DecipherGCM;
    
    decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));
    
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted.data, 'base64')),
      decipher.final()
    ]);
    
    return JSON.parse(decrypted.toString('utf8'));
  }

  /**
   * Create a deterministic key from user DID and passphrase
   */
  static async deriveKey(
    userDID: string,
    passphrase: string
  ): Promise<Uint8Array> {
    const salt = crypto.createHash('sha256').update(userDID).digest();
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(passphrase, salt, 100000, 32, 'sha256', (err, derivedKey) => {
        if (err) reject(err);
        else resolve(new Uint8Array(derivedKey));
      });
    });
  }

  /**
   * Create a hash of an activity for integrity verification
   */
  static createActivityHash(activity: AgentActivity): string {
    const hash = crypto.createHash('sha256');
    hash.update(JSON.stringify({
      id: activity.id,
      agentDID: activity.agentDID,
      parentDID: activity.parentDID,
      timestamp: activity.timestamp,
      type: activity.type,
      serviceDID: activity.serviceDID,
      status: activity.status,
      scopes: activity.scopes
    }));
    return hash.digest('hex');
  }

  /**
   * Create a merkle root for a batch of activities
   */
  static createBatchMerkleRoot(activities: AgentActivity[]): string {
    if (activities.length === 0) return '';
    
    // Create leaf hashes
    let hashes = activities.map(activity => this.createActivityHash(activity));
    
    // Build merkle tree
    while (hashes.length > 1) {
      const newHashes: string[] = [];
      
      for (let i = 0; i < hashes.length; i += 2) {
        const left = hashes[i];
        const right = hashes[i + 1] || left; // Duplicate last hash if odd number
        
        const combined = crypto.createHash('sha256');
        combined.update(left + right);
        newHashes.push(combined.digest('hex'));
      }
      
      hashes = newHashes;
    }
    
    return hashes[0];
  }
}