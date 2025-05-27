import { KeyPair } from '../types';
import { CryptoService } from './crypto';
import * as crypto from 'crypto';

export interface StoredKeyPair {
  publicKey: string;
  encryptedPrivateKey: string;
  salt: string;
  iv: string;
}

export class SecureStorage {
  private static storage = new Map<string, any>();
  
  static async storeKeyPair(
    keyPair: KeyPair, 
    passphrase: string,
    identifier: string = 'default'
  ): Promise<void> {
    const salt = crypto.randomBytes(32);
    const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encryptedPrivateKey = Buffer.concat([
      cipher.update(keyPair.privateKey),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();
    
    const storedData: StoredKeyPair = {
      publicKey: CryptoService.bytesToHex(keyPair.publicKey),
      encryptedPrivateKey: Buffer.concat([authTag, encryptedPrivateKey]).toString('base64'),
      salt: salt.toString('base64'),
      iv: iv.toString('base64')
    };
    
    this.storage.set(`keypair:${identifier}`, storedData);
  }
  
  static async retrieveKeyPair(
    passphrase: string,
    identifier: string = 'default'
  ): Promise<KeyPair | null> {
    const storedData = this.storage.get(`keypair:${identifier}`) as StoredKeyPair;
    if (!storedData) return null;
    
    try {
      const salt = Buffer.from(storedData.salt, 'base64');
      const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
      const iv = Buffer.from(storedData.iv, 'base64');
      
      const encryptedData = Buffer.from(storedData.encryptedPrivateKey, 'base64');
      const authTag = encryptedData.slice(0, 16);
      const encryptedPrivateKey = encryptedData.slice(16);
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      
      const privateKey = Buffer.concat([
        decipher.update(encryptedPrivateKey),
        decipher.final()
      ]);
      
      return {
        publicKey: CryptoService.hexToBytes(storedData.publicKey),
        privateKey: new Uint8Array(privateKey)
      };
    } catch (error) {
      console.error('Failed to decrypt key pair:', error);
      return null;
    }
  }
  
  static store(key: string, value: any): void {
    this.storage.set(key, value);
  }
  
  static retrieve(key: string): any {
    return this.storage.get(key);
  }
  
  static delete(key: string): boolean {
    return this.storage.delete(key);
  }
  
  static clear(): void {
    this.storage.clear();
  }
}