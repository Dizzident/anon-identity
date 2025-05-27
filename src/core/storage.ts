import { KeyPair } from '../types';
import { CryptoService } from './crypto';
import * as crypto from 'crypto';
import { IStorageProvider, StorageFactory } from '../storage';

export interface StoredKeyPair {
  publicKey: string;
  encryptedPrivateKey: string;
  salt: string;
  iv: string;
}

export class SecureStorage {
  private static storageProvider: IStorageProvider = StorageFactory.getDefaultProvider();
  
  /**
   * Set a custom storage provider
   */
  static setStorageProvider(provider: IStorageProvider): void {
    this.storageProvider = provider;
  }
  
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
    
    await this.storageProvider.storeKeyPair(identifier, JSON.stringify(storedData));
  }
  
  static async retrieveKeyPair(
    passphrase: string,
    identifier: string = 'default'
  ): Promise<KeyPair | null> {
    const storedDataStr = await this.storageProvider.retrieveKeyPair(identifier);
    if (!storedDataStr) return null;
    
    try {
      const storedData: StoredKeyPair = JSON.parse(storedDataStr);
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
  
  static async store(key: string, value: any): Promise<void> {
    // Legacy method - stores as credential for backward compatibility
    const fakeCredential: any = {
      id: key,
      credentialSubject: { id: 'legacy', data: value }
    };
    await this.storageProvider.storeCredential(fakeCredential);
  }
  
  static async retrieve(key: string): Promise<any> {
    // Legacy method - retrieves from credential store
    const credential = await this.storageProvider.getCredential(key);
    return credential ? credential.credentialSubject.data : undefined;
  }
  
  static async delete(key: string): Promise<boolean> {
    await this.storageProvider.deleteCredential(key);
    return true;
  }
  
  static async clear(): Promise<void> {
    await this.storageProvider.clear();
  }
}