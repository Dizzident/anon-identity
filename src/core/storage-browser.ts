import { CryptoService } from './crypto-browser';

/**
 * Browser-compatible secure storage using localStorage or IndexedDB
 */
export class EncryptedStorageService {
  private storageKey = 'anon-identity-storage';
  
  async saveEncryptedData(identifier: string, data: any, password: string): Promise<void> {
    const dataStr = JSON.stringify(data);
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(dataStr);
    
    // Derive key from password
    const passwordBytes = encoder.encode(password);
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBytes,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    
    // Generate salt
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // Derive encryption key
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    
    // Generate IV
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt data
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      dataBytes
    );
    
    // Store encrypted data with metadata
    const storageData = {
      salt: Array.from(salt),
      iv: Array.from(iv),
      data: Array.from(new Uint8Array(encryptedData))
    };
    
    // Save to localStorage (or IndexedDB for larger data)
    const allData = this.getAllStoredData();
    allData[identifier] = storageData;
    localStorage.setItem(this.storageKey, JSON.stringify(allData));
  }

  async loadEncryptedData(identifier: string, password: string): Promise<any | null> {
    const allData = this.getAllStoredData();
    const storageData = allData[identifier];
    
    if (!storageData) {
      return null;
    }
    
    try {
      const encoder = new TextEncoder();
      const passwordBytes = encoder.encode(password);
      
      // Import password as key material
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordBytes,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
      );
      
      // Reconstruct arrays
      const salt = new Uint8Array(storageData.salt);
      const iv = new Uint8Array(storageData.iv);
      const encryptedData = new Uint8Array(storageData.data);
      
      // Derive decryption key
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      
      // Decrypt data
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        encryptedData
      );
      
      // Convert back to string and parse JSON
      const decoder = new TextDecoder();
      const dataStr = decoder.decode(decryptedData);
      return JSON.parse(dataStr);
    } catch (error) {
      console.error('Failed to decrypt data:', error);
      return null;
    }
  }

  deleteData(identifier: string): void {
    const allData = this.getAllStoredData();
    delete allData[identifier];
    localStorage.setItem(this.storageKey, JSON.stringify(allData));
  }

  private getAllStoredData(): Record<string, any> {
    try {
      const data = localStorage.getItem(this.storageKey);
      return data ? JSON.parse(data) : {};
    } catch {
      return {};
    }
  }

  clearAll(): void {
    localStorage.removeItem(this.storageKey);
  }
}