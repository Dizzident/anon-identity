# Browser Integration Guide

Complete guide for integrating anon-identity in web applications.

## Installation and Setup

### NPM Installation
```bash
npm install anon-identity
```

### Browser Import
```typescript
// Use browser-specific entry point
import {
  IdentityProvider,
  UserWallet,
  ServiceProvider,
  MemoryStorageProvider
} from 'anon-identity/browser';

// Or ES modules
import { IdentityProvider } from 'https://unpkg.com/anon-identity@latest/dist/browser.js';
```

### CDN Usage
```html
<!DOCTYPE html>
<html>
<head>
  <script type="module">
    import { IdentityProvider, UserWallet, ServiceProvider } from 'https://unpkg.com/anon-identity@latest/dist/browser.js';
    
    // Your code here
  </script>
</head>
</html>
```

## Browser Storage Options

### Memory Storage (Development)
```typescript
const storage = new MemoryStorageProvider();
// Data lost on page refresh - use for testing only
```

### IndexedDB Storage (Recommended)
```typescript
class IndexedDBStorageProvider implements IStorageProvider {
  private dbName = 'anon-identity-db';
  private version = 1;
  private db?: IDBDatabase;
  
  async initialize(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };
      
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        
        // Create object stores
        if (!db.objectStoreNames.contains('credentials')) {
          db.createObjectStore('credentials', { keyPath: 'id' });
        }
        
        if (!db.objectStoreNames.contains('dids')) {
          db.createObjectStore('dids', { keyPath: 'id' });
        }
        
        if (!db.objectStoreNames.contains('sessions')) {
          db.createObjectStore('sessions', { keyPath: 'id' });
        }
      };
    });
  }
  
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    const transaction = this.db!.transaction(['credentials'], 'readwrite');
    const store = transaction.objectStore('credentials');
    
    return new Promise((resolve, reject) => {
      const request = store.put(credential);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
  
  async getCredential(credentialId: string): Promise<VerifiableCredential | null> {
    const transaction = this.db!.transaction(['credentials'], 'readonly');
    const store = transaction.objectStore('credentials');
    
    return new Promise((resolve, reject) => {
      const request = store.get(credentialId);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }
  
  // Implement other IStorageProvider methods...
}
```

### Local Storage (Simple Cases)
```typescript
class LocalStorageProvider implements IStorageProvider {
  private prefix = 'anon-identity:';
  
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    const key = `${this.prefix}credential:${credential.id}`;
    localStorage.setItem(key, JSON.stringify(credential));
  }
  
  async getCredential(credentialId: string): Promise<VerifiableCredential | null> {
    const key = `${this.prefix}credential:${credentialId}`;
    const stored = localStorage.getItem(key);
    return stored ? JSON.parse(stored) : null;
  }
  
  // Note: localStorage has size limits (5-10MB typically)
  // Use for small amounts of data only
}
```

## Web Components

### Credential Verification Component
```typescript
class CredentialVerifier extends HTMLElement {
  private serviceProvider?: ServiceProvider;
  private shadowRoot: ShadowRoot;
  
  constructor() {
    super();
    this.shadowRoot = this.attachShadow({ mode: 'closed' });
    this.render();
  }
  
  connectedCallback() {
    this.setupServiceProvider();
    this.bindEvents();
  }
  
  private async setupServiceProvider() {
    const trustedIssuers = JSON.parse(this.getAttribute('trusted-issuers') || '[]');
    const storage = new MemoryStorageProvider();
    
    this.serviceProvider = new ServiceProvider('Web Verifier', trustedIssuers, {
      storageProvider: storage,
      sessionManager: {
        defaultSessionDuration: 3600000 // 1 hour
      }
    });
  }
  
  private render() {
    this.shadowRoot.innerHTML = `
      <style>
        .verifier {
          border: 1px solid #ccc;
          border-radius: 8px;
          padding: 20px;
          margin: 10px 0;
        }
        
        .drop-zone {
          border: 2px dashed #ccc;
          border-radius: 8px;
          padding: 40px;
          text-align: center;
          cursor: pointer;
          transition: border-color 0.3s;
        }
        
        .drop-zone:hover {
          border-color: #007bff;
        }
        
        .result {
          margin-top: 20px;
          padding: 15px;
          border-radius: 4px;
        }
        
        .success {
          background-color: #d4edda;
          border: 1px solid #c3e6cb;
          color: #155724;
        }
        
        .error {
          background-color: #f8d7da;
          border: 1px solid #f5c6cb;
          color: #721c24;
        }
      </style>
      
      <div class="verifier">
        <h3>Credential Verifier</h3>
        <div class="drop-zone" id="dropZone">
          Drop credential file here or click to select
          <input type="file" id="fileInput" style="display: none;" accept=".json">
        </div>
        <div id="result"></div>
      </div>
    `;
  }
  
  private bindEvents() {
    const dropZone = this.shadowRoot.getElementById('dropZone')!;
    const fileInput = this.shadowRoot.getElementById('fileInput') as HTMLInputElement;
    
    dropZone.addEventListener('click', () => fileInput.click());
    
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.style.borderColor = '#007bff';
    });
    
    dropZone.addEventListener('dragleave', () => {
      dropZone.style.borderColor = '#ccc';
    });
    
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.style.borderColor = '#ccc';
      
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) {
        this.handleFile(files[0]);
      }
    });
    
    fileInput.addEventListener('change', (e) => {
      const target = e.target as HTMLInputElement;
      if (target.files && target.files.length > 0) {
        this.handleFile(target.files[0]);
      }
    });
  }
  
  private async handleFile(file: File) {
    try {
      const text = await file.text();
      const presentation = JSON.parse(text);
      
      await this.verifyPresentation(presentation);
    } catch (error) {
      this.showResult(false, `Failed to parse file: ${error.message}`);
    }
  }
  
  private async verifyPresentation(presentation: any) {
    if (!this.serviceProvider) {
      this.showResult(false, 'Service provider not initialized');
      return;
    }
    
    try {
      const result = await this.serviceProvider.verifyPresentation(presentation);
      
      if (result.valid) {
        const attributes = result.credentials?.[0]?.attributes;
        this.showResult(true, 'Credential verified successfully', attributes);
      } else {
        const errors = result.errors?.map(e => e.message).join(', ') || 'Unknown error';
        this.showResult(false, `Verification failed: ${errors}`);
      }
    } catch (error) {
      this.showResult(false, `Verification error: ${error.message}`);
    }
  }
  
  private showResult(success: boolean, message: string, attributes?: any) {
    const resultDiv = this.shadowRoot.getElementById('result')!;
    
    resultDiv.className = `result ${success ? 'success' : 'error'}`;
    resultDiv.innerHTML = `
      <strong>${success ? 'Success' : 'Error'}</strong>
      <p>${message}</p>
      ${attributes ? `
        <details>
          <summary>Verified Attributes</summary>
          <pre>${JSON.stringify(attributes, null, 2)}</pre>
        </details>
      ` : ''}
    `;
  }
}

customElements.define('credential-verifier', CredentialVerifier);
```

### User Wallet Component
```typescript
class UserWalletComponent extends HTMLElement {
  private wallet?: UserWallet;
  private credentials: VerifiableCredential[] = [];
  
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.render();
  }
  
  async connectedCallback() {
    await this.initializeWallet();
    await this.loadCredentials();
    this.bindEvents();
  }
  
  private async initializeWallet() {
    const storage = new IndexedDBStorageProvider();
    await storage.initialize();
    
    this.wallet = await UserWallet.create(storage);
  }
  
  private async loadCredentials() {
    if (!this.wallet) return;
    
    this.credentials = await this.wallet.listCredentials();
    this.renderCredentials();
  }
  
  private render() {
    this.shadowRoot!.innerHTML = `
      <style>
        .wallet {
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        
        .credential {
          border: 1px solid #ddd;
          border-radius: 8px;
          padding: 15px;
          margin: 10px 0;
          background: white;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .credential h4 {
          margin: 0 0 10px 0;
          color: #333;
        }
        
        .credential-meta {
          font-size: 0.9em;
          color: #666;
          margin-bottom: 10px;
        }
        
        .attributes {
          background: #f8f9fa;
          padding: 10px;
          border-radius: 4px;
          font-family: monospace;
          font-size: 0.9em;
        }
        
        .actions {
          margin-top: 15px;
        }
        
        button {
          background: #007bff;
          color: white;
          border: none;
          padding: 8px 16px;
          border-radius: 4px;
          cursor: pointer;
          margin-right: 10px;
        }
        
        button:hover {
          background: #0056b3;
        }
        
        .empty {
          text-align: center;
          color: #666;
          font-style: italic;
          padding: 40px;
        }
      </style>
      
      <div class="wallet">
        <h2>My Credentials</h2>
        <div id="credentials-list"></div>
      </div>
    `;
  }
  
  private renderCredentials() {
    const listDiv = this.shadowRoot!.getElementById('credentials-list')!;
    
    if (this.credentials.length === 0) {
      listDiv.innerHTML = '<div class="empty">No credentials in wallet</div>';
      return;
    }
    
    listDiv.innerHTML = this.credentials.map(cred => `
      <div class="credential">
        <h4>${cred.type.filter(t => t !== 'VerifiableCredential').join(', ')}</h4>
        <div class="credential-meta">
          <strong>Issuer:</strong> ${cred.issuer}<br>
          <strong>Issued:</strong> ${new Date(cred.issuanceDate).toLocaleDateString()}<br>
          <strong>ID:</strong> ${cred.id}
        </div>
        <div class="attributes">
          ${Object.entries(cred.credentialSubject)
            .filter(([key]) => key !== 'id')
            .map(([key, value]) => `<div><strong>${key}:</strong> ${value}</div>`)
            .join('')}
        </div>
        <div class="actions">
          <button onclick="this.createPresentation('${cred.id}')">Create Presentation</button>
          <button onclick="this.createSelectivePresentation('${cred.id}')">Selective Disclosure</button>
        </div>
      </div>
    `).join('');
  }
  
  private bindEvents() {
    // Add global methods for button clicks
    (window as any).createPresentation = async (credentialId: string) => {
      if (!this.wallet) return;
      
      try {
        const presentation = await this.wallet.createVerifiablePresentation([credentialId]);
        this.downloadPresentation(presentation, 'full-presentation.json');
      } catch (error) {
        alert(`Failed to create presentation: ${error.message}`);
      }
    };
    
    (window as any).createSelectivePresentation = async (credentialId: string) => {
      const credential = this.credentials.find(c => c.id === credentialId);
      if (!credential || !this.wallet) return;
      
      // Show attribute selection dialog
      const attributes = Object.keys(credential.credentialSubject).filter(key => key !== 'id');
      const selected = await this.showAttributeSelector(attributes);
      
      if (selected.length > 0) {
        try {
          const presentation = await this.wallet.createSelectiveDisclosurePresentation(
            credentialId,
            selected,
            'selective-disclosure'
          );
          this.downloadPresentation(presentation, 'selective-presentation.json');
        } catch (error) {
          alert(`Failed to create selective presentation: ${error.message}`);
        }
      }
    };
  }
  
  private downloadPresentation(presentation: any, filename: string) {
    const blob = new Blob([JSON.stringify(presentation, null, 2)], {
      type: 'application/json'
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    
    URL.revokeObjectURL(url);
  }
  
  private async showAttributeSelector(attributes: string[]): Promise<string[]> {
    return new Promise((resolve) => {
      const dialog = document.createElement('div');
      dialog.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        z-index: 1000;
        max-width: 400px;
        width: 90%;
      `;
      
      dialog.innerHTML = `
        <h3>Select Attributes to Disclose</h3>
        ${attributes.map(attr => `
          <label style="display: block; margin: 10px 0;">
            <input type="checkbox" value="${attr}" checked>
            ${attr}
          </label>
        `).join('')}
        <div style="margin-top: 20px;">
          <button id="confirm">Create Presentation</button>
          <button id="cancel">Cancel</button>
        </div>
      `;
      
      // Add backdrop
      const backdrop = document.createElement('div');
      backdrop.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.5);
        z-index: 999;
      `;
      
      document.body.appendChild(backdrop);
      document.body.appendChild(dialog);
      
      dialog.querySelector('#confirm')!.addEventListener('click', () => {
        const checkboxes = dialog.querySelectorAll('input[type="checkbox"]:checked') as NodeListOf<HTMLInputElement>;
        const selected = Array.from(checkboxes).map(cb => cb.value);
        
        document.body.removeChild(backdrop);
        document.body.removeChild(dialog);
        resolve(selected);
      });
      
      dialog.querySelector('#cancel')!.addEventListener('click', () => {
        document.body.removeChild(backdrop);
        document.body.removeChild(dialog);
        resolve([]);
      });
    });
  }
}

customElements.define('user-wallet', UserWalletComponent);
```

## Progressive Web App Integration

### Service Worker for Offline Support
```typescript
// sw.js
const CACHE_NAME = 'anon-identity-v1';
const urlsToCache = [
  '/',
  '/dist/browser.js',
  '/manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        // Return cached version or fetch from network
        return response || fetch(event.request);
      })
  );
});

// Handle credential verification offline
self.addEventListener('message', async (event) => {
  if (event.data.type === 'VERIFY_CREDENTIAL') {
    try {
      // Load anon-identity library
      importScripts('/dist/browser.js');
      
      // Perform verification
      const serviceProvider = new ServiceProvider(
        'Offline Verifier',
        event.data.trustedIssuers
      );
      
      const result = await serviceProvider.verifyPresentation(event.data.presentation);
      
      event.ports[0].postMessage({
        type: 'VERIFICATION_RESULT',
        result
      });
    } catch (error) {
      event.ports[0].postMessage({
        type: 'VERIFICATION_ERROR',
        error: error.message
      });
    }
  }
});
```

### PWA Manifest
```json
{
  "name": "Credential Verifier",
  "short_name": "CredVerifier",
  "description": "Verify credentials using anon-identity",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#ffffff",
  "theme_color": "#007bff",
  "icons": [
    {
      "src": "icons/icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "icons/icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}
```

## Framework Integrations

### React Hook
```typescript
import { useState, useEffect } from 'react';
import { ServiceProvider, VerificationResult } from 'anon-identity/browser';

export function useCredentialVerification(trustedIssuers: string[]) {
  const [serviceProvider, setServiceProvider] = useState<ServiceProvider | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    const sp = new ServiceProvider('React App', trustedIssuers);
    setServiceProvider(sp);
    
    return () => {
      sp.destroy();
    };
  }, [trustedIssuers]);
  
  const verifyPresentation = async (presentation: any): Promise<VerificationResult | null> => {
    if (!serviceProvider) return null;
    
    setLoading(true);
    setError(null);
    
    try {
      const result = await serviceProvider.verifyPresentation(presentation);
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      return null;
    } finally {
      setLoading(false);
    }
  };
  
  return {
    verifyPresentation,
    loading,
    error,
    serviceProvider
  };
}

// Usage in React component
function CredentialVerifier() {
  const { verifyPresentation, loading, error } = useCredentialVerification([
    'did:key:z6Mk...'
  ]);
  
  const handleVerify = async (presentation: any) => {
    const result = await verifyPresentation(presentation);
    if (result?.valid) {
      console.log('Verification successful!');
    }
  };
  
  return (
    <div>
      {loading && <p>Verifying...</p>}
      {error && <p>Error: {error}</p>}
      {/* Your UI */}
    </div>
  );
}
```

### Vue Composable
```typescript
import { ref, onUnmounted } from 'vue';
import { ServiceProvider } from 'anon-identity/browser';

export function useServiceProvider(trustedIssuers: string[]) {
  const serviceProvider = ref<ServiceProvider | null>(null);
  const loading = ref(false);
  const error = ref<string | null>(null);
  
  // Initialize service provider
  serviceProvider.value = new ServiceProvider('Vue App', trustedIssuers);
  
  const verifyPresentation = async (presentation: any) => {
    if (!serviceProvider.value) return null;
    
    loading.value = true;
    error.value = null;
    
    try {
      const result = await serviceProvider.value.verifyPresentation(presentation);
      return result;
    } catch (err) {
      error.value = err instanceof Error ? err.message : 'Unknown error';
      return null;
    } finally {
      loading.value = false;
    }
  };
  
  // Cleanup
  onUnmounted(() => {
    serviceProvider.value?.destroy();
  });
  
  return {
    serviceProvider: serviceProvider.value,
    verifyPresentation,
    loading,
    error
  };
}
```

## Browser Security Considerations

### Content Security Policy
```html
<meta http-equiv="Content-Security-Policy" content="
  default-src 'self';
  script-src 'self' 'unsafe-eval';
  worker-src 'self' blob:;
  connect-src 'self' wss: https:;
  img-src 'self' data: blob:;
">
```

### Secure Storage
```typescript
class SecureBrowserStorage {
  private async getEncryptionKey(): Promise<CryptoKey> {
    // Use Web Crypto API to derive key from user password
    const password = prompt('Enter wallet password:');
    if (!password) throw new Error('Password required');
    
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('anon-identity-salt'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }
  
  async storeSecurely(key: string, data: any): Promise<void> {
    const encryptionKey = await this.getEncryptionKey();
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      encryptionKey,
      encoder.encode(JSON.stringify(data))
    );
    
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    localStorage.setItem(key, btoa(String.fromCharCode(...combined)));
  }
  
  async retrieveSecurely(key: string): Promise<any> {
    const stored = localStorage.getItem(key);
    if (!stored) return null;
    
    const encryptionKey = await this.getEncryptionKey();
    const combined = new Uint8Array(
      atob(stored).split('').map(char => char.charCodeAt(0))
    );
    
    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      encryptionKey,
      encrypted
    );
    
    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted));
  }
}
```

## Performance in Browser

### Web Workers for Heavy Operations
```typescript
// crypto-worker.js
importScripts('/dist/browser.js');

self.onmessage = async function(e) {
  const { type, data, id } = e.data;
  
  try {
    switch (type) {
      case 'VERIFY_BATCH':
        const serviceProvider = new ServiceProvider(data.serviceName, data.trustedIssuers);
        const results = await serviceProvider.batchVerifyPresentations(data.presentations);
        
        self.postMessage({
          type: 'BATCH_RESULT',
          id,
          results
        });
        break;
        
      case 'GENERATE_KEYS':
        const keyPair = await CryptoService.generateKeyPair();
        
        self.postMessage({
          type: 'KEYS_GENERATED',
          id,
          keyPair: {
            publicKey: Array.from(keyPair.publicKey),
            privateKey: Array.from(keyPair.privateKey)
          }
        });
        break;
    }
  } catch (error) {
    self.postMessage({
      type: 'ERROR',
      id,
      error: error.message
    });
  }
};

// Main thread usage
class WorkerCrypto {
  private worker: Worker;
  private pendingRequests = new Map<number, { resolve: Function; reject: Function }>();
  private requestId = 0;
  
  constructor() {
    this.worker = new Worker('/crypto-worker.js');
    this.worker.onmessage = this.handleWorkerMessage.bind(this);
  }
  
  async batchVerify(presentations: any[], serviceName: string, trustedIssuers: string[]) {
    return this.sendToWorker('VERIFY_BATCH', {
      presentations,
      serviceName,
      trustedIssuers
    });
  }
  
  async generateKeys() {
    const result = await this.sendToWorker('GENERATE_KEYS', {});
    return {
      publicKey: new Uint8Array(result.keyPair.publicKey),
      privateKey: new Uint8Array(result.keyPair.privateKey)
    };
  }
  
  private sendToWorker(type: string, data: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = this.requestId++;
      this.pendingRequests.set(id, { resolve, reject });
      this.worker.postMessage({ type, data, id });
    });
  }
  
  private handleWorkerMessage(e: MessageEvent) {
    const { type, id, results, error } = e.data;
    const request = this.pendingRequests.get(id);
    
    if (!request) return;
    
    this.pendingRequests.delete(id);
    
    if (type === 'ERROR') {
      request.reject(new Error(error));
    } else {
      request.resolve(results);
    }
  }
}
```

This browser integration guide provides comprehensive patterns for deploying anon-identity in web applications with security, performance, and user experience considerations.