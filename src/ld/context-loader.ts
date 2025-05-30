import { VC_V2_CONTEXTS } from '../types/vc2';

// Simple cache implementation to avoid LRUCache type issues
interface CacheEntry {
  document: ContextDocument;
  expires: number;
}

class SimpleCache {
  private cache = new Map<string, CacheEntry>();
  private maxSize: number;
  private ttl: number;
  private hits = 0;
  private misses = 0;

  constructor(maxSize = 100, ttl = 3600000) {
    this.maxSize = maxSize;
    this.ttl = ttl;
  }

  get(key: string): ContextDocument | undefined {
    const entry = this.cache.get(key);
    if (entry && entry.expires > Date.now()) {
      this.hits++;
      return entry.document;
    }
    if (entry) {
      this.cache.delete(key);
    }
    this.misses++;
    return undefined;
  }

  set(key: string, value: ContextDocument): void {
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, {
      document: value,
      expires: Date.now() + this.ttl
    });
  }

  delete(key: string): void {
    this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }

  getStats(): { size: number; hits: number; misses: number } {
    return {
      size: this.cache.size,
      hits: this.hits,
      misses: this.misses
    };
  }
}

/**
 * Context document type
 */
export interface ContextDocument {
  '@context': any;
  [key: string]: any;
}

/**
 * Context loader configuration
 */
export interface ContextLoaderOptions {
  // Maximum number of contexts to cache
  maxCacheSize?: number;
  // Cache TTL in milliseconds
  cacheTTL?: number;
  // Custom document loaders for specific URLs
  customLoaders?: Map<string, () => Promise<ContextDocument>>;
  // Whether to allow remote context loading
  allowRemote?: boolean;
}

/**
 * Built-in contexts that are always available
 */
const BUILT_IN_CONTEXTS: Map<string, ContextDocument> = new Map([
  [VC_V2_CONTEXTS.CREDENTIALS_V2, {
    '@context': {
      '@version': 1.1,
      '@protected': true,
      'id': '@id',
      'type': '@type',
      'VerifiableCredential': {
        '@id': 'https://www.w3.org/2018/credentials#VerifiableCredential',
        '@context': {
          '@version': 1.1,
          '@protected': true,
          'id': '@id',
          'type': '@type',
          'credentialSchema': {
            '@id': 'https://www.w3.org/2018/credentials#credentialSchema',
            '@type': '@id'
          },
          'credentialStatus': {
            '@id': 'https://www.w3.org/2018/credentials#credentialStatus',
            '@type': '@id'
          },
          'credentialSubject': {
            '@id': 'https://www.w3.org/2018/credentials#credentialSubject',
            '@type': '@id'
          },
          'evidence': {
            '@id': 'https://www.w3.org/2018/credentials#evidence',
            '@type': '@id'
          },
          'issuer': {
            '@id': 'https://www.w3.org/2018/credentials#issuer',
            '@type': '@id'
          },
          'refreshService': {
            '@id': 'https://www.w3.org/2018/credentials#refreshService',
            '@type': '@id'
          },
          'termsOfUse': {
            '@id': 'https://www.w3.org/2018/credentials#termsOfUse',
            '@type': '@id'
          },
          'validFrom': {
            '@id': 'https://www.w3.org/2018/credentials#validFrom',
            '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
          },
          'validUntil': {
            '@id': 'https://www.w3.org/2018/credentials#validUntil',
            '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
          },
          'proof': {
            '@id': 'https://w3id.org/security#proof',
            '@type': '@id',
            '@container': '@graph'
          }
        }
      }
    }
  }],
  [VC_V2_CONTEXTS.CREDENTIALS_V1, {
    '@context': {
      '@version': 1.1,
      'id': '@id',
      'type': '@type',
      'VerifiableCredential': {
        '@id': 'https://www.w3.org/2018/credentials#VerifiableCredential'
      },
      'VerifiablePresentation': {
        '@id': 'https://www.w3.org/2018/credentials#VerifiablePresentation'
      },
      'credentialSubject': {
        '@id': 'https://www.w3.org/2018/credentials#credentialSubject',
        '@type': '@id'
      },
      'issuer': {
        '@id': 'https://www.w3.org/2018/credentials#issuer',
        '@type': '@id'
      },
      'issuanceDate': {
        '@id': 'https://www.w3.org/2018/credentials#issuanceDate',
        '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
      },
      'expirationDate': {
        '@id': 'https://www.w3.org/2018/credentials#expirationDate',
        '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
      },
      'proof': {
        '@id': 'https://w3id.org/security#proof',
        '@type': '@id',
        '@container': '@graph'
      }
    }
  }],
  [VC_V2_CONTEXTS.ED25519_2020, {
    '@context': {
      'id': '@id',
      'type': '@type',
      '@protected': true,
      'Ed25519Signature2020': {
        '@id': 'https://w3id.org/security#Ed25519Signature2020',
        '@context': {
          '@protected': true,
          'id': '@id',
          'type': '@type',
          'challenge': 'https://w3id.org/security#challenge',
          'created': {
            '@id': 'http://purl.org/dc/terms/created',
            '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
          },
          'domain': 'https://w3id.org/security#domain',
          'expires': {
            '@id': 'https://w3id.org/security#expiration',
            '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
          },
          'nonce': 'https://w3id.org/security#nonce',
          'proofPurpose': {
            '@id': 'https://w3id.org/security#proofPurpose',
            '@type': '@vocab'
          },
          'proofValue': {
            '@id': 'https://w3id.org/security#proofValue'
          },
          'verificationMethod': {
            '@id': 'https://w3id.org/security#verificationMethod',
            '@type': '@id'
          }
        }
      },
      'Ed25519VerificationKey2020': {
        '@id': 'https://w3id.org/security#Ed25519VerificationKey2020'
      },
      'publicKeyMultibase': {
        '@id': 'https://w3id.org/security#publicKeyMultibase'
      }
    }
  }],
  [VC_V2_CONTEXTS.STATUS_LIST_2021, {
    '@context': {
      '@protected': true,
      'StatusList2021Credential': {
        '@id': 'https://w3id.org/vc/status-list#StatusList2021Credential'
      },
      'StatusList2021': {
        '@id': 'https://w3id.org/vc/status-list#StatusList2021'
      },
      'StatusList2021Entry': {
        '@id': 'https://w3id.org/vc/status-list#StatusList2021Entry',
        '@context': {
          '@protected': true,
          'id': '@id',
          'type': '@type',
          'statusPurpose': {
            '@id': 'https://w3id.org/vc/status-list#statusPurpose'
          },
          'statusListIndex': {
            '@id': 'https://w3id.org/vc/status-list#statusListIndex'
          },
          'statusListCredential': {
            '@id': 'https://w3id.org/vc/status-list#statusListCredential',
            '@type': '@id'
          }
        }
      },
      'statusPurpose': {
        '@id': 'https://w3id.org/vc/status-list#statusPurpose'
      },
      'encodedList': {
        '@id': 'https://w3id.org/vc/status-list#encodedList'
      }
    }
  }]
]);

/**
 * JSON-LD Context Loader with caching
 */
export class ContextLoader {
  private cache: SimpleCache;
  private customLoaders: Map<string, () => Promise<ContextDocument>>;
  private allowRemote: boolean;
  
  constructor(options: ContextLoaderOptions = {}) {
    this.cache = new SimpleCache(
      options.maxCacheSize || 100,
      options.cacheTTL || 3600000 // 1 hour default
    );
    
    this.customLoaders = options.customLoaders || new Map();
    this.allowRemote = options.allowRemote ?? false;
    
    // Pre-populate cache with built-in contexts
    for (const [url, doc] of BUILT_IN_CONTEXTS) {
      this.cache.set(url, doc);
    }
  }
  
  /**
   * Load a context document by URL
   */
  async loadContext(url: string): Promise<ContextDocument> {
    // Check if it's a built-in context
    const builtIn = BUILT_IN_CONTEXTS.get(url);
    if (builtIn) {
      return builtIn;
    }
    
    // Try to get from cache
    const cached = this.cache.get(url);
    if (cached) {
      return cached;
    }
    
    // Fetch and cache if not found
    try {
      const document = await this.fetchContext(url);
      this.cache.set(url, document);
      return document;
    } catch (error) {
      throw new Error(`Failed to load context: ${url} - ${error}`);
    }
  }
  
  /**
   * Fetch a context document
   */
  private async fetchContext(url: string): Promise<ContextDocument> {
    // Check custom loaders first
    const customLoader = this.customLoaders.get(url);
    if (customLoader) {
      return await customLoader();
    }
    
    // Check if remote loading is allowed
    if (!this.allowRemote) {
      throw new Error(`Remote context loading disabled for: ${url}`);
    }
    
    // In a real implementation, this would fetch from the URL
    // For now, we'll throw an error
    throw new Error(`Remote context loading not implemented for: ${url}`);
  }
  
  /**
   * Add a custom context
   */
  addContext(url: string, document: ContextDocument): void {
    this.cache.set(url, document);
  }
  
  /**
   * Clear the context cache
   */
  clearCache(): void {
    this.cache.clear();
    
    // Re-populate with built-in contexts
    for (const [url, doc] of BUILT_IN_CONTEXTS) {
      this.cache.set(url, doc);
    }
  }
  
  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; hits: number; misses: number } {
    return this.cache.getStats();
  }
  
  /**
   * Create a document loader function for jsonld library
   */
  createDocumentLoader(): (url: string) => Promise<any> {
    return async (url: string) => {
      try {
        const doc = await this.loadContext(url);
        return {
          contextUrl: null,
          document: doc,
          documentUrl: url
        };
      } catch (error) {
        throw new Error(`Error loading document ${url}: ${error}`);
      }
    };
  }
}

// Default instance
export const defaultContextLoader = new ContextLoader();