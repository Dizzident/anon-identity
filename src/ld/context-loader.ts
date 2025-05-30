import { LRUCache } from 'lru-cache';
import { VC_V2_CONTEXTS } from '../types/vc2';

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
  private cache: LRUCache<string, ContextDocument>;
  private customLoaders: Map<string, () => Promise<ContextDocument>>;
  private allowRemote: boolean;
  
  constructor(options: ContextLoaderOptions = {}) {
    this.cache = new LRUCache<string, ContextDocument>({
      max: options.maxCacheSize || 100,
      ttl: options.cacheTTL || 3600000, // 1 hour default
      fetchMethod: async (url: string) => this.fetchContext(url)
    });
    
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
    
    // Try to get from cache (will call fetchContext if not found)
    const cached = await this.cache.fetch(url);
    if (cached) {
      return cached;
    }
    
    throw new Error(`Failed to load context: ${url}`);
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
    const stats = this.cache as any;
    return {
      size: this.cache.size,
      hits: stats.hits || 0,
      misses: stats.misses || 0
    };
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