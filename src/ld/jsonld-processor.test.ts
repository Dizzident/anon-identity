import { JsonLdProcessor } from './jsonld-processor';
import { ContextLoader } from './context-loader';
import { VC_V2_CONTEXTS, VerifiableCredentialV2 } from '../types/vc2';

describe('JsonLdProcessor', () => {
  let processor: JsonLdProcessor;
  let contextLoader: ContextLoader;
  
  beforeEach(() => {
    contextLoader = new ContextLoader();
    processor = new JsonLdProcessor({ contextLoader });
  });
  
  describe('expand', () => {
    it('should expand a simple JSON-LD document', async () => {
      const doc = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        'type': 'VerifiableCredential',
        'issuer': 'did:example:123'
      };
      
      const expanded = await processor.expand(doc);
      
      expect(Array.isArray(expanded)).toBe(true);
      expect(expanded.length).toBe(1);
      expect(expanded[0]['@type']).toContain('https://www.w3.org/2018/credentials#VerifiableCredential');
      expect(expanded[0]['https://www.w3.org/2018/credentials#issuer']).toBeDefined();
    });
    
    it('should handle multiple contexts', async () => {
      const doc = {
        '@context': [
          'https://www.w3.org/ns/credentials/v2',
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        'type': 'VerifiableCredential',
        'proof': {
          'type': 'Ed25519Signature2020'
        }
      };
      
      const expanded = await processor.expand(doc);
      
      expect(expanded[0]['https://w3id.org/security#proof']).toBeDefined();
    });
  });
  
  describe('compact', () => {
    it('should compact an expanded document', async () => {
      const expanded = [{
        '@type': ['https://www.w3.org/2018/credentials#VerifiableCredential'],
        'https://www.w3.org/2018/credentials#issuer': [{
          '@id': 'did:example:123'
        }]
      }];
      
      const context = 'https://www.w3.org/ns/credentials/v2';
      const compacted = await processor.compact(expanded, context);
      
      expect(compacted['@context']).toBe(context);
      expect(compacted.type).toBe('VerifiableCredential');
      expect(compacted.issuer).toBe('did:example:123');
    });
  });
  
  describe('canonicalize', () => {
    it('should canonicalize a document', async () => {
      const doc = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        'issuer': 'did:example:123',
        'type': 'VerifiableCredential',
        'credentialSubject': {
          'name': 'Alice'
        }
      };
      
      const canonical = await processor.canonicalize(doc);
      
      expect(typeof canonical).toBe('string');
      expect(canonical).toContain('VerifiableCredential');
      expect(canonical).toContain('did:example:123');
    });
    
    it('should produce consistent output for equivalent documents', async () => {
      const doc1 = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        'type': 'VerifiableCredential',
        'issuer': 'did:example:123',
        'credentialSubject': { 'name': 'Bob', 'age': 30 }
      };
      
      const doc2 = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        'issuer': 'did:example:123',
        'type': 'VerifiableCredential',
        'credentialSubject': { 'age': 30, 'name': 'Bob' }
      };
      
      const canonical1 = await processor.canonicalize(doc1);
      const canonical2 = await processor.canonicalize(doc2);
      
      expect(canonical1).toBe(canonical2);
    });
  });
  
  describe('validateCredential', () => {
    it('should validate a valid credential', async () => {
      const credential: VerifiableCredentialV2 = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        'type': 'VerifiableCredential',
        'issuer': 'did:example:123',
        'validFrom': '2024-01-01T00:00:00Z',
        'credentialSubject': {
          'id': 'did:example:456',
          'name': 'Alice'
        }
      };
      
      const result = await processor.validateCredential(credential);
      
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });
    
    it('should detect missing context', async () => {
      const credential = {
        'type': 'VerifiableCredential',
        'issuer': 'did:example:123',
        'credentialSubject': {}
      } as any;
      
      const result = await processor.validateCredential(credential);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Missing @context property');
    });
    
    it('should detect missing required properties', async () => {
      const credential: any = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        'type': 'VerifiableCredential'
        // Missing issuer and credentialSubject
      };
      
      const result = await processor.validateCredential(credential);
      
      expect(result.valid).toBe(false);
      expect(result.errors?.some(e => e.includes('issuer'))).toBe(true);
      expect(result.errors?.some(e => e.includes('credentialSubject'))).toBe(true);
    });
  });
  
  describe('extractClaims', () => {
    it('should extract claims from credential', async () => {
      const credential: VerifiableCredentialV2 = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        'type': 'VerifiableCredential',
        'issuer': 'did:example:123',
        'credentialSubject': {
          'id': 'did:example:456',
          'name': 'Alice',
          'age': 25,
          'email': 'alice@example.com'
        }
      };
      
      const claims = await processor.extractClaims(credential);
      
      expect(claims.size).toBeGreaterThan(0);
      expect(claims.has('https://www.w3.org/2018/credentials#credentialSubject')).toBe(true);
    });
    
    it('should handle multiple subjects', async () => {
      const credential: VerifiableCredentialV2 = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        'type': 'VerifiableCredential',
        'issuer': 'did:example:123',
        'credentialSubject': [
          { 'id': 'did:example:456', 'name': 'Alice' },
          { 'id': 'did:example:789', 'name': 'Bob' }
        ]
      };
      
      const claims = await processor.extractClaims(credential);
      
      expect(claims.size).toBeGreaterThan(0);
    });
  });
  
  describe('normalize', () => {
    it('should normalize a document', async () => {
      const doc = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        'type': 'VerifiableCredential',
        'issuer': 'did:example:123',
        'credentialSubject': {
          'name': 'Charlie',
          'age': 35
        }
      };
      
      const normalized = await processor.normalize(doc);
      
      expect(normalized['@context']).toBeDefined();
      expect(normalized.type).toBeDefined();
      expect(normalized.issuer).toBeDefined();
    });
  });
});

describe('ContextLoader', () => {
  let loader: ContextLoader;
  
  beforeEach(() => {
    loader = new ContextLoader();
  });
  
  describe('loadContext', () => {
    it('should load built-in contexts', async () => {
      const contexts = [
        VC_V2_CONTEXTS.CREDENTIALS_V2,
        VC_V2_CONTEXTS.CREDENTIALS_V1,
        VC_V2_CONTEXTS.ED25519_2020,
        VC_V2_CONTEXTS.STATUS_LIST_2021
      ];
      
      for (const url of contexts) {
        const doc = await loader.loadContext(url);
        expect(doc).toBeDefined();
        expect(doc['@context']).toBeDefined();
      }
    });
    
    it('should cache contexts', async () => {
      const url = VC_V2_CONTEXTS.CREDENTIALS_V2;
      
      // First load
      const doc1 = await loader.loadContext(url);
      
      // Second load (should come from cache)
      const doc2 = await loader.loadContext(url);
      
      expect(doc1).toBe(doc2);
    });
    
    it('should throw for unknown contexts when remote disabled', async () => {
      await expect(loader.loadContext('https://example.com/unknown'))
        .rejects.toThrow('Remote context loading disabled');
    });
  });
  
  describe('addContext', () => {
    it('should add custom context', async () => {
      const customUrl = 'https://example.com/custom';
      const customDoc = {
        '@context': {
          'custom': 'https://example.com/custom#'
        }
      };
      
      loader.addContext(customUrl, customDoc);
      
      const loaded = await loader.loadContext(customUrl);
      expect(loaded).toEqual(customDoc);
    });
  });
  
  describe('clearCache', () => {
    it('should clear cache but keep built-in contexts', async () => {
      // Add custom context
      loader.addContext('https://example.com/temp', { '@context': {} });
      
      // Clear cache
      loader.clearCache();
      
      // Built-in should still work
      const builtIn = await loader.loadContext(VC_V2_CONTEXTS.CREDENTIALS_V2);
      expect(builtIn).toBeDefined();
      
      // Custom should be gone
      await expect(loader.loadContext('https://example.com/temp'))
        .rejects.toThrow();
    });
  });
  
  describe('createDocumentLoader', () => {
    it('should create a document loader function', async () => {
      const documentLoader = loader.createDocumentLoader();
      
      const result = await documentLoader(VC_V2_CONTEXTS.CREDENTIALS_V2);
      
      expect(result.document).toBeDefined();
      expect(result.documentUrl).toBe(VC_V2_CONTEXTS.CREDENTIALS_V2);
    });
  });
});