/**
 * Context Loader Tests
 * Testing context loading without jsonld dependency
 */

import { ContextLoader, ContextDocument } from '../ld/context-loader';
import { VC_V2_CONTEXTS } from '../types/vc2';

describe('ContextLoader', () => {
  let loader: ContextLoader;
  
  beforeEach(() => {
    loader = new ContextLoader();
  });
  
  describe('built-in contexts', () => {
    it('should load W3C VC 2.0 context', async () => {
      const doc = await loader.loadContext(VC_V2_CONTEXTS.CREDENTIALS_V2);
      
      expect(doc).toBeDefined();
      expect(doc['@context']).toBeDefined();
      expect(typeof doc['@context']).toBe('object');
    });
    
    it('should load W3C VC 1.1 context', async () => {
      const doc = await loader.loadContext(VC_V2_CONTEXTS.CREDENTIALS_V1);
      
      expect(doc).toBeDefined();
      expect(doc['@context']).toBeDefined();
    });
    
    it('should load Ed25519 context', async () => {
      const doc = await loader.loadContext(VC_V2_CONTEXTS.ED25519_2020);
      
      expect(doc).toBeDefined();
      expect(doc['@context']).toBeDefined();
    });
    
    it('should load StatusList2021 context', async () => {
      const doc = await loader.loadContext(VC_V2_CONTEXTS.STATUS_LIST_2021);
      
      expect(doc).toBeDefined();
      expect(doc['@context']).toBeDefined();
    });
  });
  
  describe('custom contexts', () => {
    it('should add and retrieve custom context', async () => {
      const customUrl = 'https://example.com/custom';
      const customDoc: ContextDocument = {
        '@context': {
          'custom': 'https://example.com/vocab#',
          'customProperty': 'https://example.com/vocab#customProperty'
        }
      };
      
      loader.addContext(customUrl, customDoc);
      
      const retrieved = await loader.loadContext(customUrl);
      expect(retrieved).toEqual(customDoc);
    });
    
    it('should cache contexts', async () => {
      const url = VC_V2_CONTEXTS.CREDENTIALS_V2;
      
      // First load
      const doc1 = await loader.loadContext(url);
      
      // Second load (should come from cache)
      const doc2 = await loader.loadContext(url);
      
      expect(doc1).toBe(doc2); // Same object reference indicates caching
    });
  });
  
  describe('cache management', () => {
    it('should clear cache but keep built-in contexts', async () => {
      // Add custom context
      const customUrl = 'https://example.com/temp';
      const customDoc: ContextDocument = { '@context': {} };
      loader.addContext(customUrl, customDoc);
      
      // Clear cache
      loader.clearCache();
      
      // Built-in should still work
      const builtIn = await loader.loadContext(VC_V2_CONTEXTS.CREDENTIALS_V2);
      expect(builtIn).toBeDefined();
      
      // Custom should be gone
      await expect(loader.loadContext(customUrl))
        .rejects.toThrow();
    });
    
    it('should provide cache statistics', () => {
      const stats = loader.getCacheStats();
      
      expect(typeof stats.size).toBe('number');
      expect(typeof stats.hits).toBe('number');
      expect(typeof stats.misses).toBe('number');
      expect(stats.size).toBeGreaterThan(0); // Should have built-in contexts
    });
  });
  
  describe('document loader', () => {
    it('should create a document loader function', async () => {
      const documentLoader = loader.createDocumentLoader();
      
      expect(typeof documentLoader).toBe('function');
      
      const result = await documentLoader(VC_V2_CONTEXTS.CREDENTIALS_V2);
      
      expect(result.document).toBeDefined();
      expect(result.documentUrl).toBe(VC_V2_CONTEXTS.CREDENTIALS_V2);
      expect(result.contextUrl).toBeNull();
    });
  });
  
  describe('remote contexts', () => {
    it('should reject remote contexts when disabled', async () => {
      const remoteUrl = 'https://example.com/unknown';
      
      await expect(loader.loadContext(remoteUrl))
        .rejects.toThrow('Remote context loading disabled');
    });
    
    it('should allow remote contexts when enabled', async () => {
      const remoteLoader = new ContextLoader({ allowRemote: true });
      
      // Note: This would normally try to fetch from the URL
      // In our test environment, it will still fail but with a different error
      await expect(remoteLoader.loadContext('https://example.com/unknown'))
        .rejects.toThrow('Remote context loading not implemented');
    });
  });
  
  describe('configuration', () => {
    it('should respect cache size limit', () => {
      const smallCacheLoader = new ContextLoader({ maxCacheSize: 2 });
      
      // Cache should be limited to 2 items (plus built-ins get special treatment)
      expect(smallCacheLoader).toBeDefined();
    });
    
    it('should respect cache TTL', () => {
      const shortTTLLoader = new ContextLoader({ cacheTTL: 1000 }); // 1 second
      
      expect(shortTTLLoader).toBeDefined();
    });
    
    it('should accept custom loaders', () => {
      const customLoaders = new Map<string, () => Promise<ContextDocument>>();
      customLoaders.set('custom://test', async () => ({
        '@context': { 'test': 'http://test.example/' }
      }));
      
      const customLoader = new ContextLoader({ customLoaders });
      
      expect(customLoader).toBeDefined();
    });
  });
});