import { DIDService } from './did';
import { CryptoService } from './crypto';

describe('DIDService', () => {
  describe('createDIDKey', () => {
    it('should create a valid did:key from public key', async () => {
      const keyPair = await CryptoService.generateKeyPair();
      const did = DIDService.createDIDKey(keyPair.publicKey);
      
      expect(did.id).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
      expect(did.publicKey).toEqual(keyPair.publicKey);
    });
    
    it('should create consistent DIDs for the same public key', async () => {
      const keyPair = await CryptoService.generateKeyPair();
      const did1 = DIDService.createDIDKey(keyPair.publicKey);
      const did2 = DIDService.createDIDKey(keyPair.publicKey);
      
      expect(did1.id).toBe(did2.id);
    });
  });
  
  describe('getPublicKeyFromDID', () => {
    it('should extract public key from did:key', async () => {
      const keyPair = await CryptoService.generateKeyPair();
      const did = DIDService.createDIDKey(keyPair.publicKey);
      
      const extractedPublicKey = DIDService.getPublicKeyFromDID(did.id);
      
      expect(extractedPublicKey).toEqual(keyPair.publicKey);
    });
    
    it('should throw error for invalid DID format', () => {
      expect(() => {
        DIDService.getPublicKeyFromDID('did:invalid:123');
      }).toThrow('Invalid did:key format');
    });
  });
  
  describe('createDIDDocument', () => {
    it('should create a valid DID document', async () => {
      const keyPair = await CryptoService.generateKeyPair();
      const did = DIDService.createDIDKey(keyPair.publicKey);
      
      const didDocument = await DIDService.createDIDDocument(did);
      
      expect(didDocument['@context']).toContain('https://www.w3.org/ns/did/v1');
      expect(didDocument.id).toBe(did.id);
      expect(didDocument.verificationMethod).toHaveLength(1);
      expect(didDocument.verificationMethod[0].type).toBe('Ed25519VerificationKey2020');
      expect(didDocument.authentication).toContain(`${did.id}#key-1`);
      expect(didDocument.assertionMethod).toContain(`${did.id}#key-1`);
    });
  });
});