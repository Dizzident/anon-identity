import { StatusList2021, StatusList2021StatusChecker, CompositeStatusChecker } from './credential-status';
import { CredentialStatusType } from '../types/vc2';
import { CryptoService } from '../core/crypto';
import { DIDService } from '../core/did';

describe('Credential Status', () => {
  describe('StatusList2021', () => {
    it('should set and get status correctly', () => {
      const list = new StatusList2021(1000);
      
      // Initially all should be false
      expect(list.getStatus(0)).toBe(false);
      expect(list.getStatus(999)).toBe(false);
      
      // Set some statuses
      list.setStatus(42, true);
      list.setStatus(100, true);
      list.setStatus(999, true);
      
      // Check they are set
      expect(list.getStatus(42)).toBe(true);
      expect(list.getStatus(100)).toBe(true);
      expect(list.getStatus(999)).toBe(true);
      
      // Others should still be false
      expect(list.getStatus(41)).toBe(false);
      expect(list.getStatus(43)).toBe(false);
      
      // Can unset status
      list.setStatus(42, false);
      expect(list.getStatus(42)).toBe(false);
    });
    
    it('should encode and decode correctly', () => {
      const list = new StatusList2021(1000);
      
      // Set some statuses
      list.setStatus(0, true);
      list.setStatus(7, true);
      list.setStatus(8, true);
      list.setStatus(15, true);
      list.setStatus(999, true);
      
      // Encode
      const encoded = list.encode();
      expect(typeof encoded).toBe('string');
      
      // Decode
      const decoded = StatusList2021.decode(encoded, 1000);
      
      // Check statuses match
      expect(decoded.getStatus(0)).toBe(true);
      expect(decoded.getStatus(7)).toBe(true);
      expect(decoded.getStatus(8)).toBe(true);
      expect(decoded.getStatus(15)).toBe(true);
      expect(decoded.getStatus(999)).toBe(true);
      expect(decoded.getStatus(1)).toBe(false);
      expect(decoded.getStatus(500)).toBe(false);
    });
    
    it('should throw on out of bounds access', () => {
      const list = new StatusList2021(100);
      
      expect(() => list.setStatus(-1, true)).toThrow('Index -1 out of bounds');
      expect(() => list.setStatus(100, true)).toThrow('Index 100 out of bounds');
      expect(() => list.getStatus(-1)).toThrow('Index -1 out of bounds');
      expect(() => list.getStatus(100)).toThrow('Index 100 out of bounds');
    });
    
    it('should create a signed status list credential', async () => {
      const keyPair = await CryptoService.generateKeyPair();
      const did = DIDService.createDIDKey(keyPair.publicKey);
      const list = new StatusList2021(1000);
      
      // Set some revoked credentials
      list.setStatus(10, true);
      list.setStatus(20, true);
      
      const credential = await list.createStatusListCredential(
        did,
        keyPair.privateKey,
        'https://example.com/status/1'
      );
      
      expect(credential['@context']).toContain('https://www.w3.org/ns/credentials/v2');
      expect(credential['@context']).toContain('https://w3id.org/vc/status-list/2021/v1');
      expect(credential.type).toContain('StatusList2021Credential');
      expect(credential.credentialSubject.type).toBe('StatusList2021');
      expect(credential.credentialSubject.statusPurpose).toBe('revocation');
      expect(credential.credentialSubject.encodedList).toBe(list.encode());
      expect(credential.proof).toBeDefined();
      expect(credential.proof.jws).toBeDefined();
    });
  });
  
  describe('StatusList2021StatusChecker', () => {
    it('should check status correctly', async () => {
      const checker = new StatusList2021StatusChecker();
      const list = new StatusList2021(1000);
      
      // Set some statuses
      list.setStatus(42, true);
      list.setStatus(100, true);
      
      // Add the list to checker
      checker.addStatusList('https://example.com/status/1', list);
      
      // Check revoked credential
      const result1 = await checker.checkStatus('cred1', {
        id: 'https://example.com/status/1#42',
        type: CredentialStatusType.STATUS_LIST_2021,
        statusListIndex: 42
      });
      
      expect(result1.revoked).toBe(true);
      expect(result1.statusListIndex).toBe(42);
      
      // Check non-revoked credential
      const result2 = await checker.checkStatus('cred2', {
        id: 'https://example.com/status/1#43',
        type: CredentialStatusType.STATUS_LIST_2021,
        statusListIndex: 43
      });
      
      expect(result2.revoked).toBe(false);
      expect(result2.statusListIndex).toBe(43);
    });
    
    it('should return not revoked for missing list', async () => {
      const checker = new StatusList2021StatusChecker();
      
      const result = await checker.checkStatus('cred1', {
        id: 'https://example.com/status/unknown#42',
        type: CredentialStatusType.STATUS_LIST_2021,
        statusListIndex: 42
      });
      
      expect(result.revoked).toBe(false);
    });
  });
  
  describe('CompositeStatusChecker', () => {
    it('should route to correct checker based on type', async () => {
      const checker = new CompositeStatusChecker();
      
      // Add a StatusList2021
      const list = new StatusList2021(1000);
      list.setStatus(42, true);
      (checker as any).checkers.get('StatusList2021').addStatusList('https://example.com/status/1', list);
      
      // Check with StatusList2021
      const result1 = await checker.checkStatus('cred1', {
        id: 'https://example.com/status/1#42',
        type: CredentialStatusType.STATUS_LIST_2021,
        statusListIndex: 42
      });
      
      expect(result1.revoked).toBe(true);
      
      // Check with RevocationList2020 (should work but return false as no list loaded)
      const result2 = await checker.checkStatus('cred2', {
        id: 'https://example.com/revocation/1',
        type: CredentialStatusType.REVOCATION_LIST_2020
      });
      
      expect(result2.revoked).toBe(false);
    });
    
    it('should throw for unsupported status type', async () => {
      const checker = new CompositeStatusChecker();
      
      await expect(checker.checkStatus('cred1', {
        id: 'https://example.com/status/1',
        type: 'UnsupportedStatusType' as any
      })).rejects.toThrow('No status checker registered for type: UnsupportedStatusType');
    });
  });
});