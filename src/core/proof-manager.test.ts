import { ProofManager } from './proof-manager';
import { Proof, ProofPurpose } from '../types/vc2';

describe('ProofManager', () => {
  const mockProof1: Proof = {
    type: 'Ed25519Signature2020',
    created: '2024-01-01T00:00:00Z',
    verificationMethod: 'did:key:z6Mk1#key-1',
    proofPurpose: ProofPurpose.ASSERTION_METHOD,
    jws: 'mock-jws-1'
  };
  
  const mockProof2: Proof = {
    type: 'Ed25519Signature2020',
    created: '2024-01-02T00:00:00Z',
    verificationMethod: 'did:key:z6Mk2#key-1',
    proofPurpose: ProofPurpose.AUTHENTICATION,
    jws: 'mock-jws-2'
  };
  
  const mockProof3: Proof = {
    type: 'BbsBlsSignature2020',
    created: '2024-01-03T00:00:00Z',
    verificationMethod: 'did:key:z6Mk3#key-1',
    proofPurpose: ProofPurpose.ASSERTION_METHOD,
    proofValue: 'mock-proof-value'
  };
  
  describe('addProof', () => {
    it('should add first proof as single proof', () => {
      const doc: { id: string; proof?: any } = { id: 'test-doc' };
      const result = ProofManager.addProof(doc, mockProof1);
      
      expect(result.proof).toEqual(mockProof1);
      expect(Array.isArray(result.proof)).toBe(false);
    });
    
    it('should convert single proof to array when adding second proof', () => {
      const doc = { id: 'test-doc', proof: mockProof1 };
      const result = ProofManager.addProof(doc, mockProof2);
      
      expect(Array.isArray(result.proof)).toBe(true);
      expect(result.proof).toHaveLength(2);
      expect(result.proof).toEqual([mockProof1, mockProof2]);
    });
    
    it('should append to existing array', () => {
      const doc = { id: 'test-doc', proof: [mockProof1, mockProof2] };
      const result = ProofManager.addProof(doc, mockProof3);
      
      expect(Array.isArray(result.proof)).toBe(true);
      expect(result.proof).toHaveLength(3);
      expect(result.proof).toEqual([mockProof1, mockProof2, mockProof3]);
    });
  });
  
  describe('getProofs', () => {
    it('should return empty array for no proofs', () => {
      const doc: { id: string; proof?: any } = { id: 'test-doc' };
      const proofs = ProofManager.getProofs(doc);
      
      expect(proofs).toEqual([]);
    });
    
    it('should return array with single proof', () => {
      const doc = { id: 'test-doc', proof: mockProof1 };
      const proofs = ProofManager.getProofs(doc);
      
      expect(proofs).toEqual([mockProof1]);
    });
    
    it('should return array as-is', () => {
      const doc = { id: 'test-doc', proof: [mockProof1, mockProof2] };
      const proofs = ProofManager.getProofs(doc);
      
      expect(proofs).toEqual([mockProof1, mockProof2]);
    });
  });
  
  describe('findProofsByPurpose', () => {
    it('should find proofs by purpose', () => {
      const doc = { proof: [mockProof1, mockProof2, mockProof3] };
      
      const assertionProofs = ProofManager.findProofsByPurpose(doc, ProofPurpose.ASSERTION_METHOD);
      expect(assertionProofs).toHaveLength(2);
      expect(assertionProofs).toEqual([mockProof1, mockProof3]);
      
      const authProofs = ProofManager.findProofsByPurpose(doc, ProofPurpose.AUTHENTICATION);
      expect(authProofs).toHaveLength(1);
      expect(authProofs).toEqual([mockProof2]);
    });
  });
  
  describe('findProofsByType', () => {
    it('should find proofs by type', () => {
      const doc = { proof: [mockProof1, mockProof2, mockProof3] };
      
      const ed25519Proofs = ProofManager.findProofsByType(doc, 'Ed25519Signature2020');
      expect(ed25519Proofs).toHaveLength(2);
      expect(ed25519Proofs).toEqual([mockProof1, mockProof2]);
      
      const bbsProofs = ProofManager.findProofsByType(doc, 'BbsBlsSignature2020');
      expect(bbsProofs).toHaveLength(1);
      expect(bbsProofs).toEqual([mockProof3]);
    });
  });
  
  describe('validateProofChain', () => {
    it('should validate single proof', () => {
      const result = ProofManager.validateProofChain([mockProof1]);
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });
    
    it('should validate correctly ordered proofs', () => {
      const result = ProofManager.validateProofChain([mockProof1, mockProof2, mockProof3]);
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });
    
    it('should detect out-of-order proofs', () => {
      const result = ProofManager.validateProofChain([mockProof3, mockProof1, mockProof2]);
      expect(result.valid).toBe(true); // They get sorted, so still valid
    });
    
    it('should handle missing timestamps', () => {
      const proofNoTime = { ...mockProof1, created: undefined };
      const result = ProofManager.validateProofChain([proofNoTime, mockProof2]);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Proof 1 is missing created timestamp');
    });
  });
  
  describe('removeExpiredProofs', () => {
    it('should keep non-expired proofs', () => {
      const futureProof: Proof = {
        ...mockProof1,
        expires: '2030-01-01T00:00:00Z'
      };
      const doc = { proof: futureProof };
      
      const result = ProofManager.removeExpiredProofs(doc);
      expect(result.proof).toEqual(futureProof);
    });
    
    it('should remove expired proofs', () => {
      const expiredProof: Proof = {
        ...mockProof1,
        expires: '2020-01-01T00:00:00Z'
      };
      const doc = { proof: expiredProof };
      
      const result = ProofManager.removeExpiredProofs(doc);
      expect(result.proof).toBeUndefined();
    });
    
    it('should handle mixed expired and valid proofs', () => {
      const expiredProof: Proof = {
        ...mockProof1,
        expires: '2020-01-01T00:00:00Z'
      };
      const validProof: Proof = {
        ...mockProof2,
        expires: '2030-01-01T00:00:00Z'
      };
      const doc = { proof: [expiredProof, validProof, mockProof3] };
      
      const result = ProofManager.removeExpiredProofs(doc);
      expect(Array.isArray(result.proof)).toBe(true);
      expect(result.proof).toHaveLength(2);
      expect(result.proof).toEqual([validProof, mockProof3]);
    });
  });
  
  describe('hasValidProofForPurpose', () => {
    it('should find proof with correct purpose', () => {
      const doc = { proof: [mockProof1, mockProof2] };
      
      expect(ProofManager.hasValidProofForPurpose(doc, ProofPurpose.ASSERTION_METHOD)).toBe(true);
      expect(ProofManager.hasValidProofForPurpose(doc, ProofPurpose.AUTHENTICATION)).toBe(true);
      expect(ProofManager.hasValidProofForPurpose(doc, ProofPurpose.KEY_AGREEMENT)).toBe(false);
    });
    
    it('should check verifier DIDs if provided', () => {
      const doc = { proof: [mockProof1, mockProof2] };
      
      // Should find proof from did:key:z6Mk1
      expect(ProofManager.hasValidProofForPurpose(
        doc, 
        ProofPurpose.ASSERTION_METHOD,
        ['did:key:z6Mk1', 'did:key:z6Mk9']
      )).toBe(true);
      
      // Should not find proof from did:key:z6Mk9
      expect(ProofManager.hasValidProofForPurpose(
        doc, 
        ProofPurpose.ASSERTION_METHOD,
        ['did:key:z6Mk9']
      )).toBe(false);
    });
  });
});