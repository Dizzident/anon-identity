/**
 * Enhanced Standards Compliance Tests
 * Testing the new features without problematic dependencies
 */

import { ProofManager } from '../core/proof-manager';
import { 
  VerifiableCredentialV2, 
  Proof, 
  ProofPurpose, 
  CredentialStatusType,
  VC_V2_CONTEXTS 
} from '../types/vc2';
import { migrateCredentialToV2, createV2Context } from '../utils/vc-migration';
import { VerifiableCredential } from '../types';

describe('Enhanced Standards Compliance', () => {
  describe('W3C VC 2.0 Support', () => {
    it('should migrate VC 1.1 to VC 2.0', () => {
      const vc11: VerifiableCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: 'test-credential',
        type: ['VerifiableCredential'],
        issuer: 'did:example:123',
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:456',
          name: 'Test User'
        }
      };
      
      const vc20 = migrateCredentialToV2(vc11);
      
      expect(vc20['@context']).toContain(VC_V2_CONTEXTS.CREDENTIALS_V2);
      expect(vc20.validFrom).toBe(vc11.issuanceDate);
      expect(vc20.issuanceDate).toBe(vc11.issuanceDate); // Backward compatibility
      expect(vc20.issuer).toBe(vc11.issuer);
      expect(vc20.credentialSubject).toEqual(vc11.credentialSubject);
    });
    
    it('should create V2 context correctly', () => {
      const context = createV2Context({
        ed25519: true,
        statusList: true,
        termsOfUse: true
      });
      
      expect(context).toContain(VC_V2_CONTEXTS.CREDENTIALS_V2);
      expect(context).toContain(VC_V2_CONTEXTS.ED25519_2020);
      expect(context).toContain(VC_V2_CONTEXTS.STATUS_LIST_2021);
      expect(context).toContain(VC_V2_CONTEXTS.TERMS_OF_USE);
    });
    
    it('should validate credential status types', () => {
      expect(CredentialStatusType.STATUS_LIST_2021).toBe('StatusList2021');
      expect(CredentialStatusType.REVOCATION_LIST_2020).toBe('RevocationList2020');
      expect(CredentialStatusType.BITSTRING_STATUS_LIST).toBe('BitstringStatusListEntry');
    });
  });
  
  describe('Multiple Proofs Support', () => {
    const mockProof1: Proof = {
      type: 'Ed25519Signature2020',
      created: '2024-01-01T00:00:00Z',
      verificationMethod: 'did:example:123#key-1',
      proofPurpose: ProofPurpose.ASSERTION_METHOD,
      proofValue: 'mock-proof-1'
    };
    
    const mockProof2: Proof = {
      type: 'Ed25519Signature2020',
      created: '2024-01-02T00:00:00Z',
      verificationMethod: 'did:example:456#key-1',
      proofPurpose: 'endorsement' as ProofPurpose,
      proofValue: 'mock-proof-2'
    };
    
    it('should add multiple proofs to credential', () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:123',
        credentialSubject: { id: 'did:example:456' }
      };
      
      let enhanced = ProofManager.addProof(credential, mockProof1);
      enhanced = ProofManager.addProof(enhanced, mockProof2);
      
      const proofs = ProofManager.getProofs(enhanced);
      expect(proofs).toHaveLength(2);
      expect(proofs[0]).toEqual(mockProof1);
      expect(proofs[1]).toEqual(mockProof2);
    });
    
    it('should find proofs by purpose', () => {
      const doc = { proof: [mockProof1, mockProof2] };
      
      const assertionProofs = ProofManager.findProofsByPurpose(doc, ProofPurpose.ASSERTION_METHOD);
      expect(assertionProofs).toHaveLength(1);
      expect(assertionProofs[0]).toEqual(mockProof1);
      
      const endorsementProofs = ProofManager.findProofsByPurpose(doc, 'endorsement');
      expect(endorsementProofs).toHaveLength(1);
      expect(endorsementProofs[0]).toEqual(mockProof2);
    });
    
    it('should validate proof chain timing', () => {
      const validProofs = [
        { ...mockProof1, created: '2024-01-01T00:00:00Z' },
        { ...mockProof2, created: '2024-01-02T00:00:00Z' }
      ];
      
      const result = ProofManager.validateProofChain(validProofs);
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });
    
    it('should check for valid proof by purpose and verifier', () => {
      const doc = { proof: [mockProof1, mockProof2] };
      
      // Should find proof from correct verifier
      const hasProof = ProofManager.hasValidProofForPurpose(
        doc,
        ProofPurpose.ASSERTION_METHOD,
        ['did:example:123']
      );
      expect(hasProof).toBe(true);
      
      // Should not find proof from wrong verifier
      const noProof = ProofManager.hasValidProofForPurpose(
        doc,
        ProofPurpose.ASSERTION_METHOD,
        ['did:example:999']
      );
      expect(noProof).toBe(false);
    });
  });
  
  describe('Enhanced Credential Features', () => {
    it('should support terms of use structure', () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.TERMS_OF_USE],
        type: 'VerifiableCredential',
        issuer: 'did:example:123',
        credentialSubject: { id: 'did:example:456' },
        termsOfUse: {
          type: 'IssuerPolicy',
          id: 'https://example.com/policies/1',
          prohibition: [{
            assigner: 'did:example:123',
            assignee: 'AllVerifiers',
            target: 'credential-data',
            action: ['Archival', 'ThirdPartySharing']
          }]
        }
      };
      
      expect(credential.termsOfUse).toBeDefined();
      const termsOfUse = Array.isArray(credential.termsOfUse) 
        ? credential.termsOfUse[0] 
        : credential.termsOfUse!;
      expect(termsOfUse.type).toBe('IssuerPolicy');
      expect(Array.isArray(termsOfUse.prohibition)).toBe(true);
    });
    
    it('should support evidence structure', () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:123',
        credentialSubject: { id: 'did:example:456' },
        evidence: {
          type: 'DocumentVerification',
          verifier: 'did:example:verifier',
          evidenceDocument: 'DriversLicense',
          subjectPresence: 'Physical',
          documentPresence: 'Physical'
        }
      };
      
      expect(credential.evidence).toBeDefined();
      const evidence = Array.isArray(credential.evidence) 
        ? credential.evidence[0] 
        : credential.evidence!;
      expect(evidence.type).toBe('DocumentVerification');
      expect(evidence.verifier).toBe('did:example:verifier');
    });
    
    it('should support credential status structure', () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.STATUS_LIST_2021],
        type: 'VerifiableCredential',
        issuer: 'did:example:123',
        credentialSubject: { id: 'did:example:456' },
        credentialStatus: {
          id: 'https://example.com/status/1#42',
          type: CredentialStatusType.STATUS_LIST_2021,
          statusPurpose: 'revocation',
          statusListIndex: 42,
          statusListCredential: 'https://example.com/status/1'
        }
      };
      
      expect(credential.credentialStatus).toBeDefined();
      const status = Array.isArray(credential.credentialStatus) 
        ? credential.credentialStatus[0] 
        : credential.credentialStatus!;
      expect(status.type).toBe(CredentialStatusType.STATUS_LIST_2021);
      expect((status as any).statusListIndex).toBe(42);
    });
  });
  
  describe('Backward Compatibility', () => {
    it('should maintain compatibility with legacy credential structure', () => {
      const legacyCredential: VerifiableCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: 'legacy-credential',
        type: ['VerifiableCredential'],
        issuer: 'did:example:123',
        issuanceDate: '2023-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:456',
          name: 'Legacy User'
        }
      };
      
      // Should be able to migrate without losing data
      const migrated = migrateCredentialToV2(legacyCredential);
      
      expect(migrated.issuer).toBe(legacyCredential.issuer);
      expect(migrated.credentialSubject).toEqual(legacyCredential.credentialSubject);
      expect(migrated.issuanceDate).toBe(legacyCredential.issuanceDate);
      expect(migrated.validFrom).toBe(legacyCredential.issuanceDate);
    });
  });
  
  describe('Type System', () => {
    it('should have correct proof purpose enum values', () => {
      expect(ProofPurpose.ASSERTION_METHOD).toBe('assertionMethod');
      expect(ProofPurpose.AUTHENTICATION).toBe('authentication');
      expect(ProofPurpose.KEY_AGREEMENT).toBe('keyAgreement');
      expect(ProofPurpose.CAPABILITY_INVOCATION).toBe('capabilityInvocation');
      expect(ProofPurpose.CAPABILITY_DELEGATION).toBe('capabilityDelegation');
    });
    
    it('should have correct context URLs', () => {
      expect(VC_V2_CONTEXTS.CREDENTIALS_V2).toBe('https://www.w3.org/ns/credentials/v2');
      expect(VC_V2_CONTEXTS.CREDENTIALS_V1).toBe('https://www.w3.org/2018/credentials/v1');
      expect(VC_V2_CONTEXTS.ED25519_2020).toBe('https://w3id.org/security/suites/ed25519-2020/v1');
      expect(VC_V2_CONTEXTS.BBS_2023).toBe('https://w3id.org/security/bbs/v1');
    });
  });
});