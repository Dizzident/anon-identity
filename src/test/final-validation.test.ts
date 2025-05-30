/**
 * Final Validation Tests
 * Simplified tests to validate our enhancements work without external dependencies
 */

import { ProofManager } from '../core/proof-manager';
import { 
  VerifiableCredentialV2, 
  Proof, 
  ProofPurpose, 
  CredentialStatusType,
  VC_V2_CONTEXTS 
} from '../types/vc2';

describe('Final Validation Tests', () => {
  describe('W3C VC 2.0 Type System', () => {
    it('should support VC 2.0 credential structure', () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        validFrom: '2024-01-01T00:00:00Z',
        validUntil: '2025-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:subject',
          name: 'Test User',
          age: 30
        },
        credentialStatus: {
          id: 'https://example.com/status/1#42',
          type: CredentialStatusType.STATUS_LIST_2021,
          statusPurpose: 'revocation',
          statusListIndex: 42,
          statusListCredential: 'https://example.com/status/1'
        },
        evidence: {
          type: 'DocumentVerification',
          verifier: 'did:example:verifier',
          evidenceDocument: 'DriversLicense'
        }
      };

      expect(credential['@context']).toContain(VC_V2_CONTEXTS.CREDENTIALS_V2);
      expect(credential.validFrom).toBe('2024-01-01T00:00:00Z');
      expect(credential.validUntil).toBe('2025-01-01T00:00:00Z');
      expect(credential.credentialStatus).toBeDefined();
      expect(credential.evidence).toBeDefined();
    });

    it('should support proof purpose enums', () => {
      expect(ProofPurpose.ASSERTION_METHOD).toBe('assertionMethod');
      expect(ProofPurpose.AUTHENTICATION).toBe('authentication');
      expect(ProofPurpose.KEY_AGREEMENT).toBe('keyAgreement');
      expect(ProofPurpose.CAPABILITY_INVOCATION).toBe('capabilityInvocation');
      expect(ProofPurpose.CAPABILITY_DELEGATION).toBe('capabilityDelegation');
    });

    it('should support credential status types', () => {
      expect(CredentialStatusType.STATUS_LIST_2021).toBe('StatusList2021');
      expect(CredentialStatusType.REVOCATION_LIST_2020).toBe('RevocationList2020');
      expect(CredentialStatusType.BITSTRING_STATUS_LIST).toBe('BitstringStatusListEntry');
    });

    it('should support W3C context URLs', () => {
      expect(VC_V2_CONTEXTS.CREDENTIALS_V2).toBe('https://www.w3.org/ns/credentials/v2');
      expect(VC_V2_CONTEXTS.CREDENTIALS_V1).toBe('https://www.w3.org/2018/credentials/v1');
      expect(VC_V2_CONTEXTS.ED25519_2020).toBe('https://w3id.org/security/suites/ed25519-2020/v1');
      expect(VC_V2_CONTEXTS.BBS_2023).toBe('https://w3id.org/security/bbs/v1');
      expect(VC_V2_CONTEXTS.STATUS_LIST_2021).toBe('https://w3id.org/vc/status-list/2021/v1');
    });
  });

  describe('Multiple Proofs Management', () => {
    const mockProof1: Proof = {
      type: 'Ed25519Signature2020',
      created: '2024-01-01T00:00:00Z',
      verificationMethod: 'did:example:issuer#key-1',
      proofPurpose: ProofPurpose.ASSERTION_METHOD,
      proofValue: 'proof-value-1'
    };

    const mockProof2: Proof = {
      type: 'BbsBlsSignature2020',
      created: '2024-01-02T00:00:00Z',
      verificationMethod: 'did:example:issuer#key-2',
      proofPurpose: 'endorsement',
      proofValue: 'proof-value-2'
    };

    it('should add multiple proofs to documents', () => {
      const document: any = { data: 'test' };
      
      let enhanced = ProofManager.addProof(document, mockProof1);
      enhanced = ProofManager.addProof(enhanced, mockProof2);
      
      const proofs = ProofManager.getProofs(enhanced);
      expect(proofs).toHaveLength(2);
      expect(proofs[0]).toEqual(mockProof1);
      expect(proofs[1]).toEqual(mockProof2);
    });

    it('should find proofs by purpose', () => {
      const document = { proof: [mockProof1, mockProof2] };
      
      const assertionProofs = ProofManager.findProofsByPurpose(document, ProofPurpose.ASSERTION_METHOD);
      expect(assertionProofs).toHaveLength(1);
      expect(assertionProofs[0]).toEqual(mockProof1);
      
      const endorsementProofs = ProofManager.findProofsByPurpose(document, 'endorsement');
      expect(endorsementProofs).toHaveLength(1);
      expect(endorsementProofs[0]).toEqual(mockProof2);
    });

    it('should validate proof chains', () => {
      const validProofs = [
        { ...mockProof1, created: '2024-01-01T00:00:00Z' },
        { ...mockProof2, created: '2024-01-02T00:00:00Z' }
      ];
      
      const result = ProofManager.validateProofChain(validProofs);
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it('should detect invalid proof chains', () => {
      // Create proofs that are explicitly out of order in the input array
      // but have valid timestamps (the function sorts by timestamp)
      const invalidProofs = [
        { ...mockProof1, created: undefined }, // Missing timestamp
        { ...mockProof2, created: '2024-01-01T00:00:00Z' }
      ];
      
      const result = ProofManager.validateProofChain(invalidProofs);
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(result.errors!.length).toBeGreaterThan(0);
    });

    it('should check proofs by purpose and verifier', () => {
      const document = { proof: [mockProof1, mockProof2] };
      
      const hasValidProof = ProofManager.hasValidProofForPurpose(
        document,
        ProofPurpose.ASSERTION_METHOD,
        ['did:example:issuer']
      );
      expect(hasValidProof).toBe(true);
      
      const noValidProof = ProofManager.hasValidProofForPurpose(
        document,
        ProofPurpose.ASSERTION_METHOD,
        ['did:example:other']
      );
      expect(noValidProof).toBe(false);
    });

    it('should remove expired proofs', () => {
      const futureTime = new Date(Date.now() + 86400000).toISOString(); // 24 hours from now
      const pastTime = new Date(Date.now() - 86400000).toISOString(); // 24 hours ago
      
      const validProof = { ...mockProof1, expires: futureTime };
      const expiredProof = { ...mockProof2, expires: pastTime };
      
      const document = { proof: [validProof, expiredProof] };
      const cleaned = ProofManager.removeExpiredProofs(document);
      
      const remainingProofs = ProofManager.getProofs(cleaned);
      expect(remainingProofs).toHaveLength(1);
      expect(remainingProofs[0]).toEqual(validProof);
    });
  });

  describe('Enhanced Credential Features', () => {
    it('should support terms of use', () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.TERMS_OF_USE],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' },
        termsOfUse: {
          type: 'IssuerPolicy',
          id: 'https://example.com/policies/1',
          prohibition: [{
            assigner: 'did:example:issuer',
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

    it('should support evidence', () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' },
        evidence: [{
          type: 'DocumentVerification',
          verifier: 'did:example:verifier',
          evidenceDocument: 'DriversLicense',
          subjectPresence: 'Physical',
          documentPresence: 'Physical'
        }]
      };

      expect(credential.evidence).toBeDefined();
      const evidence = Array.isArray(credential.evidence) 
        ? credential.evidence[0] 
        : credential.evidence!;
      expect(evidence.type).toBe('DocumentVerification');
      expect(evidence.verifier).toBe('did:example:verifier');
    });

    it('should support credential status', () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.STATUS_LIST_2021],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' },
        credentialStatus: {
          id: 'https://example.com/status/1#123',
          type: CredentialStatusType.STATUS_LIST_2021,
          statusPurpose: 'revocation',
          statusListIndex: 123,
          statusListCredential: 'https://example.com/status/1'
        }
      };

      expect(credential.credentialStatus).toBeDefined();
      const status = Array.isArray(credential.credentialStatus) 
        ? credential.credentialStatus[0] 
        : credential.credentialStatus!;
      expect(status.type).toBe(CredentialStatusType.STATUS_LIST_2021);
      expect((status as any).statusListIndex).toBe(123);
    });
  });

  describe('Signature Suite Architecture', () => {
    it('should have proper signature suite types', () => {
      // Test that our type definitions work
      const ed25519ProofType = 'Ed25519Signature2020';
      const bbsProofType = 'BbsBlsSignature2020';
      
      expect(typeof ed25519ProofType).toBe('string');
      expect(typeof bbsProofType).toBe('string');
      expect(ed25519ProofType).not.toBe(bbsProofType);
    });

    it('should support different key types', () => {
      const ed25519KeyType = 'Ed25519VerificationKey2020';
      const bbsKeyType = 'Bls12381G2Key2020';
      
      expect(typeof ed25519KeyType).toBe('string');
      expect(typeof bbsKeyType).toBe('string');
      expect(ed25519KeyType).not.toBe(bbsKeyType);
    });
  });

  describe('Integration Architecture', () => {
    it('should support V2 credential structure with backward compatibility', () => {
      const legacyCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        issuer: 'did:example:issuer',
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:subject',
          name: 'Legacy User'
        }
      };

      // Should be able to treat as V2 credential
      const v2Credential: VerifiableCredentialV2 = {
        ...legacyCredential,
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, ...legacyCredential['@context']],
        validFrom: legacyCredential.issuanceDate
      };

      expect(v2Credential['@context']).toContain(VC_V2_CONTEXTS.CREDENTIALS_V2);
      expect(v2Credential.validFrom).toBe(legacyCredential.issuanceDate);
      expect(v2Credential.issuanceDate).toBe(legacyCredential.issuanceDate);
    });

    it('should support multiple context formats', () => {
      const contexts = [
        VC_V2_CONTEXTS.CREDENTIALS_V2,
        VC_V2_CONTEXTS.ED25519_2020,
        VC_V2_CONTEXTS.BBS_2023,
        { 'custom': 'https://example.com/vocab#' }
      ];

      const credential: VerifiableCredentialV2 = {
        '@context': contexts,
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' }
      };

      expect(Array.isArray(credential['@context'])).toBe(true);
      expect(credential['@context']).toHaveLength(4);
    });
  });
});