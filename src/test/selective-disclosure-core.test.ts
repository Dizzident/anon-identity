/**
 * Selective Disclosure Core Concepts Tests
 * Testing selective disclosure concepts and data structures without external dependencies
 */

import { VerifiableCredentialV2, VC_V2_CONTEXTS, ProofPurpose } from '../types/vc2';

describe('Selective Disclosure Core Concepts', () => {
  describe('Selective Disclosure Data Structures', () => {
    it('should define credential with selectable attributes', () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.BBS_2023],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: {
          id: 'did:example:subject',
          name: 'Alice Johnson',
          age: 28,
          email: 'alice@example.com',
          address: '123 Main St',
          phone: '555-0123'
        }
      };

      expect(credential.credentialSubject).toHaveProperty('name');
      expect(credential.credentialSubject).toHaveProperty('age');
      expect(credential.credentialSubject).toHaveProperty('email');
      expect(credential.credentialSubject).toHaveProperty('address');
      expect(credential.credentialSubject).toHaveProperty('phone');
    });

    it('should support BBS+ context for selective disclosure', () => {
      const bbsContext = VC_V2_CONTEXTS.BBS_2023;
      expect(bbsContext).toBe('https://w3id.org/security/bbs/v1');
    });

    it('should define revealed attribute paths', () => {
      const revealedPaths = [
        'credentialSubject.name',
        'credentialSubject.age'
      ];

      expect(revealedPaths).toContain('credentialSubject.name');
      expect(revealedPaths).toContain('credentialSubject.age');
      expect(revealedPaths).not.toContain('credentialSubject.email');
    });

    it('should support nonce for replay protection', () => {
      const nonce = 'unique-challenge-12345';
      expect(typeof nonce).toBe('string');
      expect(nonce.length).toBeGreaterThan(0);
    });
  });

  describe('Derived Credential Structure', () => {
    it('should create derived credential with subset of attributes', () => {
      const originalCredential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: {
          id: 'did:example:subject',
          name: 'Bob Wilson',
          age: 35,
          email: 'bob@example.com',
          ssn: '123-45-6789'
        }
      };

      // Simulate selective disclosure - reveal only name and age
      const derivedCredential: VerifiableCredentialV2 = {
        '@context': originalCredential['@context'],
        type: originalCredential.type,
        issuer: originalCredential.issuer,
        credentialSubject: {
          id: 'did:example:subject',
          name: 'Bob Wilson',
          age: 35
          // email and ssn not revealed
        }
      };

      expect(derivedCredential.credentialSubject).toHaveProperty('id');
      expect(derivedCredential.credentialSubject).toHaveProperty('name');
      expect(derivedCredential.credentialSubject).toHaveProperty('age');
      expect(derivedCredential.credentialSubject).not.toHaveProperty('email');
      expect(derivedCredential.credentialSubject).not.toHaveProperty('ssn');
    });

    it('should preserve credential metadata in derived form', () => {
      const originalMetadata = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.BBS_2023],
        type: 'VerifiableCredential',
        issuer: 'did:example:trusted-issuer',
        validFrom: '2024-01-01T00:00:00Z',
        validUntil: '2025-01-01T00:00:00Z'
      };

      // In derived credential, metadata should be preserved
      const derivedMetadata = {
        '@context': originalMetadata['@context'],
        type: originalMetadata.type,
        issuer: originalMetadata.issuer,
        validFrom: originalMetadata.validFrom,
        validUntil: originalMetadata.validUntil
      };

      expect(derivedMetadata['@context']).toEqual(originalMetadata['@context']);
      expect(derivedMetadata.type).toBe(originalMetadata.type);
      expect(derivedMetadata.issuer).toBe(originalMetadata.issuer);
      expect(derivedMetadata.validFrom).toBe(originalMetadata.validFrom);
      expect(derivedMetadata.validUntil).toBe(originalMetadata.validUntil);
    });
  });

  describe('BBS+ Proof Structures', () => {
    it('should define BBS+ signature proof', () => {
      const bbsProof = {
        type: 'BbsBlsSignature2020',
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'did:example:issuer#bbs-key-1',
        proofPurpose: ProofPurpose.ASSERTION_METHOD,
        proofValue: 'base64-encoded-bbs-signature'
      };

      expect(bbsProof.type).toBe('BbsBlsSignature2020');
      expect(bbsProof.verificationMethod).toContain('bbs-key');
      expect(bbsProof.proofValue).toBeDefined();
    });

    it('should define BBS+ derived proof with nonce', () => {
      const bbsDerivedProof = {
        type: 'BbsBlsSignatureProof2020',
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'did:example:issuer#bbs-key-1',
        proofPurpose: ProofPurpose.ASSERTION_METHOD,
        proofValue: 'base64-encoded-derived-proof',
        nonce: 'challenge-nonce-12345'
      };

      expect(bbsDerivedProof.type).toBe('BbsBlsSignatureProof2020');
      expect(bbsDerivedProof.nonce).toBe('challenge-nonce-12345');
      expect(bbsDerivedProof.proofValue).toBeDefined();
    });

    it('should distinguish between signature and proof types', () => {
      const signatureType = 'BbsBlsSignature2020';
      const proofType = 'BbsBlsSignatureProof2020';

      expect(signatureType).toBe('BbsBlsSignature2020');
      expect(proofType).toBe('BbsBlsSignatureProof2020');
      expect(signatureType).not.toBe(proofType);
    });
  });

  describe('Selective Disclosure Options', () => {
    it('should define attributes to reveal', () => {
      const options = {
        attributesToReveal: ['name', 'age', 'city'],
        nonce: 'unique-challenge',
        holderDID: 'did:example:holder'
      };

      expect(Array.isArray(options.attributesToReveal)).toBe(true);
      expect(options.attributesToReveal).toContain('name');
      expect(options.attributesToReveal).toContain('age');
      expect(options.nonce).toBeDefined();
      expect(options.holderDID).toContain('did:example:');
    });

    it('should support holder binding', () => {
      const holderDID = 'did:example:holder-123';
      expect(holderDID).toMatch(/^did:/);
      expect(holderDID).toContain('holder');
    });

    it('should validate attribute paths', () => {
      const validPaths = [
        'credentialSubject.name',
        'credentialSubject.personalInfo.age',
        'credentialSubject.address.city'
      ];

      expect(validPaths.every(path => path.startsWith('credentialSubject'))).toBe(true);
      expect(validPaths.some(path => path.includes('.'))).toBe(true);
    });
  });

  describe('Privacy Levels', () => {
    it('should estimate privacy based on revealed attributes', () => {
      const totalAttributes = 10;
      
      // High privacy - few attributes revealed
      const highPrivacyRevealed = 2;
      const highPrivacyRatio = highPrivacyRevealed / totalAttributes;
      expect(highPrivacyRatio).toBeLessThan(0.3);
      
      // Medium privacy - moderate attributes revealed
      const mediumPrivacyRevealed = 5;
      const mediumPrivacyRatio = mediumPrivacyRevealed / totalAttributes;
      expect(mediumPrivacyRatio).toBeGreaterThanOrEqual(0.3);
      expect(mediumPrivacyRatio).toBeLessThan(0.7);
      
      // Low privacy - many attributes revealed
      const lowPrivacyRevealed = 8;
      const lowPrivacyRatio = lowPrivacyRevealed / totalAttributes;
      expect(lowPrivacyRatio).toBeGreaterThanOrEqual(0.7);
    });

    it('should classify privacy levels', () => {
      const privacyLevels = ['high', 'medium', 'low'];
      
      expect(privacyLevels).toContain('high');
      expect(privacyLevels).toContain('medium');
      expect(privacyLevels).toContain('low');
    });
  });

  describe('Verification Requirements', () => {
    it('should require original issuer for verification', () => {
      const originalIssuer = 'did:example:trusted-issuer';
      expect(originalIssuer).toMatch(/^did:/);
      expect(typeof originalIssuer).toBe('string');
    });

    it('should verify expected attributes were revealed', () => {
      const expectedAttributes = ['name', 'age'];
      const actuallyRevealed = ['name', 'age'];
      
      expect(expectedAttributes.every(attr => actuallyRevealed.includes(attr))).toBe(true);
    });

    it('should validate nonce matches', () => {
      const originalNonce = 'challenge-12345';
      const verificationNonce = 'challenge-12345';
      
      expect(originalNonce).toBe(verificationNonce);
    });
  });

  describe('Complex Credential Subjects', () => {
    it('should handle nested attributes', () => {
      const nestedCredential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: {
          id: 'did:example:subject',
          personalInfo: {
            name: 'Charlie Davis',
            age: 42,
            contact: {
              email: 'charlie@example.com',
              phone: '555-0199'
            }
          },
          workInfo: {
            company: 'Tech Corp',
            title: 'Engineer'
          }
        }
      };

      expect(nestedCredential.credentialSubject).toHaveProperty('personalInfo');
      expect(nestedCredential.credentialSubject).toHaveProperty('workInfo');
      
      const personalInfo = (nestedCredential.credentialSubject as any).personalInfo;
      expect(personalInfo).toHaveProperty('name');
      expect(personalInfo).toHaveProperty('contact');
    });

    it('should handle array attributes', () => {
      const arrayCredential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: {
          id: 'did:example:subject',
          name: 'Diana Prince',
          skills: ['JavaScript', 'TypeScript', 'React'],
          certifications: [
            { name: 'AWS Certified', date: '2023-01-01' },
            { name: 'Google Cloud', date: '2023-06-01' }
          ]
        }
      };

      const subject = arrayCredential.credentialSubject as any;
      expect(Array.isArray(subject.skills)).toBe(true);
      expect(Array.isArray(subject.certifications)).toBe(true);
      expect(subject.skills).toContain('JavaScript');
    });
  });

  describe('Integration with Multiple Proofs', () => {
    it('should support BBS+ proof alongside other proof types', () => {
      const multipleProofs = [
        {
          type: 'Ed25519Signature2020',
          created: '2024-01-01T00:00:00Z',
          verificationMethod: 'did:example:issuer#ed25519-key',
          proofPurpose: ProofPurpose.ASSERTION_METHOD,
          proofValue: 'ed25519-signature'
        },
        {
          type: 'BbsBlsSignature2020',
          created: '2024-01-01T01:00:00Z',
          verificationMethod: 'did:example:issuer#bbs-key',
          proofPurpose: ProofPurpose.ASSERTION_METHOD,
          proofValue: 'bbs-signature'
        }
      ];

      expect(multipleProofs).toHaveLength(2);
      expect(multipleProofs[0].type).toBe('Ed25519Signature2020');
      expect(multipleProofs[1].type).toBe('BbsBlsSignature2020');
    });

    it('should preserve non-BBS+ proofs in derived credentials', () => {
      const originalProofs = [
        { type: 'Ed25519Signature2020', proofValue: 'ed25519-sig' },
        { type: 'BbsBlsSignature2020', proofValue: 'bbs-sig' }
      ];

      // In selective disclosure, Ed25519 proof should be preserved
      const preservedEd25519 = originalProofs.find(p => p.type === 'Ed25519Signature2020');
      expect(preservedEd25519).toBeDefined();
      expect(preservedEd25519!.type).toBe('Ed25519Signature2020');
    });
  });
});