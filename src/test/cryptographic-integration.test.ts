/**
 * Simplified Cryptographic Integration Tests
 * Testing core cryptographic functionality with proper mocking
 */

import { Ed25519Signature2020Suite } from '../ld/signature-suites/ed25519-signature-2020';
import { BbsBlsSignature2020Suite } from '../ld/signature-suites/bbs-bls-signature-2020';
import { BbsSelectiveDisclosure } from '../zkp/bbs-selective-disclosure';
import { ProofPurpose, VerifiableCredentialV2, VC_V2_CONTEXTS } from '../types/vc2';

describe('Cryptographic Integration Tests', () => {
  let ed25519Suite: Ed25519Signature2020Suite;
  let bbsSuite: BbsBlsSignature2020Suite;
  let bbsDisclosure: BbsSelectiveDisclosure;

  beforeEach(() => {
    ed25519Suite = new Ed25519Signature2020Suite();
    bbsSuite = new BbsBlsSignature2020Suite();
    bbsDisclosure = new BbsSelectiveDisclosure();
  });

  describe('Ed25519 Signature Suite', () => {
    const mockDocument: VerifiableCredentialV2 = {
      '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.ED25519_2020],
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer',
      credentialSubject: {
        id: 'did:example:subject',
        name: 'John Doe',
        age: 30
      }
    };

    it('should create Ed25519 signature proofs', async () => {
      const proof = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      expect(proof.type).toBe('Ed25519Signature2020');
      expect(proof.created).toBe('2024-01-01T00:00:00Z');
      expect(proof.verificationMethod).toBe('did:example:issuer#key-1');
      expect(proof.proofPurpose).toBe(ProofPurpose.ASSERTION_METHOD);
      expect(proof.proofValue).toBeDefined();
    });

    it('should verify Ed25519 signature proofs', async () => {
      const proof = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      const isValid = await ed25519Suite.verifyProof({
        document: mockDocument,
        proof,
        publicKey: new Uint8Array(32),
        expectedPurpose: ProofPurpose.ASSERTION_METHOD
      });

      expect(isValid).toBe(true);
    });

    it('should support different proof purposes', async () => {
      const purposes = [
        ProofPurpose.ASSERTION_METHOD,
        ProofPurpose.AUTHENTICATION,
        ProofPurpose.KEY_AGREEMENT
      ];

      for (const purpose of purposes) {
        const proof = await ed25519Suite.createProof({
          document: mockDocument,
          purpose,
          verificationMethod: 'did:example:issuer#key-1',
          privateKey: new Uint8Array(32),
          created: '2024-01-01T00:00:00Z'
        });

        expect(proof.proofPurpose).toBe(purpose);
        expect(proof.type).toBe('Ed25519Signature2020');
      }
    });
  });

  describe('BBS+ Signature Suite', () => {
    const mockDocument: VerifiableCredentialV2 = {
      '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.BBS_2023],
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer',
      credentialSubject: {
        id: 'did:example:subject',
        name: 'Alice Smith',
        age: 28,
        email: 'alice@example.com'
      }
    };

    it('should create BBS+ signature proofs', async () => {
      const proof = await bbsSuite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#bbs-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      expect(proof.type).toBe('BbsBlsSignature2020');
      expect(proof.created).toBe('2024-01-01T00:00:00Z');
      expect(proof.verificationMethod).toBe('did:example:issuer#bbs-key-1');
      expect(proof.proofValue).toBeDefined();
    });

    it('should verify BBS+ signature proofs', async () => {
      const proof = await bbsSuite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#bbs-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      const isValid = await bbsSuite.verifyProof({
        document: mockDocument,
        proof,
        publicKey: new Uint8Array(48), // BBS+ uses 48-byte public keys
        expectedPurpose: ProofPurpose.ASSERTION_METHOD
      });

      expect(isValid).toBe(true);
    });

    it('should handle selective disclosure capability', async () => {
      // Test that BBS+ suite indicates selective disclosure support
      expect(bbsSuite.supportsSelectiveDisclosure).toBe(true);
      expect(bbsSuite.type).toBe('BbsBlsSignature2020');
      expect(bbsSuite.requiredKeyType).toBe('Bls12381G2Key2020');
    });
  });

  describe('BBS+ Selective Disclosure', () => {
    const mockCredential: VerifiableCredentialV2 = {
      '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer',
      credentialSubject: {
        id: 'did:example:subject',
        name: 'Bob Wilson',
        age: 35,
        email: 'bob@example.com',
        address: '123 Main St'
      }
    };

    it('should derive credentials with selective disclosure', async () => {
      const result = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name', 'age'],
        nonce: 'test-nonce-123'
      });

      expect(result.derivedCredential).toBeDefined();
      expect(result.derivedCredential!.credentialSubject).toHaveProperty('name');
      expect(result.derivedCredential!.credentialSubject).toHaveProperty('age');
      // Should not have unrevealed attributes
      expect(result.derivedCredential!.credentialSubject).not.toHaveProperty('email');
      expect(result.derivedCredential!.credentialSubject).not.toHaveProperty('address');
    });

    it('should verify derived credentials', async () => {
      const derivedResult = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name', 'age'],
        nonce: 'verify-test-nonce'
      });

      const verifyResult = await bbsDisclosure.verifyDerivedCredential(
        derivedResult.derivedCredential!,
        new Uint8Array(48) // Mock public key for verification
      );

      expect(verifyResult).toBe(true);
    });

    it('should handle different numbers of revealed attributes', async () => {
      // Test few attributes revealed
      const fewAttrsResult = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name'],
        nonce: 'privacy-test'
      });
      expect(fewAttrsResult.derivedCredential).toBeDefined();
      expect(fewAttrsResult.revealedPaths).toHaveLength(1);

      // Test many attributes revealed
      const manyAttrsResult = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name', 'age', 'email', 'address'],
        nonce: 'privacy-test'
      });
      expect(manyAttrsResult.derivedCredential).toBeDefined();
      expect(manyAttrsResult.revealedPaths).toHaveLength(4);
    });
  });

  describe('Signature Suite Integration', () => {
    const testDocument = {
      '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:subject', data: 'test' }
    };

    it('should support both Ed25519 and BBS+ signatures', async () => {
      // Create Ed25519 proof
      const ed25519Proof = await ed25519Suite.createProof({
        document: testDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      // Create BBS+ proof
      const bbsProof = await bbsSuite.createProof({
        document: testDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#bbs-key',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T01:00:00Z'
      });

      expect(ed25519Proof.type).toBe('Ed25519Signature2020');
      expect(bbsProof.type).toBe('BbsBlsSignature2020');
      expect(ed25519Proof.proofValue).not.toBe(bbsProof.proofValue);
    });

    it('should handle concurrent signing operations', async () => {
      const documents = Array.from({ length: 3 }, (_, i) => ({
        ...testDocument,
        id: `credential-${i}`
      }));

      const concurrentProofs = await Promise.all(
        documents.map((doc, i) => 
          ed25519Suite.createProof({
            document: doc,
            purpose: ProofPurpose.ASSERTION_METHOD,
            verificationMethod: `did:example:issuer#key-${i}`,
            privateKey: new Uint8Array(32).fill(i),
            created: '2024-01-01T00:00:00Z'
          })
        )
      );

      expect(concurrentProofs).toHaveLength(3);
      expect(concurrentProofs.every(p => p.type === 'Ed25519Signature2020')).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid proof verification gracefully', async () => {
      const invalidProof = {
        type: 'Ed25519Signature2020',
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'did:example:issuer#key-1',
        proofPurpose: ProofPurpose.ASSERTION_METHOD,
        proofValue: 'invalid-signature-data'
      };

      const isValid = await ed25519Suite.verifyProof({
        document: { test: 'data' },
        proof: invalidProof,
        publicKey: new Uint8Array(32),
        expectedPurpose: ProofPurpose.ASSERTION_METHOD
      });

      expect(isValid).toBe(false);
    });

    it('should handle malformed documents', async () => {
      const malformedDoc = {
        // Missing required fields
        type: 'VerifiableCredential'
      };

      await expect(ed25519Suite.createProof({
        document: malformedDoc,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      })).resolves.toBeDefined(); // Should not throw, just create proof
    });
  });

  describe('Performance Characteristics', () => {
    it('should complete signature operations within reasonable time', async () => {
      const document = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' }
      };

      const startTime = Date.now();

      // Perform multiple operations
      const operations = await Promise.all([
        ed25519Suite.createProof({
          document,
          purpose: ProofPurpose.ASSERTION_METHOD,
          verificationMethod: 'did:example:issuer#key-1',
          privateKey: new Uint8Array(32),
          created: '2024-01-01T00:00:00Z'
        }),
        bbsSuite.createProof({
          document,
          purpose: ProofPurpose.ASSERTION_METHOD,
          verificationMethod: 'did:example:issuer#key-2',
          privateKey: new Uint8Array(32),
          created: '2024-01-01T00:00:00Z'
        })
      ]);

      const endTime = Date.now();

      expect(operations).toHaveLength(2);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
    });
  });
});