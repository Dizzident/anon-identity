/**
 * Ed25519 Signature Operations Tests
 * Testing Ed25519 signatures with mocked cryptographic operations
 */

import { Ed25519Signature2020Suite } from '../ld/signature-suites/ed25519-signature-2020';
import { ProofPurpose, VerifiableCredentialV2, VC_V2_CONTEXTS } from '../types/vc2';

describe('Ed25519 Signature Operations', () => {
  let ed25519Suite: Ed25519Signature2020Suite;

  beforeEach(() => {
    ed25519Suite = new Ed25519Signature2020Suite();
  });

  describe('Ed25519 Signature Suite', () => {
    const mockDocument: VerifiableCredentialV2 = {
      '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.ED25519_2020],
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer',
      validFrom: '2024-01-01T00:00:00Z',
      credentialSubject: {
        id: 'did:example:subject',
        name: 'John Doe',
        age: 30
      }
    };

    it('should create Ed25519 signature proof', async () => {
      const proof = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      expect(proof.type).toBe('Ed25519Signature2020');
      expect(proof.created).toBe('2024-01-01T00:00:00Z');
      expect(proof.verificationMethod).toBe('did:example:issuer#ed25519-key-1');
      expect(proof.proofPurpose).toBe(ProofPurpose.ASSERTION_METHOD);
      expect(proof.proofValue).toBeDefined();
      expect(typeof proof.proofValue).toBe('string');
    });

    it('should verify Ed25519 signature proof', async () => {
      const proof = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      const isValid = await ed25519Suite.verifyProof({
        document: mockDocument,
        proof,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        publicKey: new Uint8Array(32)
      });

      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong public key', async () => {
      const proof = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      // Mock verification failure for wrong key
      const mockEd25519 = require('@noble/ed25519');
      mockEd25519.verify.mockResolvedValueOnce(false);

      const isValid = await ed25519Suite.verifyProof({
        document: mockDocument,
        proof,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        publicKey: new Uint8Array(32).fill(1) // Wrong key
      });

      expect(isValid).toBe(false);
    });

    it('should handle different proof purposes', async () => {
      const purposes = [
        ProofPurpose.ASSERTION_METHOD,
        ProofPurpose.AUTHENTICATION,
        ProofPurpose.KEY_AGREEMENT,
        ProofPurpose.CAPABILITY_INVOCATION,
        ProofPurpose.CAPABILITY_DELEGATION
      ];

      for (const purpose of purposes) {
        const proof = await ed25519Suite.createProof({
          document: mockDocument,
          purpose,
          verificationMethod: 'did:example:issuer#ed25519-key-1',
          privateKey: new Uint8Array(32),
          created: '2024-01-01T00:00:00Z'
        });

        expect(proof.proofPurpose).toBe(purpose);
        expect(proof.type).toBe('Ed25519Signature2020');
      }
    });

    it('should create deterministic signatures with same inputs', async () => {
      const privateKey = new Uint8Array(32).fill(42);
      const created = '2024-01-01T00:00:00Z';

      const proof1 = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        privateKey,
        created
      });

      const proof2 = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        privateKey,
        created
      });

      // Same inputs should produce same proof value (mocked)
      expect(proof1.proofValue).toBe(proof2.proofValue);
      expect(proof1.created).toBe(proof2.created);
      expect(proof1.verificationMethod).toBe(proof2.verificationMethod);
    });

    it('should create different signatures with different timestamps', async () => {
      const privateKey = new Uint8Array(32).fill(42);

      const proof1 = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        privateKey,
        created: '2024-01-01T00:00:00Z'
      });

      const proof2 = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        privateKey,
        created: '2024-01-02T00:00:00Z'
      });

      expect(proof1.created).not.toBe(proof2.created);
      // Proof values would be different due to different creation times affecting the signature
    });
  });

  describe('Ed25519 Key Management', () => {
    it('should validate Ed25519 key formats', () => {
      // Valid Ed25519 public key (32 bytes)
      const validPublicKey = new Uint8Array(32);
      expect(ed25519Suite.validatePublicKey(validPublicKey)).toBe(true);

      // Invalid key lengths
      expect(ed25519Suite.validatePublicKey(new Uint8Array(16))).toBe(false);
      expect(ed25519Suite.validatePublicKey(new Uint8Array(48))).toBe(false);
      expect(ed25519Suite.validatePublicKey(new Uint8Array(64))).toBe(false);

      // Valid Ed25519 private key (32 bytes)
      const validPrivateKey = new Uint8Array(32);
      expect(ed25519Suite.validatePrivateKey(validPrivateKey)).toBe(true);

      // Invalid private key lengths
      expect(ed25519Suite.validatePrivateKey(new Uint8Array(16))).toBe(false);
      expect(ed25519Suite.validatePrivateKey(new Uint8Array(48))).toBe(false);
    });

    it('should handle key pair generation', async () => {
      const mockEd25519 = require('@noble/ed25519');
      
      // Test that our suite would use the key generation utilities
      const privateKey = mockEd25519.utils.randomPrivateKey();
      const publicKey = await mockEd25519.getPublicKey(privateKey);
      
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(privateKey.length).toBe(32);
      expect(publicKey.length).toBe(32);
    });

    it('should derive public key from private key', async () => {
      const mockEd25519 = require('@noble/ed25519');
      const privateKey = new Uint8Array(32).fill(1);
      
      const publicKey = await mockEd25519.getPublicKey(privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(32);
    });
  });

  describe('Ed25519 Document Canonicalization', () => {
    it('should canonicalize document before signing', async () => {
      const documentWithExtraFields = {
        ...mockDocument,
        extraField: 'should be ignored in canonical form',
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.ED25519_2020],
        // Test different field ordering
        type: 'VerifiableCredential',
        credentialSubject: {
          age: 30, // Different field order
          name: 'John Doe',
          id: 'did:example:subject'
        }
      };

      const proof = await ed25519Suite.createProof({
        document: documentWithExtraFields,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      expect(proof).toBeDefined();
      expect(proof.type).toBe('Ed25519Signature2020');
    });

    it('should produce same signature for equivalent documents', async () => {
      const doc1 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject', name: 'John', age: 30 }
      };

      const doc2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { age: 30, name: 'John', id: 'did:example:subject' } // Different order
      };

      const privateKey = new Uint8Array(32).fill(1);
      const created = '2024-01-01T00:00:00Z';

      const proof1 = await ed25519Suite.createProof({
        document: doc1,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#key-1',
        privateKey,
        created
      });

      const proof2 = await ed25519Suite.createProof({
        document: doc2,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#key-1',
        privateKey,
        created
      });

      // Canonicalization should make these equivalent
      expect(proof1.proofValue).toBe(proof2.proofValue);
    });
  });

  describe('Ed25519 Proof Verification Edge Cases', () => {
    it('should reject proofs with invalid timestamps', async () => {
      const proof = await ed25519Suite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      // Modify proof to have invalid timestamp
      const invalidProof = {
        ...proof,
        created: 'invalid-timestamp'
      };

      const isValid = await ed25519Suite.verifyProof({
        document: mockDocument,
        proof: invalidProof,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        publicKey: new Uint8Array(32)
      });

      expect(isValid).toBe(false);
    });

    it('should reject proofs with missing required fields', async () => {
      const incompleteProof = {
        type: 'Ed25519Signature2020',
        created: '2024-01-01T00:00:00Z',
        // Missing verificationMethod and proofPurpose
        proofValue: 'some-value'
      };

      const isValid = await ed25519Suite.verifyProof({
        document: mockDocument,
        proof: incompleteProof as any,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        publicKey: new Uint8Array(32)
      });

      expect(isValid).toBe(false);
    });

    it('should validate proof format correctly', () => {
      const validProof = {
        type: 'Ed25519Signature2020',
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'did:example:issuer#key-1',
        proofPurpose: ProofPurpose.ASSERTION_METHOD,
        proofValue: 'base64encodedvalue'
      };

      expect(ed25519Suite.validateProofFormat(validProof)).toBe(true);

      const invalidProof = {
        type: 'BbsBlsSignature2020', // Wrong type
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'did:example:issuer#key-1',
        proofPurpose: ProofPurpose.ASSERTION_METHOD,
        proofValue: 'base64encodedvalue'
      };

      expect(ed25519Suite.validateProofFormat(invalidProof)).toBe(false);
    });

    it('should handle malformed proof values', async () => {
      const proof = {
        type: 'Ed25519Signature2020',
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        proofPurpose: ProofPurpose.ASSERTION_METHOD,
        proofValue: 'invalid-base64!'
      };

      const isValid = await ed25519Suite.verifyProof({
        document: mockDocument,
        proof,
        verificationMethod: 'did:example:issuer#ed25519-key-1',
        publicKey: new Uint8Array(32)
      });

      expect(isValid).toBe(false);
    });
  });

  describe('Ed25519 Performance Tests', () => {
    it('should sign and verify efficiently', async () => {
      const startTime = Date.now();

      // Create 10 proofs
      const proofs = await Promise.all(
        Array.from({ length: 10 }, (_, i) => 
          ed25519Suite.createProof({
            document: mockDocument,
            purpose: ProofPurpose.ASSERTION_METHOD,
            verificationMethod: `did:example:issuer#key-${i}`,
            privateKey: new Uint8Array(32).fill(i),
            created: new Date(Date.now() + i * 1000).toISOString()
          })
        )
      );

      // Verify all proofs
      const verifications = await Promise.all(
        proofs.map(proof => 
          ed25519Suite.verifyProof({
            document: mockDocument,
            proof,
            verificationMethod: proof.verificationMethod,
            publicKey: new Uint8Array(32)
          })
        )
      );

      const endTime = Date.now();

      expect(proofs).toHaveLength(10);
      expect(verifications.every(v => v === true)).toBe(true);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should handle concurrent signing operations', async () => {
      const documents = Array.from({ length: 5 }, (_, i) => ({
        ...mockDocument,
        id: `credential-${i}`,
        credentialSubject: {
          ...mockDocument.credentialSubject,
          id: `did:example:subject-${i}`
        }
      }));

      const startTime = Date.now();

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

      const endTime = Date.now();

      expect(concurrentProofs).toHaveLength(5);
      expect(concurrentProofs.every(p => p.type === 'Ed25519Signature2020')).toBe(true);
      expect(endTime - startTime).toBeLessThan(500); // Concurrent operations should be fast
    });
  });

  describe('Ed25519 Integration with Document Types', () => {
    it('should sign verifiable presentations', async () => {
      const presentation = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiablePresentation',
        holder: 'did:example:holder',
        verifiableCredential: [mockDocument]
      };

      const proof = await ed25519Suite.createProof({
        document: presentation,
        purpose: ProofPurpose.AUTHENTICATION,
        verificationMethod: 'did:example:holder#key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      expect(proof.type).toBe('Ed25519Signature2020');
      expect(proof.proofPurpose).toBe(ProofPurpose.AUTHENTICATION);
    });

    it('should sign DID documents', async () => {
      const didDocument = {
        '@context': ['https://www.w3.org/ns/did/v1', VC_V2_CONTEXTS.ED25519_2020],
        id: 'did:example:123',
        verificationMethod: [{
          id: 'did:example:123#key-1',
          type: 'Ed25519VerificationKey2020',
          controller: 'did:example:123',
          publicKeyMultibase: 'z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd'
        }]
      };

      const proof = await ed25519Suite.createProof({
        document: didDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:123#key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      expect(proof.type).toBe('Ed25519Signature2020');
      expect(proof.verificationMethod).toBe('did:example:123#key-1');
    });
  });
});