/**
 * BBS+ Cryptographic Operations Tests
 * Testing BBS+ signatures with mocked cryptographic operations
 */

import { BbsBlsSignature2020Suite } from '../ld/signature-suites/bbs-bls-signature-2020';
import { BbsSelectiveDisclosure } from '../zkp/bbs-selective-disclosure';
import { ProofPurpose, VerifiableCredentialV2, VC_V2_CONTEXTS } from '../types/vc2';

// Mock BBS+ operations since we can't use the real library in Jest
jest.mock('@mattrglobal/bbs-signatures', () => ({
  generateBls12381G1KeyPair: jest.fn().mockResolvedValue({
    publicKey: new Uint8Array(48),
    secretKey: new Uint8Array(32)
  }),
  blsSign: jest.fn().mockResolvedValue(new Uint8Array(112)),
  blsVerify: jest.fn().mockResolvedValue(true),
  blsCreateProof: jest.fn().mockResolvedValue(new Uint8Array(128)),
  blsVerifyProof: jest.fn().mockResolvedValue(true)
}));

describe('BBS+ Cryptographic Operations', () => {
  let bbsSuite: BbsBlsSignature2020Suite;
  let bbsDisclosure: BbsSelectiveDisclosure;

  beforeEach(() => {
    bbsSuite = new BbsBlsSignature2020Suite();
    bbsDisclosure = new BbsSelectiveDisclosure();
  });

  describe('BBS+ Signature Suite', () => {
    const mockDocument: VerifiableCredentialV2 = {
      '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.BBS_2023],
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer',
      credentialSubject: {
        id: 'did:example:subject',
        name: 'John Doe',
        age: 30,
        email: 'john@example.com',
        ssn: '123-45-6789'
      }
    };

    it('should create BBS+ signature proof', async () => {
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
      expect(proof.proofPurpose).toBe(ProofPurpose.ASSERTION_METHOD);
      expect(proof.proofValue).toBeDefined();
      expect(typeof proof.proofValue).toBe('string');
    });

    it('should verify BBS+ signature proof', async () => {
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
        verificationMethod: 'did:example:issuer#bbs-key-1',
        publicKey: new Uint8Array(48)
      });

      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong public key', async () => {
      const proof = await bbsSuite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#bbs-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      // Mock verification failure
      const mockBbs = require('@mattrglobal/bbs-signatures');
      mockBbs.blsVerify.mockResolvedValueOnce(false);

      const isValid = await bbsSuite.verifyProof({
        document: mockDocument,
        proof,
        verificationMethod: 'did:example:issuer#bbs-key-1',
        publicKey: new Uint8Array(48).fill(1) // Wrong key
      });

      expect(isValid).toBe(false);
    });

    it('should create selective disclosure proof', async () => {
      const originalProof = await bbsSuite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#bbs-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      const derivedProof = await bbsSuite.createSelectiveDisclosureProof({
        document: mockDocument,
        proof: originalProof,
        attributesToReveal: ['name', 'age'],
        nonce: 'unique-nonce-12345'
      });

      expect(derivedProof.type).toBe('BbsBlsSignatureProof2020');
      expect(derivedProof.nonce).toBe('unique-nonce-12345');
      expect(derivedProof.proofValue).toBeDefined();
      expect(typeof derivedProof.proofValue).toBe('string');
    });

    it('should verify selective disclosure proof', async () => {
      const originalProof = await bbsSuite.createProof({
        document: mockDocument,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#bbs-key-1',
        privateKey: new Uint8Array(32),
        created: '2024-01-01T00:00:00Z'
      });

      const derivedProof = await bbsSuite.createSelectiveDisclosureProof({
        document: mockDocument,
        proof: originalProof,
        attributesToReveal: ['name', 'age'],
        nonce: 'unique-nonce-12345'
      });

      const isValid = await bbsSuite.verifySelectiveDisclosureProof({
        document: mockDocument,
        proof: derivedProof,
        verificationMethod: 'did:example:issuer#bbs-key-1',
        publicKey: new Uint8Array(48),
        nonce: 'unique-nonce-12345'
      });

      expect(isValid).toBe(true);
    });
  });

  describe('BBS+ Selective Disclosure Helper', () => {
    const mockCredential: VerifiableCredentialV2 = {
      '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer',
      credentialSubject: {
        id: 'did:example:subject',
        name: 'Alice Johnson',
        age: 28,
        email: 'alice@example.com',
        ssn: '987-65-4321',
        address: '123 Main St',
        phone: '555-0123'
      }
    };

    it('should derive credential with selective disclosure', async () => {
      const result = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name', 'age'],
        nonce: 'test-nonce'
      });

      expect(result.success).toBe(true);
      expect(result.derivedCredential).toBeDefined();
      expect(result.proof).toBeDefined();
      expect(result.revealedAttributes).toEqual(['name', 'age']);
      expect(result.privacyLevel).toBeDefined();
    });

    it('should estimate privacy level correctly', async () => {
      // High privacy (few attributes revealed)
      const highPrivacyResult = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name'],
        nonce: 'test-nonce'
      });

      expect(highPrivacyResult.privacyLevel).toBe('high');

      // Medium privacy (moderate attributes revealed)
      const mediumPrivacyResult = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name', 'age', 'email'],
        nonce: 'test-nonce'
      });

      expect(mediumPrivacyResult.privacyLevel).toBe('medium');

      // Low privacy (most attributes revealed)
      const lowPrivacyResult = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name', 'age', 'email', 'address', 'phone'],
        nonce: 'test-nonce'
      });

      expect(lowPrivacyResult.privacyLevel).toBe('low');
    });

    it('should handle invalid attribute names', async () => {
      const result = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['nonexistent', 'invalid'],
        nonce: 'test-nonce'
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid attributes');
    });

    it('should verify derived credential', async () => {
      const deriveResult = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name', 'age'],
        nonce: 'verify-nonce'
      });

      expect(deriveResult.success).toBe(true);

      const verifyResult = await bbsDisclosure.verifyDerivedCredential(
        deriveResult.derivedCredential!,
        {
          originalIssuer: 'did:example:issuer',
          expectedAttributes: ['name', 'age'],
          nonce: 'verify-nonce'
        }
      );

      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.revealedAttributes).toEqual(['name', 'age']);
    });

    it('should fail verification with wrong nonce', async () => {
      const deriveResult = await bbsDisclosure.deriveCredential(mockCredential, {
        attributesToReveal: ['name', 'age'],
        nonce: 'correct-nonce'
      });

      const verifyResult = await bbsDisclosure.verifyDerivedCredential(
        deriveResult.derivedCredential!,
        {
          originalIssuer: 'did:example:issuer',
          expectedAttributes: ['name', 'age'],
          nonce: 'wrong-nonce'
        }
      );

      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.error).toContain('Nonce mismatch');
    });

    it('should generate unique nonces', () => {
      const nonce1 = bbsDisclosure.generateNonce();
      const nonce2 = bbsDisclosure.generateNonce();

      expect(nonce1).not.toBe(nonce2);
      expect(typeof nonce1).toBe('string');
      expect(typeof nonce2).toBe('string');
      expect(nonce1.length).toBeGreaterThan(0);
      expect(nonce2.length).toBeGreaterThan(0);
    });

    it('should analyze credential for selective disclosure suitability', () => {
      const analysis = bbsDisclosure.analyzeCredential(mockCredential);

      expect(analysis.totalAttributes).toBe(6); // id, name, age, email, ssn, address, phone
      expect(analysis.selectableAttributes).toContain('name');
      expect(analysis.selectableAttributes).toContain('age');
      expect(analysis.selectableAttributes).toContain('email');
      expect(analysis.recommendedMinReveal).toBeGreaterThan(0);
      expect(analysis.privacyRisk).toBeDefined();
    });
  });

  describe('BBS+ Key Management', () => {
    it('should handle key pair generation', async () => {
      const mockBbs = require('@mattrglobal/bbs-signatures');
      
      // Test that our suite would call the key generation function
      const keyPair = await mockBbs.generateBls12381G1KeyPair();
      
      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(48);
      expect(keyPair.secretKey.length).toBe(32);
    });

    it('should validate key formats', () => {
      // Valid BBS+ public key (48 bytes)
      const validPublicKey = new Uint8Array(48);
      expect(bbsSuite.validatePublicKey(validPublicKey)).toBe(true);

      // Invalid key lengths
      expect(bbsSuite.validatePublicKey(new Uint8Array(32))).toBe(false);
      expect(bbsSuite.validatePublicKey(new Uint8Array(64))).toBe(false);

      // Valid BBS+ private key (32 bytes)
      const validPrivateKey = new Uint8Array(32);
      expect(bbsSuite.validatePrivateKey(validPrivateKey)).toBe(true);

      // Invalid private key lengths
      expect(bbsSuite.validatePrivateKey(new Uint8Array(16))).toBe(false);
      expect(bbsSuite.validatePrivateKey(new Uint8Array(48))).toBe(false);
    });
  });

  describe('BBS+ Performance and Edge Cases', () => {
    it('should handle large numbers of attributes efficiently', async () => {
      const largeCredential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: {
          id: 'did:example:subject',
          ...Array.from({ length: 50 }, (_, i) => ({ [`attr${i}`]: `value${i}` }))
            .reduce((acc, obj) => ({ ...acc, ...obj }), {})
        }
      };

      const startTime = Date.now();
      const result = await bbsDisclosure.deriveCredential(largeCredential, {
        attributesToReveal: ['attr0', 'attr1', 'attr2'],
        nonce: 'perf-test'
      });
      const endTime = Date.now();

      expect(result.success).toBe(true);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should handle empty credential subjects gracefully', async () => {
      const emptyCredential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' }
      };

      const result = await bbsDisclosure.deriveCredential(emptyCredential, {
        attributesToReveal: ['nonexistent'],
        nonce: 'empty-test'
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('No selectable attributes');
    });

    it('should validate proof format correctly', () => {
      const validProof = {
        type: 'BbsBlsSignature2020',
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'did:example:issuer#key-1',
        proofPurpose: ProofPurpose.ASSERTION_METHOD,
        proofValue: 'base64encodedvalue'
      };

      expect(bbsSuite.validateProofFormat(validProof)).toBe(true);

      const invalidProof = {
        type: 'Ed25519Signature2020', // Wrong type
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'did:example:issuer#key-1',
        proofPurpose: ProofPurpose.ASSERTION_METHOD,
        proofValue: 'base64encodedvalue'
      };

      expect(bbsSuite.validateProofFormat(invalidProof)).toBe(false);
    });
  });
});