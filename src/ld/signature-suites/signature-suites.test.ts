import { Ed25519Signature2020Suite } from './ed25519-signature-2020';
import { BbsBlsSignature2020Suite } from './bbs-bls-signature-2020';
import { SignatureSuiteRegistry, KeyType } from './signature-suite';
import { ProofPurpose } from '../../types/vc2';
import { CryptoService } from '../../core/crypto';

describe('Ed25519Signature2020Suite', () => {
  let suite: Ed25519Signature2020Suite;
  let keyPair: { publicKey: Uint8Array; privateKey: Uint8Array };
  
  beforeAll(async () => {
    suite = new Ed25519Signature2020Suite();
    keyPair = await CryptoService.generateKeyPair();
  });
  
  describe('createProof and verifyProof', () => {
    it('should create and verify a valid proof', async () => {
      const document = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        type: 'VerifiableCredential',
        issuer: 'did:example:123',
        credentialSubject: {
          id: 'did:example:456',
          name: 'Test User'
        }
      };
      
      // Create proof
      const proof = await suite.createProof({
        document,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:123#key-1',
        privateKey: keyPair.privateKey
      });
      
      expect(proof.type).toBe('Ed25519Signature2020');
      expect(proof.proofPurpose).toBe(ProofPurpose.ASSERTION_METHOD);
      expect(proof.proofValue).toBeDefined();
      expect(typeof proof.proofValue).toBe('string');
      
      // Verify proof
      const isValid = await suite.verifyProof({
        document,
        proof,
        publicKey: keyPair.publicKey,
        expectedPurpose: ProofPurpose.ASSERTION_METHOD
      });
      
      expect(isValid).toBe(true);
    });
    
    it('should fail verification with wrong public key', async () => {
      const document = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        type: 'VerifiableCredential',
        issuer: 'did:example:123'
      };
      
      const proof = await suite.createProof({
        document,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:123#key-1',
        privateKey: keyPair.privateKey
      });
      
      // Generate different key pair
      const wrongKeyPair = await CryptoService.generateKeyPair();
      
      const isValid = await suite.verifyProof({
        document,
        proof,
        publicKey: wrongKeyPair.publicKey,
        expectedPurpose: ProofPurpose.ASSERTION_METHOD
      });
      
      expect(isValid).toBe(false);
    });
    
    it('should fail verification with modified document', async () => {
      const document = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        type: 'VerifiableCredential',
        issuer: 'did:example:123',
        value: 'original'
      };
      
      const proof = await suite.createProof({
        document,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:123#key-1',
        privateKey: keyPair.privateKey
      });
      
      // Modify document
      const modifiedDoc = { ...document, value: 'modified' };
      
      const isValid = await suite.verifyProof({
        document: modifiedDoc,
        proof,
        publicKey: keyPair.publicKey,
        expectedPurpose: ProofPurpose.ASSERTION_METHOD
      });
      
      expect(isValid).toBe(false);
    });
    
    it('should support challenge and domain', async () => {
      const document = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        type: 'VerifiablePresentation'
      };
      
      const challenge = 'test-challenge-123';
      const domain = 'https://example.com';
      
      const proof = await suite.createProof({
        document,
        purpose: ProofPurpose.AUTHENTICATION,
        verificationMethod: 'did:example:123#key-1',
        privateKey: keyPair.privateKey,
        challenge,
        domain
      });
      
      expect(proof.challenge).toBe(challenge);
      expect(proof.domain).toBe(domain);
      
      // Verify with correct challenge/domain
      const isValid = await suite.verifyProof({
        document,
        proof,
        publicKey: keyPair.publicKey,
        expectedPurpose: ProofPurpose.AUTHENTICATION,
        expectedChallenge: challenge,
        expectedDomain: domain
      });
      
      expect(isValid).toBe(true);
      
      // Verify with wrong challenge
      const isInvalid = await suite.verifyProof({
        document,
        proof,
        publicKey: keyPair.publicKey,
        expectedPurpose: ProofPurpose.AUTHENTICATION,
        expectedChallenge: 'wrong-challenge',
        expectedDomain: domain
      });
      
      expect(isInvalid).toBe(false);
    });
    
    it('should handle proof expiration', async () => {
      const document = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        type: 'VerifiableCredential'
      };
      
      // Create proof that expires in the past
      const proof = await suite.createProof({
        document,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:123#key-1',
        privateKey: keyPair.privateKey,
        expires: new Date(Date.now() - 1000).toISOString() // 1 second ago
      });
      
      const isValid = await suite.verifyProof({
        document,
        proof,
        publicKey: keyPair.publicKey,
        expectedPurpose: ProofPurpose.ASSERTION_METHOD
      });
      
      expect(isValid).toBe(false);
    });
  });
  
  describe('selective disclosure', () => {
    it('should not support selective disclosure', async () => {
      expect(suite.supportsSelectiveDisclosure).toBe(false);
      
      await expect(suite.createDerivedProof({
        document: {},
        proof: {} as any,
        revealedAttributes: []
      })).rejects.toThrow('does not support selective disclosure');
    });
  });
});

describe('BbsBlsSignature2020Suite', () => {
  let suite: BbsBlsSignature2020Suite;
  let keyPair: { publicKey: Uint8Array; privateKey: Uint8Array };
  
  beforeAll(async () => {
    suite = new BbsBlsSignature2020Suite();
    // Note: In real tests, you'd generate actual BLS12-381 G2 keys
    // For now, we'll skip the actual BBS+ tests as they require proper key generation
  });
  
  describe('properties', () => {
    it('should have correct properties', () => {
      expect(suite.type).toBe('BbsBlsSignature2020');
      expect(suite.requiredKeyType).toBe(KeyType.BLS12381G2);
      expect(suite.supportsSelectiveDisclosure).toBe(true);
    });
  });
  
  // Note: Actual BBS+ signature tests would require proper BLS12-381 G2 key generation
  // and would be more complex. For now, we're testing the structure.
});

describe('SignatureSuiteRegistry', () => {
  beforeAll(() => {
    // Register suites
    SignatureSuiteRegistry.register('Ed25519Signature2020', Ed25519Signature2020Suite);
    SignatureSuiteRegistry.register('BbsBlsSignature2020', BbsBlsSignature2020Suite);
  });
  
  it('should register and retrieve suites', () => {
    expect(SignatureSuiteRegistry.hasSuite('Ed25519Signature2020')).toBe(true);
    expect(SignatureSuiteRegistry.hasSuite('BbsBlsSignature2020')).toBe(true);
    expect(SignatureSuiteRegistry.hasSuite('UnknownSuite')).toBe(false);
  });
  
  it('should get suite instance', () => {
    const ed25519Suite = SignatureSuiteRegistry.getSuite('Ed25519Signature2020');
    expect(ed25519Suite).toBeInstanceOf(Ed25519Signature2020Suite);
    
    const bbsSuite = SignatureSuiteRegistry.getSuite('BbsBlsSignature2020');
    expect(bbsSuite).toBeInstanceOf(BbsBlsSignature2020Suite);
  });
  
  it('should throw for unknown suite', () => {
    expect(() => SignatureSuiteRegistry.getSuite('UnknownSuite'))
      .toThrow('Unknown signature suite: UnknownSuite');
  });
  
  it('should list registered types', () => {
    const types = SignatureSuiteRegistry.getRegisteredTypes();
    expect(types).toContain('Ed25519Signature2020');
    expect(types).toContain('BbsBlsSignature2020');
  });
});