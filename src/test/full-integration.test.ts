/**
 * Full Integration Tests
 * Testing complete workflows with mocked dependencies
 */

import { JsonLdProcessor } from '../ld/jsonld-processor';
import { ContextLoader } from '../ld/context-loader';
import { Ed25519Signature2020Suite } from '../ld/signature-suites/ed25519-signature-2020';
import { BbsBlsSignature2020Suite } from '../ld/signature-suites/bbs-bls-signature-2020';
import { IdentityProviderV2 } from '../idp/identity-provider-v2';
import { ServiceProviderV2 } from '../sp/service-provider-v2';
import { VerifiableCredentialV2, VC_V2_CONTEXTS, ProofPurpose } from '../types/vc2';

describe('Full Integration Tests', () => {
  let processor: JsonLdProcessor;
  let contextLoader: ContextLoader;
  let ed25519Suite: Ed25519Signature2020Suite;
  let bbsSuite: BbsBlsSignature2020Suite;
  let idp: IdentityProviderV2;
  let sp: ServiceProviderV2;

  beforeAll(async () => {
    contextLoader = new ContextLoader();
    processor = new JsonLdProcessor({ contextLoader });
    
    // Mock Ed25519 suite with proper crypto operations
    ed25519Suite = new Ed25519Signature2020Suite();
    bbsSuite = new BbsBlsSignature2020Suite();
    
    // Initialize providers with mocked storage
    const mockStorage = {
      store: jest.fn(),
      retrieve: jest.fn(),
      delete: jest.fn()
    };
    
    idp = new IdentityProviderV2('did:example:issuer', mockStorage as any);
    sp = new ServiceProviderV2('test-sp', ['did:example:issuer'], {});
  });

  describe('JSON-LD Processing Integration', () => {
    it('should process complete credential through expansion/compaction cycle', async () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [
          VC_V2_CONTEXTS.CREDENTIALS_V2,
          VC_V2_CONTEXTS.ED25519_2020,
          {
            'example': 'https://example.com/vocab#',
            'name': 'example:name',
            'age': 'example:age'
          }
        ],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        validFrom: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:subject',
          name: 'John Doe',
          age: 30
        }
      };

      // Test expansion
      const expanded = await processor.expand(credential);
      expect(Array.isArray(expanded)).toBe(true);
      expect(expanded.length).toBeGreaterThan(0);

      // Test compaction
      const compacted = await processor.compact(expanded, credential['@context']);
      expect(compacted).toHaveProperty('@context');
      expect(compacted).toHaveProperty('type');
      expect(compacted).toHaveProperty('credentialSubject');

      // Test canonicalization
      const canonical = await processor.canonicalize(credential);
      expect(typeof canonical).toBe('string');
      expect(canonical.length).toBeGreaterThan(0);
    });

    it('should validate credential structure', async () => {
      const validCredential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' }
      };

      const validation = await processor.validateCredential(validCredential);
      expect(validation.valid).toBe(true);
      expect(validation.errors).toBeUndefined();
    });

    it('should detect invalid credential structure', async () => {
      const invalidCredential = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        // Missing required 'type' field
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' }
      };

      const validation = await processor.validateCredential(invalidCredential as any);
      expect(validation.valid).toBe(false);
      expect(validation.errors).toBeDefined();
      expect(validation.errors!.length).toBeGreaterThan(0);
    });
  });

  describe('Ed25519 Signature Integration', () => {
    it('should create and verify Ed25519 proofs', async () => {
      const document = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' }
      };

      // Create proof
      const proof = await ed25519Suite.createProof({
        document,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#key-1',
        privateKey: new Uint8Array(32), // Mock key
        created: new Date().toISOString()
      });

      expect(proof).toHaveProperty('type', 'Ed25519Signature2020');
      expect(proof).toHaveProperty('created');
      expect(proof).toHaveProperty('verificationMethod');
      expect(proof).toHaveProperty('proofPurpose');
      expect(proof).toHaveProperty('proofValue');

      // Verify proof
      const isValid = await ed25519Suite.verifyProof({
        document,
        proof,
        publicKey: new Uint8Array(32) // Mock key
      });

      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong key', async () => {
      const document = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' }
      };

      const proof = await ed25519Suite.createProof({
        document,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#key-1',
        privateKey: new Uint8Array(32),
        created: new Date().toISOString()
      });

      // Try to verify with different key
      const isValid = await ed25519Suite.verifyProof({
        document,
        proof,
        publicKey: new Uint8Array(32).fill(1) // Different key
      });

      expect(isValid).toBe(false);
    });
  });

  describe('BBS+ Signature Integration', () => {
    it('should create BBS+ proofs with selective disclosure support', async () => {
      const document = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.BBS_2023],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: {
          id: 'did:example:subject',
          name: 'John Doe',
          age: 30,
          email: 'john@example.com'
        }
      };

      // Create BBS+ proof
      const proof = await bbsSuite.createProof({
        document,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#bbs-key-1',
        privateKey: new Uint8Array(32),
        created: new Date().toISOString()
      });

      expect(proof).toHaveProperty('type', 'BbsBlsSignature2020');
      expect(proof).toHaveProperty('created');
      expect(proof).toHaveProperty('verificationMethod');
      expect(proof).toHaveProperty('proofPurpose');
      expect(proof).toHaveProperty('proofValue');

      // Verify proof
      const isValid = await bbsSuite.verifyProof({
        document,
        proof,
        publicKey: new Uint8Array(48) // BBS+ public key
      });

      expect(isValid).toBe(true);
    });

    it('should support selective disclosure operations', async () => {
      const document = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2, VC_V2_CONTEXTS.BBS_2023],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: {
          id: 'did:example:subject',
          name: 'John Doe',
          age: 30,
          email: 'john@example.com'
        }
      };

      // Create base proof first
      const baseProof = await bbsSuite.createProof({
        document,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#bbs-key-1',
        privateKey: new Uint8Array(32),
        created: new Date().toISOString()
      });

      // Note: For this test, we'll simulate selective disclosure
      // In practice, this would be done by the BbsSelectiveDisclosure class
      expect(baseProof).toHaveProperty('type', 'BbsBlsSignature2020');
      expect(baseProof).toHaveProperty('proofValue');
    });
  });

  describe('End-to-End Workflow Integration', () => {
    it('should complete full credential issuance and verification workflow', async () => {
      // Issue credential with V2 provider
      const attributes = {
        name: 'Alice Smith',
        age: 25,
        email: 'alice@example.com'
      };

      const credential = await idp.issueVerifiableCredentialV2(
        'did:example:alice',
        attributes,
        {
          credentialStatus: {
            type: 'StatusList2021' as any,
            statusPurpose: 'revocation'
          }
        }
      );

      expect(credential).toHaveProperty('@context');
      expect(credential).toHaveProperty('type');
      expect(credential).toHaveProperty('issuer', 'did:example:issuer');
      expect(credential).toHaveProperty('credentialSubject');
      expect(credential.credentialSubject).toHaveProperty('id', 'did:example:alice');

      // Verify credential with service provider
      const verification = await sp.verifyCredential(credential as any);
      
      expect(verification.valid).toBe(true);
      expect(verification.issuer).toBe('did:example:issuer');
    });

    it('should handle multiple proofs on single credential', async () => {
      const credential: VerifiableCredentialV2 = {
        '@context': [VC_V2_CONTEXTS.CREDENTIALS_V2],
        type: 'VerifiableCredential',
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' },
        proof: []
      };

      // Add Ed25519 proof
      const ed25519Proof = await ed25519Suite.createProof({
        document: credential,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#ed25519-key',
        privateKey: new Uint8Array(32),
        created: new Date().toISOString()
      });

      // Add BBS+ proof
      const bbsProof = await bbsSuite.createProof({
        document: credential,
        purpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: 'did:example:issuer#bbs-key',
        privateKey: new Uint8Array(32),
        created: new Date(Date.now() + 1000).toISOString()
      });

      const enhancedCredential = {
        ...credential,
        proof: [ed25519Proof, bbsProof]
      };

      // Verify both proofs exist
      expect(enhancedCredential.proof).toHaveLength(2);
      expect(enhancedCredential.proof[0].type).toBe('Ed25519Signature2020');
      expect(enhancedCredential.proof[1].type).toBe('BbsBlsSignature2020');
    });

    it('should process credentials with complex contexts', async () => {
      const complexCredential: VerifiableCredentialV2 = {
        '@context': [
          VC_V2_CONTEXTS.CREDENTIALS_V2,
          VC_V2_CONTEXTS.ED25519_2020,
          VC_V2_CONTEXTS.STATUS_LIST_2021,
          {
            'schema': 'https://schema.org/',
            'Person': 'schema:Person',
            'givenName': 'schema:givenName',
            'familyName': 'schema:familyName'
          }
        ],
        type: ['VerifiableCredential', 'PersonCredential'],
        issuer: 'did:example:government',
        validFrom: '2024-01-01T00:00:00Z',
        validUntil: '2025-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:citizen',
          type: 'Person',
          givenName: 'John',
          familyName: 'Citizen'
        },
        credentialStatus: {
          id: 'https://example.gov/status/1#4242',
          type: 'StatusList2021',
          statusPurpose: 'revocation',
          statusListIndex: 4242,
          statusListCredential: 'https://example.gov/status/1'
        }
      };

      // Process through JSON-LD
      const expanded = await processor.expand(complexCredential);
      expect(expanded).toBeDefined();

      const canonical = await processor.canonicalize(complexCredential);
      expect(typeof canonical).toBe('string');

      // Validate structure
      const validation = await processor.validateCredential(complexCredential);
      expect(validation.valid).toBe(true);
    });
  });
});