import { IdentityProviderV2 } from '../src/idp/identity-provider-v2';
import { UserWallet } from '../src/wallet/user-wallet';
import { ServiceProviderV2 } from '../src/sp/service-provider-v2';
import { JsonLdProcessor } from '../src/ld/jsonld-processor';
import { ContextLoader } from '../src/ld/context-loader';
import { Ed25519Signature2020Suite } from '../src/ld/signature-suites/ed25519-signature-2020';
import { SignatureSuiteRegistry } from '../src/ld/signature-suites/signature-suite';
import { ProofPurpose } from '../src/types/vc2';
import { ProofManager } from '../src/core/proof-manager';

async function demonstrateAdvancedStandards() {
  console.log('=== Advanced Standards Compliance Demo ===\n');
  
  // Register signature suites
  SignatureSuiteRegistry.register('Ed25519Signature2020', Ed25519Signature2020Suite);
  
  // 1. Initialize components with JSON-LD support
  const contextLoader = new ContextLoader({
    maxCacheSize: 50,
    cacheTTL: 3600000 // 1 hour
  });
  
  const jsonLdProcessor = new JsonLdProcessor({ contextLoader });
  
  // 2. Create Identity Provider
  const idp = await IdentityProviderV2.create();
  console.log('Identity Provider DID:', idp.getDID());
  
  // 3. Create User Wallet
  const wallet = await UserWallet.create();
  console.log('User DID:', wallet.getDID());
  
  // 4. Issue a credential with JSON-LD validation
  console.log('\n--- Issuing Credential with JSON-LD Validation ---');
  
  const credential = await idp.issueVerifiableCredentialV2(
    wallet.getDID(),
    {
      givenName: 'Alice',
      familyName: 'Smith',
      dateOfBirth: '1990-05-15',
      emailAddresses: [{
        email: 'alice.smith@example.com',
        type: 'work',
        isPrimary: true,
        verified: true
      }],
      jobTitle: 'Software Engineer',
      employer: 'Tech Corp'
    },
    {
      additionalContexts: [
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ]
    }
  );
  
  console.log('Credential issued:', credential.id);
  
  // 5. Validate JSON-LD structure
  console.log('\n--- Validating JSON-LD Structure ---');
  
  const validation = await jsonLdProcessor.validateCredential(credential);
  console.log('JSON-LD valid:', validation.valid);
  if (!validation.valid) {
    console.log('Validation errors:', validation.errors);
  }
  
  // 6. Expand and compact the credential
  console.log('\n--- JSON-LD Processing ---');
  
  const expanded = await jsonLdProcessor.expand(credential);
  console.log('Expanded statements:', expanded.length);
  
  const compacted = await jsonLdProcessor.compact(
    expanded,
    'https://www.w3.org/ns/credentials/v2'
  );
  console.log('Compacted type:', compacted.type);
  
  // 7. Canonicalize for consistent hashing
  const canonical = await jsonLdProcessor.canonicalize(credential);
  console.log('Canonical form length:', canonical.length);
  console.log('First 100 chars:', canonical.substring(0, 100) + '...');
  
  // 8. Extract claims from the credential
  console.log('\n--- Extracting Claims ---');
  
  const claims = await jsonLdProcessor.extractClaims(credential);
  console.log('Total claims extracted:', claims.size);
  
  // 9. Create additional proof using Linked Data Proofs
  console.log('\n--- Adding Linked Data Proof ---');
  
  const suite = new Ed25519Signature2020Suite({ jsonLdProcessor });
  
  // Create a notary attestation proof
  const notaryKeyPair = await wallet.getKeyPair(); // In real scenario, this would be notary's keys
  
  const notaryProof = await suite.createProof({
    document: credential,
    purpose: 'endorsement' as ProofPurpose,
    verificationMethod: `${wallet.getDID()}#key-1`,
    privateKey: notaryKeyPair.privateKey,
    created: new Date().toISOString()
  });
  
  // Add the proof to the credential
  const multiProofCredential = ProofManager.addProof(credential, notaryProof);
  console.log('Total proofs:', ProofManager.getProofs(multiProofCredential).length);
  
  // 10. Store credential
  await wallet.storeCredential(multiProofCredential as any);
  
  // 11. Create Service Provider with JSON-LD validation
  const sp = new ServiceProviderV2('VerifierService', [idp.getDID()], {
    checkCredentialStatus: true
  });
  
  // 12. Create and verify presentation
  console.log('\n--- Creating and Verifying Presentation ---');
  
  const presentation = await wallet.createPresentation([credential.id!]);
  
  // Validate presentation JSON-LD
  const presentationValidation = await jsonLdProcessor.validatePresentation(presentation as any);
  console.log('Presentation JSON-LD valid:', presentationValidation.valid);
  
  // Verify presentation
  const result = await sp.verifyPresentationV2(presentation);
  console.log('Verification result:', result.valid);
  
  // 13. Demonstrate context caching
  console.log('\n--- Context Loader Statistics ---');
  
  const stats = contextLoader.getCacheStats();
  console.log('Cache size:', stats.size);
  console.log('Cache hits:', stats.hits);
  console.log('Cache misses:', stats.misses);
  
  // 14. Custom context example
  console.log('\n--- Custom Context Example ---');
  
  const customContext = {
    '@context': {
      '@version': 1.1,
      'tech': 'https://example.com/tech-vocabulary#',
      'jobTitle': 'tech:jobTitle',
      'employer': 'tech:employer',
      'programmingLanguages': {
        '@id': 'tech:programmingLanguages',
        '@container': '@list'
      }
    }
  };
  
  contextLoader.addContext('https://example.com/tech-context', customContext);
  
  // Create credential with custom context
  const techCredential = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://example.com/tech-context'
    ],
    type: 'VerifiableCredential',
    issuer: idp.getDID(),
    credentialSubject: {
      id: wallet.getDID(),
      jobTitle: 'Senior Developer',
      employer: 'Tech Corp',
      programmingLanguages: ['TypeScript', 'Python', 'Rust']
    }
  };
  
  // Validate with custom context
  const techExpanded = await jsonLdProcessor.expand(techCredential);
  console.log('Tech credential expanded successfully');
  
  // 15. Signature suite registry
  console.log('\n--- Signature Suite Registry ---');
  
  const registeredSuites = SignatureSuiteRegistry.getRegisteredTypes();
  console.log('Registered suites:', registeredSuites);
  
  // Get suite from registry
  const registrySuite = SignatureSuiteRegistry.getSuite('Ed25519Signature2020');
  console.log('Suite from registry:', registrySuite.type);
  
  console.log('\n✅ Advanced standards compliance demo completed!');
}

// Run the demo
demonstrateAdvancedStandards().catch(console.error);