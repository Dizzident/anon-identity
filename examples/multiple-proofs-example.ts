import { IdentityProviderV2 } from '../src/idp/identity-provider-v2';
import { UserWallet } from '../src/wallet/user-wallet';
import { CryptoService } from '../src/core/crypto';
import { DIDService } from '../src/core/did';
import { ProofPurpose, Proof } from '../src/types/vc2';
import { ProofManager } from '../src/core/proof-manager';
import { SignJWT, importJWK } from 'jose';

async function demonstrateMultipleProofs() {
  console.log('=== Multiple Proofs Demo ===\n');
  
  // 1. Create Identity Provider (issuer)
  const idp = await IdentityProviderV2.create();
  console.log('Issuer DID:', idp.getDID());
  
  // 2. Create User Wallet
  const wallet = await UserWallet.create();
  console.log('User DID:', wallet.getDID());
  
  // 3. Create additional verifiers/endorsers
  const notaryKeyPair = await CryptoService.generateKeyPair();
  const notaryDID = DIDService.createDIDKey(notaryKeyPair.publicKey);
  console.log('Notary DID:', notaryDID.id);
  
  const regulatorKeyPair = await CryptoService.generateKeyPair();
  const regulatorDID = DIDService.createDIDKey(regulatorKeyPair.publicKey);
  console.log('Regulator DID:', regulatorDID.id);
  
  // 4. Issue credential with initial issuer proof
  console.log('\n--- Issuing Credential ---');
  const credential = await idp.issueVerifiableCredentialV2(
    wallet.getDID(),
    {
      givenName: 'Bob',
      dateOfBirth: '1985-06-15',
      licenseNumber: 'DL-987654321'
    }
  );
  
  console.log('Credential issued with issuer proof');
  console.log('Initial proofs:', ProofManager.getProofs(credential).length);
  
  // 5. Add notary endorsement proof
  console.log('\n--- Adding Notary Endorsement ---');
  const notaryProof = await createEndorsementProof(
    credential,
    notaryDID,
    notaryKeyPair,
    'Notarized and verified original documents'
  );
  
  let endorsedCredential = ProofManager.addProof(credential, notaryProof);
  console.log('Proofs after notary:', ProofManager.getProofs(endorsedCredential).length);
  
  // 6. Add regulatory compliance proof
  console.log('\n--- Adding Regulatory Compliance ---');
  const regulatorProof = await createComplianceProof(
    endorsedCredential,
    regulatorDID,
    regulatorKeyPair,
    'Compliant with KYC/AML regulations'
  );
  
  endorsedCredential = ProofManager.addProof(endorsedCredential, regulatorProof);
  console.log('Proofs after regulator:', ProofManager.getProofs(endorsedCredential).length);
  
  // 7. Analyze the proofs
  console.log('\n--- Analyzing Proofs ---');
  const allProofs = ProofManager.getProofs(endorsedCredential);
  
  console.log('\nProof Details:');
  allProofs.forEach((proof, index) => {
    console.log(`\nProof ${index + 1}:`);
    console.log('- Type:', proof.type);
    console.log('- Purpose:', proof.proofPurpose);
    console.log('- Created:', proof.created);
    console.log('- Verifier:', proof.verificationMethod.split('#')[0]);
  });
  
  // 8. Find proofs by purpose
  console.log('\n--- Finding Proofs by Purpose ---');
  const assertionProofs = ProofManager.findProofsByPurpose(
    endorsedCredential, 
    ProofPurpose.ASSERTION_METHOD
  );
  console.log('Assertion proofs:', assertionProofs.length);
  
  const endorsementProofs = ProofManager.findProofsByPurpose(
    endorsedCredential,
    'endorsement' // Custom purpose
  );
  console.log('Endorsement proofs:', endorsementProofs.length);
  
  // 9. Validate proof chain
  console.log('\n--- Validating Proof Chain ---');
  const chainValidation = ProofManager.validateProofChain(allProofs);
  console.log('Proof chain valid:', chainValidation.valid);
  if (!chainValidation.valid) {
    console.log('Errors:', chainValidation.errors);
  }
  
  // 10. Check for specific verifier endorsements
  console.log('\n--- Checking Verifier Endorsements ---');
  const hasNotaryEndorsement = ProofManager.hasValidProofForPurpose(
    endorsedCredential,
    'endorsement',
    [notaryDID.id]
  );
  console.log('Has notary endorsement:', hasNotaryEndorsement);
  
  const hasRegulatoryCompliance = ProofManager.hasValidProofForPurpose(
    endorsedCredential,
    'compliance',
    [regulatorDID.id]
  );
  console.log('Has regulatory compliance:', hasRegulatoryCompliance);
  
  // 11. Store the multi-proof credential
  await wallet.storeCredential(endorsedCredential as any);
  console.log('\n✅ Multi-proof credential stored in wallet');
}

// Helper function to create endorsement proof
async function createEndorsementProof(
  credential: any,
  endorserDID: { id: string; publicKey: Uint8Array },
  endorserKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array },
  endorsementNote: string
): Promise<Proof> {
  // Create endorsement claim
  const endorsement = {
    credentialId: credential.id,
    endorser: endorserDID.id,
    endorsementNote,
    endorsedAt: new Date().toISOString(),
    credentialHash: 'hash-of-credential' // In practice, compute actual hash
  };
  
  // Sign the endorsement
  const privateKeyJwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(endorserKeyPair.publicKey).toString('base64url'),
    d: Buffer.from(endorserKeyPair.privateKey).toString('base64url')
  };
  
  const privateKey = await importJWK(privateKeyJwk, 'EdDSA');
  
  const jwt = await new SignJWT(endorsement)
    .setProtectedHeader({ 
      alg: 'EdDSA',
      typ: 'JWT',
      kid: `${endorserDID.id}#key-1`
    })
    .setIssuedAt()
    .setIssuer(endorserDID.id)
    .sign(privateKey);
  
  return {
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: `${endorserDID.id}#key-1`,
    proofPurpose: 'endorsement', // Custom proof purpose
    jws: jwt,
    endorsementNote // Additional metadata
  };
}

// Helper function to create compliance proof
async function createComplianceProof(
  credential: any,
  regulatorDID: { id: string; publicKey: Uint8Array },
  regulatorKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array },
  complianceNote: string
): Promise<Proof> {
  // Create compliance attestation
  const compliance = {
    credentialId: credential.id,
    regulator: regulatorDID.id,
    complianceNote,
    regulations: ['KYC', 'AML', 'GDPR'],
    verifiedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString() // 1 year
  };
  
  // Sign the compliance attestation
  const privateKeyJwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(regulatorKeyPair.publicKey).toString('base64url'),
    d: Buffer.from(regulatorKeyPair.privateKey).toString('base64url')
  };
  
  const privateKey = await importJWK(privateKeyJwk, 'EdDSA');
  
  const jwt = await new SignJWT(compliance)
    .setProtectedHeader({ 
      alg: 'EdDSA',
      typ: 'JWT',
      kid: `${regulatorDID.id}#key-1`
    })
    .setIssuedAt()
    .setIssuer(regulatorDID.id)
    .setExpirationTime('1y')
    .sign(privateKey);
  
  return {
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: `${regulatorDID.id}#key-1`,
    proofPurpose: 'compliance', // Custom proof purpose
    jws: jwt,
    expires: compliance.expiresAt,
    regulations: compliance.regulations // Additional metadata
  } as Proof;
}

// Run the demo
demonstrateMultipleProofs().catch(console.error);