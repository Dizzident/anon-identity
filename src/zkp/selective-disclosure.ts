import * as crypto from 'crypto';
import { 
  VerifiableCredential, 
  SelectivelyDisclosedCredential,
  SelectiveDisclosureRequest 
} from '../types';
import { CryptoService } from '../core/crypto';
import { SignJWT, importJWK, jwtVerify } from 'jose';

export class SelectiveDisclosure {
  /**
   * Create a selectively disclosed credential revealing only specified attributes
   */
  static async createSelectivelyDisclosedCredential(
    originalCredential: VerifiableCredential,
    attributesToDisclose: string[],
    holderPrivateKey: Uint8Array,
    holderDID: string
  ): Promise<SelectivelyDisclosedCredential> {
    // Validate that requested attributes exist in the credential
    const availableAttributes = Object.keys(originalCredential.credentialSubject)
      .filter(key => key !== 'id');
    
    for (const attr of attributesToDisclose) {
      if (!availableAttributes.includes(attr)) {
        throw new Error(`Attribute '${attr}' not found in credential`);
      }
    }
    
    // Create disclosed credential subject with only requested attributes
    const disclosedSubject: any = {
      id: originalCredential.credentialSubject.id
    };
    
    for (const attr of attributesToDisclose) {
      disclosedSubject[attr] = originalCredential.credentialSubject[attr];
    }
    
    // Generate a nonce for this disclosure
    const nonce = crypto.randomBytes(32).toString('base64');
    
    // Create proof of selective disclosure
    const disclosureData = {
      originalCredentialId: originalCredential.id,
      issuer: originalCredential.issuer,
      issuanceDate: originalCredential.issuanceDate,
      disclosedAttributes: attributesToDisclose,
      nonce,
      timestamp: new Date().toISOString()
    };
    
    // Sign the disclosure proof with holder's private key
    const proofValue = await this.createDisclosureProof(
      disclosureData,
      holderPrivateKey,
      holderDID
    );
    
    // Create the selectively disclosed credential
    const disclosedCredential: SelectivelyDisclosedCredential = {
      "@context": originalCredential["@context"],
      id: `${originalCredential.id}#disclosed-${Date.now()}`,
      type: [...originalCredential.type, "SelectivelyDisclosedCredential"],
      issuer: originalCredential.issuer,
      issuanceDate: originalCredential.issuanceDate,
      credentialSubject: disclosedSubject,
      proof: originalCredential.proof, // Keep original issuer's proof
      disclosureProof: {
        type: "SelectiveDisclosureProof2024",
        originalCredentialId: originalCredential.id,
        disclosedAttributes: attributesToDisclose,
        nonce,
        proofValue
      }
    };
    
    return disclosedCredential;
  }
  
  /**
   * Create a cryptographic proof for the selective disclosure
   */
  private static async createDisclosureProof(
    disclosureData: any,
    privateKey: Uint8Array,
    holderDID: string
  ): Promise<string> {
    // Convert private key to JWK format
    const publicKey = await CryptoService.getPublicKeyFromPrivate(privateKey);
    const privateKeyJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(publicKey).toString('base64url'),
      d: Buffer.from(privateKey).toString('base64url')
    };
    
    const key = await importJWK(privateKeyJwk, 'EdDSA');
    
    // Create JWT proof
    const jwt = await new SignJWT(disclosureData)
      .setProtectedHeader({ 
        alg: 'EdDSA',
        typ: 'DisclosureProof',
        kid: `${holderDID}#key-1`
      })
      .setIssuedAt()
      .setIssuer(holderDID)
      .sign(key);
    
    return jwt;
  }
  
  /**
   * Verify a selective disclosure proof
   */
  static async verifySelectiveDisclosure(
    disclosedCredential: SelectivelyDisclosedCredential,
    holderPublicKey: Uint8Array
  ): Promise<boolean> {
    try {
      if (!disclosedCredential.disclosureProof) {
        return false;
      }
      
      // Verify the disclosure proof JWT
      const publicKeyJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(holderPublicKey).toString('base64url')
      };
      
      const key = await importJWK(publicKeyJwk, 'EdDSA');
      
      const { payload } = await jwtVerify(
        disclosedCredential.disclosureProof.proofValue,
        key,
        { algorithms: ['EdDSA'] }
      );
      
      // Verify the disclosed attributes match what's claimed
      const claimedAttributes = disclosedCredential.disclosureProof.disclosedAttributes;
      const actualAttributes = Object.keys(disclosedCredential.credentialSubject)
        .filter(key => key !== 'id');
      
      if (!this.arraysEqual(claimedAttributes.sort(), actualAttributes.sort())) {
        return false;
      }
      
      // Verify the original credential ID matches
      if (payload.originalCredentialId !== disclosedCredential.disclosureProof.originalCredentialId) {
        return false;
      }
      
      return true;
    } catch (error) {
      return false;
    }
  }
  
  /**
   * Create a commitment to a value (for future ZKP enhancement)
   */
  static createCommitment(value: any, salt?: string): string {
    const actualSalt = salt || crypto.randomBytes(32).toString('base64');
    const data = JSON.stringify({ value, salt: actualSalt });
    return crypto.createHash('sha256').update(data).digest('base64');
  }
  
  /**
   * Verify a commitment (for future ZKP enhancement)
   */
  static verifyCommitment(value: any, salt: string, commitment: string): boolean {
    const computedCommitment = this.createCommitment(value, salt);
    return computedCommitment === commitment;
  }
  
  private static arraysEqual(a: string[], b: string[]): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

// Add helper to CryptoService
export async function getPublicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array> {
  const ed = await import('@noble/ed25519');
  return await ed.getPublicKey(privateKey);
}