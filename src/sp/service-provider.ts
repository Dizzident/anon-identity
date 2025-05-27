import { jwtVerify, importJWK } from 'jose';
import { VerifiablePresentation, VerifiableCredential } from '../types';
import { DIDService } from '../core/did';

export interface VerificationResult {
  valid: boolean;
  holder?: string;
  credentials?: Array<{
    id: string;
    issuer: string;
    type: string[];
    attributes: Record<string, any>;
  }>;
  errors?: string[];
}

export class ServiceProvider {
  private trustedIssuers: Set<string>;
  private name: string;
  
  constructor(name: string, trustedIssuers: string[] = []) {
    this.name = name;
    this.trustedIssuers = new Set(trustedIssuers);
  }
  
  async verifyPresentation(presentation: VerifiablePresentation): Promise<VerificationResult> {
    const errors: string[] = [];
    
    try {
      // 1. Verify the presentation signature
      if (!presentation.proof?.jws) {
        return {
          valid: false,
          errors: ['Presentation missing proof']
        };
      }
      
      // Extract holder DID from proof
      const holderDID = presentation.proof.verificationMethod.split('#')[0];
      
      // Verify presentation JWT
      const isPresentationValid = await this.verifyJWT(presentation.proof.jws, holderDID);
      if (!isPresentationValid.valid) {
        return {
          valid: false,
          errors: [`Invalid presentation signature: ${isPresentationValid.error}`]
        };
      }
      
      // 2. Verify each credential in the presentation
      const verifiedCredentials = [];
      
      for (const credential of presentation.verifiableCredential) {
        const credResult = await this.verifyCredential(credential);
        
        if (!credResult.valid) {
          errors.push(`Credential ${credential.id} verification failed: ${credResult.error}`);
          continue;
        }
        
        // Check if issuer is trusted
        if (!this.trustedIssuers.has(credential.issuer)) {
          errors.push(`Credential ${credential.id} from untrusted issuer: ${credential.issuer}`);
          continue;
        }
        
        // Extract relevant attributes
        const { id, ...attributes } = credential.credentialSubject;
        verifiedCredentials.push({
          id: credential.id,
          issuer: credential.issuer,
          type: credential.type,
          attributes
        });
      }
      
      if (verifiedCredentials.length === 0 && errors.length > 0) {
        return {
          valid: false,
          errors
        };
      }
      
      return {
        valid: true,
        holder: holderDID,
        credentials: verifiedCredentials,
        errors: errors.length > 0 ? errors : undefined
      };
      
    } catch (error) {
      return {
        valid: false,
        errors: [`Verification error: ${error instanceof Error ? error.message : 'Unknown error'}`]
      };
    }
  }
  
  private async verifyCredential(
    credential: VerifiableCredential
  ): Promise<{ valid: boolean; error?: string }> {
    try {
      if (!credential.proof?.jws) {
        return { valid: false, error: 'Credential missing proof' };
      }
      
      const result = await this.verifyJWT(credential.proof.jws, credential.issuer);
      return result;
      
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }
  
  private async verifyJWT(
    jwt: string, 
    issuerDID: string
  ): Promise<{ valid: boolean; error?: string }> {
    try {
      // Extract public key from DID
      const publicKey = DIDService.getPublicKeyFromDID(issuerDID);
      
      // Convert to JWK for jose
      const publicKeyJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(publicKey).toString('base64url')
      };
      
      const key = await importJWK(publicKeyJwk, 'EdDSA');
      
      // Verify JWT
      await jwtVerify(jwt, key, {
        algorithms: ['EdDSA']
      });
      
      return { valid: true };
      
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Invalid signature'
      };
    }
  }
  
  addTrustedIssuer(issuerDID: string): void {
    this.trustedIssuers.add(issuerDID);
  }
  
  removeTrustedIssuer(issuerDID: string): void {
    this.trustedIssuers.delete(issuerDID);
  }
  
  getTrustedIssuers(): string[] {
    return Array.from(this.trustedIssuers);
  }
  
  getName(): string {
    return this.name;
  }
}