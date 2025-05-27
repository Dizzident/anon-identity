import { jwtVerify, importJWK } from 'jose';
import { VerifiablePresentation, VerifiableCredential, SelectivelyDisclosedCredential } from '../types';
import { DIDService } from '../core/did';
import { SelectiveDisclosure } from '../zkp/selective-disclosure';
import { RevocationService } from '../revocation/revocation-service';

export interface VerificationResult {
  valid: boolean;
  holder?: string;
  credentials?: Array<{
    id: string;
    issuer: string;
    type: string[];
    attributes: Record<string, any>;
    selectivelyDisclosed?: boolean;
    disclosedAttributes?: string[];
  }>;
  errors?: string[];
}

export class ServiceProvider {
  private trustedIssuers: Set<string>;
  private name: string;
  private checkRevocation: boolean;
  
  constructor(name: string, trustedIssuers: string[] = [], checkRevocation: boolean = true) {
    this.name = name;
    this.trustedIssuers = new Set(trustedIssuers);
    this.checkRevocation = checkRevocation;
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
        // Check if this is a selectively disclosed credential
        const isSelectivelyDisclosed = credential.type.includes('SelectivelyDisclosedCredential');
        
        if (isSelectivelyDisclosed) {
          const sdCredential = credential as SelectivelyDisclosedCredential;
          
          // Verify the original issuer's signature
          const credResult = await this.verifyCredential(sdCredential);
          if (!credResult.valid) {
            errors.push(`Credential ${sdCredential.id} verification failed: ${credResult.error}`);
            continue;
          }
          
          // Verify the selective disclosure proof
          const holderKey = DIDService.getPublicKeyFromDID(holderDID);
          const sdValid = await SelectiveDisclosure.verifySelectiveDisclosure(sdCredential, holderKey);
          if (!sdValid) {
            errors.push(`Selective disclosure proof invalid for credential ${sdCredential.id}`);
            continue;
          }
          
          // Check if issuer is trusted
          if (!this.trustedIssuers.has(sdCredential.issuer)) {
            errors.push(`Credential ${sdCredential.id} from untrusted issuer: ${sdCredential.issuer}`);
            continue;
          }
          
          // Check revocation status
          if (this.checkRevocation) {
            const isRevoked = await this.checkCredentialRevocation(sdCredential.id, sdCredential.issuer);
            if (isRevoked) {
              errors.push(`Credential ${sdCredential.id} has been revoked`);
              continue;
            }
          }
          
          // Extract disclosed attributes
          const { id, ...attributes } = sdCredential.credentialSubject;
          verifiedCredentials.push({
            id: sdCredential.id,
            issuer: sdCredential.issuer,
            type: sdCredential.type,
            attributes,
            selectivelyDisclosed: true,
            disclosedAttributes: sdCredential.disclosureProof?.disclosedAttributes
          });
        } else {
          // Regular credential verification
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
          
          // Check revocation status
          if (this.checkRevocation) {
            const isRevoked = await this.checkCredentialRevocation(credential.id, credential.issuer);
            if (isRevoked) {
              errors.push(`Credential ${credential.id} has been revoked`);
              continue;
            }
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
    credential: VerifiableCredential | SelectivelyDisclosedCredential
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
  
  setRevocationCheck(enabled: boolean): void {
    this.checkRevocation = enabled;
  }
  
  private async checkCredentialRevocation(
    credentialId: string,
    issuerDID: string
  ): Promise<boolean> {
    try {
      // Fetch the revocation list from the issuer
      const revocationList = await RevocationService.fetchRevocationListByIssuer(issuerDID);
      
      if (!revocationList) {
        // No revocation list published - credential is not revoked
        return false;
      }
      
      // Verify the revocation list signature
      const issuerPublicKey = DIDService.getPublicKeyFromDID(issuerDID);
      const isValid = await RevocationService.verifyRevocationList(revocationList, issuerPublicKey);
      
      if (!isValid) {
        // Invalid revocation list - treat as not revoked but log warning
        console.warn(`Invalid revocation list signature from issuer ${issuerDID}`);
        return false;
      }
      
      // Check if the credential ID is in the revocation list
      return revocationList.revokedCredentials.includes(credentialId);
      
    } catch (error) {
      // Error checking revocation - treat as not revoked
      console.error(`Error checking revocation for credential ${credentialId}:`, error);
      return false;
    }
  }
}