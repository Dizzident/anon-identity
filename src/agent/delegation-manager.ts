import { signData } from '../core/crypto';
import { DelegationCredential, AccessGrant } from './types';
import { KeyPair } from '../types/index';
import * as ed from '@noble/ed25519';

export class DelegationManager {
  async createDelegationCredential(
    issuerDID: string,
    issuerKeyPair: KeyPair,
    agentDID: string,
    agentName: string,
    grant: AccessGrant
  ): Promise<DelegationCredential> {
    const now = new Date();
    const credentialId = `${issuerDID}/delegations/${Date.now()}`;
    
    const credential: DelegationCredential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      type: ['VerifiableCredential', 'DelegationCredential'],
      id: credentialId,
      issuer: issuerDID,
      issuanceDate: now.toISOString(),
      expirationDate: grant.expiresAt.toISOString(),
      credentialSubject: {
        id: agentDID,
        parentDID: issuerDID,
        name: agentName,
        scopes: grant.scopes,
        services: {
          [grant.serviceDID]: {
            scopes: grant.scopes,
            constraints: grant.constraints
          }
        },
        validFrom: now.toISOString(),
        validUntil: grant.expiresAt.toISOString()
      }
    };

    // Sign the credential
    const proof = await this.createProof(credential, issuerDID, issuerKeyPair);
    credential.proof = proof;

    return credential;
  }

  async createProof(
    credential: DelegationCredential,
    issuerDID: string,
    keyPair: KeyPair
  ): Promise<any> {
    // Remove proof from credential for signing
    const { proof, ...credentialWithoutProof } = credential;
    
    // Create canonical string representation
    const canonicalCredential = JSON.stringify(credentialWithoutProof, Object.keys(credentialWithoutProof).sort());
    
    // Sign the credential
    const signature = signData(canonicalCredential, keyPair.privateKey);
    
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: `${issuerDID}#key-1`,
      proofPurpose: 'assertionMethod',
      jws: signature
    };
  }

  validateDelegation(credential: DelegationCredential): boolean {
    // Check expiration
    if (new Date(credential.expirationDate) < new Date()) {
      return false;
    }

    // Check validity period
    const validFrom = new Date(credential.credentialSubject.validFrom);
    const validUntil = new Date(credential.credentialSubject.validUntil);
    const now = new Date();

    if (now < validFrom || now > validUntil) {
      return false;
    }

    // Additional validation would include signature verification
    // This would be done by the service provider
    return true;
  }

  extractScopes(credential: DelegationCredential, serviceDID: string): string[] {
    const serviceGrant = credential.credentialSubject.services[serviceDID];
    return serviceGrant?.scopes || [];
  }

  hasScope(credential: DelegationCredential, serviceDID: string, scope: string): boolean {
    const scopes = this.extractScopes(credential, serviceDID);
    return scopes.includes(scope);
  }
}