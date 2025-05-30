import { jwtVerify, importJWK } from 'jose';
import { VerifiablePresentation, VerifiableCredential, SelectivelyDisclosedCredential } from '../types';
import { DIDService } from '../core/did';
import { SelectiveDisclosure } from '../zkp/selective-disclosure';
import { RevocationService } from '../revocation/revocation-service';
import { IStorageProvider, StorageFactory } from '../storage';
import { SessionManager, Session, SessionValidation, SessionManagerOptions } from './session-manager';
import { VerificationError, VerificationErrorCode, isVerificationError } from './verification-errors';
import { BatchOperations, BatchVerificationResult, BatchRevocationResult, BatchOperationOptions } from './batch-operations';
import { PresentationRequest, PresentationRequestOptions, ValidationResult } from './presentation-request';

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
  errors?: VerificationError[];
  timestamp?: Date;
}

export interface ServiceProviderOptions {
  sessionManager?: SessionManagerOptions;
  checkRevocation?: boolean;
  storageProvider?: IStorageProvider;
  batchOperations?: BatchOperationOptions;
}

export class ServiceProvider {
  private trustedIssuers: Set<string>;
  private name: string;
  private checkRevocation: boolean;
  private storageProvider: IStorageProvider;
  private sessionManager: SessionManager;
  private batchOperations: BatchOperations;
  private presentationRequest: PresentationRequest;
  
  constructor(
    name: string, 
    trustedIssuers: string[] = [], 
    options: ServiceProviderOptions = {}
  ) {
    this.name = name;
    this.trustedIssuers = new Set(trustedIssuers);
    this.checkRevocation = options.checkRevocation ?? true;
    this.storageProvider = options.storageProvider || StorageFactory.getDefaultProvider();
    this.sessionManager = new SessionManager(options.sessionManager);
    this.batchOperations = new BatchOperations(options.batchOperations);
    // For presentation requests, we need a DID - in practice this would be the service provider's DID
    this.presentationRequest = new PresentationRequest(`did:key:${name}`);
  }

  // Backward compatibility constructor
  static create(
    name: string, 
    trustedIssuers: string[] = [], 
    checkRevocation: boolean = true,
    storageProvider?: IStorageProvider
  ): ServiceProvider {
    return new ServiceProvider(name, trustedIssuers, {
      checkRevocation,
      storageProvider
    });
  }
  
  async verifyPresentation(presentation: VerifiablePresentation): Promise<VerificationResult> {
    const errors: VerificationError[] = [];
    const timestamp = new Date();
    
    try {
      // 1. Verify the presentation signature
      if (!presentation.proof?.jws) {
        return {
          valid: false,
          errors: [VerificationError.missingProof('presentation')],
          timestamp
        };
      }
      
      // Extract holder DID from proof
      const holderDID = presentation.proof.verificationMethod.split('#')[0];
      
      // Verify presentation JWT
      const isPresentationValid = await this.verifyJWT(presentation.proof.jws, holderDID);
      if (!isPresentationValid.valid) {
        return {
          valid: false,
          errors: [VerificationError.invalidPresentationSignature(isPresentationValid.error)],
          timestamp
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
            errors.push(VerificationError.invalidSignature(sdCredential.id, credResult.error));
            continue;
          }
          
          // Verify the selective disclosure proof
          const holderKey = DIDService.getPublicKeyFromDID(holderDID);
          const sdValid = await SelectiveDisclosure.verifySelectiveDisclosure(sdCredential, holderKey);
          if (!sdValid) {
            errors.push(VerificationError.invalidDisclosureProof(sdCredential.id));
            continue;
          }
          
          // Check if issuer is trusted
          if (!this.trustedIssuers.has(sdCredential.issuer)) {
            errors.push(VerificationError.untrustedIssuer(sdCredential.issuer, sdCredential.id));
            continue;
          }
          
          // Check revocation status
          if (this.checkRevocation) {
            const isRevoked = await this.checkCredentialRevocation(sdCredential.id, sdCredential.issuer);
            if (isRevoked) {
              errors.push(VerificationError.revokedCredential(sdCredential.id, sdCredential.issuer));
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
            errors.push(VerificationError.invalidSignature(credential.id, credResult.error));
            continue;
          }
          
          // Check if issuer is trusted
          if (!this.trustedIssuers.has(credential.issuer)) {
            errors.push(VerificationError.untrustedIssuer(credential.issuer, credential.id));
            continue;
          }
          
          // Check revocation status
          if (this.checkRevocation) {
            const isRevoked = await this.checkCredentialRevocation(credential.id, credential.issuer);
            if (isRevoked) {
              errors.push(VerificationError.revokedCredential(credential.id, credential.issuer));
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
          errors,
          timestamp
        };
      }
      
      return {
        valid: true,
        holder: holderDID,
        credentials: verifiedCredentials,
        errors: errors.length > 0 ? errors : undefined,
        timestamp
      };
      
    } catch (error) {
      const verificationError = error instanceof Error 
        ? new VerificationError(VerificationErrorCode.NETWORK_ERROR, `Verification error: ${error.message}`)
        : new VerificationError(VerificationErrorCode.NETWORK_ERROR, 'Unknown verification error');
      
      return {
        valid: false,
        errors: [verificationError],
        timestamp
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
      // First check storage provider
      const isRevoked = await this.storageProvider.checkRevocation(issuerDID, credentialId);
      if (isRevoked) {
        return true;
      }
      
      // Also check the mock registry for backward compatibility
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
  
  setStorageProvider(provider: IStorageProvider): void {
    this.storageProvider = provider;
  }

  // Session Management Methods
  async createSession(verificationResult: VerificationResult, metadata?: Record<string, any>): Promise<Session> {
    return this.sessionManager.createSession(verificationResult, metadata);
  }

  async validateSession(sessionId: string): Promise<SessionValidation> {
    return this.sessionManager.validateSession(sessionId);
  }

  async setSessionExpiry(sessionId: string, duration: number): Promise<void> {
    return this.sessionManager.setSessionExpiry(sessionId, duration);
  }

  getSession(sessionId: string): Session | undefined {
    return this.sessionManager.getSession(sessionId);
  }

  getAllSessions(): Session[] {
    return this.sessionManager.getAllSessions();
  }

  getSessionsByHolder(holderDID: string): Session[] {
    return this.sessionManager.getSessionsByHolder(holderDID);
  }

  removeSession(sessionId: string): void {
    this.sessionManager.removeSession(sessionId);
  }

  clearAllSessions(): void {
    this.sessionManager.clearAllSessions();
  }

  // Enhanced verification with automatic session creation
  async verifyPresentationWithSession(
    presentation: VerifiablePresentation, 
    createSession: boolean = true,
    sessionMetadata?: Record<string, any>
  ): Promise<{ verification: VerificationResult; session?: Session }> {
    const verificationResult = await this.verifyPresentation(presentation);
    
    if (createSession && verificationResult.valid) {
      const session = await this.createSession(verificationResult, sessionMetadata);
      return { verification: verificationResult, session };
    }
    
    return { verification: verificationResult };
  }

  // Handle credential revocation by invalidating related sessions
  async handleCredentialRevocation(credentialId: string): Promise<void> {
    await this.sessionManager.revokeSessions(credentialId);
  }

  // Cleanup method
  destroy(): void {
    this.sessionManager.destroy();
  }

  // Batch Operations
  async batchVerifyPresentations(presentations: VerifiablePresentation[]): Promise<BatchVerificationResult[]> {
    return this.batchOperations.batchVerifyPresentations(
      presentations,
      (presentation) => this.verifyPresentation(presentation)
    );
  }

  async batchCheckRevocations(credentialIds: string[]): Promise<Map<string, BatchRevocationResult>> {
    return this.batchOperations.batchCheckRevocations(
      credentialIds,
      (credentialId) => this.checkCredentialRevocation(credentialId, 'unknown')
    );
  }

  async batchVerifyWithRevocationCheck(presentations: VerifiablePresentation[]): Promise<BatchVerificationResult[]> {
    return this.batchOperations.batchVerifyWithRevocationCheck(
      presentations,
      (presentation) => this.verifyPresentation(presentation),
      (credentialId) => this.checkCredentialRevocation(credentialId, 'unknown')
    );
  }

  // Presentation Request Protocol
  async createPresentationRequest(options: PresentationRequestOptions) {
    return this.presentationRequest.createRequest(options);
  }

  async createSimplePresentationRequest(
    credentialTypes: string[],
    purpose: string,
    requiredAttributes: string[] = [],
    optionalAttributes: string[] = []
  ) {
    return this.presentationRequest.createSimpleRequest(
      credentialTypes,
      purpose,
      requiredAttributes,
      optionalAttributes
    );
  }

  async validatePresentationAgainstRequest(
    presentation: VerifiablePresentation,
    request: any
  ): Promise<ValidationResult> {
    return this.presentationRequest.validateAgainstRequest(presentation, request);
  }

  // Enhanced verification that includes request validation
  async verifyPresentationWithRequest(
    presentation: VerifiablePresentation,
    request: any
  ): Promise<{ verification: VerificationResult; requestValidation: ValidationResult }> {
    const [verification, requestValidation] = await Promise.all([
      this.verifyPresentation(presentation),
      this.validatePresentationAgainstRequest(presentation, request)
    ]);

    return { verification, requestValidation };
  }
}