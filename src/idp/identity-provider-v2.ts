import { v4 as uuidv4 } from 'uuid';
import { SignJWT, importJWK } from 'jose';
import { VerifiableCredential, KeyPair, UserAttributes, RevocationList } from '../types';
import { 
  VerifiableCredentialV2, 
  CredentialStatus, 
  CredentialStatusType,
  TermsOfUse,
  Evidence,
  VC_V2_CONTEXTS,
  ProofPurpose,
  Proof
} from '../types/vc2';
import { CryptoService } from '../core/crypto';
import { DIDService } from '../core/did';
import { RevocationService } from '../revocation/revocation-service';
import { StatusList2021 } from '../status/credential-status';
import { 
  BASIC_PROFILE_SCHEMA, 
  CREDENTIAL_CONTEXTS, 
  CREDENTIAL_TYPES, 
  validateAttributes 
} from './schemas';
import { IStorageProvider, StorageFactory, DIDDocument, CredentialSchema } from '../storage';
import { IdentityProvider } from './identity-provider';
import { ProofManager } from '../core/proof-manager';

export interface IssueCredentialOptionsV2 {
  // Credential status configuration
  credentialStatus?: {
    type: CredentialStatusType;
    statusListUrl?: string;
    statusListIndex?: number;
  };
  // Terms of use
  termsOfUse?: TermsOfUse | TermsOfUse[];
  // Evidence
  evidence?: Evidence | Evidence[];
  // Credential validity period
  validFrom?: string;
  validUntil?: string;
  // Additional contexts
  additionalContexts?: string[];
  // Whether to use VC 2.0 format (default: true)
  useV2Format?: boolean;
  // Additional proofs to add (beyond the issuer's signature)
  additionalProofs?: Proof[];
}

/**
 * Enhanced Identity Provider with W3C VC 2.0 support
 */
export class IdentityProviderV2 extends IdentityProvider {
  private statusList: StatusList2021;
  private statusListUrl?: string;
  private nextStatusIndex: number = 0;
  
  constructor(keyPair: KeyPair, storageProvider?: IStorageProvider) {
    super(keyPair, storageProvider);
    this.statusList = new StatusList2021();
  }
  
  static async create(storageProvider?: IStorageProvider): Promise<IdentityProviderV2> {
    const keyPair = await CryptoService.generateKeyPair();
    const provider = new IdentityProviderV2(keyPair, storageProvider);
    
    // Call parent initialization
    const baseProvider = await IdentityProvider.create(storageProvider);
    Object.assign(provider, baseProvider);
    
    return provider;
  }
  
  /**
   * Issue a W3C VC 2.0 compliant credential
   */
  async issueVerifiableCredentialV2(
    userDID: string,
    attributes: UserAttributes,
    options: IssueCredentialOptionsV2 = {}
  ): Promise<VerifiableCredentialV2> {
    // Validate attributes against schema
    const validation = validateAttributes(attributes, BASIC_PROFILE_SCHEMA);
    if (!validation.valid) {
      throw new Error(`Invalid attributes: ${validation.errors.join(', ')}`);
    }
    
    // Auto-calculate isOver18 if dateOfBirth is provided
    if (attributes.dateOfBirth && !attributes.hasOwnProperty('isOver18')) {
      const birthDate = new Date(attributes.dateOfBirth);
      const today = new Date();
      const age = today.getFullYear() - birthDate.getFullYear();
      const monthDiff = today.getMonth() - birthDate.getMonth();
      
      if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
        attributes.isOver18 = age - 1 >= 18;
      } else {
        attributes.isOver18 = age >= 18;
      }
    }
    
    const credentialId = `urn:uuid:${uuidv4()}`;
    const now = new Date().toISOString();
    
    // Build contexts
    const contexts: string[] = [
      options.useV2Format !== false ? VC_V2_CONTEXTS.CREDENTIALS_V2 : CREDENTIAL_CONTEXTS.W3C_VC,
      CREDENTIAL_CONTEXTS.BASIC_PROFILE,
      VC_V2_CONTEXTS.ED25519_2020
    ];
    
    if (options.credentialStatus) {
      contexts.push(VC_V2_CONTEXTS.STATUS_LIST_2021);
    }
    
    if (options.termsOfUse) {
      contexts.push(VC_V2_CONTEXTS.TERMS_OF_USE);
    }
    
    if (options.additionalContexts) {
      contexts.push(...options.additionalContexts);
    }
    
    // Create the credential
    const credential: VerifiableCredentialV2 = {
      "@context": contexts,
      id: credentialId,
      type: [
        CREDENTIAL_TYPES.VERIFIABLE_CREDENTIAL,
        CREDENTIAL_TYPES.BASIC_PROFILE
      ],
      issuer: this.getDID(),
      validFrom: options.validFrom || now,
      credentialSubject: {
        id: userDID,
        ...attributes
      }
    };
    
    // Add optional fields
    if (options.validUntil) {
      credential.validUntil = options.validUntil;
    }
    
    // Add credential status if requested
    if (options.credentialStatus) {
      credential.credentialStatus = await this.createCredentialStatus(
        credentialId,
        options.credentialStatus
      );
    }
    
    // Add terms of use if provided
    if (options.termsOfUse) {
      credential.termsOfUse = options.termsOfUse;
    }
    
    // Add evidence if provided
    if (options.evidence) {
      credential.evidence = options.evidence;
    }
    
    // For backward compatibility with VC 1.1
    if (options.useV2Format === false) {
      credential.issuanceDate = credential.validFrom!;
      if (credential.validUntil) {
        credential.expirationDate = credential.validUntil;
      }
    }
    
    // Sign the credential
    let signedCredential = await this.signCredentialV2(credential);
    
    // Add any additional proofs
    if (options.additionalProofs && options.additionalProofs.length > 0) {
      for (const proof of options.additionalProofs) {
        signedCredential = ProofManager.addProof(signedCredential, proof);
      }
    }
    
    // Store the issued credential
    await this.storageProvider.storeCredential(signedCredential as any);
    
    return signedCredential;
  }
  
  /**
   * Create credential status information
   */
  private async createCredentialStatus(
    credentialId: string,
    statusConfig: IssueCredentialOptionsV2['credentialStatus']
  ): Promise<CredentialStatus> {
    if (!statusConfig) {
      throw new Error('Status configuration required');
    }
    
    let statusListUrl = statusConfig.statusListUrl;
    let statusListIndex = statusConfig.statusListIndex;
    
    // If no URL provided, generate one
    if (!statusListUrl) {
      statusListUrl = `https://example.com/status/${this.getDID()}/list`;
      this.statusListUrl = statusListUrl;
    }
    
    // If no index provided, use next available
    if (statusListIndex === undefined) {
      statusListIndex = this.nextStatusIndex++;
    }
    
    switch (statusConfig.type) {
      case CredentialStatusType.STATUS_LIST_2021:
        return {
          id: `${statusListUrl}#${statusListIndex}`,
          type: CredentialStatusType.STATUS_LIST_2021,
          statusPurpose: 'revocation',
          statusListIndex,
          statusListCredential: statusListUrl
        };
        
      case CredentialStatusType.REVOCATION_LIST_2020:
        return {
          id: statusListUrl,
          type: CredentialStatusType.REVOCATION_LIST_2020,
          revocationListIndex: statusListIndex.toString(),
          revocationListCredential: statusListUrl
        };
        
      default:
        throw new Error(`Unsupported credential status type: ${statusConfig.type}`);
    }
  }
  
  /**
   * Sign a VC 2.0 credential
   */
  private async signCredentialV2(credential: VerifiableCredentialV2): Promise<VerifiableCredentialV2> {
    // Create a copy without the proof field for signing
    const credentialToSign = { ...credential };
    delete credentialToSign.proof;
    
    // Convert private key to JWK format for jose
    const privateKeyJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(this.keyPair.publicKey).toString('base64url'),
      d: Buffer.from(this.keyPair.privateKey).toString('base64url')
    };
    
    const privateKey = await importJWK(privateKeyJwk, 'EdDSA');
    
    // Create JWT
    const jwt = await new SignJWT({ vc: credentialToSign })
      .setProtectedHeader({ 
        alg: 'EdDSA',
        typ: 'JWT',
        kid: `${this.getDID()}#key-1`
      })
      .setIssuedAt()
      .setIssuer(this.getDID())
      .setSubject(Array.isArray(credential.credentialSubject) 
        ? credential.credentialSubject[0].id || this.getDID()
        : credential.credentialSubject.id || this.getDID())
      .sign(privateKey);
    
    // Add proof to credential
    const signedCredential: VerifiableCredentialV2 = {
      ...credential,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        proofPurpose: ProofPurpose.ASSERTION_METHOD,
        verificationMethod: `${this.getDID()}#key-1`,
        jws: jwt
      }
    };
    
    return signedCredential;
  }
  
  /**
   * Revoke a credential using StatusList2021
   */
  async revokeCredentialV2(credentialId: string, statusListIndex: number): Promise<void> {
    this.statusList.setStatus(statusListIndex, true);
    
    // Also update the legacy revocation list for compatibility
    super.revokeCredential(credentialId);
    
    // Publish updated status list
    if (this.statusListUrl) {
      await this.publishStatusList();
    }
  }
  
  /**
   * Publish the current status list
   */
  async publishStatusList(): Promise<string> {
    if (!this.statusListUrl) {
      this.statusListUrl = `https://example.com/status/${this.getDID()}/list`;
    }
    
    const statusListCredential = await this.statusList.createStatusListCredential(
      { id: this.getDID(), publicKey: this.keyPair.publicKey },
      this.keyPair.privateKey,
      this.statusListUrl
    );
    
    // Store the status list credential
    await this.storageProvider.storeCredential(statusListCredential);
    
    return this.statusListUrl;
  }
  
  /**
   * Create example terms of use
   */
  static createExampleTermsOfUse(): TermsOfUse {
    return {
      type: "IssuerPolicy",
      id: "https://example.com/policies/credential-tos",
      profile: "https://example.com/profiles/v1",
      prohibition: [{
        assigner: "https://example.com/issuers/14",
        assignee: "AllVerifiers",
        target: "https://example.com/credentials/14",
        action: ["Archival"]
      }]
    };
  }
  
  /**
   * Create example evidence
   */
  static createExampleEvidence(verifierId: string): Evidence {
    return {
      type: ["DocumentVerification"],
      verifier: verifierId,
      evidenceDocument: "DriversLicense",
      subjectPresence: "Physical",
      documentPresence: "Physical",
      licenseNumber: "123-456-789"
    };
  }
}