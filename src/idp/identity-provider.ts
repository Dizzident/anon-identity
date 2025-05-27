import { v4 as uuidv4 } from 'uuid';
import { SignJWT, importJWK } from 'jose';
import { VerifiableCredential, KeyPair, UserAttributes, RevocationList } from '../types';
import { CryptoService } from '../core/crypto';
import { DIDService } from '../core/did';
import { RevocationService } from '../revocation/revocation-service';
import { 
  BASIC_PROFILE_SCHEMA, 
  CREDENTIAL_CONTEXTS, 
  CREDENTIAL_TYPES, 
  validateAttributes 
} from './schemas';
import { IStorageProvider, StorageFactory, DIDDocument, CredentialSchema } from '../storage';

export class IdentityProvider {
  private keyPair: KeyPair;
  private did: string;
  private revocationService: RevocationService;
  private storageProvider: IStorageProvider;
  
  constructor(keyPair: KeyPair, storageProvider?: IStorageProvider) {
    this.keyPair = keyPair;
    const didObject = DIDService.createDIDKey(keyPair.publicKey);
    this.did = didObject.id;
    this.storageProvider = storageProvider || StorageFactory.getDefaultProvider();
    this.revocationService = new RevocationService(keyPair, this.did, this.storageProvider);
  }
  
  static async create(storageProvider?: IStorageProvider): Promise<IdentityProvider> {
    const keyPair = await CryptoService.generateKeyPair();
    const provider = new IdentityProvider(keyPair, storageProvider);
    
    // Store DID document
    const publicKeyMultibase = provider.did.substring('did:key:'.length); // Extract multibase from DID
    const didDocument: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: provider.did,
      verificationMethod: [{
        id: `${provider.did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: provider.did,
        publicKeyMultibase: publicKeyMultibase
      }],
      authentication: [`${provider.did}#key-1`],
      assertionMethod: [`${provider.did}#key-1`],
      created: new Date().toISOString()
    };
    
    await provider.storageProvider.storeDID(provider.did, didDocument);
    
    // Register basic profile schema
    const schema: CredentialSchema = {
      name: 'BasicProfile',
      description: 'Basic user profile schema',
      properties: BASIC_PROFILE_SCHEMA,
      issuerDID: provider.did,
      version: '1.0.0',
      active: true
    };
    
    await provider.storageProvider.registerSchema(schema);
    
    return provider;
  }
  
  async issueVerifiableCredential(
    userDID: string,
    attributes: UserAttributes
  ): Promise<VerifiableCredential> {
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
    const issuanceDate = new Date().toISOString();
    
    // Create the credential without proof first
    const credential: VerifiableCredential = {
      "@context": [
        CREDENTIAL_CONTEXTS.W3C_VC,
        CREDENTIAL_CONTEXTS.BASIC_PROFILE
      ],
      id: credentialId,
      type: [
        CREDENTIAL_TYPES.VERIFIABLE_CREDENTIAL,
        CREDENTIAL_TYPES.BASIC_PROFILE
      ],
      issuer: this.did,
      issuanceDate: issuanceDate,
      credentialSubject: {
        id: userDID,
        ...attributes
      }
    };
    
    // Sign the credential
    const signedCredential = await this.signCredential(credential);
    
    // Store the issued credential
    await this.storageProvider.storeCredential(signedCredential);
    
    return signedCredential;
  }
  
  private async signCredential(credential: VerifiableCredential): Promise<VerifiableCredential> {
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
    const jwt = await new SignJWT(credentialToSign)
      .setProtectedHeader({ 
        alg: 'EdDSA',
        typ: 'JWT',
        kid: `${this.did}#key-1`
      })
      .setIssuedAt()
      .setIssuer(this.did)
      .setSubject(credential.credentialSubject.id)
      .sign(privateKey);
    
    // Add proof to credential
    const signedCredential: VerifiableCredential = {
      ...credential,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: `${this.did}#key-1`,
        jws: jwt
      }
    };
    
    return signedCredential;
  }
  
  getDID(): string {
    return this.did;
  }
  
  /**
   * Revoke a previously issued credential
   */
  revokeCredential(credentialId: string): void {
    this.revocationService.revokeCredentialSync(credentialId);
  }
  
  /**
   * Unrevoke a credential
   */
  unrevokeCredential(credentialId: string): void {
    this.revocationService.unrevokeCredentialSync(credentialId);
  }
  
  /**
   * Check if a credential is revoked
   */
  isCredentialRevoked(credentialId: string): boolean {
    return this.revocationService.isRevokedSync(credentialId);
  }
  
  /**
   * Get the current revocation list
   */
  async getRevocationList(): Promise<RevocationList> {
    return this.revocationService.createRevocationList();
  }
  
  /**
   * Publish the revocation list and return the URL
   */
  async publishRevocationList(): Promise<string> {
    return this.revocationService.publishRevocationList();
  }
  
  /**
   * Get all revoked credential IDs
   */
  getRevokedCredentials(): string[] {
    return this.revocationService.getRevokedCredentialsSync();
  }
  
  setStorageProvider(provider: IStorageProvider): void {
    this.storageProvider = provider;
    this.revocationService.setStorageProvider(provider);
  }
}