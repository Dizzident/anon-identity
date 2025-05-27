import { v4 as uuidv4 } from 'uuid';
import { SignJWT, importJWK } from 'jose';
import { VerifiableCredential, KeyPair, UserAttributes } from '../types';
import { CryptoService } from '../core/crypto';
import { DIDService } from '../core/did';
import { 
  BASIC_PROFILE_SCHEMA, 
  CREDENTIAL_CONTEXTS, 
  CREDENTIAL_TYPES, 
  validateAttributes 
} from './schemas';

export class IdentityProvider {
  private keyPair: KeyPair;
  private did: string;
  
  constructor(keyPair: KeyPair) {
    this.keyPair = keyPair;
    const didObject = DIDService.createDIDKey(keyPair.publicKey);
    this.did = didObject.id;
  }
  
  static async create(): Promise<IdentityProvider> {
    const keyPair = await CryptoService.generateKeyPair();
    return new IdentityProvider(keyPair);
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
}