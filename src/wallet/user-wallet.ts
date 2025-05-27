import { v4 as uuidv4 } from 'uuid';
import { SignJWT, importJWK } from 'jose';
import { 
  VerifiableCredential, 
  VerifiablePresentation, 
  KeyPair,
  SelectiveDisclosureRequest,
  SelectivelyDisclosedCredential
} from '../types';
import { CryptoService } from '../core/crypto';
import { DIDService } from '../core/did';
import { SecureStorage } from '../core/storage';
import { SelectiveDisclosure } from '../zkp/selective-disclosure';

export class UserWallet {
  private keyPair: KeyPair;
  private did: string;
  private credentials: Map<string, VerifiableCredential>;
  
  constructor(keyPair: KeyPair) {
    this.keyPair = keyPair;
    const didObject = DIDService.createDIDKey(keyPair.publicKey);
    this.did = didObject.id;
    this.credentials = new Map();
  }
  
  static async create(): Promise<UserWallet> {
    const keyPair = await CryptoService.generateKeyPair();
    return new UserWallet(keyPair);
  }
  
  static async restore(passphrase: string, identifier: string = 'default'): Promise<UserWallet | null> {
    const keyPair = await SecureStorage.retrieveKeyPair(passphrase, identifier);
    if (!keyPair) return null;
    
    const wallet = new UserWallet(keyPair);
    
    // Restore stored credentials
    const storedCredentials = SecureStorage.retrieve(`credentials:${identifier}`);
    if (storedCredentials && Array.isArray(storedCredentials)) {
      storedCredentials.forEach(vc => {
        wallet.credentials.set(vc.id, vc);
      });
    }
    
    return wallet;
  }
  
  async save(passphrase: string, identifier: string = 'default'): Promise<void> {
    // Store key pair
    await SecureStorage.storeKeyPair(this.keyPair, passphrase, identifier);
    
    // Store credentials
    const credentialsArray = Array.from(this.credentials.values());
    SecureStorage.store(`credentials:${identifier}`, credentialsArray);
  }
  
  storeCredential(credential: VerifiableCredential): void {
    this.credentials.set(credential.id, credential);
  }
  
  getCredential(credentialId: string): VerifiableCredential | undefined {
    return this.credentials.get(credentialId);
  }
  
  getAllCredentials(): VerifiableCredential[] {
    return Array.from(this.credentials.values());
  }
  
  getCredentialsByType(type: string): VerifiableCredential[] {
    return Array.from(this.credentials.values()).filter(
      vc => vc.type.includes(type)
    );
  }
  
  async createVerifiablePresentation(
    credentialIds: string[]
  ): Promise<VerifiablePresentation> {
    // Collect selected credentials
    const selectedCredentials: VerifiableCredential[] = [];
    
    for (const credId of credentialIds) {
      const credential = this.credentials.get(credId);
      if (!credential) {
        throw new Error(`Credential not found: ${credId}`);
      }
      selectedCredentials.push(credential);
    }
    
    if (selectedCredentials.length === 0) {
      throw new Error('No credentials selected for presentation');
    }
    
    // Create the presentation without proof
    const presentation: VerifiablePresentation = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiablePresentation"],
      verifiableCredential: selectedCredentials
    };
    
    // Sign the presentation
    const signedPresentation = await this.signPresentation(presentation);
    
    return signedPresentation;
  }
  
  async createSelectiveDisclosurePresentation(
    disclosureRequests: SelectiveDisclosureRequest[]
  ): Promise<VerifiablePresentation> {
    const disclosedCredentials: (VerifiableCredential | SelectivelyDisclosedCredential)[] = [];
    
    for (const request of disclosureRequests) {
      const credential = this.credentials.get(request.credentialId);
      if (!credential) {
        throw new Error(`Credential not found: ${request.credentialId}`);
      }
      
      // If no specific attributes requested, include the full credential
      if (!request.attributesToDisclose || request.attributesToDisclose.length === 0) {
        disclosedCredentials.push(credential);
      } else {
        // Create selectively disclosed credential
        const disclosedCredential = await SelectiveDisclosure.createSelectivelyDisclosedCredential(
          credential,
          request.attributesToDisclose,
          this.keyPair.privateKey,
          this.did
        );
        disclosedCredentials.push(disclosedCredential);
      }
    }
    
    if (disclosedCredentials.length === 0) {
      throw new Error('No credentials selected for presentation');
    }
    
    // Create the presentation with selectively disclosed credentials
    const presentation: VerifiablePresentation = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ],
      type: ["VerifiablePresentation", "SelectiveDisclosurePresentation"],
      verifiableCredential: disclosedCredentials
    };
    
    // Sign the presentation
    const signedPresentation = await this.signPresentation(presentation);
    
    return signedPresentation;
  }
  
  private async signPresentation(
    presentation: VerifiablePresentation
  ): Promise<VerifiablePresentation> {
    // Create a copy without the proof field for signing
    const presentationToSign = { ...presentation };
    delete presentationToSign.proof;
    
    // Convert private key to JWK format for jose
    const privateKeyJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(this.keyPair.publicKey).toString('base64url'),
      d: Buffer.from(this.keyPair.privateKey).toString('base64url')
    };
    
    const privateKey = await importJWK(privateKeyJwk, 'EdDSA');
    
    // Create JWT
    const jwt = await new SignJWT(presentationToSign)
      .setProtectedHeader({ 
        alg: 'EdDSA',
        typ: 'JWT',
        kid: `${this.did}#key-1`
      })
      .setIssuedAt()
      .setIssuer(this.did)
      .sign(privateKey);
    
    // Add proof to presentation
    const signedPresentation: VerifiablePresentation = {
      ...presentation,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        proofPurpose: 'authentication',
        verificationMethod: `${this.did}#key-1`,
        jws: jwt
      }
    };
    
    return signedPresentation;
  }
  
  getDID(): string {
    return this.did;
  }
  
  getPublicKey(): Uint8Array {
    return this.keyPair.publicKey;
  }
}