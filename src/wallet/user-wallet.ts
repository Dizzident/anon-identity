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
import { IStorageProvider, StorageFactory, DIDDocument } from '../storage';

export class UserWallet {
  private keyPair: KeyPair;
  private did: string;
  private storageProvider: IStorageProvider;
  
  constructor(keyPair: KeyPair, storageProvider?: IStorageProvider) {
    this.keyPair = keyPair;
    const didObject = DIDService.createDIDKey(keyPair.publicKey);
    this.did = didObject.id;
    this.storageProvider = storageProvider || StorageFactory.getDefaultProvider();
  }
  
  static async create(storageProvider?: IStorageProvider): Promise<UserWallet> {
    const keyPair = await CryptoService.generateKeyPair();
    const wallet = new UserWallet(keyPair, storageProvider);
    
    // Store DID document
    const publicKeyMultibase = wallet.did.substring('did:key:'.length); // Extract multibase from DID
    const didDocument: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: wallet.did,
      verificationMethod: [{
        id: `${wallet.did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: wallet.did,
        publicKeyMultibase: publicKeyMultibase
      }],
      authentication: [`${wallet.did}#key-1`],
      assertionMethod: [`${wallet.did}#key-1`],
      created: new Date().toISOString()
    };
    
    await wallet.storageProvider.storeDID(wallet.did, didDocument);
    
    return wallet;
  }
  
  static async restore(
    passphrase: string, 
    identifier: string = 'default',
    storageProvider?: IStorageProvider
  ): Promise<UserWallet | null> {
    const keyPair = await SecureStorage.retrieveKeyPair(passphrase, identifier);
    if (!keyPair) return null;
    
    const wallet = new UserWallet(keyPair, storageProvider);
    return wallet;
  }
  
  async save(passphrase: string, identifier: string = 'default'): Promise<void> {
    // Store key pair using SecureStorage (which uses the storage provider internally)
    await SecureStorage.storeKeyPair(this.keyPair, passphrase, identifier);
  }
  
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    await this.storageProvider.storeCredential(credential);
  }
  
  async getCredential(credentialId: string): Promise<VerifiableCredential | null> {
    return await this.storageProvider.getCredential(credentialId);
  }
  
  async getAllCredentials(): Promise<VerifiableCredential[]> {
    return await this.storageProvider.listCredentials(this.did);
  }
  
  async getCredentialsByType(type: string): Promise<VerifiableCredential[]> {
    const allCredentials = await this.getAllCredentials();
    return allCredentials.filter(vc => vc.type.includes(type));
  }
  
  async createVerifiablePresentation(
    credentialIds: string[]
  ): Promise<VerifiablePresentation> {
    // Collect selected credentials
    const selectedCredentials: VerifiableCredential[] = [];
    
    for (const credId of credentialIds) {
      const credential = await this.storageProvider.getCredential(credId);
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
      const credential = await this.storageProvider.getCredential(request.credentialId);
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
  
  setStorageProvider(provider: IStorageProvider): void {
    this.storageProvider = provider;
  }
}