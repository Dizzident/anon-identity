import { v4 as uuidv4 } from 'uuid';
import { SignJWT, importJWK, jwtVerify } from 'jose';
import { RevocationList, KeyPair } from '../types';
import { CryptoService } from '../core/crypto';
import { IStorageProvider, StorageFactory, RevocationList as StorageRevocationList } from '../storage';

/**
 * Mock revocation registry - in production this would be a distributed ledger or database
 */
class MockRevocationRegistry {
  private static registry: Map<string, RevocationList> = new Map();
  private static readonly BASE_URL = 'https://revocation.example.com';
  
  static publish(issuerDID: string, revocationList: RevocationList): string {
    this.registry.set(issuerDID, revocationList);
    return `${this.BASE_URL}/${encodeURIComponent(issuerDID)}`;
  }
  
  static async fetch(issuerDID: string): Promise<RevocationList | null> {
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 100));
    return this.registry.get(issuerDID) || null;
  }
  
  static async fetchByUrl(url: string): Promise<RevocationList | null> {
    const match = url.match(/https:\/\/revocation\.example\.com\/(.+)$/);
    if (!match) return null;
    
    const issuerDID = decodeURIComponent(match[1]);
    return this.fetch(issuerDID);
  }
  
  static clear(): void {
    this.registry.clear();
  }
}

export class RevocationService {
  private keyPair: KeyPair;
  private issuerDID: string;
  private storageProvider: IStorageProvider;
  
  constructor(keyPair: KeyPair, issuerDID: string, storageProvider?: IStorageProvider) {
    this.keyPair = keyPair;
    this.issuerDID = issuerDID;
    this.storageProvider = storageProvider || StorageFactory.getDefaultProvider();
  }
  
  /**
   * Revoke a credential by adding its ID to the revocation list
   */
  async revokeCredential(credentialId: string): Promise<void> {
    const currentList = await this.storageProvider.getRevocationList(this.issuerDID);
    const revokedIds = currentList ? [...currentList.revokedCredentialIds] : [];
    
    if (!revokedIds.includes(credentialId)) {
      revokedIds.push(credentialId);
      await this.updateRevocationList(revokedIds);
    }
  }
  
  /**
   * Unrevoke a credential by removing its ID from the revocation list
   */
  async unrevokeCredential(credentialId: string): Promise<void> {
    const currentList = await this.storageProvider.getRevocationList(this.issuerDID);
    if (!currentList) return;
    
    const revokedIds = currentList.revokedCredentialIds.filter(id => id !== credentialId);
    await this.updateRevocationList(revokedIds);
  }
  
  /**
   * Check if a credential is revoked
   */
  async isRevoked(credentialId: string): Promise<boolean> {
    return await this.storageProvider.checkRevocation(this.issuerDID, credentialId);
  }
  
  /**
   * Get all revoked credential IDs
   */
  async getRevokedCredentials(): Promise<string[]> {
    const revocationList = await this.storageProvider.getRevocationList(this.issuerDID);
    return revocationList ? revocationList.revokedCredentialIds : [];
  }
  
  /**
   * Update the revocation list in storage
   */
  private async updateRevocationList(revokedIds: string[]): Promise<void> {
    const timestamp = Date.now();
    const signature = await this.createRevocationSignature(revokedIds, timestamp);
    
    const revocationList: StorageRevocationList = {
      issuerDID: this.issuerDID,
      revokedCredentialIds: revokedIds,
      timestamp,
      signature
    };
    
    await this.storageProvider.publishRevocation(this.issuerDID, revocationList);
  }
  
  /**
   * Create a signature for the revocation list
   */
  private async createRevocationSignature(revokedIds: string[], timestamp: number): Promise<string> {
    const dataToSign = {
      issuerDID: this.issuerDID,
      revokedCredentialIds: revokedIds,
      timestamp
    };
    
    // Convert private key to JWK format for jose
    const privateKeyJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(this.keyPair.publicKey).toString('base64url'),
      d: Buffer.from(this.keyPair.privateKey).toString('base64url')
    };
    
    const privateKey = await importJWK(privateKeyJwk, 'EdDSA');
    
    // Create JWT
    const jwt = await new SignJWT(dataToSign)
      .setProtectedHeader({ 
        alg: 'EdDSA',
        typ: 'JWT',
        kid: `${this.issuerDID}#key-1`
      })
      .setIssuedAt()
      .setIssuer(this.issuerDID)
      .sign(privateKey);
    
    return jwt;
  }
  
  /**
   * Create and sign a revocation list (for backward compatibility)
   */
  async createRevocationList(): Promise<RevocationList> {
    const revocationListId = `urn:uuid:${uuidv4()}`;
    const issuanceDate = new Date().toISOString();
    const revokedCredentials = await this.getRevokedCredentials();
    
    // Create the revocation list without proof
    const revocationList: RevocationList = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/vc-revocation-list-2020/v1"
      ],
      id: revocationListId,
      type: ["RevocationList2020"],
      issuer: this.issuerDID,
      issuanceDate: issuanceDate,
      revokedCredentials: revokedCredentials
    };
    
    // Sign the revocation list
    const signedList = await this.signRevocationList(revocationList);
    
    return signedList;
  }
  
  /**
   * Sign a revocation list
   */
  private async signRevocationList(revocationList: RevocationList): Promise<RevocationList> {
    // Create a copy without the proof field for signing
    const listToSign = { ...revocationList };
    delete listToSign.proof;
    
    // Convert private key to JWK format for jose
    const privateKeyJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(this.keyPair.publicKey).toString('base64url'),
      d: Buffer.from(this.keyPair.privateKey).toString('base64url')
    };
    
    const privateKey = await importJWK(privateKeyJwk, 'EdDSA');
    
    // Create JWT
    const jwt = await new SignJWT(listToSign)
      .setProtectedHeader({ 
        alg: 'EdDSA',
        typ: 'JWT',
        kid: `${this.issuerDID}#key-1`
      })
      .setIssuedAt()
      .setIssuer(this.issuerDID)
      .sign(privateKey);
    
    // Add proof to revocation list
    const signedList: RevocationList = {
      ...revocationList,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: `${this.issuerDID}#key-1`,
        jws: jwt
      }
    };
    
    return signedList;
  }
  
  /**
   * Publish the revocation list to the mock registry
   */
  async publishRevocationList(): Promise<string> {
    const revocationList = await this.createRevocationList();
    const url = MockRevocationRegistry.publish(this.issuerDID, revocationList);
    
    // Also update storage provider
    const revokedCredentials = await this.getRevokedCredentials();
    await this.updateRevocationList(revokedCredentials);
    
    return url;
  }
  
  /**
   * Verify a revocation list signature
   */
  static async verifyRevocationList(
    revocationList: RevocationList,
    issuerPublicKey: Uint8Array
  ): Promise<boolean> {
    try {
      if (!revocationList.proof?.jws) {
        return false;
      }
      
      // Convert public key to JWK for jose
      const publicKeyJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(issuerPublicKey).toString('base64url')
      };
      
      const key = await importJWK(publicKeyJwk, 'EdDSA');
      
      // Verify JWT
      const { payload } = await jwtVerify(revocationList.proof.jws, key, {
        algorithms: ['EdDSA']
      });
      
      // Verify the payload matches the revocation list
      if (payload.issuer !== revocationList.issuer) {
        return false;
      }
      
      // Check if revokedCredentials match
      const payloadRevoked = (payload as any).revokedCredentials || [];
      if (JSON.stringify(payloadRevoked.sort()) !== JSON.stringify(revocationList.revokedCredentials.sort())) {
        return false;
      }
      
      return true;
    } catch (error) {
      return false;
    }
  }
  
  /**
   * Fetch a revocation list from a URL (using mock registry)
   */
  static async fetchRevocationList(url: string): Promise<RevocationList | null> {
    return MockRevocationRegistry.fetchByUrl(url);
  }
  
  /**
   * Fetch a revocation list by issuer DID (using mock registry)
   */
  static async fetchRevocationListByIssuer(issuerDID: string): Promise<RevocationList | null> {
    return MockRevocationRegistry.fetch(issuerDID);
  }
  
  /**
   * Clear the mock registry (for testing)
   */
  static clearRegistry(): void {
    MockRevocationRegistry.clear();
  }
  
  // Sync compatibility methods (for backward compatibility)
  revokeCredentialSync(credentialId: string): void {
    // Convert to async internally but maintain sync interface for backward compatibility
    this.revokeCredential(credentialId).catch(console.error);
  }
  
  unrevokeCredentialSync(credentialId: string): void {
    // Convert to async internally but maintain sync interface for backward compatibility
    this.unrevokeCredential(credentialId).catch(console.error);
  }
  
  isRevokedSync(credentialId: string): boolean {
    // This is a breaking change - need to handle differently
    console.warn('isRevokedSync() sync method is deprecated. Use async isRevoked() instead.');
    return false;
  }
  
  getRevokedCredentialsSync(): string[] {
    // This is a breaking change - need to handle differently
    console.warn('getRevokedCredentialsSync() sync method is deprecated. Use async getRevokedCredentials() instead.');
    return [];
  }
  
  setStorageProvider(provider: IStorageProvider): void {
    this.storageProvider = provider;
  }
}

export { MockRevocationRegistry };