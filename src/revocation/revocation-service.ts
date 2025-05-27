import { v4 as uuidv4 } from 'uuid';
import { SignJWT, importJWK, jwtVerify } from 'jose';
import { RevocationList, KeyPair } from '../types';
import { CryptoService } from '../core/crypto';

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
  private revokedCredentials: Set<string>;
  
  constructor(keyPair: KeyPair, issuerDID: string) {
    this.keyPair = keyPair;
    this.issuerDID = issuerDID;
    this.revokedCredentials = new Set();
  }
  
  /**
   * Revoke a credential by adding its ID to the revocation list
   */
  revokeCredential(credentialId: string): void {
    this.revokedCredentials.add(credentialId);
  }
  
  /**
   * Unrevoke a credential by removing its ID from the revocation list
   */
  unrevokeCredential(credentialId: string): void {
    this.revokedCredentials.delete(credentialId);
  }
  
  /**
   * Check if a credential is revoked
   */
  isRevoked(credentialId: string): boolean {
    return this.revokedCredentials.has(credentialId);
  }
  
  /**
   * Get all revoked credential IDs
   */
  getRevokedCredentials(): string[] {
    return Array.from(this.revokedCredentials);
  }
  
  /**
   * Create and sign a revocation list
   */
  async createRevocationList(): Promise<RevocationList> {
    const revocationListId = `urn:uuid:${uuidv4()}`;
    const issuanceDate = new Date().toISOString();
    
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
      revokedCredentials: this.getRevokedCredentials()
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
}

export { MockRevocationRegistry };