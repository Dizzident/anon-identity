import { Proof, ProofPurpose } from '../../types/vc2';
import { JsonLdProcessor } from '../jsonld-processor';

/**
 * Key type supported by a signature suite
 */
export enum KeyType {
  Ed25519 = 'Ed25519',
  BLS12381G2 = 'Bls12381G2'
}

/**
 * Signature suite configuration
 */
export interface SignatureSuiteOptions {
  // JSON-LD processor to use
  jsonLdProcessor?: JsonLdProcessor;
  // Additional suite-specific options
  [key: string]: any;
}

/**
 * Signing options
 */
export interface SigningOptions {
  // The document to sign
  document: any;
  // Proof purpose
  purpose: ProofPurpose | string;
  // Verification method (DID URL)
  verificationMethod: string;
  // Private key for signing
  privateKey: Uint8Array;
  // Optional challenge
  challenge?: string;
  // Optional domain
  domain?: string;
  // Creation date (defaults to now)
  created?: string;
  // Expiration date
  expires?: string;
}

/**
 * Verification options
 */
export interface VerificationOptions {
  // The document with proof
  document: any;
  // The proof to verify
  proof: Proof;
  // Public key for verification
  publicKey: Uint8Array;
  // Expected proof purpose
  expectedPurpose: ProofPurpose | string;
  // Optional expected challenge
  expectedChallenge?: string;
  // Optional expected domain
  expectedDomain?: string;
}

/**
 * Selective disclosure options (for BBS+)
 */
export interface SelectiveDisclosureOptions {
  // Original signed document
  document: any;
  // Original proof
  proof: Proof;
  // Attributes to reveal
  revealedAttributes: string[];
  // Holder's private key (for holder binding)
  holderPrivateKey?: Uint8Array;
  // Nonce for the derived proof
  nonce?: string;
}

/**
 * Abstract base class for signature suites
 */
export abstract class SignatureSuite {
  // Suite type identifier
  abstract readonly type: string;
  
  // Required key type
  abstract readonly requiredKeyType: KeyType;
  
  // Whether the suite supports selective disclosure
  abstract readonly supportsSelectiveDisclosure: boolean;
  
  // Canonicalization algorithm
  readonly canonicalizationAlgorithm: string = 'URDNA2015';
  
  // JSON-LD processor
  protected jsonLdProcessor: JsonLdProcessor;
  
  constructor(options: SignatureSuiteOptions = {}) {
    this.jsonLdProcessor = options.jsonLdProcessor || new JsonLdProcessor();
  }
  
  /**
   * Create a proof for a document
   */
  abstract createProof(options: SigningOptions): Promise<Proof>;
  
  /**
   * Verify a proof on a document
   */
  abstract verifyProof(options: VerificationOptions): Promise<boolean>;
  
  /**
   * Create a derived proof with selective disclosure (if supported)
   */
  async createDerivedProof(options: SelectiveDisclosureOptions): Promise<Proof> {
    if (!this.supportsSelectiveDisclosure) {
      throw new Error(`${this.type} does not support selective disclosure`);
    }
    throw new Error('Method not implemented');
  }
  
  /**
   * Verify a derived proof (if supported)
   */
  async verifyDerivedProof(options: VerificationOptions): Promise<boolean> {
    if (!this.supportsSelectiveDisclosure) {
      throw new Error(`${this.type} does not support selective disclosure`);
    }
    throw new Error('Method not implemented');
  }
  
  /**
   * Canonicalize document for signing/verification
   */
  protected async canonicalizeDocument(document: any): Promise<string> {
    // Remove proof before canonicalization
    const docCopy = { ...document };
    delete docCopy.proof;
    
    return await this.jsonLdProcessor.canonicalize(docCopy);
  }
  
  /**
   * Create proof value metadata
   */
  protected createProofMetadata(options: SigningOptions): Partial<Proof> {
    const proof: Partial<Proof> = {
      type: this.type,
      created: options.created || new Date().toISOString(),
      verificationMethod: options.verificationMethod,
      proofPurpose: options.purpose
    };
    
    if (options.challenge) proof.challenge = options.challenge;
    if (options.domain) proof.domain = options.domain;
    if (options.expires) proof.expires = options.expires;
    
    return proof;
  }
  
  /**
   * Validate proof metadata
   */
  protected validateProofMetadata(
    proof: Proof,
    options: VerificationOptions
  ): { valid: boolean; error?: string } {
    // Check proof type
    if (proof.type !== this.type) {
      return { valid: false, error: `Invalid proof type: ${proof.type}` };
    }
    
    // Check proof purpose
    if (proof.proofPurpose !== options.expectedPurpose) {
      return { 
        valid: false, 
        error: `Invalid proof purpose: ${proof.proofPurpose}, expected: ${options.expectedPurpose}` 
      };
    }
    
    // Check expiration
    if (proof.expires) {
      const expirationDate = new Date(proof.expires);
      if (expirationDate < new Date()) {
        return { valid: false, error: 'Proof has expired' };
      }
    }
    
    // Check challenge if expected
    if (options.expectedChallenge && proof.challenge !== options.expectedChallenge) {
      return { valid: false, error: 'Challenge mismatch' };
    }
    
    // Check domain if expected
    if (options.expectedDomain && proof.domain !== options.expectedDomain) {
      return { valid: false, error: 'Domain mismatch' };
    }
    
    return { valid: true };
  }
}

/**
 * Registry for signature suites
 */
export class SignatureSuiteRegistry {
  private static suites = new Map<string, new (options?: SignatureSuiteOptions) => SignatureSuite>();
  
  /**
   * Register a signature suite
   */
  static register(
    type: string, 
    suiteClass: new (options?: SignatureSuiteOptions) => SignatureSuite
  ): void {
    this.suites.set(type, suiteClass);
  }
  
  /**
   * Get a signature suite by type
   */
  static getSuite(type: string, options?: SignatureSuiteOptions): SignatureSuite {
    const SuiteClass = this.suites.get(type);
    if (!SuiteClass) {
      throw new Error(`Unknown signature suite: ${type}`);
    }
    return new SuiteClass(options);
  }
  
  /**
   * Check if a suite is registered
   */
  static hasSuite(type: string): boolean {
    return this.suites.has(type);
  }
  
  /**
   * Get all registered suite types
   */
  static getRegisteredTypes(): string[] {
    return Array.from(this.suites.keys());
  }
}