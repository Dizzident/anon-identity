import { BbsBlsSignature2020Suite } from '../ld/signature-suites/bbs-bls-signature-2020';
import { JsonLdProcessor } from '../ld/jsonld-processor';
import { VerifiableCredentialV2, Proof } from '../types/vc2';

/**
 * BBS+ based selective disclosure options
 */
export interface BbsSelectiveDisclosureOptions {
  // The attributes to reveal
  attributesToReveal: string[];
  // Optional holder binding
  holderDID?: string;
  // Optional nonce for freshness
  nonce?: string;
  // JSON-LD processor to use
  jsonLdProcessor?: JsonLdProcessor;
}

/**
 * BBS+ based selective disclosure result
 */
export interface BbsSelectiveDisclosureResult {
  // The derived credential with selective disclosure
  derivedCredential: VerifiableCredentialV2;
  // The derived proof
  derivedProof: Proof;
  // Revealed attribute paths
  revealedPaths: string[];
}

/**
 * BBS+ based selective disclosure for Verifiable Credentials
 */
export class BbsSelectiveDisclosure {
  private suite: BbsBlsSignature2020Suite;
  private jsonLdProcessor: JsonLdProcessor;
  
  constructor(jsonLdProcessor?: JsonLdProcessor) {
    this.jsonLdProcessor = jsonLdProcessor || new JsonLdProcessor();
    this.suite = new BbsBlsSignature2020Suite({ jsonLdProcessor: this.jsonLdProcessor });
  }
  
  /**
   * Create a derived credential with selective disclosure
   */
  async deriveCredential(
    originalCredential: VerifiableCredentialV2,
    options: BbsSelectiveDisclosureOptions
  ): Promise<BbsSelectiveDisclosureResult> {
    // 1. Validate original credential has BBS+ proof
    if (!originalCredential.proof || !this.isBbsProof(originalCredential.proof)) {
      throw new Error('Original credential must have BbsBlsSignature2020 proof');
    }
    
    const originalProof = Array.isArray(originalCredential.proof) 
      ? originalCredential.proof.find(p => p.type === 'BbsBlsSignature2020')!
      : originalCredential.proof;
    
    // 2. Create frame for selective disclosure
    const frame = await this.createFrame(originalCredential, options.attributesToReveal);
    
    // 3. Frame the credential
    const framedCredential = await this.jsonLdProcessor.frame(originalCredential, frame);
    
    // 4. Extract revealed paths
    const revealedPaths = await this.extractRevealedPaths(
      originalCredential,
      framedCredential
    );
    
    // 5. Create derived proof
    const derivedProof = await this.suite.createDerivedProof({
      document: originalCredential,
      proof: originalProof,
      revealedAttributes: revealedPaths,
      nonce: options.nonce
    });
    
    // 6. Build derived credential
    const derivedCredential: VerifiableCredentialV2 = {
      ...framedCredential,
      proof: derivedProof
    };
    
    // 7. Add holder binding if requested
    if (options.holderDID) {
      (derivedCredential as any).holder = options.holderDID;
    }
    
    return {
      derivedCredential,
      derivedProof,
      revealedPaths
    };
  }
  
  /**
   * Verify a derived credential
   */
  async verifyDerivedCredential(
    derivedCredential: VerifiableCredentialV2,
    issuerPublicKey: Uint8Array,
    expectedNonce?: string
  ): Promise<boolean> {
    // 1. Check proof type
    if (!derivedCredential.proof || !this.isBbsDerivedProof(derivedCredential.proof)) {
      return false;
    }
    
    const derivedProof = Array.isArray(derivedCredential.proof)
      ? derivedCredential.proof.find(p => p.type === 'BbsBlsSignatureProof2020')!
      : derivedCredential.proof;
    
    // 2. Check nonce if expected
    if (expectedNonce && derivedProof.nonce !== expectedNonce) {
      return false;
    }
    
    // 3. Verify the derived proof
    return await this.suite.verifyDerivedProof({
      document: derivedCredential,
      proof: derivedProof,
      publicKey: issuerPublicKey,
      expectedPurpose: derivedProof.proofPurpose
    });
  }
  
  /**
   * Create a JSON-LD frame for selective disclosure
   */
  private async createFrame(
    credential: VerifiableCredentialV2,
    attributesToReveal: string[]
  ): Promise<any> {
    // Basic frame structure
    const frame: any = {
      '@context': credential['@context'],
      type: credential.type,
      credentialSubject: {}
    };
    
    // Add required fields
    if (credential.issuer) frame.issuer = {};
    if (credential.validFrom) frame.validFrom = {};
    if (credential.validUntil) frame.validUntil = {};
    
    // Build credentialSubject frame
    const subject = Array.isArray(credential.credentialSubject)
      ? credential.credentialSubject[0]
      : credential.credentialSubject;
    
    // Always include subject ID if present
    if (subject.id) {
      frame.credentialSubject['@id'] = {};
    }
    
    // Add requested attributes
    for (const attr of attributesToReveal) {
      const path = attr.split('.');
      let current = frame.credentialSubject;
      
      for (let i = 0; i < path.length - 1; i++) {
        if (!current[path[i]]) {
          current[path[i]] = {};
        }
        current = current[path[i]];
      }
      
      current[path[path.length - 1]] = {};
    }
    
    return frame;
  }
  
  /**
   * Extract revealed paths from original and framed credentials
   */
  private async extractRevealedPaths(
    original: VerifiableCredentialV2,
    framed: any
  ): Promise<string[]> {
    const paths: string[] = [];
    
    // Extract paths from credentialSubject
    const originalSubject = Array.isArray(original.credentialSubject)
      ? original.credentialSubject[0]
      : original.credentialSubject;
    
    const framedSubject = framed.credentialSubject;
    
    this.extractPathsRecursive(originalSubject, framedSubject, 'credentialSubject', paths);
    
    // Add other revealed top-level properties
    const topLevelProps = ['issuer', 'validFrom', 'validUntil', 'type', '@context'];
    for (const prop of topLevelProps) {
      if (framed[prop] !== undefined) {
        paths.push(prop);
      }
    }
    
    return paths;
  }
  
  /**
   * Recursively extract paths
   */
  private extractPathsRecursive(
    original: any,
    framed: any,
    currentPath: string,
    paths: string[]
  ): void {
    if (!framed || typeof framed !== 'object') {
      return;
    }
    
    for (const key of Object.keys(framed)) {
      if (key === '@id' || key === '@type') continue;
      
      const fullPath = `${currentPath}.${key}`;
      
      if (original[key] !== undefined) {
        paths.push(fullPath);
        
        if (typeof framed[key] === 'object' && !Array.isArray(framed[key])) {
          this.extractPathsRecursive(original[key], framed[key], fullPath, paths);
        }
      }
    }
  }
  
  /**
   * Check if proof is BBS+ signature
   */
  private isBbsProof(proof: Proof | Proof[]): boolean {
    if (Array.isArray(proof)) {
      return proof.some(p => p.type === 'BbsBlsSignature2020');
    }
    return proof.type === 'BbsBlsSignature2020';
  }
  
  /**
   * Check if proof is BBS+ derived proof
   */
  private isBbsDerivedProof(proof: Proof | Proof[]): boolean {
    if (Array.isArray(proof)) {
      return proof.some(p => p.type === 'BbsBlsSignatureProof2020');
    }
    return proof.type === 'BbsBlsSignatureProof2020';
  }
  
  /**
   * Estimate the privacy level of a selective disclosure
   * Returns a score from 0 (all revealed) to 1 (minimal revelation)
   */
  async estimatePrivacyLevel(
    originalCredential: VerifiableCredentialV2,
    revealedPaths: string[]
  ): Promise<number> {
    // Extract all possible paths from original
    const allPaths = await this.extractAllPaths(originalCredential);
    
    // Calculate privacy score
    const totalPaths = allPaths.length;
    const revealedCount = revealedPaths.length;
    
    if (totalPaths === 0) return 1;
    
    return 1 - (revealedCount / totalPaths);
  }
  
  /**
   * Extract all attribute paths from a credential
   */
  private async extractAllPaths(credential: VerifiableCredentialV2): Promise<string[]> {
    const paths: string[] = [];
    
    // Add top-level paths
    const topLevel = ['@context', 'type', 'issuer', 'validFrom', 'validUntil'];
    paths.push(...topLevel.filter(p => (credential as any)[p] !== undefined));
    
    // Extract from credentialSubject
    const subject = Array.isArray(credential.credentialSubject)
      ? credential.credentialSubject[0]
      : credential.credentialSubject;
    
    this.extractAllPathsRecursive(subject, 'credentialSubject', paths);
    
    return paths;
  }
  
  /**
   * Recursively extract all paths
   */
  private extractAllPathsRecursive(obj: any, currentPath: string, paths: string[]): void {
    if (!obj || typeof obj !== 'object') {
      return;
    }
    
    for (const key of Object.keys(obj)) {
      if (key === '@id' || key === '@type') continue;
      
      const fullPath = `${currentPath}.${key}`;
      paths.push(fullPath);
      
      if (typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
        this.extractAllPathsRecursive(obj[key], fullPath, paths);
      }
    }
  }
}