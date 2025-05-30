import {
  generateBls12381G2KeyPair,
  blsSign,
  blsVerify,
  blsCreateProof,
  blsVerifyProof,
  BbsSignRequest,
  BbsVerifyRequest,
  BbsCreateProofRequest,
  BbsVerifyProofRequest
} from '@mattrglobal/bbs-signatures';
import { 
  SignatureSuite, 
  KeyType, 
  SigningOptions, 
  VerificationOptions,
  SelectiveDisclosureOptions,
  SignatureSuiteOptions 
} from './signature-suite';
import { Proof } from '../../types/vc2';
import { sha256 } from '@noble/hashes/sha256';

/**
 * BbsBlsSignature2020 implementation
 * Supports selective disclosure of attributes
 */
export class BbsBlsSignature2020Suite extends SignatureSuite {
  readonly type = 'BbsBlsSignature2020';
  readonly requiredKeyType = KeyType.BLS12381G2;
  readonly supportsSelectiveDisclosure = true;
  
  constructor(options: SignatureSuiteOptions = {}) {
    super(options);
  }
  
  /**
   * Create a BBS+ signature proof
   */
  async createProof(options: SigningOptions): Promise<Proof> {
    try {
      // 1. Create proof metadata
      const proofMetadata = this.createProofMetadata(options);
      
      // 2. Canonicalize and prepare messages
      const messages = await this.prepareMessages(options.document);
      
      // 3. Create signature
      const signRequest: BbsSignRequest = {
        keyPair: {
          secretKey: options.privateKey,
          publicKey: new Uint8Array(0), // Will be derived from secret key
          messageCount: messages.length
        },
        messages
      };
      
      const signature = await blsSign(signRequest);
      
      // 4. Create the final proof
      const proof: Proof = {
        ...proofMetadata as Proof,
        proofValue: Buffer.from(signature).toString('base64')
      };
      
      return proof;
    } catch (error) {
      throw new Error(`Failed to create BbsBlsSignature2020: ${error}`);
    }
  }
  
  /**
   * Verify a BBS+ signature proof
   */
  async verifyProof(options: VerificationOptions): Promise<boolean> {
    try {
      // 1. Validate proof metadata
      const metadataValidation = this.validateProofMetadata(options.proof, options);
      if (!metadataValidation.valid) {
        return false;
      }
      
      // 2. Extract signature
      if (!options.proof.proofValue) {
        return false;
      }
      
      const signature = Buffer.from(options.proof.proofValue, 'base64');
      
      // 3. Prepare messages
      const messages = await this.prepareMessages(options.document);
      
      // 4. Verify signature
      const verifyRequest: BbsVerifyRequest = {
        publicKey: options.publicKey,
        messages,
        signature
      };
      
      const { verified } = await blsVerify(verifyRequest);
      
      return verified;
    } catch (error) {
      console.error('BbsBlsSignature2020 verification error:', error);
      return false;
    }
  }
  
  /**
   * Create a derived proof with selective disclosure
   */
  async createDerivedProof(options: SelectiveDisclosureOptions): Promise<Proof> {
    try {
      // 1. Extract original signature
      if (!options.proof.proofValue) {
        throw new Error('Original proof missing proofValue');
      }
      
      const signature = Buffer.from(options.proof.proofValue, 'base64');
      
      // 2. Prepare all messages and determine revealed indices
      const allMessages = await this.prepareMessages(options.document);
      const revealedIndices = await this.getRevealedIndices(
        options.document,
        options.revealedAttributes
      );
      
      // 3. Create nonce
      const nonce = options.nonce || this.generateNonce();
      
      // 4. Extract public key from verification method
      const publicKey = await this.extractPublicKey(options.proof.verificationMethod);
      
      // 5. Create derived proof
      const proofRequest: BbsCreateProofRequest = {
        signature,
        publicKey,
        messages: allMessages,
        revealed: revealedIndices,
        nonce: Buffer.from(nonce)
      };
      
      const derivedProof = await blsCreateProof(proofRequest);
      
      // 6. Create proof object
      const proof: Proof = {
        type: 'BbsBlsSignatureProof2020',
        created: new Date().toISOString(),
        verificationMethod: options.proof.verificationMethod,
        proofPurpose: options.proof.proofPurpose,
        proofValue: Buffer.from(derivedProof).toString('base64'),
        nonce,
        revealedAttributes: options.revealedAttributes
      };
      
      return proof;
    } catch (error) {
      throw new Error(`Failed to create BBS+ derived proof: ${error}`);
    }
  }
  
  /**
   * Verify a derived proof
   */
  async verifyDerivedProof(options: VerificationOptions): Promise<boolean> {
    try {
      // 1. Check proof type
      if (options.proof.type !== 'BbsBlsSignatureProof2020') {
        return false;
      }
      
      // 2. Extract proof value
      if (!options.proof.proofValue) {
        return false;
      }
      
      const proof = Buffer.from(options.proof.proofValue, 'base64');
      
      // 3. Extract nonce
      if (!options.proof.nonce) {
        return false;
      }
      
      const nonce = Buffer.from(options.proof.nonce);
      
      // 4. Prepare revealed messages
      const revealedMessages = await this.prepareRevealedMessages(
        options.document,
        options.proof.revealedAttributes || []
      );
      
      // 5. Get revealed indices
      const revealedIndices = await this.getRevealedIndices(
        options.document,
        options.proof.revealedAttributes || []
      );
      
      // 6. Verify derived proof
      const verifyRequest: BbsVerifyProofRequest = {
        proof,
        publicKey: options.publicKey,
        messages: Array.from(revealedMessages.values()),
        nonce
      } as any;
      
      const { verified } = await blsVerifyProof(verifyRequest);
      
      return verified;
    } catch (error) {
      console.error('BBS+ derived proof verification error:', error);
      return false;
    }
  }
  
  /**
   * Prepare messages from document for signing/verification
   */
  private async prepareMessages(document: any): Promise<Uint8Array[]> {
    // Canonicalize the document
    const canonical = await this.canonicalizeDocument(document);
    
    // Split into statements (lines)
    const statements = canonical.split('\n').filter(s => s.length > 0);
    
    // Convert each statement to bytes
    return statements.map(stmt => new TextEncoder().encode(stmt));
  }
  
  /**
   * Get indices of revealed attributes
   */
  private async getRevealedIndices(
    document: any,
    revealedAttributes: string[]
  ): Promise<number[]> {
    // This is a simplified implementation
    // In practice, you'd map attribute paths to statement indices
    const canonical = await this.canonicalizeDocument(document);
    const statements = canonical.split('\n').filter(s => s.length > 0);
    
    const indices: number[] = [];
    
    // For each revealed attribute, find matching statements
    for (const attr of revealedAttributes) {
      statements.forEach((stmt, idx) => {
        if (stmt.includes(attr)) {
          indices.push(idx);
        }
      });
    }
    
    return [...new Set(indices)].sort((a, b) => a - b);
  }
  
  /**
   * Prepare revealed messages for derived proof verification
   */
  private async prepareRevealedMessages(
    document: any,
    revealedAttributes: string[]
  ): Promise<Map<number, Uint8Array>> {
    const messages = await this.prepareMessages(document);
    const indices = await this.getRevealedIndices(document, revealedAttributes);
    
    const revealedMessages = new Map<number, Uint8Array>();
    
    for (const idx of indices) {
      if (idx < messages.length) {
        revealedMessages.set(idx, messages[idx]);
      }
    }
    
    return revealedMessages;
  }
  
  /**
   * Extract public key from verification method
   */
  private async extractPublicKey(verificationMethod: string): Promise<Uint8Array> {
    // In a real implementation, this would resolve the DID and extract the key
    // For now, we'll throw an error
    throw new Error('Public key extraction from DID not implemented');
  }
  
  /**
   * Generate a random nonce
   */
  private generateNonce(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Buffer.from(bytes).toString('base64');
  }
  
  /**
   * Generate a BLS12-381 G2 key pair
   */
  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
    const keyPair = await generateBls12381G2KeyPair();
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey
    };
  }
}