import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { 
  SignatureSuite, 
  KeyType, 
  SigningOptions, 
  VerificationOptions,
  SignatureSuiteOptions 
} from './signature-suite';
import { Proof } from '../../types/vc2';

// Configure ed25519 to use sha512
ed25519.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed25519.etc.concatBytes(...m));

/**
 * Ed25519Signature2020 implementation
 * https://w3c-ccg.github.io/lds-ed25519-2020/
 */
export class Ed25519Signature2020Suite extends SignatureSuite {
  readonly type = 'Ed25519Signature2020';
  readonly requiredKeyType = KeyType.Ed25519;
  readonly supportsSelectiveDisclosure = false;
  
  constructor(options: SignatureSuiteOptions = {}) {
    super(options);
  }
  
  /**
   * Create an Ed25519 signature proof
   */
  async createProof(options: SigningOptions): Promise<Proof> {
    try {
      // 1. Create proof metadata
      const proofMetadata = this.createProofMetadata(options);
      
      // 2. Canonicalize the document
      const canonicalDocument = await this.canonicalizeDocument(options.document);
      
      // 3. Create the verification hash
      const verifyData = await this.createVerifyData(canonicalDocument, proofMetadata);
      
      // 4. Sign the data
      const signature = await ed25519.sign(verifyData, options.privateKey);
      
      // 5. Create the final proof
      const proof: Proof = {
        ...proofMetadata as Proof,
        proofValue: Buffer.from(signature).toString('base64')
      };
      
      return proof;
    } catch (error) {
      throw new Error(`Failed to create Ed25519Signature2020: ${error}`);
    }
  }
  
  /**
   * Verify an Ed25519 signature proof
   */
  async verifyProof(options: VerificationOptions): Promise<boolean> {
    try {
      // 1. Validate proof metadata
      const metadataValidation = this.validateProofMetadata(options.proof, options);
      if (!metadataValidation.valid) {
        console.error('Proof metadata validation failed:', metadataValidation.error);
        return false;
      }
      
      // 2. Extract signature
      if (!options.proof.proofValue) {
        console.error('Missing proofValue');
        return false;
      }
      
      const signature = Buffer.from(options.proof.proofValue, 'base64');
      
      // 3. Canonicalize the document
      const canonicalDocument = await this.canonicalizeDocument(options.document);
      
      // 4. Create the verification hash
      const verifyData = await this.createVerifyData(canonicalDocument, options.proof);
      
      // 5. Verify the signature
      const isValid = await ed25519.verify(signature, verifyData, options.publicKey);
      
      return isValid;
    } catch (error) {
      console.error('Ed25519Signature2020 verification error:', error);
      return false;
    }
  }
  
  /**
   * Create the data to be signed/verified
   */
  private async createVerifyData(
    canonicalDocument: string,
    proof: Partial<Proof>
  ): Promise<Uint8Array> {
    // Create proof options without proofValue
    const proofOptions = { ...proof };
    delete proofOptions.proofValue;
    
    // Canonicalize proof options
    const canonicalProofOptions = await this.jsonLdProcessor.canonicalize(proofOptions);
    
    // Combine document and proof options
    const combined = canonicalDocument + canonicalProofOptions;
    
    // Hash the combined data
    return sha512(new TextEncoder().encode(combined));
  }
}