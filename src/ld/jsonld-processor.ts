import * as jsonld from 'jsonld';
import { ContextLoader, defaultContextLoader } from './context-loader';
import { VerifiableCredentialV2, VerifiablePresentationV2 } from '../types/vc2';

/**
 * JSON-LD processing options
 */
export interface JsonLdProcessorOptions {
  // Context loader to use
  contextLoader?: ContextLoader;
  // Whether to perform safe mode processing
  safeMode?: boolean;
  // Whether to validate contexts
  validateContexts?: boolean;
  // Custom processing options
  processingOptions?: any;
}

/**
 * JSON-LD Processor for Verifiable Credentials
 */
export class JsonLdProcessor {
  private contextLoader: ContextLoader;
  private documentLoader: (url: string) => Promise<any>;
  private safeMode: boolean;
  private validateContexts: boolean;
  
  constructor(options: JsonLdProcessorOptions = {}) {
    this.contextLoader = options.contextLoader || defaultContextLoader;
    this.documentLoader = this.contextLoader.createDocumentLoader();
    this.safeMode = options.safeMode ?? true;
    this.validateContexts = options.validateContexts ?? true;
  }
  
  /**
   * Expand a JSON-LD document
   */
  async expand(document: any): Promise<any> {
    try {
      const expanded = await jsonld.expand(document, {
        documentLoader: this.documentLoader
      } as any);
      return expanded;
    } catch (error) {
      throw new Error(`JSON-LD expansion failed: ${error}`);
    }
  }
  
  /**
   * Compact a JSON-LD document
   */
  async compact(document: any, context: any): Promise<any> {
    try {
      const compacted = await jsonld.compact(document, context, {
        documentLoader: this.documentLoader
      } as any);
      return compacted;
    } catch (error) {
      throw new Error(`JSON-LD compaction failed: ${error}`);
    }
  }
  
  /**
   * Canonicalize a JSON-LD document for signing
   */
  async canonicalize(document: any): Promise<string> {
    try {
      const canonicalized = await jsonld.canonize(document, {
        algorithm: 'URDNA2015',
        format: 'application/n-quads',
        documentLoader: this.documentLoader
      } as any) as unknown as string;
      return canonicalized;
    } catch (error) {
      throw new Error(`JSON-LD canonicalization failed: ${error}`);
    }
  }
  
  /**
   * Frame a JSON-LD document
   */
  async frame(document: any, frame: any): Promise<any> {
    try {
      const framed = await jsonld.frame(document, frame, {
        documentLoader: this.documentLoader
      } as any);
      return framed;
    } catch (error) {
      throw new Error(`JSON-LD framing failed: ${error}`);
    }
  }
  
  /**
   * Validate a credential's JSON-LD structure
   */
  async validateCredential(credential: VerifiableCredentialV2): Promise<{
    valid: boolean;
    errors?: string[];
  }> {
    const errors: string[] = [];
    
    try {
      // 1. Check that @context is present
      if (!credential['@context']) {
        errors.push('Missing @context property');
        return { valid: false, errors };
      }
      
      // 2. Expand the document to check for errors
      const expanded = await this.expand(credential);
      
      // 3. Check that required properties expanded correctly
      if (expanded.length === 0) {
        errors.push('Document expanded to empty array');
      }
      
      // 4. Validate specific credential properties
      const expandedCred = expanded[0];
      
      // Check for required credential properties
      const requiredProps = [
        'https://www.w3.org/2018/credentials#credentialSubject',
        'https://www.w3.org/2018/credentials#issuer'
      ];
      
      for (const prop of requiredProps) {
        if (!expandedCred[prop]) {
          errors.push(`Missing required property: ${prop}`);
        }
      }
      
      // 5. If proof exists, validate it expanded correctly
      if (credential.proof && !expandedCred['https://w3id.org/security#proof']) {
        errors.push('Proof property did not expand correctly');
      }
      
      return {
        valid: errors.length === 0,
        errors: errors.length > 0 ? errors : undefined
      };
      
    } catch (error) {
      errors.push(`JSON-LD processing error: ${error}`);
      return { valid: false, errors };
    }
  }
  
  /**
   * Validate a presentation's JSON-LD structure
   */
  async validatePresentation(presentation: VerifiablePresentationV2): Promise<{
    valid: boolean;
    errors?: string[];
  }> {
    const errors: string[] = [];
    
    try {
      // 1. Check that @context is present
      if (!presentation['@context']) {
        errors.push('Missing @context property');
        return { valid: false, errors };
      }
      
      // 2. Expand the document
      const expanded = await this.expand(presentation);
      
      if (expanded.length === 0) {
        errors.push('Document expanded to empty array');
      }
      
      // 3. Validate credentials if present
      if (presentation.verifiableCredential) {
        for (let i = 0; i < presentation.verifiableCredential.length; i++) {
          const cred = presentation.verifiableCredential[i];
          if (typeof cred !== 'string') {
            const result = await this.validateCredential(cred);
            if (!result.valid) {
              errors.push(`Credential ${i}: ${result.errors?.join(', ')}`);
            }
          }
        }
      }
      
      return {
        valid: errors.length === 0,
        errors: errors.length > 0 ? errors : undefined
      };
      
    } catch (error) {
      errors.push(`JSON-LD processing error: ${error}`);
      return { valid: false, errors };
    }
  }
  
  /**
   * Normalize a document for comparison
   */
  async normalize(document: any): Promise<any> {
    // First expand, then compact with a standard context
    const expanded = await this.expand(document);
    const context = document['@context'] || 'https://www.w3.org/ns/credentials/v2';
    return await this.compact(expanded, context);
  }
  
  /**
   * Extract claims from an expanded credential
   */
  async extractClaims(credential: VerifiableCredentialV2): Promise<Map<string, any>> {
    const claims = new Map<string, any>();
    
    try {
      const expanded = await this.expand(credential);
      if (expanded.length === 0) return claims;
      
      const expandedCred = expanded[0];
      const subject = expandedCred['https://www.w3.org/2018/credentials#credentialSubject'];
      
      if (Array.isArray(subject)) {
        // Multiple subjects
        subject.forEach((subj, index) => {
          this.extractClaimsFromSubject(subj, claims, `subject${index}`);
        });
      } else if (subject) {
        // Single subject
        this.extractClaimsFromSubject(subject, claims);
      }
      
      return claims;
    } catch (error) {
      throw new Error(`Failed to extract claims: ${error}`);
    }
  }
  
  /**
   * Extract claims from a subject object
   */
  private extractClaimsFromSubject(subject: any, claims: Map<string, any>, prefix = ''): void {
    for (const [key, value] of Object.entries(subject)) {
      if (key === '@id' || key === '@type') continue;
      
      const claimKey = prefix ? `${prefix}.${key}` : key;
      
      if (Array.isArray(value) && value.length > 0 && value[0] && typeof value[0] === 'object' && '@value' in value[0]) {
        // Literal value
        claims.set(claimKey, value[0]['@value']);
      } else if (value && typeof value === 'object' && '@value' in value) {
        // Single literal value
        claims.set(claimKey, value['@value']);
      } else {
        // Complex value or reference
        claims.set(claimKey, value);
      }
    }
  }
}

// Default instance
export const defaultJsonLdProcessor = new JsonLdProcessor();