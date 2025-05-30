import { Proof, ProofPurpose } from '../types/vc2';
import { VerificationError } from '../sp/verification-errors';

/**
 * Manages multiple proofs on credentials and presentations
 */
export class ProofManager {
  /**
   * Add a proof to a document (credential or presentation)
   * @param document The document to add proof to
   * @param newProof The proof to add
   * @returns The document with the new proof added
   */
  static addProof<T extends { proof?: Proof | Proof[] }>(
    document: T,
    newProof: Proof
  ): T {
    const documentCopy = { ...document };
    
    if (!documentCopy.proof) {
      // No existing proof, add as single proof
      documentCopy.proof = newProof;
    } else if (Array.isArray(documentCopy.proof)) {
      // Already an array, add to it
      documentCopy.proof = [...documentCopy.proof, newProof];
    } else {
      // Single proof exists, convert to array
      documentCopy.proof = [documentCopy.proof, newProof];
    }
    
    return documentCopy;
  }
  
  /**
   * Get all proofs from a document
   * @param document The document to get proofs from
   * @returns Array of proofs (empty if none)
   */
  static getProofs(document: { proof?: Proof | Proof[] }): Proof[] {
    if (!document.proof) {
      return [];
    }
    
    return Array.isArray(document.proof) ? document.proof : [document.proof];
  }
  
  /**
   * Find proofs by purpose
   * @param document The document to search
   * @param purpose The proof purpose to find
   * @returns Array of matching proofs
   */
  static findProofsByPurpose(
    document: { proof?: Proof | Proof[] },
    purpose: ProofPurpose | string
  ): Proof[] {
    const proofs = this.getProofs(document);
    return proofs.filter(p => p.proofPurpose === purpose);
  }
  
  /**
   * Find proofs by type
   * @param document The document to search
   * @param type The proof type to find
   * @returns Array of matching proofs
   */
  static findProofsByType(
    document: { proof?: Proof | Proof[] },
    type: string
  ): Proof[] {
    const proofs = this.getProofs(document);
    return proofs.filter(p => p.type === type);
  }
  
  /**
   * Find proofs by verification method
   * @param document The document to search
   * @param verificationMethod The verification method to find
   * @returns Array of matching proofs
   */
  static findProofsByVerificationMethod(
    document: { proof?: Proof | Proof[] },
    verificationMethod: string
  ): Proof[] {
    const proofs = this.getProofs(document);
    return proofs.filter(p => p.verificationMethod === verificationMethod);
  }
  
  /**
   * Validate proof chain (each proof must be created before the next)
   * @param proofs Array of proofs to validate
   * @returns Validation result
   */
  static validateProofChain(proofs: Proof[]): {
    valid: boolean;
    errors?: string[];
  } {
    if (proofs.length < 2) {
      return { valid: true };
    }
    
    const errors: string[] = [];
    const sortedProofs = [...proofs].sort((a, b) => {
      if (!a.created || !b.created) return 0;
      return new Date(a.created).getTime() - new Date(b.created).getTime();
    });
    
    for (let i = 1; i < sortedProofs.length; i++) {
      const prev = sortedProofs[i - 1];
      const curr = sortedProofs[i];
      
      if (!prev.created || !curr.created) {
        errors.push(`Proof ${i} is missing created timestamp`);
        continue;
      }
      
      const prevTime = new Date(prev.created).getTime();
      const currTime = new Date(curr.created).getTime();
      
      if (currTime < prevTime) {
        errors.push(
          `Proof ${i} created at ${curr.created} is before proof ${i-1} created at ${prev.created}`
        );
      }
    }
    
    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined
    };
  }
  
  /**
   * Remove expired proofs
   * @param document The document to clean
   * @returns The document with expired proofs removed
   */
  static removeExpiredProofs<T extends { proof?: Proof | Proof[] }>(
    document: T,
    now: Date = new Date()
  ): T {
    const proofs = this.getProofs(document);
    const validProofs = proofs.filter(p => {
      if (!p.expires) return true;
      return new Date(p.expires) > now;
    });
    
    if (validProofs.length === proofs.length) {
      return document; // No changes needed
    }
    
    const documentCopy = { ...document };
    if (validProofs.length === 0) {
      delete documentCopy.proof;
    } else if (validProofs.length === 1) {
      documentCopy.proof = validProofs[0];
    } else {
      documentCopy.proof = validProofs;
    }
    
    return documentCopy;
  }
  
  /**
   * Merge proofs from multiple documents
   * @param documents Array of documents with proofs
   * @returns Array of all unique proofs
   */
  static mergeProofs(...documents: Array<{ proof?: Proof | Proof[] }>): Proof[] {
    const allProofs: Proof[] = [];
    const seenProofs = new Set<string>();
    
    for (const doc of documents) {
      const proofs = this.getProofs(doc);
      for (const proof of proofs) {
        // Create a unique key for the proof
        const key = `${proof.type}:${proof.verificationMethod}:${proof.created || 'no-date'}`;
        if (!seenProofs.has(key)) {
          seenProofs.add(key);
          allProofs.push(proof);
        }
      }
    }
    
    return allProofs;
  }
  
  /**
   * Check if a document has a valid proof for a given purpose
   * @param document The document to check
   * @param purpose The proof purpose required
   * @param verifierDIDs Optional list of acceptable verifier DIDs
   * @returns Whether a valid proof exists
   */
  static hasValidProofForPurpose(
    document: { proof?: Proof | Proof[] },
    purpose: ProofPurpose | string,
    verifierDIDs?: string[]
  ): boolean {
    const proofs = this.findProofsByPurpose(document, purpose);
    
    if (proofs.length === 0) {
      return false;
    }
    
    // If no specific verifiers required, any proof with the purpose is valid
    if (!verifierDIDs || verifierDIDs.length === 0) {
      return true;
    }
    
    // Check if any proof is from an acceptable verifier
    return proofs.some(proof => {
      const proofDID = proof.verificationMethod.split('#')[0];
      return verifierDIDs.includes(proofDID);
    });
  }
}