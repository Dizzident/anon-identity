import { VerifiablePresentation } from '../types';
import { VerificationResult } from './service-provider';
import { VerificationError, VerificationErrorCode } from './verification-errors';

export interface BatchVerificationResult {
  presentationIndex: number;
  presentationId?: string;
  result: VerificationResult;
  processingTime: number; // milliseconds
}

export interface BatchRevocationResult {
  credentialId: string;
  isRevoked: boolean;
  error?: VerificationError;
  processingTime: number;
}

export interface BatchOperationOptions {
  maxConcurrency?: number; // Maximum number of concurrent operations
  timeout?: number; // Timeout per operation in milliseconds
  continueOnError?: boolean; // Whether to continue processing if individual operations fail
}

export class BatchOperations {
  private defaultOptions: Required<BatchOperationOptions> = {
    maxConcurrency: 10,
    timeout: 30000, // 30 seconds
    continueOnError: true
  };

  constructor(private options: BatchOperationOptions = {}) {
    this.options = { ...this.defaultOptions, ...options };
  }

  /**
   * Verify multiple presentations in parallel with controlled concurrency
   */
  async batchVerifyPresentations(
    presentations: VerifiablePresentation[],
    verifyFunction: (presentation: VerifiablePresentation) => Promise<VerificationResult>
  ): Promise<BatchVerificationResult[]> {
    const results: BatchVerificationResult[] = [];
    const chunks = this.chunkArray(presentations, this.options.maxConcurrency!);

    for (const chunk of chunks) {
      const chunkPromises = chunk.map(async (presentation, index) => {
        const startTime = Date.now();
        const presentationIndex = presentations.indexOf(presentation);
        
        try {
          // Apply timeout to individual verification
          const result = await this.withTimeout(
            verifyFunction(presentation),
            this.options.timeout!
          );
          
          const processingTime = Date.now() - startTime;
          
          return {
            presentationIndex,
            presentationId: this.extractPresentationId(presentation),
            result,
            processingTime
          };
        } catch (error) {
          const processingTime = Date.now() - startTime;
          const verificationError = error instanceof Error
            ? new VerificationError(VerificationErrorCode.NETWORK_ERROR, `Batch verification failed: ${error.message}`)
            : new VerificationError(VerificationErrorCode.NETWORK_ERROR, 'Unknown batch verification error');

          return {
            presentationIndex,
            presentationId: this.extractPresentationId(presentation),
            result: {
              valid: false,
              errors: [verificationError],
              timestamp: new Date()
            },
            processingTime
          };
        }
      });

      try {
        const chunkResults = await Promise.all(chunkPromises);
        results.push(...chunkResults);
      } catch (error) {
        if (!this.options.continueOnError) {
          throw error;
        }
        // Individual errors are already handled in the map function
      }
    }

    return results.sort((a, b) => a.presentationIndex - b.presentationIndex);
  }

  /**
   * Check multiple credential revocations in parallel
   */
  async batchCheckRevocations(
    credentialIds: string[],
    checkFunction: (credentialId: string) => Promise<boolean>
  ): Promise<Map<string, BatchRevocationResult>> {
    const results = new Map<string, BatchRevocationResult>();
    const chunks = this.chunkArray(credentialIds, this.options.maxConcurrency!);

    for (const chunk of chunks) {
      const chunkPromises = chunk.map(async (credentialId) => {
        const startTime = Date.now();
        
        try {
          const isRevoked = await this.withTimeout(
            checkFunction(credentialId),
            this.options.timeout!
          );
          
          const processingTime = Date.now() - startTime;
          
          return {
            credentialId,
            result: {
              credentialId,
              isRevoked,
              processingTime
            }
          };
        } catch (error) {
          const processingTime = Date.now() - startTime;
          const verificationError = error instanceof Error
            ? new VerificationError(VerificationErrorCode.NETWORK_ERROR, `Revocation check failed: ${error.message}`)
            : new VerificationError(VerificationErrorCode.NETWORK_ERROR, 'Unknown revocation check error');

          return {
            credentialId,
            result: {
              credentialId,
              isRevoked: false, // Default to not revoked on error
              error: verificationError,
              processingTime
            }
          };
        }
      });

      try {
        const chunkResults = await Promise.all(chunkPromises);
        chunkResults.forEach(({ credentialId, result }) => {
          results.set(credentialId, result);
        });
      } catch (error) {
        if (!this.options.continueOnError) {
          throw error;
        }
      }
    }

    return results;
  }

  /**
   * Batch verify presentations with revocation checks
   */
  async batchVerifyWithRevocationCheck(
    presentations: VerifiablePresentation[],
    verifyFunction: (presentation: VerifiablePresentation) => Promise<VerificationResult>,
    checkRevocationFunction: (credentialId: string) => Promise<boolean>
  ): Promise<BatchVerificationResult[]> {
    // First, verify all presentations
    const verificationResults = await this.batchVerifyPresentations(presentations, verifyFunction);
    
    // Extract all credential IDs from valid presentations
    const credentialIds = new Set<string>();
    verificationResults.forEach(result => {
      if (result.result.valid && result.result.credentials) {
        result.result.credentials.forEach(cred => credentialIds.add(cred.id));
      }
    });

    // Batch check revocations
    const revocationResults = await this.batchCheckRevocations(
      Array.from(credentialIds),
      checkRevocationFunction
    );

    // Update verification results with revocation status
    return verificationResults.map(result => {
      if (!result.result.valid || !result.result.credentials) {
        return result;
      }

      const revokedCredentials = result.result.credentials.filter(cred => {
        const revocationResult = revocationResults.get(cred.id);
        return revocationResult?.isRevoked || false;
      });

      if (revokedCredentials.length > 0) {
        const revokedErrors = revokedCredentials.map(cred => 
          VerificationError.revokedCredential(cred.id, cred.issuer)
        );

        return {
          ...result,
          result: {
            ...result.result,
            valid: false,
            errors: [...(result.result.errors || []), ...revokedErrors]
          }
        };
      }

      return result;
    });
  }

  /**
   * Get batch operation statistics
   */
  generateBatchStatistics(results: BatchVerificationResult[]): {
    total: number;
    valid: number;
    invalid: number;
    averageProcessingTime: number;
    maxProcessingTime: number;
    minProcessingTime: number;
    errorDistribution: Record<string, number>;
  } {
    const total = results.length;
    const valid = results.filter(r => r.result.valid).length;
    const invalid = total - valid;
    
    const processingTimes = results.map(r => r.processingTime);
    const averageProcessingTime = processingTimes.reduce((a, b) => a + b, 0) / total;
    const maxProcessingTime = Math.max(...processingTimes);
    const minProcessingTime = Math.min(...processingTimes);

    const errorDistribution: Record<string, number> = {};
    results.forEach(result => {
      if (result.result.errors) {
        result.result.errors.forEach(error => {
          const code = error.code || 'UNKNOWN';
          errorDistribution[code] = (errorDistribution[code] || 0) + 1;
        });
      }
    });

    return {
      total,
      valid,
      invalid,
      averageProcessingTime,
      maxProcessingTime,
      minProcessingTime,
      errorDistribution
    };
  }

  /**
   * Filter results by criteria
   */
  filterResults(
    results: BatchVerificationResult[],
    criteria: {
      validOnly?: boolean;
      maxProcessingTime?: number;
      minProcessingTime?: number;
      excludeErrorCodes?: VerificationErrorCode[];
    }
  ): BatchVerificationResult[] {
    return results.filter(result => {
      if (criteria.validOnly && !result.result.valid) {
        return false;
      }

      if (criteria.maxProcessingTime && result.processingTime > criteria.maxProcessingTime) {
        return false;
      }

      if (criteria.minProcessingTime && result.processingTime < criteria.minProcessingTime) {
        return false;
      }

      if (criteria.excludeErrorCodes && result.result.errors) {
        const hasExcludedError = result.result.errors.some(error => 
          criteria.excludeErrorCodes!.includes(error.code)
        );
        if (hasExcludedError) {
          return false;
        }
      }

      return true;
    });
  }

  /**
   * Utility: Add timeout to a promise
   */
  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`Operation timed out after ${timeoutMs}ms`)), timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
  }

  /**
   * Utility: Split array into chunks
   */
  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  /**
   * Extract presentation ID from presentation object
   */
  private extractPresentationId(presentation: VerifiablePresentation): string | undefined {
    // Look for id in various possible locations
    return (presentation as any).id || 
           (presentation.proof as any)?.id ||
           undefined;
  }
}