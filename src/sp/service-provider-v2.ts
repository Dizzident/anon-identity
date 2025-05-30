import { ServiceProvider, ServiceProviderOptions, VerificationResult } from './service-provider';
import { VerifiablePresentation, VerifiableCredential } from '../types';
import { 
  VerifiableCredentialV2, 
  VerifiablePresentationV2,
  isVerifiableCredentialV2,
  CredentialStatus
} from '../types/vc2';
import { 
  CompositeStatusChecker, 
  StatusCheckResult,
  RevocationList2020StatusChecker,
  StatusList2021StatusChecker
} from '../status/credential-status';
import { VerificationError, VerificationErrorCode } from './verification-errors';
import { ProofManager } from '../core/proof-manager';

export interface ServiceProviderV2Options extends ServiceProviderOptions {
  // Enable credential status checking (default: true)
  checkCredentialStatus?: boolean;
  // Custom status checker
  statusChecker?: CompositeStatusChecker;
  // Status list cache TTL in seconds
  statusCacheTTL?: number;
}

/**
 * Enhanced Service Provider with W3C VC 2.0 support
 */
export class ServiceProviderV2 extends ServiceProvider {
  private checkCredentialStatus: boolean;
  private statusChecker: CompositeStatusChecker;
  private statusCache: Map<string, { result: StatusCheckResult; expires: number }> = new Map();
  private statusCacheTTL: number;
  
  constructor(
    name: string,
    trustedIssuers: string[] = [],
    options: ServiceProviderV2Options = {}
  ) {
    super(name, trustedIssuers, options);
    
    this.checkCredentialStatus = options.checkCredentialStatus ?? true;
    this.statusChecker = options.statusChecker || new CompositeStatusChecker();
    this.statusCacheTTL = (options.statusCacheTTL || 300) * 1000; // Convert to milliseconds
  }
  
  /**
   * Verify a presentation that may contain VC 2.0 credentials
   */
  async verifyPresentationV2(
    presentation: VerifiablePresentation | VerifiablePresentationV2
  ): Promise<VerificationResult> {
    // First, perform standard verification
    const baseResult = await super.verifyPresentation(presentation as VerifiablePresentation);
    
    // If base verification failed, return immediately
    if (!baseResult.valid) {
      return baseResult;
    }
    
    // Now check credential status for V2 credentials
    if (this.checkCredentialStatus && presentation.verifiableCredential) {
      const additionalErrors: VerificationError[] = [];
      
      for (const credential of presentation.verifiableCredential) {
        if (typeof credential === 'string') continue;
        
        // Check if this is a V2 credential with status
        if (isVerifiableCredentialV2(credential) && credential.credentialStatus) {
          const statusResult = await this.checkCredentialStatusWithCache(
            credential.id || 'unknown',
            credential.credentialStatus
          );
          
          if (statusResult.revoked) {
            additionalErrors.push(
              VerificationError.revokedCredential(
                credential.id || 'unknown',
                typeof credential.issuer === 'string' 
                  ? credential.issuer 
                  : credential.issuer.id
              )
            );
          }
          
          if (statusResult.suspended) {
            additionalErrors.push(
              new VerificationError(
                VerificationErrorCode.CREDENTIAL_SUSPENDED,
                `Credential ${credential.id} is suspended: ${statusResult.reason || 'No reason provided'}`,
                { credentialId: credential.id, reason: statusResult.reason }
              )
            );
          }
        }
      }
      
      // If we found status issues, update the result
      if (additionalErrors.length > 0) {
        return {
          ...baseResult,
          valid: false,
          errors: [...(baseResult.errors || []), ...additionalErrors]
        };
      }
    }
    
    return baseResult;
  }
  
  /**
   * Check credential status with caching
   */
  private async checkCredentialStatusWithCache(
    credentialId: string,
    statusInfo: CredentialStatus | CredentialStatus[]
  ): Promise<StatusCheckResult> {
    const statusArray = Array.isArray(statusInfo) ? statusInfo : [statusInfo];
    
    // Check each status (a credential might have multiple status entries)
    for (const status of statusArray) {
      const cacheKey = `${credentialId}:${status.id}`;
      
      // Check cache first
      const cached = this.statusCache.get(cacheKey);
      if (cached && cached.expires > Date.now()) {
        return cached.result;
      }
      
      // Perform status check
      try {
        const result = await this.statusChecker.checkStatus(credentialId, status);
        
        // Cache the result
        this.statusCache.set(cacheKey, {
          result,
          expires: Date.now() + this.statusCacheTTL
        });
        
        // If revoked or suspended, return immediately
        if (result.revoked || result.suspended) {
          return result;
        }
      } catch (error) {
        console.warn(`Failed to check credential status: ${error}`);
        // On error, assume credential is valid (fail open)
        return {
          revoked: false,
          checkedAt: new Date().toISOString()
        };
      }
    }
    
    // If all status checks passed, return not revoked
    return {
      revoked: false,
      checkedAt: new Date().toISOString()
    };
  }
  
  /**
   * Load a revocation list into the status checker
   */
  async loadRevocationList(listId: string, list: any): Promise<void> {
    const checker = this.statusChecker['checkers'].get('RevocationList2020');
    if (checker instanceof RevocationList2020StatusChecker) {
      checker.addRevocationList(listId, list);
    }
  }
  
  /**
   * Load a status list credential into the status checker
   */
  async loadStatusListCredential(credential: any): Promise<void> {
    const checker = this.statusChecker['checkers'].get('StatusList2021');
    if (checker instanceof StatusList2021StatusChecker) {
      await checker.loadStatusListCredential(credential);
    }
  }
  
  /**
   * Clear the status cache
   */
  clearStatusCache(): void {
    this.statusCache.clear();
  }
  
  /**
   * Get cache statistics
   */
  getStatusCacheStats(): { size: number; hits: number; misses: number } {
    return {
      size: this.statusCache.size,
      hits: 0, // Would need to track this
      misses: 0 // Would need to track this
    };
  }
}