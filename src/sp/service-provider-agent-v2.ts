import { ServiceProvider, VerificationResult, ServiceProviderOptions } from './service-provider';
import { VerifiablePresentation } from '../types/index';
import { 
  ServiceManifest, 
  AgentValidation, 
  DelegationCredential,
  ScopeDefinition 
} from '../agent/types';
import { ScopeValidator } from '../agent/scope-validator';
import { ScopeRegistry } from '../agent/scope-registry';
import { ServiceManifestBuilder } from '../agent/service-manifest';
import { VerificationError, VerificationErrorCode } from './verification-errors';
import { AgentRevocationService } from '../agent/agent-revocation-service';
import { ActivityLogger, createActivity } from '../agent/activity/activity-logger';
import { ActivityType, ActivityStatus } from '../agent/activity/types';
import { DelegationChainValidator } from '../agent/delegation-chain-validator';
import { DelegationManager } from '../agent/delegation-manager';
import { AgentIdentityManager } from '../agent/agent-identity';

export interface AgentServiceProviderV2Options extends ServiceProviderOptions {
  serviceManifest?: ServiceManifest;
  requireAgentValidation?: boolean;
  agentRevocationService?: AgentRevocationService;
  agentIdentityManager?: AgentIdentityManager;
  delegationManager?: DelegationManager;
  validateDelegationChains?: boolean;
  maxChainDepth?: number;
}

export class AgentEnabledServiceProviderV2 extends ServiceProvider {
  private serviceManifest: ServiceManifest;
  private scopeValidator: ScopeValidator;
  private requireAgentValidation: boolean;
  private agentRevocationService?: AgentRevocationService;
  private activityLogger: ActivityLogger;
  private chainValidator?: DelegationChainValidator;
  private validateChains: boolean;
  private maxChainDepth: number;
  private agentSessions: Map<string, { 
    agentDID: string; 
    parentDID: string; 
    scopes: string[]; 
    sessionId: string;
    delegationChain?: any;
  }> = new Map();

  constructor(
    name: string,
    did: string,
    trustedIssuers: string[] = [],
    options: AgentServiceProviderV2Options = {}
  ) {
    super(name, trustedIssuers, options);
    
    this.scopeValidator = new ScopeValidator();
    this.requireAgentValidation = options.requireAgentValidation ?? false;
    this.agentRevocationService = options.agentRevocationService;
    this.activityLogger = new ActivityLogger();
    this.validateChains = options.validateDelegationChains ?? true;
    this.maxChainDepth = options.maxChainDepth ?? 5;
    
    // Initialize chain validator if provided
    if (options.agentIdentityManager && options.delegationManager) {
      this.chainValidator = new DelegationChainValidator(
        options.delegationManager,
        options.agentIdentityManager
      );
    }
    
    // Create default service manifest if not provided
    this.serviceManifest = options.serviceManifest || 
      ServiceManifestBuilder.createBasicReadService(did, name);
  }

  setServiceManifest(manifest: ServiceManifest): void {
    this.serviceManifest = manifest;
  }

  getServiceManifest(): ServiceManifest {
    return this.serviceManifest;
  }

  async verifyPresentation(presentation: VerifiablePresentation): Promise<VerificationResult> {
    // Check if this is an agent presentation
    if (presentation.type?.includes('AgentPresentation')) {
      return this.verifyAgentPresentation(presentation);
    }
    
    // For regular presentations, use parent class verification
    const result = await super.verifyPresentation(presentation);
    
    // If agent validation is required and this is not an agent, fail
    if (this.requireAgentValidation && result.valid) {
      return {
        ...result,
        valid: false,
        errors: [
          ...(result.errors || []),
          new VerificationError(
            VerificationErrorCode.INVALID_CREDENTIAL,
            'Agent validation required but presentation is not from an agent'
          )
        ]
      };
    }
    
    return result;
  }

  private async verifyAgentPresentation(presentation: VerifiablePresentation): Promise<VerificationResult> {
    const errors: VerificationError[] = [];
    const timestamp = new Date();
    const startTime = Date.now();
    
    // Extract agent info early for logging
    const delegationCredential = presentation.verifiableCredential?.[0] as unknown as DelegationCredential;
    const agentDID = delegationCredential?.credentialSubject?.id || 'unknown';
    const parentDID = delegationCredential?.credentialSubject?.parentDID || 'unknown';
    
    try {
      // Log authentication attempt
      await this.activityLogger.logActivity(createActivity(
        ActivityType.AUTHENTICATION,
        {
          agentDID,
          parentDID,
          serviceDID: this.serviceManifest.serviceDID,
          status: ActivityStatus.SUCCESS,
          scopes: [],
          details: {
            presentationId: (presentation as any).id,
            message: 'Agent authentication attempt started'
          }
        }
      ));
      
      // First, perform standard presentation verification
      const baseResult = await super.verifyPresentation(presentation);
      if (!baseResult.valid) {
        // Log authentication failure
        await this.activityLogger.logActivity(createActivity(
          ActivityType.AUTHENTICATION,
          {
            agentDID,
            parentDID,
            serviceDID: this.serviceManifest.serviceDID,
            status: ActivityStatus.FAILED,
            scopes: [],
            details: {
              errorMessage: 'Base presentation verification failed',
              errors: baseResult.errors?.map(e => e.message)
            }
          }
        ));
        return baseResult;
      }
      
      // Extract required scopes from manifest
      const requiredScopes = this.serviceManifest.requiredScopes.map(s => s.id);
      
      // Validate agent authorization
      const agentValidation = await this.validateAgent(presentation, requiredScopes);
      
      if (!agentValidation.isValid) {
        // Log authorization failure
        await this.activityLogger.logActivity(createActivity(
          ActivityType.AUTHORIZATION,
          {
            agentDID,
            parentDID,
            serviceDID: this.serviceManifest.serviceDID,
            status: ActivityStatus.DENIED,
            scopes: requiredScopes,
            details: {
              errorMessage: 'Agent authorization failed',
              errors: agentValidation.errors,
              scopesRequested: requiredScopes,
              scopesDenied: requiredScopes
            }
          }
        ));
        
        return {
          valid: false,
          errors: agentValidation.errors?.map(e => 
            new VerificationError(VerificationErrorCode.INSUFFICIENT_PERMISSIONS, e)
          ) || [],
          timestamp
        };
      }

      // NEW: Validate delegation chain if enabled and chain validator is available
      if (this.validateChains && this.chainValidator && agentValidation.agentDID) {
        const rootDID = await this.findRootDID(delegationCredential);
        
        if (rootDID) {
          const chainValidation = await this.chainValidator.validateDelegationChain(
            agentValidation.agentDID,
            rootDID,
            this.serviceManifest.serviceDID
          );
          
          if (!chainValidation.valid) {
            await this.activityLogger.logActivity(createActivity(
              ActivityType.AUTHORIZATION,
              {
                agentDID,
                parentDID,
                serviceDID: this.serviceManifest.serviceDID,
                status: ActivityStatus.DENIED,
                scopes: requiredScopes,
                details: {
                  errorMessage: 'Delegation chain validation failed',
                  errors: chainValidation.errors,
                  warnings: chainValidation.warnings
                }
              }
            ));
            
            return {
              valid: false,
              errors: chainValidation.errors.map(e => 
                new VerificationError(VerificationErrorCode.INVALID_CREDENTIAL, e)
              ),
              timestamp
            };
          }
          
          // Store chain information in session if valid
          if (chainValidation.chain && agentValidation.parentDID && agentValidation.grantedScopes) {
            const sessionId = `${agentValidation.agentDID}:${Date.now()}`;
            this.agentSessions.set(sessionId, {
              agentDID: agentValidation.agentDID,
              parentDID: agentValidation.parentDID,
              scopes: agentValidation.grantedScopes,
              sessionId,
              delegationChain: this.chainValidator.exportChain(chainValidation.chain)
            });
            
            // Log successful authorization with chain info
            await this.activityLogger.logActivity(createActivity(
              ActivityType.AUTHORIZATION,
              {
                agentDID: agentValidation.agentDID,
                parentDID: agentValidation.parentDID,
                serviceDID: this.serviceManifest.serviceDID,
                status: ActivityStatus.SUCCESS,
                scopes: agentValidation.grantedScopes,
                sessionId,
                details: {
                  scopesRequested: requiredScopes,
                  scopesGranted: agentValidation.grantedScopes,
                  message: 'Agent authorization successful with chain validation',
                  chainDepth: chainValidation.chain.currentDepth,
                  chainWarnings: chainValidation.warnings
                }
              }
            ));
            
            return {
              valid: true,
              credentials: baseResult.credentials,
              timestamp,
              holder: agentValidation.agentDID
            };
          }
        }
      }
      
      // Check revocation status if revocation service is available
      if (this.agentRevocationService && agentValidation.agentDID && agentValidation.parentDID) {
        // Check if agent is revoked
        const isRevoked = await this.agentRevocationService.isAgentRevoked(
          agentValidation.agentDID,
          agentValidation.parentDID
        );
        
        if (isRevoked) {
          return {
            valid: false,
            errors: [new VerificationError(
              VerificationErrorCode.CREDENTIAL_REVOKED,
              'Agent has been revoked'
            )],
            timestamp
          };
        }
        
        // Check service-specific revocation
        const isServiceRevoked = await this.agentRevocationService.isAgentServiceRevoked(
          agentValidation.agentDID,
          agentValidation.parentDID,
          this.serviceManifest.serviceDID
        );
        
        if (isServiceRevoked) {
          return {
            valid: false,
            errors: [new VerificationError(
              VerificationErrorCode.CREDENTIAL_REVOKED,
              `Agent access to this service has been revoked`
            )],
            timestamp
          };
        }
        
        // Validate the delegation credential itself
        const credentialValidation = await this.agentRevocationService.validateDelegationCredential(
          delegationCredential
        );
        
        if (!credentialValidation.valid) {
          return {
            valid: false,
            errors: [new VerificationError(
              VerificationErrorCode.CREDENTIAL_REVOKED,
              credentialValidation.reason || 'Delegation credential validation failed'
            )],
            timestamp
          };
        }
      }
      
      // Store agent session (without chain info if chain validation wasn't performed)
      if (agentValidation.agentDID && agentValidation.parentDID && agentValidation.grantedScopes) {
        const sessionId = `${agentValidation.agentDID}:${Date.now()}`;
        if (!this.agentSessions.has(sessionId)) {
          this.agentSessions.set(sessionId, {
            agentDID: agentValidation.agentDID,
            parentDID: agentValidation.parentDID,
            scopes: agentValidation.grantedScopes,
            sessionId
          });
        }
        
        return {
          valid: true,
          credentials: baseResult.credentials,
          timestamp,
          holder: agentValidation.agentDID
        };
      }
      
      return {
        valid: true,
        credentials: baseResult.credentials,
        timestamp
      };
      
    } catch (error) {
      // Log error
      await this.activityLogger.logActivity(createActivity(
        ActivityType.AUTHENTICATION,
        {
          agentDID,
          parentDID,
          serviceDID: this.serviceManifest.serviceDID,
          status: ActivityStatus.FAILED,
          scopes: [],
          details: {
            errorMessage: error instanceof Error ? error.message : 'Unknown error',
            errorType: 'exception'
          }
        }
      ));
      
      return {
        valid: false,
        errors: [new VerificationError(
          VerificationErrorCode.INVALID_CREDENTIAL,
          `Agent verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        )],
        timestamp
      };
    }
  }

  private async validateAgent(
    presentation: VerifiablePresentation, 
    requiredScopes: string[]
  ): Promise<AgentValidation> {
    // Extract delegation credential
    const delegationCredential = presentation.verifiableCredential?.[0] as unknown as DelegationCredential;
    if (!delegationCredential) {
      return {
        isValid: false,
        errors: ['No delegation credential found in presentation']
      };
    }

    // Extract agent information
    const agentDID = delegationCredential.credentialSubject.id;
    const parentDID = delegationCredential.credentialSubject.parentDID;
    
    // Get service-specific grants
    const serviceGrants = delegationCredential.credentialSubject.services[this.serviceManifest.serviceDID];
    if (!serviceGrants) {
      return {
        isValid: false,
        errors: [`No access grants found for service ${this.serviceManifest.serviceDID}`],
        agentDID,
        parentDID
      };
    }

    // Validate required scopes
    const grantedScopes = serviceGrants.scopes;
    const missingScopes = requiredScopes.filter(scope => !grantedScopes.includes(scope));
    
    if (missingScopes.length > 0) {
      return {
        isValid: false,
        errors: [`Missing required scopes: ${missingScopes.join(', ')}`],
        agentDID,
        parentDID,
        grantedScopes
      };
    }

    // Additional scope validation
    const scopeRegistry = ScopeRegistry.getInstance();
    const validation = scopeRegistry.validateScopes(requiredScopes);
    if (!validation.valid) {
      return {
        isValid: false,
        errors: validation.errors || ['Invalid scope configuration'],
        agentDID,
        parentDID,
        grantedScopes
      };
    }

    return {
      isValid: true,
      agentDID,
      parentDID,
      grantedScopes
    };
  }

  private async findRootDID(credential: DelegationCredential): Promise<string | null> {
    // For now, we'll check if the issuer is in trusted issuers
    // In a full implementation, this would traverse up the chain
    if (this.isTrustedIssuer(credential.issuer)) {
      return credential.issuer;
    }
    
    // Check if any trusted issuer is in the credential subject's parent chain
    // This is simplified - in reality would need to traverse the full chain
    if (this.isTrustedIssuer(credential.credentialSubject.parentDID)) {
      return credential.credentialSubject.parentDID;
    }
    
    return null;
  }

  private isTrustedIssuer(did: string): boolean {
    // Access parent class method or implement our own check
    return (this as any).trustedIssuers?.has(did) || false;
  }

  getAgentSession(sessionId: string) {
    return this.agentSessions.get(sessionId);
  }

  clearExpiredSessions(): void {
    // Clear sessions older than 1 hour
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    for (const [sessionId, session] of this.agentSessions.entries()) {
      const sessionTime = parseInt(sessionId.split(':')[1]);
      if (sessionTime < oneHourAgo) {
        this.agentSessions.delete(sessionId);
      }
    }
  }
}