import { ServiceProvider, VerificationResult, ServiceProviderOptions } from './service-provider';
import { VerifiablePresentation } from '../types/index';
import { 
  ServiceManifest, 
  AgentValidation, 
  DelegationCredential,
  ScopeDefinition 
} from '../agent/types';
import { ScopeValidator } from '../agent/scope-validator';
import { ServiceManifestBuilder } from '../agent/service-manifest';
import { VerificationError, VerificationErrorCode } from './verification-errors';
import { AgentRevocationService } from '../agent/agent-revocation-service';

export interface AgentServiceProviderOptions extends ServiceProviderOptions {
  serviceManifest?: ServiceManifest;
  requireAgentValidation?: boolean;
  agentRevocationService?: AgentRevocationService;
}

export class AgentEnabledServiceProvider extends ServiceProvider {
  private serviceManifest: ServiceManifest;
  private scopeValidator: ScopeValidator;
  private requireAgentValidation: boolean;
  private agentRevocationService?: AgentRevocationService;
  private agentSessions: Map<string, { agentDID: string; parentDID: string; scopes: string[] }> = new Map();

  constructor(
    name: string,
    did: string,
    trustedIssuers: string[] = [],
    options: AgentServiceProviderOptions = {}
  ) {
    super(name, trustedIssuers, options);
    
    this.scopeValidator = new ScopeValidator();
    this.requireAgentValidation = options.requireAgentValidation ?? false;
    this.agentRevocationService = options.agentRevocationService;
    
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
    
    try {
      // First, perform standard presentation verification
      const baseResult = await super.verifyPresentation(presentation);
      if (!baseResult.valid) {
        return baseResult;
      }
      
      // Extract required scopes from manifest
      const requiredScopes = this.serviceManifest.requiredScopes.map(s => s.id);
      
      // Validate agent authorization
      const agentValidation = await this.validateAgent(presentation, requiredScopes);
      
      if (!agentValidation.isValid) {
        return {
          valid: false,
          errors: agentValidation.errors?.map(e => 
            new VerificationError(VerificationErrorCode.INSUFFICIENT_PERMISSIONS, e)
          ) || [],
          timestamp
        };
      }
      
      // Check revocation status if revocation service is available
      if (this.agentRevocationService && agentValidation.agentDID && agentValidation.parentDID) {
        const delegationCredential = presentation.verifiableCredential?.[0] as unknown as DelegationCredential;
        
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
      
      // Store agent session
      if (agentValidation.agentDID && agentValidation.parentDID && agentValidation.grantedScopes) {
        const sessionId = `${agentValidation.agentDID}:${Date.now()}`;
        this.agentSessions.set(sessionId, {
          agentDID: agentValidation.agentDID,
          parentDID: agentValidation.parentDID,
          scopes: agentValidation.grantedScopes
        });
      }
      
      // Extract delegation credential for result
      const delegationCredential = presentation.verifiableCredential?.[0] as unknown as DelegationCredential;
      
      return {
        valid: true,
        holder: agentValidation.agentDID,
        credentials: [{
          id: delegationCredential.id,
          issuer: delegationCredential.issuer,
          type: delegationCredential.type,
          attributes: {
            agentDID: agentValidation.agentDID,
            parentDID: agentValidation.parentDID,
            scopes: agentValidation.grantedScopes,
            agentName: delegationCredential.credentialSubject.name
          }
        }],
        timestamp
      };
      
    } catch (error) {
      return {
        valid: false,
        errors: [
          new VerificationError(
            VerificationErrorCode.PROCESSING_ERROR,
            error instanceof Error ? error.message : 'Unknown error during agent verification'
          )
        ],
        timestamp
      };
    }
  }

  async validateAgent(
    presentation: VerifiablePresentation,
    requiredScopes: string[]
  ): Promise<AgentValidation> {
    return this.scopeValidator.validateAgentPresentation(
      presentation,
      requiredScopes,
      this.serviceManifest.serviceDID
    );
  }

  hasScope(agentDID: string, scope: string): boolean {
    // Check all sessions for this agent
    for (const session of this.agentSessions.values()) {
      if (session.agentDID === agentDID) {
        return session.scopes.includes(scope);
      }
    }
    return false;
  }

  getAgentScopes(agentDID: string): string[] {
    // Collect all scopes from all sessions for this agent
    const allScopes = new Set<string>();
    for (const session of this.agentSessions.values()) {
      if (session.agentDID === agentDID) {
        session.scopes.forEach(scope => allScopes.add(scope));
      }
    }
    return Array.from(allScopes);
  }

  getAgentParent(agentDID: string): string | null {
    for (const session of this.agentSessions.values()) {
      if (session.agentDID === agentDID) {
        return session.parentDID;
      }
    }
    return null;
  }

  revokeAgentSession(agentDID: string): boolean {
    let revoked = false;
    for (const [sessionId, session] of this.agentSessions.entries()) {
      if (session.agentDID === agentDID) {
        this.agentSessions.delete(sessionId);
        revoked = true;
      }
    }
    return revoked;
  }

  getAllAgentSessions(): Array<{
    sessionId: string;
    agentDID: string;
    parentDID: string;
    scopes: string[];
  }> {
    const sessions: Array<{
      sessionId: string;
      agentDID: string;
      parentDID: string;
      scopes: string[];
    }> = [];
    
    for (const [sessionId, session] of this.agentSessions.entries()) {
      sessions.push({
        sessionId,
        ...session
      });
    }
    
    return sessions;
  }

  // Helper method to create a service manifest for this provider
  static createManifestBuilder(serviceDID: string, name: string): ServiceManifestBuilder {
    return new ServiceManifestBuilder(serviceDID, name);
  }

  // Method to get human-readable scope descriptions
  getScopeDescriptions(): Record<string, string> {
    const descriptions: Record<string, string> = {};
    
    const allScopes = [
      ...this.serviceManifest.requiredScopes,
      ...(this.serviceManifest.optionalScopes || [])
    ];
    
    allScopes.forEach(scope => {
      descriptions[scope.id] = scope.description;
    });
    
    return descriptions;
  }

  // Method to check if a set of scopes meets minimum requirements
  validateScopeRequirements(grantedScopes: string[]): {
    valid: boolean;
    missingRequired: string[];
    additionalOptional: string[];
  } {
    const requiredScopeIds = this.serviceManifest.requiredScopes.map(s => s.id);
    const optionalScopeIds = (this.serviceManifest.optionalScopes || []).map(s => s.id);
    
    const missingRequired = requiredScopeIds.filter(s => !grantedScopes.includes(s));
    const additionalOptional = grantedScopes.filter(s => 
      optionalScopeIds.includes(s) && !requiredScopeIds.includes(s)
    );
    
    return {
      valid: missingRequired.length === 0,
      missingRequired,
      additionalOptional
    };
  }
}