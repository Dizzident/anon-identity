import { DelegationCredential, AgentValidation } from './types';
import { ScopeRegistry } from './scope-registry';
import { verifyData } from '../core/crypto';
import { VerifiablePresentation } from '../types/index';

export class ScopeValidator {
  private scopeRegistry: ScopeRegistry;

  constructor() {
    this.scopeRegistry = ScopeRegistry.getInstance();
  }

  async validateAgentPresentation(
    presentation: VerifiablePresentation,
    requiredScopes: string[],
    serviceDID: string
  ): Promise<AgentValidation> {
    const errors: string[] = [];

    // Extract delegation credential from presentation
    if (!presentation.verifiableCredential || presentation.verifiableCredential.length === 0) {
      return {
        isValid: false,
        errors: ['No delegation credential found in presentation']
      };
    }

    const credential = presentation.verifiableCredential[0] as unknown as DelegationCredential;
    
    // Check if it's a delegation credential
    if (!credential.type.includes('DelegationCredential')) {
      return {
        isValid: false,
        errors: ['Credential is not a delegation credential']
      };
    }

    // Validate credential expiration
    if (new Date(credential.expirationDate) < new Date()) {
      errors.push('Delegation credential has expired');
    }

    // Validate credential validity period
    const validFrom = new Date(credential.credentialSubject.validFrom);
    const validUntil = new Date(credential.credentialSubject.validUntil);
    const now = new Date();

    if (now < validFrom || now > validUntil) {
      errors.push('Credential is not within valid time period');
    }

    // Check if credential is for the correct service
    const serviceScopes = credential.credentialSubject.services[serviceDID];
    if (!serviceScopes) {
      errors.push(`No access granted for service: ${serviceDID}`);
    }

    // Validate required scopes
    const grantedScopes = serviceScopes?.scopes || [];
    const missingScopes = requiredScopes.filter(scope => !grantedScopes.includes(scope));
    
    if (missingScopes.length > 0) {
      errors.push(`Missing required scopes: ${missingScopes.join(', ')}`);
    }

    // Validate scope definitions exist
    for (const scope of grantedScopes) {
      if (!this.scopeRegistry.getScope(scope)) {
        errors.push(`Unknown scope: ${scope}`);
      }
    }

    // Check presentation holder matches credential subject (if holder is present)
    const holder = (presentation as any).holder;
    if (holder && holder !== credential.credentialSubject.id) {
      errors.push('Presentation holder does not match credential subject');
    }

    if (errors.length > 0) {
      return {
        isValid: false,
        errors
      };
    }

    return {
      isValid: true,
      agentDID: credential.credentialSubject.id,
      parentDID: credential.credentialSubject.parentDID,
      grantedScopes: grantedScopes
    };
  }

  validateScopeFormat(scope: string): boolean {
    const parts = scope.split(':');
    if (parts.length < 2 || parts.length > 4) return false;

    const validPartRegex = /^[a-z0-9]+$/;
    return parts.every(part => validPartRegex.test(part));
  }

  checkScopeHierarchy(grantedScopes: string[], requestedScope: string): boolean {
    // Direct match
    if (grantedScopes.includes(requestedScope)) return true;

    // Check for wildcard or broader scopes
    const requestedParts = requestedScope.split(':');
    
    for (const granted of grantedScopes) {
      const grantedParts = granted.split(':');
      
      // Check if granted scope is broader (has fewer parts but matching prefix)
      if (grantedParts.length < requestedParts.length) {
        const matches = grantedParts.every((part, index) => 
          part === requestedParts[index] || part === '*'
        );
        if (matches) return true;
      }
      
      // Check for wildcard matches at same level
      if (grantedParts.length === requestedParts.length) {
        const matches = grantedParts.every((part, index) => 
          part === requestedParts[index] || part === '*'
        );
        if (matches) return true;
      }
    }

    return false;
  }

  evaluateRiskLevel(scopes: string[]): 'low' | 'medium' | 'high' {
    let maxRisk: 'low' | 'medium' | 'high' = 'low';

    for (const scopeId of scopes) {
      const scope = this.scopeRegistry.getScope(scopeId);
      if (!scope) continue;

      if (scope.riskLevel === 'high') return 'high';
      if (scope.riskLevel === 'medium') maxRisk = 'medium';
    }

    return maxRisk;
  }

  filterScopesByConstraints(
    scopes: string[], 
    constraints?: Record<string, any>
  ): string[] {
    if (!constraints) return scopes;

    return scopes.filter(scope => {
      // Check for constraint-based scopes
      const parts = scope.split(':');
      if (parts.length >= 3) {
        // Extract constraint type and value
        const constraintType = parts[2];
        const constraintValue = parts[3];

        if (constraints[constraintType] !== undefined) {
          // For numeric constraints, check if within limit
          if (constraintType === 'limit' && constraintValue) {
            const limit = parseInt(constraintValue, 10);
            const requestedValue = constraints[constraintType];
            if (typeof requestedValue === 'number' && requestedValue > limit) {
              return false;
            }
          }
        }
      }

      return true;
    });
  }

  generateScopeReport(scopes: string[]): {
    categories: Record<string, string[]>;
    riskLevel: 'low' | 'medium' | 'high';
    dependencies: string[];
    warnings: string[];
  } {
    const categories: Record<string, string[]> = {};
    const allDependencies = new Set<string>();
    const warnings: string[] = [];

    for (const scopeId of scopes) {
      const scope = this.scopeRegistry.getScope(scopeId);
      if (!scope) {
        warnings.push(`Unknown scope: ${scopeId}`);
        continue;
      }

      // Group by category
      if (!categories[scope.category]) {
        categories[scope.category] = [];
      }
      categories[scope.category].push(scopeId);

      // Collect dependencies
      if (scope.dependencies) {
        scope.dependencies.forEach(dep => allDependencies.add(dep));
      }
    }

    // Check for missing dependencies
    const missingDeps = Array.from(allDependencies).filter(dep => !scopes.includes(dep));
    if (missingDeps.length > 0) {
      warnings.push(`Missing dependencies: ${missingDeps.join(', ')}`);
    }

    return {
      categories,
      riskLevel: this.evaluateRiskLevel(scopes),
      dependencies: Array.from(allDependencies),
      warnings
    };
  }
}