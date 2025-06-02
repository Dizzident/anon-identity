import { 
  AgentIdentity, 
  AgentDelegationOptions, 
  ScopeReductionPolicy,
  ExpirationPolicy,
  DelegationCredential,
  AccessGrant,
  DelegationContext
} from './types';
import { AgentIdentityManager } from './agent-identity';

export interface DelegationPolicy {
  id: string;
  name: string;
  description: string;
  maxDepth: number;
  scopeReduction: ScopeReductionPolicy;
  expirationPolicy: ExpirationPolicy;
  constraints?: DelegationConstraints;
  enabled: boolean;
}

export interface DelegationConstraints {
  allowedServices?: string[];
  deniedServices?: string[];
  maxScopes?: number;
  requiredScopes?: string[];
  timeOfDayRestrictions?: TimeRestriction[];
  ipWhitelist?: string[];
  customConstraints?: Array<(context: DelegationContext) => boolean>;
}

export interface TimeRestriction {
  startHour: number;
  endHour: number;
  timezone: string;
  daysOfWeek?: number[]; // 0 = Sunday, 6 = Saturday
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  policy?: DelegationPolicy;
  violations: string[];
  warnings: string[];
  appliedConstraints: string[];
}

export class DelegationPolicyEngine {
  private policies: Map<string, DelegationPolicy> = new Map();
  private globalMaxDepth: number = 5;
  private defaultPolicy: DelegationPolicy;

  constructor(private agentManager: AgentIdentityManager) {
    this.defaultPolicy = this.createDefaultPolicy();
    this.initializeBuiltInPolicies();
  }

  /**
   * Sets the global maximum delegation depth
   */
  setGlobalMaxDepth(depth: number): void {
    if (depth < 1 || depth > 10) {
      throw new Error('Global max depth must be between 1 and 10');
    }
    this.globalMaxDepth = depth;
  }

  /**
   * Registers a delegation policy
   */
  registerPolicy(policy: DelegationPolicy): void {
    // Validate policy
    if (policy.maxDepth > this.globalMaxDepth) {
      throw new Error(`Policy max depth (${policy.maxDepth}) exceeds global max (${this.globalMaxDepth})`);
    }
    
    this.policies.set(policy.id, policy);
  }

  /**
   * Evaluates whether a delegation is allowed based on policies
   */
  async evaluatePolicy(
    context: DelegationContext,
    policyId?: string
  ): Promise<PolicyEvaluationResult> {
    const violations: string[] = [];
    const warnings: string[] = [];
    const appliedConstraints: string[] = [];

    // Get the policy to evaluate
    const policy = policyId 
      ? this.policies.get(policyId) || this.defaultPolicy
      : this.findApplicablePolicy(context) || this.defaultPolicy;

    if (!policy.enabled) {
      return {
        allowed: false,
        policy,
        violations: ['Policy is disabled'],
        warnings,
        appliedConstraints
      };
    }

    // Check global max depth
    const currentDepth = context.parentAgent.delegationDepth;
    if (currentDepth >= this.globalMaxDepth) {
      violations.push(`Global max delegation depth (${this.globalMaxDepth}) reached`);
    }

    // Check policy max depth
    if (currentDepth >= policy.maxDepth) {
      violations.push(`Policy max delegation depth (${policy.maxDepth}) reached`);
    }

    // Apply scope reduction
    const parentScopes = await this.getParentScopes(context.parentAgent);
    const allowedScopes = this.agentManager.reduceScopesForDelegation(
      parentScopes,
      context.requestedScopes,
      policy.scopeReduction
    );

    if (allowedScopes.length === 0) {
      violations.push('No scopes would be granted after reduction');
    } else if (allowedScopes.length < context.requestedScopes.length) {
      warnings.push(`Scope reduction applied: ${context.requestedScopes.length - allowedScopes.length} scopes removed`);
      appliedConstraints.push('scope-reduction');
    }

    // Apply constraints
    if (policy.constraints) {
      const constraintResults = this.evaluateConstraints(policy.constraints, context);
      violations.push(...constraintResults.violations);
      warnings.push(...constraintResults.warnings);
      appliedConstraints.push(...constraintResults.applied);
    }

    return {
      allowed: violations.length === 0,
      policy,
      violations,
      warnings,
      appliedConstraints
    };
  }

  /**
   * Creates a delegation options object based on policy
   */
  createDelegationOptions(
    policy: DelegationPolicy,
    parentAgent: AgentIdentity
  ): AgentDelegationOptions {
    const remainingDepth = Math.min(
      policy.maxDepth - parentAgent.delegationDepth - 1,
      this.globalMaxDepth - parentAgent.delegationDepth - 1
    );

    return {
      maxDepth: remainingDepth,
      scopeReduction: policy.scopeReduction,
      expirationPolicy: policy.expirationPolicy,
      auditLevel: 'detailed'
    };
  }

  /**
   * Applies expiration policy to determine credential expiration
   */
  calculateExpiration(
    policy: DelegationPolicy,
    parentExpiration: Date
  ): Date {
    const now = new Date();
    const { strategy, fixedDuration, reductionFactor } = policy.expirationPolicy;

    switch (strategy) {
      case 'inherit':
        return parentExpiration;
      
      case 'fixed':
        const duration = fixedDuration || 24 * 60 * 60 * 1000; // Default 24 hours
        return new Date(now.getTime() + duration);
      
      case 'reduced':
        const parentRemaining = parentExpiration.getTime() - now.getTime();
        const factor = reductionFactor || 0.5;
        return new Date(now.getTime() + parentRemaining * factor);
      
      default:
        return parentExpiration;
    }
  }

  /**
   * Validates that a delegation request complies with all policies
   */
  async validateDelegationRequest(
    parentAgentDID: string,
    requestedScopes: string[],
    serviceDID?: string
  ): Promise<{ valid: boolean; errors: string[]; maxDepth?: number }> {
    const parentAgent = this.agentManager.getAgent(parentAgentDID);
    if (!parentAgent) {
      return { valid: false, errors: ['Parent agent not found'] };
    }

    const context: DelegationContext = {
      parentAgent,
      requestedScopes,
      serviceDID
    };

    const evaluation = await this.evaluatePolicy(context);
    
    if (!evaluation.allowed) {
      return { valid: false, errors: evaluation.violations };
    }

    const maxDepth = Math.min(
      evaluation.policy?.maxDepth || this.globalMaxDepth,
      this.globalMaxDepth - parentAgent.delegationDepth - 1
    );

    return { valid: true, errors: [], maxDepth };
  }

  // Private helper methods

  private createDefaultPolicy(): DelegationPolicy {
    return {
      id: 'default',
      name: 'Default Delegation Policy',
      description: 'Default policy for agent delegations',
      maxDepth: 3,
      scopeReduction: { strategy: 'intersection' },
      expirationPolicy: { strategy: 'reduced', reductionFactor: 0.8 },
      enabled: true
    };
  }

  private initializeBuiltInPolicies(): void {
    // Restrictive policy for high-security scenarios
    this.registerPolicy({
      id: 'high-security',
      name: 'High Security Policy',
      description: 'Restrictive policy for sensitive operations',
      maxDepth: 1,
      scopeReduction: { strategy: 'subset' },
      expirationPolicy: { strategy: 'fixed', fixedDuration: 60 * 60 * 1000 }, // 1 hour
      constraints: {
        maxScopes: 3,
        requiredScopes: ['agent:audit']
      },
      enabled: true
    });

    // Permissive policy for development
    this.registerPolicy({
      id: 'development',
      name: 'Development Policy',
      description: 'Permissive policy for development environments',
      maxDepth: 5,
      scopeReduction: { strategy: 'intersection' },
      expirationPolicy: { strategy: 'inherit' },
      enabled: true
    });

    // Time-restricted policy
    this.registerPolicy({
      id: 'business-hours',
      name: 'Business Hours Policy',
      description: 'Allows delegation only during business hours',
      maxDepth: 2,
      scopeReduction: { strategy: 'intersection' },
      expirationPolicy: { strategy: 'fixed', fixedDuration: 8 * 60 * 60 * 1000 }, // 8 hours
      constraints: {
        timeOfDayRestrictions: [{
          startHour: 9,
          endHour: 17,
          timezone: 'UTC',
          daysOfWeek: [1, 2, 3, 4, 5] // Monday to Friday
        }]
      },
      enabled: true
    });
  }

  private findApplicablePolicy(context: DelegationContext): DelegationPolicy | null {
    // For now, return the default policy
    // In a full implementation, this would match based on context
    return this.defaultPolicy;
  }

  private async getParentScopes(parentAgent: AgentIdentity): Promise<string[]> {
    // Get the parent's delegation credentials
    const credentials = this.agentManager.getDelegationCredentials(parentAgent.did);
    if (credentials.length === 0) return [];

    // Extract all unique scopes from all credentials
    const allScopes = new Set<string>();
    credentials.forEach(cred => {
      cred.credentialSubject.scopes.forEach(scope => allScopes.add(scope));
    });

    return Array.from(allScopes);
  }

  private evaluateConstraints(
    constraints: DelegationConstraints,
    context: DelegationContext
  ): { violations: string[]; warnings: string[]; applied: string[] } {
    const violations: string[] = [];
    const warnings: string[] = [];
    const applied: string[] = [];

    // Check allowed services
    if (constraints.allowedServices && context.serviceDID) {
      if (!constraints.allowedServices.includes(context.serviceDID)) {
        violations.push(`Service ${context.serviceDID} is not in allowed list`);
      }
      applied.push('allowed-services');
    }

    // Check denied services
    if (constraints.deniedServices && context.serviceDID) {
      if (constraints.deniedServices.includes(context.serviceDID)) {
        violations.push(`Service ${context.serviceDID} is explicitly denied`);
      }
      applied.push('denied-services');
    }

    // Check max scopes
    if (constraints.maxScopes) {
      if (context.requestedScopes.length > constraints.maxScopes) {
        violations.push(`Requested scopes (${context.requestedScopes.length}) exceed maximum (${constraints.maxScopes})`);
      }
      applied.push('max-scopes');
    }

    // Check required scopes
    if (constraints.requiredScopes) {
      const missingRequired = constraints.requiredScopes.filter(
        req => !context.requestedScopes.includes(req)
      );
      if (missingRequired.length > 0) {
        violations.push(`Missing required scopes: ${missingRequired.join(', ')}`);
      }
      applied.push('required-scopes');
    }

    // Check time restrictions
    if (constraints.timeOfDayRestrictions) {
      const now = new Date();
      const allowed = constraints.timeOfDayRestrictions.some(restriction => {
        return this.isTimeAllowed(now, restriction);
      });
      
      if (!allowed) {
        violations.push('Current time is outside allowed delegation hours');
      }
      applied.push('time-restrictions');
    }

    // Check custom constraints
    if (constraints.customConstraints) {
      constraints.customConstraints.forEach((constraint, index) => {
        try {
          if (!constraint(context)) {
            violations.push(`Custom constraint ${index + 1} failed`);
          }
          applied.push(`custom-constraint-${index + 1}`);
        } catch (error) {
          warnings.push(`Custom constraint ${index + 1} threw error: ${error}`);
        }
      });
    }

    return { violations, warnings, applied };
  }

  private isTimeAllowed(date: Date, restriction: TimeRestriction): boolean {
    // Convert to timezone (simplified - in production would use proper timezone library)
    const hour = date.getUTCHours();
    const dayOfWeek = date.getUTCDay();

    // Check day of week
    if (restriction.daysOfWeek && !restriction.daysOfWeek.includes(dayOfWeek)) {
      return false;
    }

    // Check hour range
    return hour >= restriction.startHour && hour < restriction.endHour;
  }

  /**
   * Exports all registered policies
   */
  exportPolicies(): DelegationPolicy[] {
    return Array.from(this.policies.values());
  }

  /**
   * Imports policies from an array
   */
  importPolicies(policies: DelegationPolicy[]): void {
    policies.forEach(policy => {
      try {
        this.registerPolicy(policy);
      } catch (error) {
        // Log error but continue importing other policies
        console.error(`Failed to import policy ${policy.id}:`, error);
      }
    });
  }

  /**
   * Gets a specific policy by ID
   */
  getPolicy(policyId: string): DelegationPolicy | undefined {
    return this.policies.get(policyId);
  }

  /**
   * Updates an existing policy
   */
  updatePolicy(policyId: string, updates: Partial<DelegationPolicy>): void {
    const existing = this.policies.get(policyId);
    if (!existing) {
      throw new Error(`Policy ${policyId} not found`);
    }

    const updated = { ...existing, ...updates };
    
    // Validate updated policy
    if (updated.maxDepth > this.globalMaxDepth) {
      throw new Error(`Updated max depth exceeds global maximum`);
    }

    this.policies.set(policyId, updated);
  }

  /**
   * Enables or disables a policy
   */
  setPolicyEnabled(policyId: string, enabled: boolean): void {
    const policy = this.policies.get(policyId);
    if (!policy) {
      throw new Error(`Policy ${policyId} not found`);
    }
    
    policy.enabled = enabled;
  }
}