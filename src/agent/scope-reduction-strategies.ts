import { ScopeReductionPolicy } from './types';
import { ScopeRegistry } from './scope-registry';

export interface ScopeReductionResult {
  grantedScopes: string[];
  deniedScopes: string[];
  reason?: string;
  metadata?: Record<string, any>;
}

export interface ScopeHierarchy {
  scope: string;
  implies: string[];
  requiredBy: string[];
}

export class ScopeReductionStrategies {
  private static scopeRegistry = ScopeRegistry.getInstance();

  /**
   * Intersection strategy - only grant scopes that both parent has and child requests
   */
  static intersection(
    parentScopes: string[],
    requestedScopes: string[]
  ): ScopeReductionResult {
    const grantedScopes = requestedScopes.filter(scope => 
      parentScopes.includes(scope)
    );
    
    const deniedScopes = requestedScopes.filter(scope => 
      !parentScopes.includes(scope)
    );

    return {
      grantedScopes,
      deniedScopes,
      reason: deniedScopes.length > 0 
        ? 'Some requested scopes not available in parent' 
        : undefined
    };
  }

  /**
   * Subset strategy - grant all requested scopes only if they form a subset of parent scopes
   */
  static subset(
    parentScopes: string[],
    requestedScopes: string[]
  ): ScopeReductionResult {
    const isSubset = requestedScopes.every(scope => 
      parentScopes.includes(scope)
    );

    if (isSubset) {
      return {
        grantedScopes: requestedScopes,
        deniedScopes: [],
        reason: undefined
      };
    }

    return {
      grantedScopes: [],
      deniedScopes: requestedScopes,
      reason: 'Requested scopes must be a complete subset of parent scopes'
    };
  }

  /**
   * Hierarchical reduction - considers scope dependencies and implications
   */
  static hierarchical(
    parentScopes: string[],
    requestedScopes: string[]
  ): ScopeReductionResult {
    const grantedScopes: Set<string> = new Set();
    const deniedScopes: string[] = [];
    const scopeHierarchy = this.buildScopeHierarchy(parentScopes);

    for (const requested of requestedScopes) {
      if (this.canGrantScope(requested, parentScopes, scopeHierarchy)) {
        grantedScopes.add(requested);
        
        // Also add any scopes implied by this scope
        const scope = this.scopeRegistry.getScope(requested);
        if (scope?.dependencies) {
          scope.dependencies.forEach(dep => {
            if (parentScopes.includes(dep)) {
              grantedScopes.add(dep);
            }
          });
        }
      } else {
        deniedScopes.push(requested);
      }
    }

    return {
      grantedScopes: Array.from(grantedScopes),
      deniedScopes,
      reason: deniedScopes.length > 0 
        ? 'Some scopes cannot be granted based on hierarchy' 
        : undefined,
      metadata: { 
        hierarchyApplied: true,
        totalDependencies: grantedScopes.size - requestedScopes.filter(s => grantedScopes.has(s)).length
      }
    };
  }

  /**
   * Category-based reduction - allows scopes within certain categories
   */
  static categoryBased(
    parentScopes: string[],
    requestedScopes: string[],
    allowedCategories: string[]
  ): ScopeReductionResult {
    const grantedScopes: string[] = [];
    const deniedScopes: string[] = [];

    for (const requested of requestedScopes) {
      const scope = this.scopeRegistry.getScope(requested);
      
      if (!scope) {
        deniedScopes.push(requested);
        continue;
      }

      if (parentScopes.includes(requested) && allowedCategories.includes(scope.category)) {
        grantedScopes.push(requested);
      } else {
        deniedScopes.push(requested);
      }
    }

    return {
      grantedScopes,
      deniedScopes,
      reason: deniedScopes.length > 0 
        ? `Some scopes denied due to category restrictions (allowed: ${allowedCategories.join(', ')})` 
        : undefined,
      metadata: { allowedCategories }
    };
  }

  /**
   * Risk-based reduction - filters scopes based on risk level
   */
  static riskBased(
    parentScopes: string[],
    requestedScopes: string[],
    maxRiskLevel: 'low' | 'medium' | 'high'
  ): ScopeReductionResult {
    const riskLevels = { low: 1, medium: 2, high: 3 };
    const maxRisk = riskLevels[maxRiskLevel];
    
    const grantedScopes: string[] = [];
    const deniedScopes: string[] = [];

    for (const requested of requestedScopes) {
      if (!parentScopes.includes(requested)) {
        deniedScopes.push(requested);
        continue;
      }

      const scope = this.scopeRegistry.getScope(requested);
      if (!scope) {
        deniedScopes.push(requested);
        continue;
      }

      const scopeRisk = riskLevels[scope.riskLevel];
      if (scopeRisk <= maxRisk) {
        grantedScopes.push(requested);
      } else {
        deniedScopes.push(requested);
      }
    }

    return {
      grantedScopes,
      deniedScopes,
      reason: deniedScopes.length > 0 
        ? `Some scopes exceed maximum risk level (${maxRiskLevel})` 
        : undefined,
      metadata: { maxRiskLevel }
    };
  }

  /**
   * Time-based reduction - grants different scopes based on time/duration
   */
  static timeBased(
    parentScopes: string[],
    requestedScopes: string[],
    duration: number // milliseconds
  ): ScopeReductionResult {
    const shortTermThreshold = 60 * 60 * 1000; // 1 hour
    const mediumTermThreshold = 24 * 60 * 60 * 1000; // 24 hours

    if (duration <= shortTermThreshold) {
      // Short-term: allow all low-risk scopes
      return this.riskBased(parentScopes, requestedScopes, 'low');
    } else if (duration <= mediumTermThreshold) {
      // Medium-term: allow low and medium risk
      return this.riskBased(parentScopes, requestedScopes, 'medium');
    } else {
      // Long-term: standard intersection
      return this.intersection(parentScopes, requestedScopes);
    }
  }

  /**
   * Composite strategy - combines multiple strategies
   */
  static composite(
    parentScopes: string[],
    requestedScopes: string[],
    strategies: Array<{
      type: 'intersection' | 'subset' | 'hierarchical' | 'category' | 'risk' | 'time';
      params?: any;
      weight?: number;
    }>
  ): ScopeReductionResult {
    const results: ScopeReductionResult[] = [];
    
    for (const strategy of strategies) {
      let result: ScopeReductionResult;
      
      switch (strategy.type) {
        case 'intersection':
          result = this.intersection(parentScopes, requestedScopes);
          break;
        case 'subset':
          result = this.subset(parentScopes, requestedScopes);
          break;
        case 'hierarchical':
          result = this.hierarchical(parentScopes, requestedScopes);
          break;
        case 'category':
          result = this.categoryBased(
            parentScopes, 
            requestedScopes, 
            strategy.params?.allowedCategories || []
          );
          break;
        case 'risk':
          result = this.riskBased(
            parentScopes, 
            requestedScopes, 
            strategy.params?.maxRiskLevel || 'medium'
          );
          break;
        case 'time':
          result = this.timeBased(
            parentScopes, 
            requestedScopes, 
            strategy.params?.duration || Infinity
          );
          break;
        default:
          result = this.intersection(parentScopes, requestedScopes);
      }
      
      results.push(result);
    }

    // Combine results - take intersection of all granted scopes
    const finalGranted = requestedScopes.filter(scope =>
      results.every(r => r.grantedScopes.includes(scope))
    );

    const finalDenied = requestedScopes.filter(scope =>
      !finalGranted.includes(scope)
    );

    return {
      grantedScopes: finalGranted,
      deniedScopes: finalDenied,
      reason: finalDenied.length > 0 
        ? 'Composite strategy denied some scopes' 
        : undefined,
      metadata: {
        strategiesApplied: strategies.length,
        individualResults: results
      }
    };
  }

  /**
   * Creates a custom reducer that applies a specific policy
   */
  static createCustomReducer(
    policy: ScopeReductionPolicy
  ): (parentScopes: string[], requestedScopes: string[]) => string[] {
    return (parentScopes: string[], requestedScopes: string[]) => {
      let result: ScopeReductionResult;

      switch (policy.strategy) {
        case 'intersection':
          result = this.intersection(parentScopes, requestedScopes);
          break;
        case 'subset':
          result = this.subset(parentScopes, requestedScopes);
          break;
        case 'custom':
          if (policy.customReducer) {
            return policy.customReducer(parentScopes, requestedScopes);
          }
          result = this.intersection(parentScopes, requestedScopes);
          break;
        default:
          result = this.intersection(parentScopes, requestedScopes);
      }

      return result.grantedScopes;
    };
  }

  // Helper methods

  private static buildScopeHierarchy(scopes: string[]): Map<string, ScopeHierarchy> {
    const hierarchy = new Map<string, ScopeHierarchy>();

    for (const scope of scopes) {
      const scopeDef = this.scopeRegistry.getScope(scope);
      if (!scopeDef) continue;

      hierarchy.set(scope, {
        scope,
        implies: scopeDef.dependencies || [],
        requiredBy: this.findRequiredBy(scope, scopes)
      });
    }

    return hierarchy;
  }

  private static findRequiredBy(targetScope: string, allScopes: string[]): string[] {
    const requiredBy: string[] = [];

    for (const scope of allScopes) {
      const scopeDef = this.scopeRegistry.getScope(scope);
      if (scopeDef?.dependencies?.includes(targetScope)) {
        requiredBy.push(scope);
      }
    }

    return requiredBy;
  }

  private static canGrantScope(
    scope: string,
    parentScopes: string[],
    hierarchy: Map<string, ScopeHierarchy>
  ): boolean {
    // Direct match
    if (parentScopes.includes(scope)) {
      return true;
    }

    // Check if any parent scope implies this scope
    for (const parentScope of parentScopes) {
      const parentHierarchy = hierarchy.get(parentScope);
      if (parentHierarchy?.implies.includes(scope)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Analyzes the impact of scope reduction
   */
  static analyzeReduction(
    original: string[],
    reduced: string[]
  ): {
    removed: string[];
    retained: string[];
    reductionPercentage: number;
    categoryImpact: Record<string, { removed: number; retained: number }>;
    riskImpact: Record<string, { removed: number; retained: number }>;
  } {
    const removed = original.filter(s => !reduced.includes(s));
    const retained = reduced;
    const reductionPercentage = (removed.length / original.length) * 100;

    // Analyze category impact
    const categoryImpact: Record<string, { removed: number; retained: number }> = {};
    const riskImpact: Record<string, { removed: number; retained: number }> = {};

    for (const scope of original) {
      const scopeDef = this.scopeRegistry.getScope(scope);
      if (!scopeDef) continue;

      // Category analysis
      if (!categoryImpact[scopeDef.category]) {
        categoryImpact[scopeDef.category] = { removed: 0, retained: 0 };
      }
      
      if (removed.includes(scope)) {
        categoryImpact[scopeDef.category].removed++;
      } else {
        categoryImpact[scopeDef.category].retained++;
      }

      // Risk analysis
      if (!riskImpact[scopeDef.riskLevel]) {
        riskImpact[scopeDef.riskLevel] = { removed: 0, retained: 0 };
      }
      
      if (removed.includes(scope)) {
        riskImpact[scopeDef.riskLevel].removed++;
      } else {
        riskImpact[scopeDef.riskLevel].retained++;
      }
    }

    return {
      removed,
      retained,
      reductionPercentage,
      categoryImpact,
      riskImpact
    };
  }
}