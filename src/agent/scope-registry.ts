import { ScopeDefinition } from './types';

export class ScopeRegistry {
  private static instance: ScopeRegistry;
  private scopes: Map<string, ScopeDefinition> = new Map();
  private categories: Set<string> = new Set(['profile', 'data', 'actions', 'admin', 'analytics']);

  private constructor() {
    this.initializeDefaultScopes();
  }

  static getInstance(): ScopeRegistry {
    if (!ScopeRegistry.instance) {
      ScopeRegistry.instance = new ScopeRegistry();
    }
    return ScopeRegistry.instance;
  }

  private initializeDefaultScopes(): void {
    // Profile scopes
    this.registerScope({
      id: 'read:profile:basic',
      name: 'Read Basic Profile',
      description: 'Read basic profile information including name and public identifiers',
      category: 'profile',
      riskLevel: 'low'
    });

    this.registerScope({
      id: 'read:profile:full',
      name: 'Read Full Profile',
      description: 'Read complete profile information including sensitive data',
      category: 'profile',
      riskLevel: 'medium',
      dependencies: ['read:profile:basic']
    });

    this.registerScope({
      id: 'write:profile:basic',
      name: 'Update Basic Profile',
      description: 'Update basic profile information',
      category: 'profile',
      riskLevel: 'medium'
    });

    // Data scopes
    this.registerScope({
      id: 'read:data:own',
      name: 'Read Own Data',
      description: 'Read data created by this agent',
      category: 'data',
      riskLevel: 'low'
    });

    this.registerScope({
      id: 'read:data:all',
      name: 'Read All Data',
      description: 'Read all user data regardless of creator',
      category: 'data',
      riskLevel: 'medium'
    });

    this.registerScope({
      id: 'write:data:create',
      name: 'Create Data',
      description: 'Create new data entries',
      category: 'data',
      riskLevel: 'medium'
    });

    this.registerScope({
      id: 'write:data:update:own',
      name: 'Update Own Data',
      description: 'Update data created by this agent',
      category: 'data',
      riskLevel: 'medium',
      dependencies: ['read:data:own']
    });

    this.registerScope({
      id: 'delete:data:own',
      name: 'Delete Own Data',
      description: 'Delete data created by this agent',
      category: 'data',
      riskLevel: 'medium',
      dependencies: ['read:data:own']
    });

    // Action scopes
    this.registerScope({
      id: 'execute:transactions:read',
      name: 'View Transactions',
      description: 'View transaction history and details',
      category: 'actions',
      riskLevel: 'low'
    });

    this.registerScope({
      id: 'execute:transactions:create',
      name: 'Create Transactions',
      description: 'Create new transactions',
      category: 'actions',
      riskLevel: 'high'
    });

    this.registerScope({
      id: 'execute:payments:limit:100',
      name: 'Limited Payments',
      description: 'Execute payments up to $100',
      category: 'actions',
      riskLevel: 'high',
      dependencies: ['execute:transactions:create']
    });

    // Admin scopes
    this.registerScope({
      id: 'admin:agents:read',
      name: 'View Other Agents',
      description: 'View information about other agents',
      category: 'admin',
      riskLevel: 'low'
    });

    this.registerScope({
      id: 'admin:agents:manage',
      name: 'Manage Agents',
      description: 'Create, update, or delete other agents',
      category: 'admin',
      riskLevel: 'high',
      dependencies: ['admin:agents:read']
    });

    // Analytics scopes
    this.registerScope({
      id: 'analytics:read:aggregate',
      name: 'Read Aggregate Analytics',
      description: 'Access aggregated analytics data',
      category: 'analytics',
      riskLevel: 'low'
    });

    this.registerScope({
      id: 'analytics:read:detailed',
      name: 'Read Detailed Analytics',
      description: 'Access detailed analytics including individual events',
      category: 'analytics',
      riskLevel: 'medium',
      dependencies: ['analytics:read:aggregate']
    });
  }

  registerScope(scope: ScopeDefinition): void {
    if (!this.categories.has(scope.category)) {
      throw new Error(`Invalid category: ${scope.category}`);
    }

    // Validate scope ID format
    if (!this.isValidScopeId(scope.id)) {
      throw new Error(`Invalid scope ID format: ${scope.id}`);
    }

    // Check dependencies exist
    if (scope.dependencies) {
      for (const dep of scope.dependencies) {
        if (!this.scopes.has(dep)) {
          throw new Error(`Dependency scope not found: ${dep}`);
        }
      }
    }

    this.scopes.set(scope.id, scope);
  }

  getScope(scopeId: string): ScopeDefinition | undefined {
    return this.scopes.get(scopeId);
  }

  getAllScopes(): ScopeDefinition[] {
    return Array.from(this.scopes.values());
  }

  getScopesByCategory(category: string): ScopeDefinition[] {
    return this.getAllScopes().filter(scope => scope.category === category);
  }

  getScopesByRiskLevel(riskLevel: 'low' | 'medium' | 'high'): ScopeDefinition[] {
    return this.getAllScopes().filter(scope => scope.riskLevel === riskLevel);
  }

  validateScopes(scopeIds: string[]): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    const validScopes = new Set<string>();

    for (const scopeId of scopeIds) {
      const scope = this.scopes.get(scopeId);
      if (!scope) {
        errors.push(`Unknown scope: ${scopeId}`);
        continue;
      }

      validScopes.add(scopeId);

      // Check if dependencies are included
      if (scope.dependencies) {
        for (const dep of scope.dependencies) {
          if (!scopeIds.includes(dep)) {
            errors.push(`Scope ${scopeId} requires dependency: ${dep}`);
          }
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  getRequiredScopes(scopeIds: string[]): string[] {
    const required = new Set<string>();
    const toProcess = [...scopeIds];

    while (toProcess.length > 0) {
      const scopeId = toProcess.pop()!;
      if (required.has(scopeId)) continue;

      const scope = this.scopes.get(scopeId);
      if (!scope) continue;

      required.add(scopeId);

      if (scope.dependencies) {
        toProcess.push(...scope.dependencies);
      }
    }

    return Array.from(required);
  }

  private isValidScopeId(scopeId: string): boolean {
    // Format: action:resource[:constraint[:value]]
    const parts = scopeId.split(':');
    if (parts.length < 2 || parts.length > 4) return false;

    // All parts should be non-empty and contain only allowed characters
    const validPartRegex = /^[a-z0-9]+$/;
    return parts.every(part => validPartRegex.test(part));
  }

  addCategory(category: string): void {
    this.categories.add(category);
  }

  getCategories(): string[] {
    return Array.from(this.categories);
  }

  exportScopeDefinitions(): Record<string, ScopeDefinition> {
    const result: Record<string, ScopeDefinition> = {};
    this.scopes.forEach((scope, id) => {
      result[id] = scope;
    });
    return result;
  }

  importScopeDefinitions(definitions: Record<string, ScopeDefinition>): void {
    // First pass: register all scopes without dependencies
    for (const [id, scope] of Object.entries(definitions)) {
      if (!scope.dependencies || scope.dependencies.length === 0) {
        this.registerScope({ ...scope, id });
      }
    }

    // Second pass: register scopes with dependencies
    for (const [id, scope] of Object.entries(definitions)) {
      if (scope.dependencies && scope.dependencies.length > 0) {
        this.registerScope({ ...scope, id });
      }
    }
  }
}