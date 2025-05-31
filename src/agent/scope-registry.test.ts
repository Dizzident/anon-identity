import { ScopeRegistry } from './scope-registry';
import { ScopeDefinition } from './types';

describe('ScopeRegistry', () => {
  let registry: ScopeRegistry;

  beforeEach(() => {
    // Reset singleton instance for testing
    (ScopeRegistry as any).instance = undefined;
    registry = ScopeRegistry.getInstance();
  });

  describe('getInstance', () => {
    it('should return the same instance', () => {
      const instance1 = ScopeRegistry.getInstance();
      const instance2 = ScopeRegistry.getInstance();
      expect(instance1).toBe(instance2);
    });
  });

  describe('default scopes', () => {
    it('should have default scopes initialized', () => {
      const allScopes = registry.getAllScopes();
      expect(allScopes.length).toBeGreaterThan(0);

      // Check for some expected default scopes
      expect(registry.getScope('read:profile:basic')).toBeDefined();
      expect(registry.getScope('write:data:create')).toBeDefined();
      expect(registry.getScope('execute:payments:limit:100')).toBeDefined();
    });
  });

  describe('registerScope', () => {
    it('should register a new scope', () => {
      const newScope: ScopeDefinition = {
        id: 'custom:test:scope',
        name: 'Custom Test Scope',
        description: 'A custom scope for testing',
        category: 'data',
        riskLevel: 'low'
      };

      registry.registerScope(newScope);
      const retrieved = registry.getScope(newScope.id);

      expect(retrieved).toEqual(newScope);
    });

    it('should reject invalid category', () => {
      const invalidScope: ScopeDefinition = {
        id: 'test:scope',
        name: 'Test Scope',
        description: 'Test',
        category: 'invalid-category',
        riskLevel: 'low'
      };

      expect(() => registry.registerScope(invalidScope)).toThrow('Invalid category');
    });

    it('should reject invalid scope ID format', () => {
      const invalidScope: ScopeDefinition = {
        id: 'InvalidScope',
        name: 'Invalid Scope',
        description: 'Test',
        category: 'data',
        riskLevel: 'low'
      };

      expect(() => registry.registerScope(invalidScope)).toThrow('Invalid scope ID format');
    });

    it('should reject missing dependencies', () => {
      const scopeWithBadDeps: ScopeDefinition = {
        id: 'test:scope',
        name: 'Test Scope',
        description: 'Test',
        category: 'data',
        riskLevel: 'low',
        dependencies: ['non:existent:scope']
      };

      expect(() => registry.registerScope(scopeWithBadDeps)).toThrow('Dependency scope not found');
    });
  });

  describe('getScopesByCategory', () => {
    it('should return scopes filtered by category', () => {
      const profileScopes = registry.getScopesByCategory('profile');
      const dataScopes = registry.getScopesByCategory('data');

      expect(profileScopes.length).toBeGreaterThan(0);
      expect(profileScopes.every(s => s.category === 'profile')).toBe(true);

      expect(dataScopes.length).toBeGreaterThan(0);
      expect(dataScopes.every(s => s.category === 'data')).toBe(true);
    });
  });

  describe('getScopesByRiskLevel', () => {
    it('should return scopes filtered by risk level', () => {
      const lowRiskScopes = registry.getScopesByRiskLevel('low');
      const highRiskScopes = registry.getScopesByRiskLevel('high');

      expect(lowRiskScopes.length).toBeGreaterThan(0);
      expect(lowRiskScopes.every(s => s.riskLevel === 'low')).toBe(true);

      expect(highRiskScopes.length).toBeGreaterThan(0);
      expect(highRiskScopes.every(s => s.riskLevel === 'high')).toBe(true);
    });
  });

  describe('validateScopes', () => {
    it('should validate known scopes', () => {
      const result = registry.validateScopes(['read:profile:basic', 'write:data:create']);
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should report unknown scopes', () => {
      const result = registry.validateScopes(['read:profile:basic', 'unknown:scope']);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Unknown scope: unknown:scope');
    });

    it('should check for missing dependencies', () => {
      const result = registry.validateScopes(['write:data:update:own']);
      
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('requires dependency'))).toBe(true);
    });

    it('should pass when dependencies are included', () => {
      const result = registry.validateScopes(['read:data:own', 'write:data:update:own']);
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('getRequiredScopes', () => {
    it('should return all required scopes including dependencies', () => {
      const required = registry.getRequiredScopes(['write:data:update:own']);
      
      expect(required).toContain('write:data:update:own');
      expect(required).toContain('read:data:own');
    });

    it('should handle multiple levels of dependencies', () => {
      const required = registry.getRequiredScopes(['admin:agents:manage']);
      
      expect(required).toContain('admin:agents:manage');
      expect(required).toContain('admin:agents:read');
    });

    it('should not duplicate scopes', () => {
      const required = registry.getRequiredScopes([
        'read:data:own',
        'write:data:update:own'
      ]);
      
      const uniqueScopes = new Set(required);
      expect(required.length).toBe(uniqueScopes.size);
    });
  });

  describe('categories', () => {
    it('should return default categories', () => {
      const categories = registry.getCategories();
      
      expect(categories).toContain('profile');
      expect(categories).toContain('data');
      expect(categories).toContain('actions');
      expect(categories).toContain('admin');
      expect(categories).toContain('analytics');
    });

    it('should allow adding new categories', () => {
      registry.addCategory('custom');
      const categories = registry.getCategories();
      
      expect(categories).toContain('custom');
    });
  });

  describe('import/export', () => {
    it('should export and import scope definitions', () => {
      // Add a custom scope
      const customScope: ScopeDefinition = {
        id: 'custom:export:test',
        name: 'Export Test',
        description: 'Testing export',
        category: 'data',
        riskLevel: 'low'
      };
      registry.registerScope(customScope);

      // Export
      const exported = registry.exportScopeDefinitions();
      expect(exported['custom:export:test']).toBeDefined();

      // Create new registry and import
      (ScopeRegistry as any).instance = undefined;
      const newRegistry = ScopeRegistry.getInstance();
      
      // The custom scope should not exist in new instance
      expect(newRegistry.getScope('custom:export:test')).toBeUndefined();

      // Import and verify
      newRegistry.importScopeDefinitions({ 'custom:export:test': customScope });
      expect(newRegistry.getScope('custom:export:test')).toEqual(customScope);
    });

    it('should handle dependencies during import', () => {
      const baseScope: ScopeDefinition = {
        id: 'import:base',
        name: 'Base Scope',
        description: 'Base',
        category: 'data',
        riskLevel: 'low'
      };

      const dependentScope: ScopeDefinition = {
        id: 'import:dependent',
        name: 'Dependent Scope',
        description: 'Depends on base',
        category: 'data',
        riskLevel: 'medium',
        dependencies: ['import:base']
      };

      const definitions = {
        'import:dependent': dependentScope,
        'import:base': baseScope
      };

      // Import (order in object shouldn't matter)
      registry.importScopeDefinitions(definitions);

      expect(registry.getScope('import:base')).toEqual(baseScope);
      expect(registry.getScope('import:dependent')).toEqual(dependentScope);
    });
  });
});