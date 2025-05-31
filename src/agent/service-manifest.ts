import { ServiceManifest, ScopeDefinition } from './types';
import { ScopeRegistry } from './scope-registry';

export class ServiceManifestBuilder {
  private manifest: ServiceManifest;
  private scopeRegistry: ScopeRegistry;

  constructor(serviceDID: string, name: string, description?: string) {
    this.scopeRegistry = ScopeRegistry.getInstance();
    this.manifest = {
      serviceDID,
      name,
      description,
      requiredScopes: [],
      optionalScopes: []
    };
  }

  addRequiredScope(scopeId: string): ServiceManifestBuilder {
    const scope = this.scopeRegistry.getScope(scopeId);
    if (!scope) {
      throw new Error(`Unknown scope: ${scopeId}`);
    }

    // Add scope with its dependencies
    const allRequired = this.scopeRegistry.getRequiredScopes([scopeId]);
    for (const reqScopeId of allRequired) {
      const reqScope = this.scopeRegistry.getScope(reqScopeId);
      if (reqScope && !this.manifest.requiredScopes.some(s => s.id === reqScopeId)) {
        this.manifest.requiredScopes.push(reqScope);
      }
    }

    return this;
  }

  addOptionalScope(scopeId: string): ServiceManifestBuilder {
    const scope = this.scopeRegistry.getScope(scopeId);
    if (!scope) {
      throw new Error(`Unknown scope: ${scopeId}`);
    }

    if (!this.manifest.optionalScopes) {
      this.manifest.optionalScopes = [];
    }

    // Check if already in required scopes
    if (this.manifest.requiredScopes.some(s => s.id === scopeId)) {
      throw new Error(`Scope ${scopeId} is already required`);
    }

    // Add scope with its dependencies as optional
    const allRequired = this.scopeRegistry.getRequiredScopes([scopeId]);
    for (const optScopeId of allRequired) {
      const optScope = this.scopeRegistry.getScope(optScopeId);
      if (optScope && 
          !this.manifest.optionalScopes.some(s => s.id === optScopeId) &&
          !this.manifest.requiredScopes.some(s => s.id === optScopeId)) {
        this.manifest.optionalScopes.push(optScope);
      }
    }

    return this;
  }

  addCustomScope(scope: ScopeDefinition, required: boolean = true): ServiceManifestBuilder {
    // Register the custom scope if not already registered
    try {
      this.scopeRegistry.registerScope(scope);
    } catch (error) {
      // Scope might already be registered
    }

    if (required) {
      this.addRequiredScope(scope.id);
    } else {
      this.addOptionalScope(scope.id);
    }

    return this;
  }

  build(): ServiceManifest {
    if (this.manifest.requiredScopes.length === 0 && 
        (!this.manifest.optionalScopes || this.manifest.optionalScopes.length === 0)) {
      throw new Error('Service manifest must have at least one scope');
    }

    return { ...this.manifest };
  }

  static createBasicReadService(serviceDID: string, name: string): ServiceManifest {
    return new ServiceManifestBuilder(serviceDID, name)
      .addRequiredScope('read:profile:basic')
      .addOptionalScope('read:data:all')
      .build();
  }

  static createDataManagementService(serviceDID: string, name: string): ServiceManifest {
    return new ServiceManifestBuilder(serviceDID, name)
      .addRequiredScope('read:data:own')
      .addRequiredScope('write:data:create')
      .addOptionalScope('write:data:update:own')
      .addOptionalScope('delete:data:own')
      .build();
  }

  static createPaymentService(serviceDID: string, name: string, limit: number = 100): ServiceManifest {
    const builder = new ServiceManifestBuilder(serviceDID, name, 'Payment processing service');
    
    // Add transaction read as required
    builder.addRequiredScope('execute:transactions:read');

    // Add payment scope based on limit
    if (limit <= 100) {
      builder.addRequiredScope('execute:payments:limit:100');
    } else {
      // Create custom scope for higher limit
      builder.addCustomScope({
        id: `execute:payments:limit:${limit}`,
        name: `Execute Payments up to $${limit}`,
        description: `Execute payments with a maximum value of $${limit}`,
        category: 'actions',
        riskLevel: 'high',
        dependencies: ['execute:transactions:create']
      }, true);
    }

    return builder.build();
  }
}

export class ServiceManifestValidator {
  static validateManifest(manifest: ServiceManifest): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!manifest.serviceDID) {
      errors.push('Service DID is required');
    }

    if (!manifest.name) {
      errors.push('Service name is required');
    }

    if (manifest.requiredScopes.length === 0 && 
        (!manifest.optionalScopes || manifest.optionalScopes.length === 0)) {
      errors.push('At least one scope is required');
    }

    // Check for duplicate scopes
    const allScopes = [
      ...manifest.requiredScopes,
      ...(manifest.optionalScopes || [])
    ];
    const scopeIds = allScopes.map(s => s.id);
    const uniqueScopeIds = new Set(scopeIds);

    if (scopeIds.length !== uniqueScopeIds.size) {
      errors.push('Duplicate scopes found in manifest');
    }

    // Validate scope definitions
    const registry = ScopeRegistry.getInstance();
    for (const scope of allScopes) {
      const registeredScope = registry.getScope(scope.id);
      if (!registeredScope) {
        errors.push(`Unknown scope in manifest: ${scope.id}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  static compareManifests(manifest1: ServiceManifest, manifest2: ServiceManifest): {
    added: ScopeDefinition[];
    removed: ScopeDefinition[];
    changed: ScopeDefinition[];
  } {
    const scopes1 = new Map<string, ScopeDefinition>();
    const scopes2 = new Map<string, ScopeDefinition>();

    // Build maps
    [...manifest1.requiredScopes, ...(manifest1.optionalScopes || [])].forEach(s => {
      scopes1.set(s.id, s);
    });

    [...manifest2.requiredScopes, ...(manifest2.optionalScopes || [])].forEach(s => {
      scopes2.set(s.id, s);
    });

    const added: ScopeDefinition[] = [];
    const removed: ScopeDefinition[] = [];
    const changed: ScopeDefinition[] = [];

    // Find added and changed
    scopes2.forEach((scope, id) => {
      if (!scopes1.has(id)) {
        added.push(scope);
      } else {
        const oldScope = scopes1.get(id)!;
        if (JSON.stringify(oldScope) !== JSON.stringify(scope)) {
          changed.push(scope);
        }
      }
    });

    // Find removed
    scopes1.forEach((scope, id) => {
      if (!scopes2.has(id)) {
        removed.push(scope);
      }
    });

    return { added, removed, changed };
  }

  static generateManifestSummary(manifest: ServiceManifest): string {
    const lines: string[] = [
      `Service: ${manifest.name}`,
      `DID: ${manifest.serviceDID}`
    ];

    if (manifest.description) {
      lines.push(`Description: ${manifest.description}`);
    }

    lines.push('');
    lines.push('Required Scopes:');
    manifest.requiredScopes.forEach(scope => {
      lines.push(`  - ${scope.name} (${scope.id})`);
      lines.push(`    ${scope.description}`);
      lines.push(`    Risk Level: ${scope.riskLevel}`);
    });

    if (manifest.optionalScopes && manifest.optionalScopes.length > 0) {
      lines.push('');
      lines.push('Optional Scopes:');
      manifest.optionalScopes.forEach(scope => {
        lines.push(`  - ${scope.name} (${scope.id})`);
        lines.push(`    ${scope.description}`);
        lines.push(`    Risk Level: ${scope.riskLevel}`);
      });
    }

    return lines.join('\n');
  }
}