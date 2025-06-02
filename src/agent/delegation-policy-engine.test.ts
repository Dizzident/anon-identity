import { DelegationPolicyEngine } from './delegation-policy-engine';
import { AgentIdentityManager } from './agent-identity';
import { AgentIdentity, DelegationContext } from './types';

describe('DelegationPolicyEngine', () => {
  let policyEngine: DelegationPolicyEngine;
  let agentManager: AgentIdentityManager;
  
  const userDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

  beforeEach(async () => {
    agentManager = new AgentIdentityManager();
    policyEngine = new DelegationPolicyEngine(agentManager);
  });

  describe('policy evaluation', () => {
    it('should evaluate default policy', async () => {
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Test parent'
      });

      const context: DelegationContext = {
        parentAgent,
        requestedScopes: ['read:profile', 'write:data'],
        serviceDID: 'did:key:service123'
      };

      const result = await policyEngine.evaluatePolicy(context);

      expect(result.allowed).toBe(true);
      expect(result.policy?.id).toBe('default');
      expect(result.violations).toHaveLength(0);
    });

    it('should enforce global max depth', async () => {
      policyEngine.setGlobalMaxDepth(2);

      // Create agent at depth 2
      const agent1 = await agentManager.createAgent(userDID, {
        name: 'Agent 1',
        description: 'Level 1'
      });

      const agent2 = await agentManager.createSubAgent(agent1.did, {
        name: 'Agent 2',
        description: 'Level 2',
        parentAgentDID: agent1.did
      });

      const context: DelegationContext = {
        parentAgent: agent2,
        requestedScopes: ['read:profile'],
        serviceDID: 'did:key:service123'
      };

      const result = await policyEngine.evaluatePolicy(context);

      expect(result.allowed).toBe(false);
      expect(result.violations).toContain('Global max delegation depth (2) reached');
    });

    it('should apply high-security policy', async () => {
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Test parent'
      });

      const context: DelegationContext = {
        parentAgent,
        requestedScopes: ['read:profile', 'write:data', 'delete:all', 'admin:system'],
        serviceDID: 'did:key:service123'
      };

      const result = await policyEngine.evaluatePolicy(context, 'high-security');

      expect(result.allowed).toBe(false);
      expect(result.violations).toContain('Requested scopes (4) exceed maximum (3)');
      expect(result.violations).toContain('Missing required scopes: agent:audit');
    });

    it('should apply time-based restrictions', async () => {
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Test parent'
      });

      const context: DelegationContext = {
        parentAgent,
        requestedScopes: ['read:profile'],
        serviceDID: 'did:key:service123'
      };

      // This test might pass or fail depending on current time
      // In a real test, you'd mock the current time
      const result = await policyEngine.evaluatePolicy(context, 'business-hours');

      expect(result.policy?.id).toBe('business-hours');
      expect(result.appliedConstraints).toContain('time-restrictions');
    });
  });

  describe('delegation options', () => {
    it('should create delegation options from policy', async () => {
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Test parent'
      });

      const policy = policyEngine.getPolicy('default')!;
      const options = policyEngine.createDelegationOptions(policy, parentAgent);

      expect(options.maxDepth).toBe(2); // 3 - 0 - 1
      expect(options.scopeReduction?.strategy).toBe('intersection');
      expect(options.expirationPolicy?.strategy).toBe('reduced');
      expect(options.auditLevel).toBe('detailed');
    });

    it('should respect global max depth in options', async () => {
      policyEngine.setGlobalMaxDepth(1);

      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Test parent'
      });

      const policy = policyEngine.getPolicy('development')!;
      const options = policyEngine.createDelegationOptions(policy, parentAgent);

      expect(options.maxDepth).toBe(0); // 1 - 0 - 1
    });
  });

  describe('expiration calculation', () => {
    it('should calculate fixed expiration', () => {
      const policy = policyEngine.getPolicy('high-security')!;
      const parentExpiration = new Date(Date.now() + 24 * 60 * 60 * 1000);
      
      const expiration = policyEngine.calculateExpiration(policy, parentExpiration);
      
      // Should be ~1 hour from now
      const diff = expiration.getTime() - Date.now();
      expect(diff).toBeGreaterThan(55 * 60 * 1000);
      expect(diff).toBeLessThan(65 * 60 * 1000);
    });

    it('should calculate reduced expiration', () => {
      const policy = policyEngine.getPolicy('default')!;
      const parentExpiration = new Date(Date.now() + 10 * 60 * 60 * 1000); // 10 hours
      
      const expiration = policyEngine.calculateExpiration(policy, parentExpiration);
      
      // Should be ~8 hours from now (80% of parent)
      const diff = expiration.getTime() - Date.now();
      expect(diff).toBeGreaterThan(7.5 * 60 * 60 * 1000);
      expect(diff).toBeLessThan(8.5 * 60 * 60 * 1000);
    });

    it('should inherit parent expiration', () => {
      const policy = policyEngine.getPolicy('development')!;
      const parentExpiration = new Date(Date.now() + 5 * 60 * 60 * 1000);
      
      const expiration = policyEngine.calculateExpiration(policy, parentExpiration);
      
      expect(expiration.getTime()).toBe(parentExpiration.getTime());
    });
  });

  describe('policy management', () => {
    it('should register custom policy', () => {
      const customPolicy = {
        id: 'custom-test',
        name: 'Custom Test Policy',
        description: 'Test policy',
        maxDepth: 4,
        scopeReduction: { strategy: 'subset' as const },
        expirationPolicy: { strategy: 'fixed' as const, fixedDuration: 2 * 60 * 60 * 1000 },
        enabled: true
      };

      policyEngine.registerPolicy(customPolicy);
      const retrieved = policyEngine.getPolicy('custom-test');

      expect(retrieved).toBeDefined();
      expect(retrieved?.name).toBe('Custom Test Policy');
    });

    it('should reject policy exceeding global max', () => {
      policyEngine.setGlobalMaxDepth(3);

      const invalidPolicy = {
        id: 'invalid',
        name: 'Invalid Policy',
        description: 'Exceeds global max',
        maxDepth: 5,
        scopeReduction: { strategy: 'intersection' as const },
        expirationPolicy: { strategy: 'inherit' as const },
        enabled: true
      };

      expect(() => policyEngine.registerPolicy(invalidPolicy)).toThrow(
        'exceeds global max'
      );
    });

    it('should update existing policy', () => {
      const policy = policyEngine.getPolicy('development')!;
      expect(policy.maxDepth).toBe(5);

      policyEngine.updatePolicy('development', { maxDepth: 3 });

      const updated = policyEngine.getPolicy('development')!;
      expect(updated.maxDepth).toBe(3);
    });

    it('should enable/disable policy', () => {
      policyEngine.setPolicyEnabled('high-security', false);
      
      const policy = policyEngine.getPolicy('high-security')!;
      expect(policy.enabled).toBe(false);

      policyEngine.setPolicyEnabled('high-security', true);
      expect(policy.enabled).toBe(true);
    });
  });

  describe('validation', () => {
    it('should validate delegation request', async () => {
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Test parent'
      });

      // Add some scopes to the parent
      agentManager.addAccessGrant(parentAgent.did, {
        serviceDID: 'did:key:service123',
        scopes: ['read:profile', 'write:data'],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000)
      });

      const validation = await policyEngine.validateDelegationRequest(
        parentAgent.did,
        ['read:profile'],
        'did:key:service123'
      );

      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
      expect(validation.maxDepth).toBeDefined();
    });

    it('should fail validation for invalid parent', async () => {
      const validation = await policyEngine.validateDelegationRequest(
        'did:key:nonexistent',
        ['read:profile'],
        'did:key:service123'
      );

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Parent agent not found');
    });
  });

  describe('import/export', () => {
    it('should export all policies', () => {
      const policies = policyEngine.exportPolicies();
      
      expect(policies.length).toBeGreaterThan(0);
      expect(policies.find(p => p.id === 'default')).toBeDefined();
      expect(policies.find(p => p.id === 'high-security')).toBeDefined();
      expect(policies.find(p => p.id === 'development')).toBeDefined();
      expect(policies.find(p => p.id === 'business-hours')).toBeDefined();
    });

    it('should import policies', () => {
      const newPolicies = [
        {
          id: 'imported-1',
          name: 'Imported Policy 1',
          description: 'Test import',
          maxDepth: 2,
          scopeReduction: { strategy: 'intersection' as const },
          expirationPolicy: { strategy: 'inherit' as const },
          enabled: true
        },
        {
          id: 'imported-2',
          name: 'Imported Policy 2',
          description: 'Test import 2',
          maxDepth: 3,
          scopeReduction: { strategy: 'subset' as const },
          expirationPolicy: { strategy: 'fixed' as const },
          enabled: true
        }
      ];

      policyEngine.importPolicies(newPolicies);

      expect(policyEngine.getPolicy('imported-1')).toBeDefined();
      expect(policyEngine.getPolicy('imported-2')).toBeDefined();
    });
  });
});