import { AgentIdentityManager } from './agent-identity';
import { AgentConfig, AccessGrant, SubAgentConfig, ScopeReductionPolicy } from './types';

describe('AgentIdentityManager', () => {
  let manager: AgentIdentityManager;
  const parentDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

  beforeEach(() => {
    manager = new AgentIdentityManager();
  });

  describe('createAgent', () => {
    it('should create a new agent with unique DID', async () => {
      const config: AgentConfig = {
        name: 'Test Agent',
        description: 'A test agent for unit testing'
      };

      const agent = await manager.createAgent(parentDID, config);

      expect(agent.did).toMatch(/^did:key:/);
      expect(agent.name).toBe(config.name);
      expect(agent.description).toBe(config.description);
      expect(agent.parentDID).toBe(parentDID);
      expect(agent.createdAt).toBeInstanceOf(Date);
      expect(agent.keyPair).toHaveProperty('publicKey');
      expect(agent.keyPair).toHaveProperty('privateKey');
    });

    it('should create multiple agents with different DIDs', async () => {
      const config: AgentConfig = {
        name: 'Test Agent',
        description: 'A test agent'
      };

      const agent1 = await manager.createAgent(parentDID, config);
      const agent2 = await manager.createAgent(parentDID, config);

      expect(agent1.did).not.toBe(agent2.did);
    });
  });

  describe('getAgent', () => {
    it('should retrieve an existing agent', async () => {
      const config: AgentConfig = {
        name: 'Test Agent',
        description: 'A test agent'
      };

      const createdAgent = await manager.createAgent(parentDID, config);
      const retrievedAgent = manager.getAgent(createdAgent.did);

      expect(retrievedAgent).toEqual(createdAgent);
    });

    it('should return undefined for non-existent agent', () => {
      const agent = manager.getAgent('did:key:nonexistent');
      expect(agent).toBeUndefined();
    });
  });

  describe('listAgents', () => {
    it('should list all agents for a parent DID', async () => {
      const parentDID1 = 'did:key:parent1';
      const parentDID2 = 'did:key:parent2';

      await manager.createAgent(parentDID1, { name: 'Agent 1', description: 'First agent' });
      await manager.createAgent(parentDID1, { name: 'Agent 2', description: 'Second agent' });
      await manager.createAgent(parentDID2, { name: 'Agent 3', description: 'Third agent' });

      const agentsForParent1 = manager.listAgents(parentDID1);
      const agentsForParent2 = manager.listAgents(parentDID2);

      expect(agentsForParent1).toHaveLength(2);
      expect(agentsForParent2).toHaveLength(1);
      expect(agentsForParent1.every(a => a.parentDID === parentDID1)).toBe(true);
    });
  });

  describe('deleteAgent', () => {
    it('should delete an existing agent', async () => {
      const agent = await manager.createAgent(parentDID, {
        name: 'To Delete',
        description: 'Will be deleted'
      });

      const result = manager.deleteAgent(agent.did);
      expect(result).toBe(true);

      const retrievedAgent = manager.getAgent(agent.did);
      expect(retrievedAgent).toBeUndefined();
    });

    it('should return false when deleting non-existent agent', () => {
      const result = manager.deleteAgent('did:key:nonexistent');
      expect(result).toBe(false);
    });
  });

  describe('Access Grant Management', () => {
    let agentDID: string;

    beforeEach(async () => {
      const agent = await manager.createAgent(parentDID, {
        name: 'Test Agent',
        description: 'For access grant tests'
      });
      agentDID = agent.did;
    });

    it('should add and retrieve access grants', () => {
      const grant: AccessGrant = {
        serviceDID: 'did:key:service123',
        scopes: ['read:profile', 'write:posts'],
        expiresAt: new Date(Date.now() + 3600000) // 1 hour
      };

      manager.addAccessGrant(agentDID, grant);
      const grants = manager.getAccessGrants(agentDID);

      expect(grants).toHaveLength(1);
      expect(grants[0]).toEqual(grant);
    });

    it('should check service access correctly', () => {
      const serviceDID = 'did:key:service123';
      const grant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile'],
        expiresAt: new Date(Date.now() + 3600000) // 1 hour
      };

      manager.addAccessGrant(agentDID, grant);

      expect(manager.hasServiceAccess(agentDID, serviceDID)).toBe(true);
      expect(manager.hasServiceAccess(agentDID, 'did:key:other')).toBe(false);
    });

    it('should not grant access for expired grants', () => {
      const serviceDID = 'did:key:service123';
      const grant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile'],
        expiresAt: new Date(Date.now() - 3600000) // 1 hour ago
      };

      manager.addAccessGrant(agentDID, grant);

      expect(manager.hasServiceAccess(agentDID, serviceDID)).toBe(false);
    });

    it('should revoke service access', () => {
      const serviceDID = 'did:key:service123';
      const grant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile'],
        expiresAt: new Date(Date.now() + 3600000)
      };

      manager.addAccessGrant(agentDID, grant);
      expect(manager.hasServiceAccess(agentDID, serviceDID)).toBe(true);

      const result = manager.revokeServiceAccess(agentDID, serviceDID);
      expect(result).toBe(true);
      expect(manager.hasServiceAccess(agentDID, serviceDID)).toBe(false);
    });
  });

  describe('Delegation Credentials', () => {
    let agentDID: string;

    beforeEach(async () => {
      const agent = await manager.createAgent(parentDID, {
        name: 'Test Agent',
        description: 'For delegation tests'
      });
      agentDID = agent.did;
    });

    it('should store and retrieve delegation credentials', () => {
      const credential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegationCredential'],
        id: 'test-credential',
        issuer: parentDID,
        issuanceDate: new Date().toISOString(),
        expirationDate: new Date(Date.now() + 3600000).toISOString(),
        credentialSubject: {
          id: agentDID,
          parentDID,
          name: 'Test Agent',
          scopes: ['read:profile'],
          services: {
            'did:key:service123': {
              scopes: ['read:profile']
            }
          },
          validFrom: new Date().toISOString(),
          validUntil: new Date(Date.now() + 3600000).toISOString()
        }
      };

      manager.addDelegationCredential(agentDID, credential);
      const credentials = manager.getDelegationCredentials(agentDID);

      expect(credentials).toHaveLength(1);
      expect(credentials[0]).toEqual(credential);
    });
  });

  describe('createPresentation', () => {
    it('should create a presentation for valid service access', async () => {
      const agent = await manager.createAgent(parentDID, {
        name: 'Test Agent',
        description: 'For presentation tests'
      });

      const serviceDID = 'did:key:service123';
      const credential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegationCredential'],
        id: 'test-credential',
        issuer: parentDID,
        issuanceDate: new Date().toISOString(),
        expirationDate: new Date(Date.now() + 3600000).toISOString(),
        credentialSubject: {
          id: agent.did,
          parentDID,
          name: 'Test Agent',
          scopes: ['read:profile'],
          services: {
            [serviceDID]: {
              scopes: ['read:profile']
            }
          },
          validFrom: new Date().toISOString(),
          validUntil: new Date(Date.now() + 3600000).toISOString()
        }
      };

      manager.addDelegationCredential(agent.did, credential);

      const presentation = await manager.createPresentation(agent.did, {
        serviceDID,
        challenge: 'test-challenge'
      });

      expect(presentation).not.toBeNull();
      expect(presentation?.type).toContain('AgentPresentation');
      // Note: holder and challenge properties may not be present in base type
      expect(presentation?.verifiableCredential).toBeDefined();
      expect(presentation?.proof?.type).toBeDefined();
    });

    it('should return null for invalid service access', async () => {
      const agent = await manager.createAgent(parentDID, {
        name: 'Test Agent',
        description: 'For presentation tests'
      });

      const presentation = await manager.createPresentation(agent.did, {
        serviceDID: 'did:key:unknown',
        challenge: 'test-challenge'
      });

      expect(presentation).toBeNull();
    });
  });

  describe('agent-to-agent delegation', () => {
    it('should create agent with delegation properties', async () => {
      const config: AgentConfig = {
        name: 'Parent Agent',
        description: 'Can delegate',
        maxDelegationDepth: 5,
        canDelegate: true
      };

      const agent = await manager.createAgent(parentDID, config);

      expect(agent.delegationDepth).toBe(0);
      expect(agent.maxDelegationDepth).toBe(5);
      expect(agent.canDelegate).toBe(true);
      expect(agent.delegatedBy).toBeUndefined();
    });

    it('should create sub-agent from parent agent', async () => {
      // Create parent agent
      const parentAgent = await manager.createAgent(parentDID, {
        name: 'Parent Agent',
        description: 'Can create sub-agents',
        canDelegate: true
      });

      // Create sub-agent
      const subAgentConfig: SubAgentConfig = {
        name: 'Sub Agent',
        description: 'Created by parent agent',
        parentAgentDID: parentAgent.did
      };

      const subAgent = await manager.createSubAgent(parentAgent.did, subAgentConfig);

      expect(subAgent.parentDID).toBe(parentAgent.did);
      expect(subAgent.delegationDepth).toBe(1);
      expect(subAgent.delegatedBy).toBe(parentAgent.did);
      expect(subAgent.canDelegate).toBe(true);
    });

    it('should enforce maximum delegation depth', async () => {
      // Create agent with max depth of 1
      const parentAgent = await manager.createAgent(parentDID, {
        name: 'Parent Agent',
        description: 'Limited delegation depth',
        maxDelegationDepth: 1,
        canDelegate: true
      });

      // Create first sub-agent (should succeed)
      const subAgent1 = await manager.createSubAgent(parentAgent.did, {
        name: 'Sub Agent 1',
        description: 'First level',
        parentAgentDID: parentAgent.did
      });

      expect(subAgent1.delegationDepth).toBe(1);

      // Try to create second-level sub-agent (should fail)
      await expect(
        manager.createSubAgent(subAgent1.did, {
          name: 'Sub Agent 2',
          description: 'Second level',
          parentAgentDID: subAgent1.did
        })
      ).rejects.toThrow('Maximum delegation depth (1) reached');
    });

    it('should prevent delegation from non-delegating agent', async () => {
      const parentAgent = await manager.createAgent(parentDID, {
        name: 'Non-delegating Agent',
        description: 'Cannot delegate',
        canDelegate: false
      });

      await expect(
        manager.createSubAgent(parentAgent.did, {
          name: 'Sub Agent',
          description: 'Should fail',
          parentAgentDID: parentAgent.did
        })
      ).rejects.toThrow('cannot delegate');
    });

    it('should validate delegation depth correctly', async () => {
      const agent1 = await manager.createAgent(parentDID, {
        name: 'Agent 1',
        description: 'Root agent',
        maxDelegationDepth: 3
      });

      expect(manager.validateDelegationDepth(agent1.did)).toBe(true);

      const agent2 = await manager.createSubAgent(agent1.did, {
        name: 'Agent 2',
        description: 'Level 1',
        parentAgentDID: agent1.did
      });

      expect(manager.validateDelegationDepth(agent2.did)).toBe(true);

      const agent3 = await manager.createSubAgent(agent2.did, {
        name: 'Agent 3',
        description: 'Level 2',
        parentAgentDID: agent2.did
      });

      expect(manager.validateDelegationDepth(agent3.did)).toBe(true);

      // Create agent at max depth
      const agent4 = await manager.createSubAgent(agent3.did, {
        name: 'Agent 4',
        description: 'Level 3 (max)',
        parentAgentDID: agent3.did
      });

      expect(manager.validateDelegationDepth(agent4.did)).toBe(false);
    });
  });

  describe('scope reduction', () => {
    it('should reduce scopes using intersection strategy', () => {
      const parentScopes = ['read:profile', 'write:profile', 'read:data'];
      const requestedScopes = ['read:profile', 'write:profile', 'delete:data'];

      const reducedScopes = manager.reduceScopesForDelegation(
        parentScopes,
        requestedScopes
      );

      expect(reducedScopes).toEqual(['read:profile', 'write:profile']);
    });

    it('should reduce scopes using subset strategy', () => {
      const parentScopes = ['read:profile', 'write:profile', 'read:data'];
      const requestedScopes = ['read:profile', 'write:profile'];

      const policy: ScopeReductionPolicy = { strategy: 'subset' };
      const reducedScopes = manager.reduceScopesForDelegation(
        parentScopes,
        requestedScopes,
        policy
      );

      expect(reducedScopes).toEqual(['read:profile', 'write:profile']);

      // Test invalid subset
      const invalidRequestedScopes = ['read:profile', 'delete:all'];
      const invalidReduced = manager.reduceScopesForDelegation(
        parentScopes,
        invalidRequestedScopes,
        policy
      );

      expect(invalidReduced).toEqual([]);
    });

    it('should use custom reducer when provided', () => {
      const parentScopes = ['admin:all', 'read:data'];
      const requestedScopes = ['write:data', 'read:data'];

      const policy: ScopeReductionPolicy = {
        strategy: 'custom',
        customReducer: (parent, requested) => {
          // Custom logic: if parent has admin:all, grant all requested
          if (parent.includes('admin:all')) {
            return requested;
          }
          return requested.filter(scope => parent.includes(scope));
        }
      };

      const reducedScopes = manager.reduceScopesForDelegation(
        parentScopes,
        requestedScopes,
        policy
      );

      expect(reducedScopes).toEqual(['write:data', 'read:data']);
    });
  });
});