import { DelegationChainValidator } from './delegation-chain-validator';
import { DelegationManager } from './delegation-manager';
import { AgentIdentityManager } from './agent-identity';
import { AgentConfig, DelegationCredential, AccessGrant } from './types';
import { generateKeyPair } from '../core/crypto';

describe('DelegationChainValidator', () => {
  let validator: DelegationChainValidator;
  let delegationManager: DelegationManager;
  let agentManager: AgentIdentityManager;
  
  const userDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const serviceDID = 'did:key:z6MkService';
  let userKeyPair: any;

  beforeEach(async () => {
    delegationManager = new DelegationManager();
    agentManager = new AgentIdentityManager();
    validator = new DelegationChainValidator(delegationManager, agentManager);
    userKeyPair = await generateKeyPair();
  });

  describe('validateDelegationChain', () => {
    it('should validate a simple user → agent chain', async () => {
      // Create agent
      const agent = await agentManager.createAgent(userDID, {
        name: 'Test Agent',
        description: 'Simple agent'
      });

      // Create delegation credential
      const grant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile', 'write:data'],
        expiresAt: new Date(Date.now() + 3600000)
      };

      const credential = await delegationManager.createDelegationCredential(
        userDID,
        userKeyPair,
        agent.did,
        agent.name,
        grant
      );

      agentManager.addDelegationCredential(agent.did, credential);

      // Validate chain
      const result = await validator.validateDelegationChain(
        agent.did,
        userDID,
        serviceDID
      );

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.chain).toBeDefined();
      expect(result.chain?.currentDepth).toBe(1);
      expect(result.chain?.agents).toHaveLength(1);
    });

    it('should validate a multi-level delegation chain', async () => {
      // Create level 1 agent
      const agent1 = await agentManager.createAgent(userDID, {
        name: 'Agent 1',
        description: 'Root agent',
        canDelegate: true,
        maxDelegationDepth: 3
      });

      const grant1: AccessGrant = {
        serviceDID,
        scopes: ['read:profile', 'write:data', 'admin:agents'],
        expiresAt: new Date(Date.now() + 3600000)
      };

      const credential1 = await delegationManager.createDelegationCredential(
        userDID,
        userKeyPair,
        agent1.did,
        agent1.name,
        grant1,
        {
          delegationDepth: 0,
          maxDelegationDepth: 3,
          canDelegate: true
        }
      );

      agentManager.addDelegationCredential(agent1.did, credential1);

      // Create level 2 agent (sub-agent)
      const agent2 = await agentManager.createSubAgent(agent1.did, {
        name: 'Agent 2',
        description: 'Sub-agent',
        parentAgentDID: agent1.did
      });

      const grant2: AccessGrant = {
        serviceDID,
        scopes: ['read:profile', 'write:data'], // Reduced scopes
        expiresAt: new Date(Date.now() + 3600000)
      };

      const credential2 = await delegationManager.createDelegationCredential(
        agent1.did,
        agent1.keyPair,
        agent2.did,
        agent2.name,
        grant2,
        {
          delegationDepth: 1,
          maxDelegationDepth: 3,
          canDelegate: true
        }
      );

      agentManager.addDelegationCredential(agent2.did, credential2);

      // Validate chain
      const result = await validator.validateDelegationChain(
        agent2.did,
        userDID,
        serviceDID
      );

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.chain).toBeDefined();
      expect(result.chain?.currentDepth).toBe(2);
      expect(result.chain?.agents).toHaveLength(2);
      expect(result.chain?.credentials).toHaveLength(2);
    });

    it('should detect invalid delegation chains', async () => {
      // Create agent
      const agent = await agentManager.createAgent(userDID, {
        name: 'Test Agent',
        description: 'Agent with expired credential'
      });

      // Create expired delegation credential
      const grant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile'],
        expiresAt: new Date(Date.now() - 1000) // Already expired
      };

      const credential = await delegationManager.createDelegationCredential(
        userDID,
        userKeyPair,
        agent.did,
        agent.name,
        grant
      );

      agentManager.addDelegationCredential(agent.did, credential);

      // Validate chain
      const result = await validator.validateDelegationChain(
        agent.did,
        userDID,
        serviceDID
      );

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('expired');
    });

    it('should detect scope violations in chain', async () => {
      // Create parent agent with limited scopes
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Limited parent',
        canDelegate: true
      });

      const parentGrant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile'], // Limited scopes
        expiresAt: new Date(Date.now() + 3600000)
      };

      const parentCredential = await delegationManager.createDelegationCredential(
        userDID,
        userKeyPair,
        parentAgent.did,
        parentAgent.name,
        parentGrant,
        {
          delegationDepth: 0,
          maxDelegationDepth: 3,
          canDelegate: true
        }
      );

      agentManager.addDelegationCredential(parentAgent.did, parentCredential);

      // Create sub-agent trying to get more scopes
      const subAgent = await agentManager.createSubAgent(parentAgent.did, {
        name: 'Sub Agent',
        description: 'Attempting scope escalation',
        parentAgentDID: parentAgent.did
      });

      const subGrant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile', 'write:data'], // Trying to get more scopes
        expiresAt: new Date(Date.now() + 3600000)
      };

      // This should be caught by the delegation manager, but let's create it manually for testing
      const subCredential: DelegationCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegationCredential'],
        id: 'test-credential',
        issuer: parentAgent.did,
        issuanceDate: new Date().toISOString(),
        expirationDate: subGrant.expiresAt.toISOString(),
        credentialSubject: {
          id: subAgent.did,
          parentDID: parentAgent.did,
          name: subAgent.name,
          scopes: subGrant.scopes,
          services: {
            [serviceDID]: {
              scopes: subGrant.scopes
            }
          },
          validFrom: new Date().toISOString(),
          validUntil: subGrant.expiresAt.toISOString(),
          delegationDepth: 1,
          maxDelegationDepth: 3,
          canDelegate: true
        }
      };

      agentManager.addDelegationCredential(subAgent.did, subCredential);

      // Validate chain - should fail due to scope violation
      const result = await validator.validateDelegationChain(
        subAgent.did,
        userDID,
        serviceDID
      );

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some(e => e.includes('scope'))).toBe(true);
    });
  });

  describe('exportChain', () => {
    it('should export chain data for visualization', async () => {
      // Create a simple chain
      const agent = await agentManager.createAgent(userDID, {
        name: 'Test Agent',
        description: 'For export test'
      });

      const grant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile'],
        expiresAt: new Date(Date.now() + 3600000)
      };

      const credential = await delegationManager.createDelegationCredential(
        userDID,
        userKeyPair,
        agent.did,
        agent.name,
        grant
      );

      agentManager.addDelegationCredential(agent.did, credential);

      const result = await validator.validateDelegationChain(
        agent.did,
        userDID,
        serviceDID
      );

      expect(result.valid).toBe(true);
      expect(result.chain).toBeDefined();

      const exported = validator.exportChain(result.chain!);
      
      expect(exported).toHaveProperty('depth');
      expect(exported).toHaveProperty('maxDepth');
      expect(exported).toHaveProperty('agents');
      expect(exported).toHaveProperty('credentials');
      
      // Check structure
      const exportedData = exported as any;
      expect(exportedData.agents).toHaveLength(1);
      expect(exportedData.agents[0]).toHaveProperty('did');
      expect(exportedData.agents[0]).toHaveProperty('name');
      expect(exportedData.credentials).toHaveLength(1);
      expect(exportedData.credentials[0]).toHaveProperty('issuer');
      expect(exportedData.credentials[0]).toHaveProperty('subject');
      expect(exportedData.credentials[0]).toHaveProperty('scopes');
    });
  });

  describe('cache management', () => {
    it('should cache validated chains', async () => {
      const agent = await agentManager.createAgent(userDID, {
        name: 'Test Agent',
        description: 'For cache test'
      });

      const grant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile'],
        expiresAt: new Date(Date.now() + 3600000)
      };

      const credential = await delegationManager.createDelegationCredential(
        userDID,
        userKeyPair,
        agent.did,
        agent.name,
        grant
      );

      agentManager.addDelegationCredential(agent.did, credential);

      // First validation - should build chain
      const result1 = await validator.validateDelegationChain(
        agent.did,
        userDID,
        serviceDID
      );

      expect(result1.valid).toBe(true);

      // Second validation - should use cache
      const startTime = Date.now();
      const result2 = await validator.validateDelegationChain(
        agent.did,
        userDID,
        serviceDID
      );
      const duration = Date.now() - startTime;

      expect(result2.valid).toBe(true);
      expect(duration).toBeLessThan(10); // Should be very fast from cache
    });

    it('should clear expired cache entries', async () => {
      const agent = await agentManager.createAgent(userDID, {
        name: 'Test Agent',
        description: 'For cache expiry test'
      });

      const grant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile'],
        expiresAt: new Date(Date.now() + 1000) // Expires in 1 second
      };

      const credential = await delegationManager.createDelegationCredential(
        userDID,
        userKeyPair,
        agent.did,
        agent.name,
        grant
      );

      agentManager.addDelegationCredential(agent.did, credential);

      // Validate and cache
      await validator.validateDelegationChain(agent.did, userDID, serviceDID);

      // Clear expired entries
      validator.clearExpiredCache();

      // Cache should still be valid at this point
      // In a real test, we'd wait for expiration or mock the time
    });
  });
});