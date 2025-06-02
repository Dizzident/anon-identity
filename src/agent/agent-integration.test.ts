import { UserWallet } from '../wallet/user-wallet';
import { IdentityProvider } from '../idp/identity-provider';
import { AgentEnabledServiceProvider } from '../sp/service-provider-agent';
import { ServiceManifestBuilder } from './service-manifest';
import { AgentRevocationService } from './agent-revocation-service';
import { MemoryStorageProvider } from '../storage/providers/memory-storage-provider';
import { CryptoService } from '../core/crypto';

describe('Agent Sub-Identity Integration', () => {
  let userWallet: UserWallet;
  let idp: IdentityProvider;
  let serviceProvider: AgentEnabledServiceProvider;
  let revocationService: AgentRevocationService;
  let storageProvider: MemoryStorageProvider;

  beforeEach(async () => {
    // Set up storage
    storageProvider = new MemoryStorageProvider();

    // Create user wallet
    userWallet = await UserWallet.create(storageProvider);
    
    // Create identity provider
    idp = await IdentityProvider.create(storageProvider);
    
    // Create revocation service  
    const revocationKeyPair = await CryptoService.generateKeyPair();
    revocationService = new AgentRevocationService(
      revocationKeyPair,
      idp.getDID(),
      storageProvider
    );

    // Create service provider with agent support
    const manifest = new ServiceManifestBuilder(
      'did:key:test-service',
      'Test Service',
      'A test service with agent support'
    )
      .addRequiredScope('read:profile:basic')
      .addRequiredScope('read:data:all')
      .addOptionalScope('write:data:create')
      .addOptionalScope('delete:data:own')
      .build();

    serviceProvider = new AgentEnabledServiceProvider(
      'Test Service',
      'did:key:test-service',
      [idp.getDID()],
      {
        serviceManifest: manifest,
        agentRevocationService: revocationService,
        storageProvider
      }
    );
  });

  describe('Full Agent Lifecycle', () => {
    it('should complete full agent lifecycle from creation to revocation', async () => {
      // 1. Issue credential to user
      const userCredential = await idp.issueVerifiableCredential(userWallet.getDID(), {
        givenName: 'Alice Smith'
      });
      
      await userWallet.storeCredential(userCredential);

      // 2. Create agent
      const agent = await userWallet.createAgent({
        name: 'Data Processor',
        description: 'Processes user data'
      });

      expect(agent.did).toMatch(/^did:key:/);
      expect(agent.parentDID).toBe(userWallet.getDID());

      // 3. Grant agent access to service
      const grant = await userWallet.grantAgentAccess(agent.did, {
        serviceDID: 'did:key:test-service',
        scopes: ['read:profile:basic', 'read:data:all', 'write:data:create'],
        expiresAt: new Date(Date.now() + 3600000) // 1 hour
      });

      expect(grant.credentialSubject.id).toBe(agent.did);
      expect(grant.credentialSubject.scopes).toContain('write:data:create');

      // 4. Agent creates presentation
      const agentManager = userWallet.getAgentManager();
      const presentation = await agentManager.createPresentation(agent.did, {
        serviceDID: 'did:key:test-service',
        challenge: 'test-challenge-123'
      });

      expect(presentation).not.toBeNull();
      expect(presentation?.type).toContain('AgentPresentation');

      // 5. Service provider verifies presentation
      // Mock JWT verification since we're not doing actual crypto in tests
      jest.spyOn(serviceProvider as any, 'verifyJWT').mockResolvedValue({ valid: true });

      const result = await serviceProvider.verifyPresentation(presentation!);
      
      expect(result.valid).toBe(true);
      expect(result.holder).toBe(agent.did);
      expect(result.credentials?.[0].attributes.agentDID).toBe(agent.did);
      expect(result.credentials?.[0].attributes.parentDID).toBe(userWallet.getDID());

      // 6. Check agent permissions
      expect(serviceProvider.hasScope(agent.did, 'read:data:all')).toBe(true);
      expect(serviceProvider.hasScope(agent.did, 'write:data:create')).toBe(true);
      expect(serviceProvider.hasScope(agent.did, 'delete:data:own')).toBe(false);

      // 7. Get agent scopes
      const scopes = serviceProvider.getAgentScopes(agent.did);
      expect(scopes).toContain('read:profile:basic');
      expect(scopes).toContain('read:data:all');
      expect(scopes).toContain('write:data:create');

      // 8. Revoke agent access
      await userWallet.revokeAgentAccess(agent.did, 'did:key:test-service');

      // 9. Verify revocation works
      const revokedPresentation = await agentManager.createPresentation(agent.did, {
        serviceDID: 'did:key:test-service',
        challenge: 'test-challenge-456'
      });

      // Should not be able to create presentation after revocation
      expect(revokedPresentation).toBeNull();

      // 10. Complete agent removal
      await userWallet.revokeAgent(agent.did);
      
      const agents = userWallet.listAgents();
      expect(agents).toHaveLength(0);
    });

    it('should handle multiple agents with different permissions', async () => {
      // Create multiple agents
      const readAgent = await userWallet.createAgent({
        name: 'Read-Only Agent',
        description: 'Can only read data'
      });

      const writeAgent = await userWallet.createAgent({
        name: 'Write Agent',
        description: 'Can read and write data'
      });

      // Grant different permissions
      await userWallet.grantAgentAccess(readAgent.did, {
        serviceDID: 'did:key:test-service',
        scopes: ['read:profile:basic', 'read:data:all'],
        expiresAt: new Date(Date.now() + 3600000)
      });

      await userWallet.grantAgentAccess(writeAgent.did, {
        serviceDID: 'did:key:test-service',
        scopes: ['read:profile:basic', 'read:data:all', 'write:data:create', 'delete:data:own'],
        expiresAt: new Date(Date.now() + 3600000)
      });

      // List all agents
      const agents = userWallet.listAgents();
      expect(agents).toHaveLength(2);

      // Check different access levels
      const readAccess = userWallet.getAgentAccess(readAgent.did);
      const writeAccess = userWallet.getAgentAccess(writeAgent.did);

      expect(readAccess[0].scopes).toHaveLength(2);
      expect(writeAccess[0].scopes).toHaveLength(4);
    });

    it('should handle service-specific revocation', async () => {
      const agent = await userWallet.createAgent({
        name: 'Multi-Service Agent',
        description: 'Works with multiple services'
      });

      // Grant access to multiple services
      await userWallet.grantAgentAccess(agent.did, {
        serviceDID: 'did:key:service1',
        scopes: ['read:data:all'],
        expiresAt: new Date(Date.now() + 3600000)
      });

      await userWallet.grantAgentAccess(agent.did, {
        serviceDID: 'did:key:service2',
        scopes: ['write:data:create'],
        expiresAt: new Date(Date.now() + 3600000)
      });

      // Revoke access to one service
      await userWallet.revokeAgentAccess(agent.did, 'did:key:service1');

      // Check access
      const access = userWallet.getAgentAccess(agent.did);
      expect(access).toHaveLength(1);
      expect(access[0].serviceDID).toBe('did:key:service2');

      // Verify revocation in revocation service
      const isService1Revoked = await revocationService.isAgentServiceRevoked(
        agent.did,
        userWallet.getDID(),
        'did:key:service1'
      );
      const isService2Revoked = await revocationService.isAgentServiceRevoked(
        agent.did,
        userWallet.getDID(),
        'did:key:service2'
      );

      expect(isService1Revoked).toBe(true);
      expect(isService2Revoked).toBe(false);
    });

    it('should validate scope requirements', async () => {
      const agent = await userWallet.createAgent({
        name: 'Limited Agent',
        description: 'Has limited permissions'
      });

      // Grant only partial required scopes
      await userWallet.grantAgentAccess(agent.did, {
        serviceDID: 'did:key:test-service',
        scopes: ['read:profile:basic'], // Missing 'read:data:all' which is required
        expiresAt: new Date(Date.now() + 3600000)
      });

      // Check scope validation
      const validation = serviceProvider.validateScopeRequirements(['read:profile:basic']);
      expect(validation.valid).toBe(false);
      expect(validation.missingRequired).toContain('read:data:all');
    });
  });

  describe('Error Handling', () => {
    it('should reject expired delegation credentials', async () => {
      const agent = await userWallet.createAgent({
        name: 'Expired Agent',
        description: 'Will have expired credentials'
      });

      // Grant access with past expiration
      await userWallet.grantAgentAccess(agent.did, {
        serviceDID: 'did:key:test-service',
        scopes: ['read:profile:basic', 'read:data:all'],
        expiresAt: new Date(Date.now() - 3600000) // 1 hour ago
      });

      const agentManager = userWallet.getAgentManager();
      const presentation = await agentManager.createPresentation(agent.did, {
        serviceDID: 'did:key:test-service',
        challenge: 'test-challenge'
      });

      // Should not create presentation with expired grant
      expect(presentation).toBeNull();
    });

    it('should handle agent not found errors', async () => {
      const invalidAgentDID = 'did:key:nonexistent';

      // Try to grant access to non-existent agent
      await expect(
        userWallet.grantAgentAccess(invalidAgentDID, {
          serviceDID: 'did:key:test-service',
          scopes: ['read:profile:basic'],
          expiresAt: new Date(Date.now() + 3600000)
        })
      ).rejects.toThrow('Agent not found');

      // Try to revoke non-existent agent
      await expect(
        userWallet.revokeAgent(invalidAgentDID)
      ).rejects.toThrow('Agent not found');
    });
  });
});