import { AgentRevocationService } from './agent-revocation-service';
import { CryptoService } from '../core/crypto';
import { DelegationCredential } from './types';
import { MemoryStorageProvider } from '../storage/providers/memory-storage-provider';

describe('AgentRevocationService', () => {
  let revocationService: AgentRevocationService;
  const parentDID = 'did:key:parent123';
  const agentDID = 'did:key:agent123';
  const serviceDID = 'did:key:service123';

  beforeEach(async () => {
    const keyPair = await CryptoService.generateKeyPair();
    const storageProvider = new MemoryStorageProvider();
    revocationService = new AgentRevocationService(keyPair, parentDID, storageProvider);
  });

  describe('revokeAgent', () => {
    it('should revoke an agent entirely', async () => {
      await revocationService.revokeAgent(agentDID, parentDID, 'Test revocation');
      
      const isRevoked = await revocationService.isAgentRevoked(agentDID, parentDID);
      expect(isRevoked).toBe(true);
    });

    it('should store revocation reason', async () => {
      const reason = 'Security breach';
      await revocationService.revokeAgent(agentDID, parentDID, reason);
      
      const records = revocationService.getRevocationRecords(parentDID);
      expect(records).toHaveLength(1);
      expect(records[0].reason).toBe(reason);
    });

    it('should affect all services when agent is revoked', async () => {
      await revocationService.revokeAgent(agentDID, parentDID);
      
      // Any service check should return true
      const isServiceRevoked = await revocationService.isAgentServiceRevoked(
        agentDID, 
        parentDID, 
        'any-service'
      );
      expect(isServiceRevoked).toBe(true);
    });
  });

  describe('revokeAgentServiceAccess', () => {
    it('should revoke access to specific service', async () => {
      await revocationService.revokeAgentServiceAccess(
        agentDID,
        parentDID,
        serviceDID,
        'Service discontinued'
      );
      
      const isRevoked = await revocationService.isAgentServiceRevoked(
        agentDID,
        parentDID,
        serviceDID
      );
      expect(isRevoked).toBe(true);
      
      // Other services should not be affected
      const isOtherRevoked = await revocationService.isAgentServiceRevoked(
        agentDID,
        parentDID,
        'did:key:other-service'
      );
      expect(isOtherRevoked).toBe(false);
    });

    it('should not affect agent entirely', async () => {
      await revocationService.revokeAgentServiceAccess(
        agentDID,
        parentDID,
        serviceDID
      );
      
      const isAgentRevoked = await revocationService.isAgentRevoked(agentDID, parentDID);
      expect(isAgentRevoked).toBe(false);
    });
  });

  describe('validateDelegationCredential', () => {
    const createValidCredential = (): DelegationCredential => ({
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'DelegationCredential'],
      id: 'test-delegation',
      issuer: parentDID,
      issuanceDate: new Date().toISOString(),
      expirationDate: new Date(Date.now() + 3600000).toISOString(),
      credentialSubject: {
        id: agentDID,
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
    });

    it('should validate non-revoked credential', async () => {
      const credential = createValidCredential();
      const result = await revocationService.validateDelegationCredential(credential);
      
      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('should reject expired credential', async () => {
      const credential = createValidCredential();
      credential.expirationDate = new Date(Date.now() - 3600000).toISOString();
      credential.credentialSubject.validUntil = new Date(Date.now() - 3600000).toISOString();
      
      const result = await revocationService.validateDelegationCredential(credential);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Invalid delegation credential');
    });

    it('should reject credential for revoked agent', async () => {
      await revocationService.revokeAgent(agentDID, parentDID);
      
      const credential = createValidCredential();
      const result = await revocationService.validateDelegationCredential(credential);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Agent has been revoked');
    });

    it('should reject credential for revoked service access', async () => {
      await revocationService.revokeAgentServiceAccess(agentDID, parentDID, serviceDID);
      
      const credential = createValidCredential();
      const result = await revocationService.validateDelegationCredential(credential);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toContain(`Agent access to service ${serviceDID} has been revoked`);
    });
  });

  describe('restoreAgent', () => {
    it('should restore revoked agent', async () => {
      await revocationService.revokeAgent(agentDID, parentDID);
      expect(await revocationService.isAgentRevoked(agentDID, parentDID)).toBe(true);
      
      await revocationService.restoreAgent(agentDID, parentDID);
      expect(await revocationService.isAgentRevoked(agentDID, parentDID)).toBe(false);
    });

    it('should not affect service-specific revocations', async () => {
      await revocationService.revokeAgentServiceAccess(agentDID, parentDID, serviceDID);
      await revocationService.revokeAgent(agentDID, parentDID);
      
      await revocationService.restoreAgent(agentDID, parentDID);
      
      // Agent should be restored
      expect(await revocationService.isAgentRevoked(agentDID, parentDID)).toBe(false);
      
      // But service revocation should remain
      expect(await revocationService.isAgentServiceRevoked(agentDID, parentDID, serviceDID)).toBe(true);
    });
  });

  describe('restoreAgentServiceAccess', () => {
    it('should restore service access', async () => {
      await revocationService.revokeAgentServiceAccess(agentDID, parentDID, serviceDID);
      expect(await revocationService.isAgentServiceRevoked(agentDID, parentDID, serviceDID)).toBe(true);
      
      await revocationService.restoreAgentServiceAccess(agentDID, parentDID, serviceDID);
      expect(await revocationService.isAgentServiceRevoked(agentDID, parentDID, serviceDID)).toBe(false);
    });
  });

  describe('getRevocationStats', () => {
    it('should provide accurate statistics', async () => {
      const parentDID2 = 'did:key:parent456';
      const agentDID2 = 'did:key:agent456';
      
      // Revoke some agents and services
      await revocationService.revokeAgent(agentDID, parentDID);
      await revocationService.revokeAgentServiceAccess(agentDID2, parentDID, serviceDID);
      await revocationService.revokeAgentServiceAccess(agentDID2, parentDID, 'did:key:service2');
      
      const stats = revocationService.getRevocationStats();
      
      expect(stats.totalAgentsRevoked).toBe(1);
      expect(stats.totalServiceRevocations).toBe(2);
      expect(stats.revocationsByParent[parentDID]).toBe(3);
    });
  });

  describe('import/export', () => {
    it('should export and import revocation data', async () => {
      // Create some revocations
      await revocationService.revokeAgent(agentDID, parentDID, 'Test reason');
      await revocationService.revokeAgentServiceAccess(
        'agent2', 
        parentDID, 
        serviceDID, 
        'Service reason'
      );
      
      // Export data
      const exportedData = revocationService.exportRevocationData();
      
      // Create new service and import
      const newKeyPair = await CryptoService.generateKeyPair();
      const newService = new AgentRevocationService(
        newKeyPair,
        parentDID,
        new MemoryStorageProvider()
      );
      
      newService.importRevocationData(exportedData);
      
      // Verify imported data
      expect(await newService.isAgentRevoked(agentDID, parentDID)).toBe(true);
      expect(await newService.isAgentServiceRevoked('agent2', parentDID, serviceDID)).toBe(true);
      
      const records = newService.getRevocationRecords(parentDID);
      expect(records).toHaveLength(2);
    });
  });
});