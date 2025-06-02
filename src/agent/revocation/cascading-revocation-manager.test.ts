import { CascadingRevocationManager, RevocationRequest, RevocationResult } from './cascading-revocation-manager';
import { AgentIdentityManager } from '../agent-identity';
import { DelegationManager } from '../delegation-manager';
import { DelegationChainValidator } from '../delegation-chain-validator';
import { CommunicationManager } from '../communication/communication-manager';
import { MessageFactory } from '../communication/message-factory';
import { ActivityLogger } from '../activity/activity-logger';
import { AgentIdentity } from '../types';

describe('CascadingRevocationManager', () => {
  let revocationManager: CascadingRevocationManager;
  let agentManager: AgentIdentityManager;
  let delegationManager: DelegationManager;
  let chainValidator: DelegationChainValidator;
  let communicationManager: CommunicationManager;
  let activityLogger: ActivityLogger;

  const userDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

  beforeEach(async () => {
    // Set up dependencies
    agentManager = new AgentIdentityManager();
    delegationManager = new DelegationManager();
    chainValidator = new DelegationChainValidator(delegationManager, agentManager);
    
    // Create a mock communication manager
    communicationManager = {
      sendMessage: jest.fn().mockResolvedValue(undefined)
    } as any;
    
    activityLogger = new ActivityLogger();

    revocationManager = new CascadingRevocationManager(
      agentManager,
      chainValidator,
      communicationManager,
      activityLogger
    );
  });

  describe('single agent revocation', () => {
    it('should revoke a single agent successfully', async () => {
      // Create test agent
      const agent = await agentManager.createAgent(userDID, {
        name: 'Test Agent',
        description: 'Agent for testing revocation'
      });

      const request: RevocationRequest = {
        targetAgentDID: agent.did,
        reason: 'Security violation',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      };

      const result = await revocationManager.revokeAgent(request);

      expect(result.success).toBe(true);
      expect(result.revokedAgents).toContain(agent.did);
      expect(result.failedRevocations).toHaveLength(0);
      expect(result.auditEntries).toBe(1);

      // Verify agent is no longer in manager
      expect(agentManager.getAgent(agent.did)).toBeNull();
    });

    it('should handle revocation of non-existent agent', async () => {
      const request: RevocationRequest = {
        targetAgentDID: 'did:key:nonexistent',
        reason: 'Testing non-existent agent',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      };

      const result = await revocationManager.revokeAgent(request);

      expect(result.success).toBe(false);
      expect(result.revokedAgents).toHaveLength(0);
      expect(result.failedRevocations).toHaveLength(1);
      expect(result.failedRevocations[0].error).toBe('Agent not found');
    });

    it('should handle service-specific revocation', async () => {
      // Create test agent with service access
      const agent = await agentManager.createAgent(userDID, {
        name: 'Service Agent',
        description: 'Agent with service access'
      });

      // Mock the service access methods
      jest.spyOn(agentManager, 'revokeServiceAccess').mockReturnValue(true);

      const request: RevocationRequest = {
        targetAgentDID: agent.did,
        reason: 'Service access violation',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false,
        serviceDID: 'service:example'
      };

      const result = await revocationManager.revokeAgent(request);

      expect(result.success).toBe(true);
      expect(result.revokedAgents).toContain(agent.did);
      expect(agentManager.revokeServiceAccess).toHaveBeenCalledWith(agent.did, 'service:example');
    });
  });

  describe('cascading revocation', () => {
    it('should revoke parent and all sub-agents when cascading enabled', async () => {
      // Create parent agent
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Parent agent for testing',
        canDelegate: true
      });

      // Create sub-agents
      const subAgent1 = await agentManager.createSubAgent(parentAgent.did, {
        name: 'Sub Agent 1',
        description: 'First sub-agent',
        parentAgentDID: parentAgent.did,
        requestedScopes: ['read:profile']
      });

      const subAgent2 = await agentManager.createSubAgent(parentAgent.did, {
        name: 'Sub Agent 2',
        description: 'Second sub-agent',
        parentAgentDID: parentAgent.did,
        requestedScopes: ['read:contacts']
      });

      // Create a sub-sub-agent
      const subSubAgent = await agentManager.createSubAgent(subAgent1.did, {
        name: 'Sub-Sub Agent',
        description: 'Deep sub-agent',
        parentAgentDID: subAgent1.did,
        requestedScopes: ['read:profile']
      });

      const request: RevocationRequest = {
        targetAgentDID: parentAgent.did,
        reason: 'Cascading test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: true
      };

      const result = await revocationManager.revokeAgent(request);

      expect(result.success).toBe(true);
      expect(result.revokedAgents).toContain(parentAgent.did);
      expect(result.revokedAgents).toContain(subAgent1.did);
      expect(result.revokedAgents).toContain(subAgent2.did);
      expect(result.revokedAgents).toContain(subSubAgent.did);
      expect(result.revokedAgents).toHaveLength(4);

      // Verify all agents are revoked
      expect(agentManager.getAgent(parentAgent.did)).toBeNull();
      expect(agentManager.getAgent(subAgent1.did)).toBeNull();
      expect(agentManager.getAgent(subAgent2.did)).toBeNull();
      expect(agentManager.getAgent(subSubAgent.did)).toBeNull();
    });

    it('should handle partial cascading failures gracefully', async () => {
      // Create parent agent
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Parent for partial failure test',
        canDelegate: true
      });

      // Create sub-agent
      const subAgent = await agentManager.createSubAgent(parentAgent.did, {
        name: 'Sub Agent',
        description: 'Sub-agent for partial failure test',
        parentAgentDID: parentAgent.did,
        requestedScopes: ['read:profile']
      });

      // Mock deleteAgent to fail for sub-agent
      const originalDeleteAgent = agentManager.deleteAgent.bind(agentManager);
      jest.spyOn(agentManager, 'deleteAgent').mockImplementation((did: string) => {
        if (did === subAgent.did) {
          return false; // Simulate failure
        }
        return originalDeleteAgent(did);
      });

      const request: RevocationRequest = {
        targetAgentDID: parentAgent.did,
        reason: 'Partial failure test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: true
      };

      const result = await revocationManager.revokeAgent(request);

      expect(result.success).toBe(true); // Partial success
      expect(result.revokedAgents).toContain(parentAgent.did);
      expect(result.failedRevocations).toHaveLength(1);
      expect(result.failedRevocations[0].agentDID).toBe(subAgent.did);
    });
  });

  describe('notification system', () => {
    it('should send revocation notifications', async () => {
      // Create test agent with parent chain
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Parent for notification test',
        canDelegate: true
      });

      const subAgent = await agentManager.createSubAgent(parentAgent.did, {
        name: 'Sub Agent',
        description: 'Sub-agent for notification test',
        parentAgentDID: parentAgent.did,
        requestedScopes: ['read:profile']
      });

      const request: RevocationRequest = {
        targetAgentDID: subAgent.did,
        reason: 'Notification test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      };

      const result = await revocationManager.revokeAgent(request);

      expect(result.success).toBe(true);
      expect(result.notificationsSent).toBeGreaterThan(0);
      expect(communicationManager.sendMessage).toHaveBeenCalled();
    });

    it('should handle notification failures gracefully', async () => {
      // Mock communication manager to fail
      (communicationManager.sendMessage as jest.Mock).mockRejectedValue(new Error('Network error'));

      const agent = await agentManager.createAgent(userDID, {
        name: 'Test Agent',
        description: 'Agent for notification failure test'
      });

      const request: RevocationRequest = {
        targetAgentDID: agent.did,
        reason: 'Notification failure test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      };

      const result = await revocationManager.revokeAgent(request);

      // Revocation should still succeed even if notifications fail
      expect(result.success).toBe(true);
      expect(result.revokedAgents).toContain(agent.did);
    });
  });

  describe('concurrent revocation prevention', () => {
    it('should prevent concurrent revocations of the same agent', async () => {
      const agent = await agentManager.createAgent(userDID, {
        name: 'Concurrent Test Agent',
        description: 'Agent for concurrent revocation test'
      });

      const request1: RevocationRequest = {
        targetAgentDID: agent.did,
        reason: 'First revocation',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      };

      const request2: RevocationRequest = {
        targetAgentDID: agent.did,
        reason: 'Second revocation',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      };

      // Start first revocation (but don't await)
      const promise1 = revocationManager.revokeAgent(request1);

      // Try to start second revocation immediately
      await expect(revocationManager.revokeAgent(request2))
        .rejects
        .toThrow('Revocation already in progress');

      // First revocation should complete successfully
      const result1 = await promise1;
      expect(result1.success).toBe(true);
    });
  });

  describe('audit trail', () => {
    it('should create audit entries for revocations', async () => {
      const agent = await agentManager.createAgent(userDID, {
        name: 'Audit Test Agent',
        description: 'Agent for audit trail test'
      });

      const request: RevocationRequest = {
        targetAgentDID: agent.did,
        reason: 'Audit trail test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      };

      const result = await revocationManager.revokeAgent(request);

      expect(result.success).toBe(true);
      expect(result.auditEntries).toBe(1);

      const auditEntries = revocationManager.getRevocationAudit(agent.did);
      expect(auditEntries).toHaveLength(1);
      expect(auditEntries[0].targetAgentDID).toBe(agent.did);
      expect(auditEntries[0].reason).toBe('Audit trail test');
      expect(auditEntries[0].revokedBy).toBe(userDID);
      expect(auditEntries[0].status).toBe('completed');
    });

    it('should track child revocations in audit trail', async () => {
      // Create parent and sub-agents
      const parentAgent = await agentManager.createAgent(userDID, {
        name: 'Parent Agent',
        description: 'Parent for child tracking test',
        canDelegate: true
      });

      const subAgent1 = await agentManager.createSubAgent(parentAgent.did, {
        name: 'Sub Agent 1',
        description: 'First sub-agent',
        parentAgentDID: parentAgent.did,
        requestedScopes: ['read:profile']
      });

      const subAgent2 = await agentManager.createSubAgent(parentAgent.did, {
        name: 'Sub Agent 2',
        description: 'Second sub-agent',
        parentAgentDID: parentAgent.did,
        requestedScopes: ['read:contacts']
      });

      const request: RevocationRequest = {
        targetAgentDID: parentAgent.did,
        reason: 'Child tracking test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: true
      };

      await revocationManager.revokeAgent(request);

      const auditEntries = revocationManager.getRevocationAudit(parentAgent.did);
      expect(auditEntries).toHaveLength(1);
      expect(auditEntries[0].childRevocations).toContain(subAgent1.did);
      expect(auditEntries[0].childRevocations).toContain(subAgent2.did);
    });
  });

  describe('revocation status checks', () => {
    it('should correctly identify revoked agents', async () => {
      const agent = await agentManager.createAgent(userDID, {
        name: 'Status Test Agent',
        description: 'Agent for status check test'
      });

      // Initially not revoked
      expect(revocationManager.isAgentRevoked(agent.did)).toBe(false);

      const request: RevocationRequest = {
        targetAgentDID: agent.did,
        reason: 'Status check test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      };

      await revocationManager.revokeAgent(request);

      // Now should be revoked
      expect(revocationManager.isAgentRevoked(agent.did)).toBe(true);
    });

    it('should handle service-specific revocation status', async () => {
      const agent = await agentManager.createAgent(userDID, {
        name: 'Service Status Test',
        description: 'Agent for service-specific status test'
      });

      // Mock the service access methods
      jest.spyOn(agentManager, 'revokeServiceAccess').mockReturnValue(true);

      const request: RevocationRequest = {
        targetAgentDID: agent.did,
        reason: 'Service-specific test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false,
        serviceDID: 'service:example'
      };

      await revocationManager.revokeAgent(request);

      // Should be revoked for specific service
      expect(revocationManager.isAgentRevoked(agent.did, 'service:example')).toBe(true);
      // Should not be revoked for other services
      expect(revocationManager.isAgentRevoked(agent.did, 'service:other')).toBe(false);
    });
  });

  describe('statistics and metrics', () => {
    it('should track revocation statistics', async () => {
      // Create multiple agents and revoke them
      const agent1 = await agentManager.createAgent(userDID, {
        name: 'Stats Agent 1',
        description: 'First agent for stats test'
      });

      const agent2 = await agentManager.createAgent(userDID, {
        name: 'Stats Agent 2',
        description: 'Second agent for stats test',
        canDelegate: true
      });

      const subAgent = await agentManager.createSubAgent(agent2.did, {
        name: 'Sub Agent',
        description: 'Sub-agent for stats test',
        parentAgentDID: agent2.did,
        requestedScopes: ['read:profile']
      });

      // Perform different types of revocations
      await revocationManager.revokeAgent({
        targetAgentDID: agent1.did,
        reason: 'Single revocation',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      });

      await revocationManager.revokeAgent({
        targetAgentDID: agent2.did,
        reason: 'Cascading revocation',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: true
      });

      await revocationManager.revokeAgent({
        targetAgentDID: 'did:key:service-test',
        reason: 'Service-specific',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false,
        serviceDID: 'service:example'
      });

      const stats = revocationManager.getRevocationStats();

      expect(stats.totalRevocations).toBe(3);
      expect(stats.cascadingRevocations).toBe(1);
      expect(stats.serviceSpecificRevocations).toBe(1);
      expect(stats.averageChildRevocations).toBeGreaterThan(0);
    });
  });

  describe('audit trail management', () => {
    it('should export audit trail in JSON format', async () => {
      const agent = await agentManager.createAgent(userDID, {
        name: 'Export Test Agent',
        description: 'Agent for export test'
      });

      await revocationManager.revokeAgent({
        targetAgentDID: agent.did,
        reason: 'Export test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      });

      const jsonExport = revocationManager.exportAuditTrail('json');
      const parsedExport = JSON.parse(jsonExport);

      expect(Array.isArray(parsedExport)).toBe(true);
      expect(parsedExport).toHaveLength(1);
      expect(parsedExport[0].targetAgentDID).toBe(agent.did);
    });

    it('should export audit trail in CSV format', async () => {
      const agent = await agentManager.createAgent(userDID, {
        name: 'CSV Export Test Agent',
        description: 'Agent for CSV export test'
      });

      await revocationManager.revokeAgent({
        targetAgentDID: agent.did,
        reason: 'CSV export test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      });

      const csvExport = revocationManager.exportAuditTrail('csv');
      const lines = csvExport.split('\n');

      expect(lines.length).toBeGreaterThan(1); // Header + data
      expect(lines[0]).toContain('id,targetAgentDID,revokedBy'); // Header
      expect(lines[1]).toContain(agent.did); // Data
    });

    it('should purge old audit entries', async () => {
      const agent = await agentManager.createAgent(userDID, {
        name: 'Purge Test Agent',
        description: 'Agent for purge test'
      });

      await revocationManager.revokeAgent({
        targetAgentDID: agent.did,
        reason: 'Purge test',
        revokedBy: userDID,
        timestamp: new Date(),
        cascading: false
      });

      expect(revocationManager.getRevocationAudit()).toHaveLength(1);

      // Purge entries older than tomorrow (should purge nothing)
      const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000);
      const purgedCount = revocationManager.purgeOldAuditEntries(tomorrow);

      expect(purgedCount).toBe(0);
      expect(revocationManager.getRevocationAudit()).toHaveLength(1);

      // Purge entries older than yesterday (should purge the entry)
      const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const purgedCount2 = revocationManager.purgeOldAuditEntries(yesterday);

      expect(purgedCount2).toBe(1);
      expect(revocationManager.getRevocationAudit()).toHaveLength(0);
    });
  });
});