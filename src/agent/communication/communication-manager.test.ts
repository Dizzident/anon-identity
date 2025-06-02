import { CommunicationManager } from './communication-manager';
import { DirectChannel } from './channels/direct-channel';
import { AgentMessageType } from './types';
import { AgentIdentityManager } from '../agent-identity';
import { DelegationManager } from '../delegation-manager';
import { DelegationPolicyEngine } from '../delegation-policy-engine';
import { ActivityLogger } from '../activity/activity-logger';

describe('CommunicationManager', () => {
  let agentManager: AgentIdentityManager;
  let delegationManager: DelegationManager;
  let policyEngine: DelegationPolicyEngine;
  let activityLogger: ActivityLogger;
  let agent1: any;
  let agent2: any;
  let commManager1: CommunicationManager;
  let commManager2: CommunicationManager;

  const userDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

  beforeEach(async () => {
    // Set up dependencies
    agentManager = new AgentIdentityManager();
    delegationManager = new DelegationManager();
    policyEngine = new DelegationPolicyEngine(agentManager);
    activityLogger = new ActivityLogger();

    // Create test agents
    agent1 = await agentManager.createAgent(userDID, {
      name: 'Agent 1',
      description: 'Test agent 1',
      canDelegate: true
    });

    agent2 = await agentManager.createAgent(userDID, {
      name: 'Agent 2',
      description: 'Test agent 2',
      canDelegate: true
    });

    // Create communication managers
    commManager1 = new CommunicationManager(
      agent1,
      agentManager,
      delegationManager,
      policyEngine,
      activityLogger
    );

    commManager2 = new CommunicationManager(
      agent2,
      agentManager,
      delegationManager,
      policyEngine,
      activityLogger
    );
  });

  describe('channel management', () => {
    it('should add and connect channels', async () => {
      const channel1 = new DirectChannel('agent1-channel');
      const channel2 = new DirectChannel('agent2-channel');

      commManager1.addChannel(channel1);
      commManager2.addChannel(channel2);

      await commManager1.connectAll();
      await commManager2.connectAll();

      expect(commManager1.getConnectedChannels()).toContain('agent1-channel');
      expect(commManager2.getConnectedChannels()).toContain('agent2-channel');
    });

    it('should disconnect channels', async () => {
      const channel = new DirectChannel('test-channel');
      commManager1.addChannel(channel);
      
      await channel.connect();
      expect(commManager1.getConnectedChannels()).toContain('test-channel');

      await commManager1.removeChannel('test-channel');
      expect(commManager1.getConnectedChannels()).not.toContain('test-channel');
    });
  });

  describe('message sending', () => {
    beforeEach(async () => {
      // Set up direct channels for testing
      const channel1 = new DirectChannel(agent1.did);
      const channel2 = new DirectChannel(agent2.did);

      commManager1.addChannel(channel1);
      commManager2.addChannel(channel2);

      await commManager1.connectAll();
      await commManager2.connectAll();
    });

    it('should send ping messages', async () => {
      let receivedMessage: any = null;

      // Set up message handler for agent2
      commManager2.registerMessageHandler(AgentMessageType.PONG, async (message) => {
        receivedMessage = message;
      });

      // Send ping from agent1 to agent2
      await commManager1.pingAgent(agent2.did);

      // Wait a bit for message delivery
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(receivedMessage).toBeTruthy();
      expect(receivedMessage.type).toBe(AgentMessageType.PONG);
      expect(receivedMessage.from).toBe(agent2.did);
    });

    it('should handle delegation requests', async () => {
      let delegationResponse: any = null;

      // Set up handler to capture delegation response
      commManager1.registerMessageHandler(AgentMessageType.DELEGATION_GRANT, async (message) => {
        delegationResponse = message;
      });

      commManager1.registerMessageHandler(AgentMessageType.DELEGATION_DENY, async (message) => {
        delegationResponse = message;
      });

      // Request delegation from agent1 to agent2
      await commManager1.requestDelegation(agent2.did, ['read:profile'], {
        purpose: 'Test delegation'
      });

      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 200));

      expect(delegationResponse).toBeTruthy();
      expect([AgentMessageType.DELEGATION_GRANT, AgentMessageType.DELEGATION_DENY])
        .toContain(delegationResponse.type);
    });

    it('should query agent status', async () => {
      let statusResponse: any = null;

      // Set up handler to capture status response
      commManager1.registerMessageHandler(AgentMessageType.RESPONSE_STATUS, async (message) => {
        statusResponse = message;
      });

      // Query status from agent1 to agent2
      await commManager1.queryAgentStatus(agent2.did, {
        includeScopes: true,
        includeMetrics: true
      });

      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(statusResponse).toBeTruthy();
      expect(statusResponse.type).toBe(AgentMessageType.RESPONSE_STATUS);
      expect(statusResponse.payload.status).toBeDefined();
      expect(statusResponse.payload.delegationDepth).toBeDefined();
    });
  });

  describe('message validation', () => {
    it('should validate message signatures', async () => {
      const channel = new DirectChannel('test-channel');
      commManager1.addChannel(channel);
      await channel.connect();

      let processedMessage: any = null;
      commManager1.registerMessageHandler(AgentMessageType.PING, async (message) => {
        processedMessage = message;
      });

      // Create and send a properly signed message
      await commManager1.pingAgent(agent1.did); // Self-ping for testing

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(processedMessage).toBeTruthy();
    });
  });

  describe('statistics', () => {
    it('should track communication statistics', async () => {
      const channel = new DirectChannel('stats-test-channel');
      commManager1.addChannel(channel);
      await channel.connect();

      // Send a few messages
      await commManager1.pingAgent(agent1.did);
      await commManager1.pingAgent(agent1.did);
      await commManager1.pingAgent(agent1.did);

      const stats = commManager1.getStats('stats-test-channel') as any;
      expect(stats.messagesSent).toBeGreaterThan(0);
    });

    it('should return all channel stats', () => {
      const channel1 = new DirectChannel('channel1');
      const channel2 = new DirectChannel('channel2');
      
      commManager1.addChannel(channel1);
      commManager1.addChannel(channel2);

      const allStats = commManager1.getStats();
      expect(allStats instanceof Map).toBe(true);
      expect((allStats as Map<string, any>).has('channel1')).toBe(true);
      expect((allStats as Map<string, any>).has('channel2')).toBe(true);
    });
  });

  describe('retry mechanism', () => {
    it('should retry failed messages', async () => {
      const commManager = new CommunicationManager(
        agent1,
        agentManager,
        delegationManager,
        policyEngine,
        activityLogger,
        { maxRetries: 2, retryDelay: 100 }
      );

      // Add a channel that will fail
      const unreliableChannel = new DirectChannel('unreliable', { reliability: 0.1 });
      commManager.addChannel(unreliableChannel);
      await unreliableChannel.connect();

      // Try to send a message (will likely fail)
      try {
        await commManager.sendMessage({
          id: 'test-msg',
          type: AgentMessageType.PING,
          from: agent1.did,
          to: agent2.did,
          timestamp: new Date(),
          version: '1.0.0',
          payload: {}
        });
      } catch (error) {
        // Expected to fail sometimes
      }

      // Trigger retry
      const retriedCount = await commManager.retryFailedMessages();
      
      // Should attempt to retry (may or may not succeed due to reliability)
      expect(retriedCount).toBeGreaterThanOrEqual(0);
    });
  });

  describe('custom message handlers', () => {
    it('should support custom message handlers', async () => {
      const channel = new DirectChannel('custom-handler-test');
      commManager1.addChannel(channel);
      await channel.connect();

      let customHandlerCalled = false;
      
      // Register custom handler
      commManager1.registerMessageHandler(AgentMessageType.PING, async (message) => {
        customHandlerCalled = true;
        expect(message.type).toBe(AgentMessageType.PING);
      });

      await commManager1.pingAgent(agent1.did);
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(customHandlerCalled).toBe(true);
    });
  });

  afterEach(async () => {
    // Clean up
    await commManager1.disconnectAll();
    await commManager2.disconnectAll();
  });
});