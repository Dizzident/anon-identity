import { ActivityLogger, createActivity } from './activity-logger';
import { 
  ActivityType, 
  ActivityStatus, 
  AgentActivity,
  ActivityLoggerConfig 
} from './types';

describe('ActivityLogger', () => {
  let logger: ActivityLogger;

  beforeEach(() => {
    logger = new ActivityLogger({
      batchSize: 5,
      batchInterval: 1000,
      enableBatching: true,
      enableRealtime: true
    });
  });

  afterEach(async () => {
    await logger.cleanup();
  });

  describe('logActivity', () => {
    it('should log a single activity with generated ID and timestamp', async () => {
      const activity = await logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.AUTHENTICATION,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:profile'],
        details: { message: 'Test activity' }
      });

      expect(activity.id).toBeDefined();
      expect(activity.timestamp).toBeInstanceOf(Date);
      expect(activity.agentDID).toBe('did:key:agent123');
      expect(activity.type).toBe(ActivityType.AUTHENTICATION);
    });

    it('should use provided ID and timestamp if given', async () => {
      const customId = 'custom-id-123';
      const customTime = new Date('2024-01-01');

      const activity = await logger.logActivity({
        id: customId,
        timestamp: customTime,
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.AUTHORIZATION,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {}
      });

      expect(activity.id).toBe(customId);
      expect(activity.timestamp).toEqual(customTime);
    });
  });

  describe('batching', () => {
    it('should batch activities when enabled', async () => {
      const activities: AgentActivity[] = [];
      
      for (let i = 0; i < 4; i++) {
        const activity = await logger.logActivity({
          agentDID: 'did:key:agent123',
          parentDID: 'did:key:parent123',
          type: ActivityType.SCOPE_USAGE,
          serviceDID: 'did:key:service123',
          status: ActivityStatus.SUCCESS,
          scopes: ['read:data'],
          details: { metadata: { index: i } }
        });
        activities.push(activity);
      }

      // Buffer should have 4 activities
      expect(logger.getBufferSize()).toBe(4);

      // Add one more to trigger batch processing
      await logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.SCOPE_USAGE,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data'],
        details: { metadata: { index: 4 } }
      });

      // Buffer should be empty after batch processing
      expect(logger.getBufferSize()).toBe(0);
    });

    it('should process batch on flush', async () => {
      await logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.DATA_ACCESS,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data'],
        details: {}
      });

      expect(logger.getBufferSize()).toBe(1);

      await logger.flush();

      expect(logger.getBufferSize()).toBe(0);
    });

    it('should process batch after interval', async () => {
      await logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.DATA_MODIFICATION,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: ['write:data'],
        details: {}
      });

      expect(logger.getBufferSize()).toBe(1);

      // Wait for batch interval
      await new Promise(resolve => setTimeout(resolve, 1100));

      expect(logger.getBufferSize()).toBe(0);
    });
  });

  describe('subscriptions', () => {
    it('should notify subscribers of matching activities', async () => {
      const receivedActivities: AgentActivity[] = [];

      const subscription = logger.subscribe(
        { agentDID: 'did:key:agent123' },
        (activity) => {
          receivedActivities.push(activity);
        }
      );

      await logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.SESSION_START,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {}
      });

      expect(receivedActivities).toHaveLength(1);
      expect(receivedActivities[0].type).toBe(ActivityType.SESSION_START);

      subscription.unsubscribe();
    });

    it('should filter by agent DID', async () => {
      const receivedActivities: AgentActivity[] = [];

      logger.subscribe(
        { agentDID: 'did:key:agent123' },
        (activity) => {
          receivedActivities.push(activity);
        }
      );

      await logger.logActivity({
        agentDID: 'did:key:agent456',
        parentDID: 'did:key:parent123',
        type: ActivityType.SESSION_START,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {}
      });

      expect(receivedActivities).toHaveLength(0);
    });

    it('should filter by activity type', async () => {
      const receivedActivities: AgentActivity[] = [];

      logger.subscribe(
        { types: [ActivityType.ERROR, ActivityType.REVOCATION] },
        (activity) => {
          receivedActivities.push(activity);
        }
      );

      await logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.ERROR,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.FAILED,
        scopes: [],
        details: { errorMessage: 'Test error' }
      });

      await logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.AUTHENTICATION,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {}
      });

      expect(receivedActivities).toHaveLength(1);
      expect(receivedActivities[0].type).toBe(ActivityType.ERROR);
    });
  });

  describe('hooks', () => {
    it('should run before hooks', async () => {
      let hookCalled = false;

      logger.registerHook({
        type: ActivityType.AUTHENTICATION,
        beforeActivity: async (activity) => {
          hookCalled = true;
          expect(activity.type).toBe(ActivityType.AUTHENTICATION);
          return true;
        }
      });

      await logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.AUTHENTICATION,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {}
      });

      expect(hookCalled).toBe(true);
    });

    it('should reject activity if before hook returns false', async () => {
      logger.registerHook({
        type: ActivityType.DATA_MODIFICATION,
        beforeActivity: async () => false
      });

      await expect(logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.DATA_MODIFICATION,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: ['write:data'],
        details: {}
      })).rejects.toThrow('Activity rejected by hook');
    });

    it('should run after hooks', async () => {
      let afterHookCalled = false;

      logger.registerHook({
        type: ActivityType.SESSION_END,
        afterActivity: async (activity) => {
          afterHookCalled = true;
          expect(activity.id).toBeDefined();
        }
      });

      await logger.logActivity({
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        type: ActivityType.SESSION_END,
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {}
      });

      expect(afterHookCalled).toBe(true);
    });
  });

  describe('createActivity helper', () => {
    it('should create activity object with required fields', () => {
      const activity = createActivity(ActivityType.SCOPE_USAGE, {
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        serviceDID: 'did:key:service123',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:profile', 'read:data'],
        details: { resourceId: 'resource-123' }
      });

      expect(activity.type).toBe(ActivityType.SCOPE_USAGE);
      expect(activity.agentDID).toBe('did:key:agent123');
      expect(activity.scopes).toEqual(['read:profile', 'read:data']);
      expect(activity.details?.resourceId).toBe('resource-123');
    });

    it('should handle optional fields', () => {
      const activity = createActivity(ActivityType.ERROR, {
        agentDID: 'did:key:agent123',
        parentDID: 'did:key:parent123',
        serviceDID: 'did:key:service123',
        status: ActivityStatus.FAILED,
        sessionId: 'session-123'
      });

      expect(activity.scopes).toEqual([]);
      expect(activity.details).toEqual({});
      expect(activity.sessionId).toBe('session-123');
    });
  });

  describe('cleanup', () => {
    it('should cleanup resources', async () => {
      const subscription = logger.subscribe({}, () => {});
      
      expect(logger.getSubscriptionCount()).toBe(1);

      await logger.cleanup();

      expect(logger.getSubscriptionCount()).toBe(0);
      expect(logger.getBufferSize()).toBe(0);
    });
  });
});