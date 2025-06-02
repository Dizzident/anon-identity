import { ActivityIndex } from './activity-index';
import { 
  AgentActivity, 
  ActivityType, 
  ActivityStatus, 
  ActivityQuery 
} from './types';

describe('ActivityIndex', () => {
  let index: ActivityIndex;
  let testActivities: AgentActivity[];

  beforeEach(() => {
    index = new ActivityIndex();
    
    // Create test activities
    testActivities = [
      {
        id: 'activity-1',
        agentDID: 'did:key:z6MkAgent1',
        parentDID: 'did:key:z6MkParent1',
        timestamp: new Date('2024-01-01T10:00:00Z'),
        type: ActivityType.AUTHENTICATION,
        serviceDID: 'did:key:z6MkService1',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data'],
        details: { message: 'Login successful' },
        sessionId: 'session-1'
      },
      {
        id: 'activity-2',
        agentDID: 'did:key:z6MkAgent1',
        parentDID: 'did:key:z6MkParent1',
        timestamp: new Date('2024-01-01T11:00:00Z'),
        type: ActivityType.DATA_ACCESS,
        serviceDID: 'did:key:z6MkService1',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data', 'list:resources'],
        details: { resourceId: 'resource-1' },
        sessionId: 'session-1'
      },
      {
        id: 'activity-3',
        agentDID: 'did:key:z6MkAgent2',
        parentDID: 'did:key:z6MkParent2',
        timestamp: new Date('2024-01-01T12:00:00Z'),
        type: ActivityType.DATA_MODIFICATION,
        serviceDID: 'did:key:z6MkService2',
        status: ActivityStatus.FAILED,
        scopes: ['write:data'],
        details: { errorMessage: 'Insufficient permissions' },
        sessionId: 'session-2'
      },
      {
        id: 'activity-4',
        agentDID: 'did:key:z6MkAgent1',
        parentDID: 'did:key:z6MkParent1',
        timestamp: new Date('2024-01-02T09:00:00Z'),
        type: ActivityType.SCOPE_USAGE,
        serviceDID: 'did:key:z6MkService1',
        status: ActivityStatus.SUCCESS,
        scopes: ['write:data'],
        details: { operation: 'update' },
        sessionId: 'session-3'
      }
    ];
  });

  describe('Indexing', () => {
    test('should index single activity', async () => {
      await index.indexActivity(testActivities[0]);
      
      const stats = index.getStats();
      expect(stats.totalActivities).toBe(1);
      expect(stats.agentCount).toBe(1);
      expect(stats.serviceCount).toBe(1);
    });

    test('should index multiple activities', async () => {
      await index.indexActivities(testActivities);
      
      const stats = index.getStats();
      expect(stats.totalActivities).toBe(4);
      expect(stats.agentCount).toBe(2);
      expect(stats.serviceCount).toBe(2);
    });

    test('should create proper secondary indexes', async () => {
      await index.indexActivities(testActivities);
      
      // Test agent-specific search
      const agent1Query: ActivityQuery = { agentDID: 'did:key:z6MkAgent1' };
      const agent1Result = await index.search(agent1Query);
      expect(agent1Result.total).toBe(3);
      
      // Test service-specific search
      const service1Query: ActivityQuery = { serviceDID: 'did:key:z6MkService1' };
      const service1Result = await index.search(service1Query);
      expect(service1Result.total).toBe(3);
    });
  });

  describe('Searching', () => {
    beforeEach(async () => {
      await index.indexActivities(testActivities);
    });

    test('should search by agent DID', async () => {
      const query: ActivityQuery = { agentDID: 'did:key:z6MkAgent1' };
      const result = await index.search(query);
      
      expect(result.total).toBe(3);
      expect(result.activities).toHaveLength(3);
      expect(result.activities.every(a => a.agentDID === 'did:key:z6MkAgent1')).toBe(true);
    });

    test('should search by parent DID', async () => {
      const query: ActivityQuery = { parentDID: 'did:key:z6MkParent2' };
      const result = await index.search(query);
      
      expect(result.total).toBe(1);
      expect(result.activities[0].id).toBe('activity-3');
    });

    test('should search by activity type', async () => {
      const query: ActivityQuery = { types: [ActivityType.DATA_ACCESS] };
      const result = await index.search(query);
      
      expect(result.total).toBe(1);
      expect(result.activities[0].type).toBe(ActivityType.DATA_ACCESS);
    });

    test('should search by multiple types', async () => {
      const query: ActivityQuery = { 
        types: [ActivityType.AUTHENTICATION, ActivityType.DATA_ACCESS] 
      };
      const result = await index.search(query);
      
      expect(result.total).toBe(2);
    });

    test('should search by status', async () => {
      const query: ActivityQuery = { status: [ActivityStatus.FAILED] };
      const result = await index.search(query);
      
      expect(result.total).toBe(1);
      expect(result.activities[0].status).toBe(ActivityStatus.FAILED);
    });

    test('should search by scopes', async () => {
      const query: ActivityQuery = { scopes: ['write:data'] };
      const result = await index.search(query);
      
      expect(result.total).toBe(2);
      expect(result.activities.every(a => a.scopes.includes('write:data'))).toBe(true);
    });

    test('should search by session ID', async () => {
      const query: ActivityQuery = { sessionId: 'session-1' };
      const result = await index.search(query);
      
      expect(result.total).toBe(2);
      expect(result.activities.every(a => a.sessionId === 'session-1')).toBe(true);
    });

    test('should search by date range', async () => {
      const query: ActivityQuery = {
        dateRange: {
          start: new Date('2024-01-01T10:30:00Z'),
          end: new Date('2024-01-01T23:59:59Z')
        }
      };
      const result = await index.search(query);
      
      expect(result.total).toBe(2); // activities 2 and 3
    });

    test('should combine multiple filters', async () => {
      const query: ActivityQuery = {
        agentDID: 'did:key:z6MkAgent1',
        types: [ActivityType.DATA_ACCESS, ActivityType.SCOPE_USAGE],
        status: [ActivityStatus.SUCCESS]
      };
      const result = await index.search(query);
      
      expect(result.total).toBe(2);
      expect(result.activities.every(a => 
        a.agentDID === 'did:key:z6MkAgent1' && 
        a.status === ActivityStatus.SUCCESS &&
        [ActivityType.DATA_ACCESS, ActivityType.SCOPE_USAGE].includes(a.type)
      )).toBe(true);
    });
  });

  describe('Sorting', () => {
    beforeEach(async () => {
      await index.indexActivities(testActivities);
    });

    test('should sort by timestamp descending (default)', async () => {
      const query: ActivityQuery = {};
      const result = await index.search(query);
      
      const timestamps = result.activities.map(a => a.timestamp.getTime());
      const sorted = [...timestamps].sort((a, b) => b - a);
      expect(timestamps).toEqual(sorted);
    });

    test('should sort by timestamp ascending', async () => {
      const query: ActivityQuery = { 
        sortBy: 'timestamp', 
        sortOrder: 'asc' 
      };
      const result = await index.search(query);
      
      const timestamps = result.activities.map(a => a.timestamp.getTime());
      const sorted = [...timestamps].sort((a, b) => a - b);
      expect(timestamps).toEqual(sorted);
    });

    test('should sort by type', async () => {
      const query: ActivityQuery = { 
        sortBy: 'type', 
        sortOrder: 'asc' 
      };
      const result = await index.search(query);
      
      const types = result.activities.map(a => a.type);
      const sorted = [...types].sort();
      expect(types).toEqual(sorted);
    });
  });

  describe('Pagination', () => {
    beforeEach(async () => {
      await index.indexActivities(testActivities);
    });

    test('should paginate results', async () => {
      const query: ActivityQuery = { 
        limit: 2, 
        offset: 0,
        sortBy: 'timestamp',
        sortOrder: 'asc'
      };
      const result = await index.search(query);
      
      expect(result.activities).toHaveLength(2);
      expect(result.total).toBe(4);
      expect(result.offset).toBe(0);
      expect(result.limit).toBe(2);
      expect(result.hasMore).toBe(true);
    });

    test('should handle second page', async () => {
      const query: ActivityQuery = { 
        limit: 2, 
        offset: 2,
        sortBy: 'timestamp',
        sortOrder: 'asc'
      };
      const result = await index.search(query);
      
      expect(result.activities).toHaveLength(2);
      expect(result.offset).toBe(2);
      expect(result.hasMore).toBe(false);
    });
  });

  describe('Activity Summary', () => {
    beforeEach(async () => {
      await index.indexActivities(testActivities);
    });

    test('should generate daily summary', async () => {
      const summary = await index.getActivitySummary(
        'did:key:z6MkAgent1',
        'day',
        new Date('2024-01-01T00:00:00Z')
      );
      
      expect(summary.agentDID).toBe('did:key:z6MkAgent1');
      expect(summary.totalActivities).toBe(2); // 2 activities on Jan 1st
      expect(summary.byType[ActivityType.AUTHENTICATION]).toBe(1);
      expect(summary.byType[ActivityType.DATA_ACCESS]).toBe(1);
      expect(summary.errorRate).toBe(0);
    });

    test('should generate monthly summary', async () => {
      const summary = await index.getActivitySummary(
        'did:key:z6MkAgent1',
        'month',
        new Date('2024-01-01T00:00:00Z')
      );
      
      expect(summary.totalActivities).toBe(3); // All 3 activities for agent1
      expect(summary.byStatus[ActivityStatus.SUCCESS]).toBe(3);
    });

    test('should calculate error rate correctly', async () => {
      const summary = await index.getActivitySummary(
        'did:key:z6MkAgent2',
        'day',
        new Date('2024-01-01T00:00:00Z')
      );
      
      expect(summary.totalActivities).toBe(1);
      expect(summary.errorRate).toBe(1.0); // 100% error rate
    });
  });

  describe('Removal', () => {
    beforeEach(async () => {
      await index.indexActivities(testActivities);
    });

    test('should remove activity from index', async () => {
      const removed = await index.removeActivity('activity-1');
      expect(removed).toBe(true);
      
      const stats = index.getStats();
      expect(stats.totalActivities).toBe(3);
      
      // Should not find the removed activity
      const query: ActivityQuery = { agentDID: 'did:key:z6MkAgent1' };
      const result = await index.search(query);
      expect(result.total).toBe(2); // One less activity
    });

    test('should return false for non-existent activity', async () => {
      const removed = await index.removeActivity('non-existent');
      expect(removed).toBe(false);
    });

    test('should clear all data', () => {
      index.clear();
      
      const stats = index.getStats();
      expect(stats.totalActivities).toBe(0);
      expect(stats.agentCount).toBe(0);
      expect(stats.serviceCount).toBe(0);
    });
  });

  describe('Statistics', () => {
    beforeEach(async () => {
      await index.indexActivities(testActivities);
    });

    test('should provide accurate statistics', () => {
      const stats = index.getStats();
      
      expect(stats.totalActivities).toBe(4);
      expect(stats.agentCount).toBe(2);
      expect(stats.serviceCount).toBe(2);
      expect(stats.byType[ActivityType.AUTHENTICATION]).toBe(1);
      expect(stats.byType[ActivityType.DATA_ACCESS]).toBe(1);
      expect(stats.byType[ActivityType.DATA_MODIFICATION]).toBe(1);
      expect(stats.byType[ActivityType.SCOPE_USAGE]).toBe(1);
      expect(stats.byStatus[ActivityStatus.SUCCESS]).toBe(3);
      expect(stats.byStatus[ActivityStatus.FAILED]).toBe(1);
    });

    test('should handle empty index', () => {
      const emptyIndex = new ActivityIndex();
      const stats = emptyIndex.getStats();
      
      expect(stats.totalActivities).toBe(0);
      expect(stats.agentCount).toBe(0);
      expect(stats.serviceCount).toBe(0);
    });
  });
});