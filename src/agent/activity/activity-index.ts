import { 
  AgentActivity, 
  ActivityQuery, 
  ActivitySearchResult, 
  ActivitySummary,
  ActivityType,
  ActivityStatus
} from './types';

export interface IndexEntry {
  id: string;
  agentDID: string;
  parentDID: string;
  timestamp: Date;
  type: ActivityType;
  serviceDID: string;
  status: ActivityStatus;
  scopes: string[];
  sessionId?: string;
  ipfsHash?: string;
  // Additional indexed fields for fast queries
  year: number;
  month: number;
  day: number;
  hour: number;
}

export interface IndexStats {
  totalActivities: number;
  agentCount: number;
  serviceCount: number;
  dateRange: {
    earliest: Date;
    latest: Date;
  };
  byType: Record<ActivityType, number>;
  byStatus: Record<ActivityStatus, number>;
}

export class ActivityIndex {
  private index: Map<string, IndexEntry> = new Map();
  private agentIndex: Map<string, Set<string>> = new Map(); // agentDID -> activity IDs
  private serviceIndex: Map<string, Set<string>> = new Map(); // serviceDID -> activity IDs
  private typeIndex: Map<ActivityType, Set<string>> = new Map(); // type -> activity IDs
  private statusIndex: Map<ActivityStatus, Set<string>> = new Map(); // status -> activity IDs
  private dateIndex: Map<string, Set<string>> = new Map(); // YYYY-MM-DD -> activity IDs
  private scopeIndex: Map<string, Set<string>> = new Map(); // scope -> activity IDs

  /**
   * Index a single activity for fast searching
   */
  async indexActivity(activity: AgentActivity): Promise<void> {
    const entry: IndexEntry = {
      id: activity.id,
      agentDID: activity.agentDID,
      parentDID: activity.parentDID,
      timestamp: activity.timestamp,
      type: activity.type,
      serviceDID: activity.serviceDID,
      status: activity.status,
      scopes: activity.scopes,
      sessionId: activity.sessionId,
      ipfsHash: activity.ipfsHash,
      year: activity.timestamp.getFullYear(),
      month: activity.timestamp.getMonth() + 1,
      day: activity.timestamp.getDate(),
      hour: activity.timestamp.getHours()
    };

    // Store in main index
    this.index.set(activity.id, entry);

    // Update secondary indexes
    this.addToIndex(this.agentIndex, activity.agentDID, activity.id);
    this.addToIndex(this.serviceIndex, activity.serviceDID, activity.id);
    this.addToIndex(this.typeIndex, activity.type, activity.id);
    this.addToIndex(this.statusIndex, activity.status, activity.id);

    // Date index (YYYY-MM-DD format)
    const dateKey = `${entry.year}-${entry.month.toString().padStart(2, '0')}-${entry.day.toString().padStart(2, '0')}`;
    this.addToIndex(this.dateIndex, dateKey, activity.id);

    // Scope index
    activity.scopes.forEach(scope => {
      this.addToIndex(this.scopeIndex, scope, activity.id);
    });
  }

  /**
   * Index multiple activities in batch
   */
  async indexActivities(activities: AgentActivity[]): Promise<void> {
    for (const activity of activities) {
      await this.indexActivity(activity);
    }
  }

  /**
   * Search activities based on query parameters
   */
  async search(query: ActivityQuery): Promise<ActivitySearchResult> {
    let candidateIds: Set<string> = new Set();
    let isFirstFilter = true;

    // Apply filters to get candidate activity IDs
    if (query.agentDID) {
      const agentIds = this.agentIndex.get(query.agentDID) || new Set();
      candidateIds = this.intersectSets(candidateIds, agentIds, isFirstFilter);
      isFirstFilter = false;
    }

    if (query.parentDID) {
      const parentIds = new Set<string>();
      for (const [id, entry] of this.index.entries()) {
        if (entry.parentDID === query.parentDID) {
          parentIds.add(id);
        }
      }
      candidateIds = this.intersectSets(candidateIds, parentIds, isFirstFilter);
      isFirstFilter = false;
    }

    if (query.serviceDID) {
      const serviceIds = this.serviceIndex.get(query.serviceDID) || new Set();
      candidateIds = this.intersectSets(candidateIds, serviceIds, isFirstFilter);
      isFirstFilter = false;
    }

    if (query.types && query.types.length > 0) {
      const typeIds = new Set<string>();
      query.types.forEach(type => {
        const ids = this.typeIndex.get(type) || new Set();
        ids.forEach(id => typeIds.add(id));
      });
      candidateIds = this.intersectSets(candidateIds, typeIds, isFirstFilter);
      isFirstFilter = false;
    }

    if (query.status && query.status.length > 0) {
      const statusIds = new Set<string>();
      query.status.forEach(status => {
        const ids = this.statusIndex.get(status) || new Set();
        ids.forEach(id => statusIds.add(id));
      });
      candidateIds = this.intersectSets(candidateIds, statusIds, isFirstFilter);
      isFirstFilter = false;
    }

    if (query.scopes && query.scopes.length > 0) {
      const scopeIds = new Set<string>();
      query.scopes.forEach(scope => {
        const ids = this.scopeIndex.get(scope) || new Set();
        ids.forEach(id => scopeIds.add(id));
      });
      candidateIds = this.intersectSets(candidateIds, scopeIds, isFirstFilter);
      isFirstFilter = false;
    }

    if (query.sessionId) {
      const sessionIds = new Set<string>();
      for (const [id, entry] of this.index.entries()) {
        if (entry.sessionId === query.sessionId) {
          sessionIds.add(id);
        }
      }
      candidateIds = this.intersectSets(candidateIds, sessionIds, isFirstFilter);
      isFirstFilter = false;
    }

    // If no filters applied, get all activities
    if (isFirstFilter) {
      candidateIds = new Set(this.index.keys());
    }

    // Apply date range filter
    if (query.dateRange) {
      candidateIds = this.filterByDateRange(candidateIds, query.dateRange.start, query.dateRange.end);
    }

    // Convert to activities and sort
    const activities = this.getActivitiesFromIds(candidateIds);
    const sortedActivities = this.sortActivities(activities, query.sortBy, query.sortOrder);

    // Apply pagination
    const offset = query.offset || 0;
    const limit = query.limit || 100;
    const total = sortedActivities.length;
    const paginatedActivities = sortedActivities.slice(offset, offset + limit);

    return {
      activities: paginatedActivities,
      total,
      offset,
      limit,
      hasMore: offset + limit < total
    };
  }

  /**
   * Get activity summary for an agent
   */
  async getActivitySummary(
    agentDID: string, 
    period: 'hour' | 'day' | 'week' | 'month' | 'year',
    startDate?: Date
  ): Promise<ActivitySummary> {
    const agentIds = this.agentIndex.get(agentDID) || new Set();
    const activities = this.getActivitiesFromIds(agentIds);

    if (activities.length === 0) {
      throw new Error(`No activities found for agent: ${agentDID}`);
    }

    // Determine period boundaries
    const now = new Date();
    const periodStart = startDate || this.getPeriodStart(now, period);
    const periodEnd = this.getPeriodEnd(periodStart, period);

    // Filter activities by period
    const periodActivities = activities.filter(
      activity => activity.timestamp >= periodStart && activity.timestamp <= periodEnd
    );

    // Calculate statistics
    const byType: Record<ActivityType, number> = {} as Record<ActivityType, number>;
    const byStatus: Record<ActivityStatus, number> = {} as Record<ActivityStatus, number>;
    const byService: Record<string, number> = {};
    const scopeUsage: Record<string, number> = {};
    
    let totalDuration = 0;
    let durationsCount = 0;
    let errorCount = 0;

    periodActivities.forEach(activity => {
      // Count by type
      byType[activity.type] = (byType[activity.type] || 0) + 1;
      
      // Count by status
      byStatus[activity.status] = (byStatus[activity.status] || 0) + 1;
      
      // Count by service
      const serviceEntry = this.index.get(activity.id);
      if (serviceEntry) {
        byService[serviceEntry.serviceDID] = (byService[serviceEntry.serviceDID] || 0) + 1;
      }
      
      // Count scope usage
      activity.scopes.forEach(scope => {
        scopeUsage[scope] = (scopeUsage[scope] || 0) + 1;
      });
      
      // Calculate duration stats
      if (activity.duration) {
        totalDuration += activity.duration;
        durationsCount++;
      }
      
      // Count errors
      if (activity.status === ActivityStatus.FAILED || activity.status === ActivityStatus.DENIED) {
        errorCount++;
      }
    });

    // Find peak hour
    const hourCounts: Record<number, number> = {};
    periodActivities.forEach(activity => {
      const hour = activity.timestamp.getHours();
      hourCounts[hour] = (hourCounts[hour] || 0) + 1;
    });
    const peakHour = Object.entries(hourCounts)
      .sort(([,a], [,b]) => b - a)[0]?.[0];

    // Find most used service and scope
    const mostUsedService = Object.entries(byService)
      .sort(([,a], [,b]) => b - a)[0]?.[0];
    const mostUsedScope = Object.entries(scopeUsage)
      .sort(([,a], [,b]) => b - a)[0]?.[0];

    const parentDID = activities[0]?.parentDID || '';

    return {
      agentDID,
      parentDID,
      period: {
        start: periodStart,
        end: periodEnd,
        type: period
      },
      totalActivities: periodActivities.length,
      byType,
      byStatus,
      byService,
      scopeUsage,
      averageDuration: durationsCount > 0 ? totalDuration / durationsCount : 0,
      errorRate: periodActivities.length > 0 ? errorCount / periodActivities.length : 0,
      peakHour: peakHour ? `${peakHour}:00` : undefined,
      mostUsedService,
      mostUsedScope
    };
  }

  /**
   * Get activities by multiple agent DIDs
   */
  async getActivitiesByAgents(agentDIDs: string[]): Promise<AgentActivity[]> {
    const allIds = new Set<string>();
    
    agentDIDs.forEach(agentDID => {
      const agentIds = this.agentIndex.get(agentDID) || new Set();
      agentIds.forEach(id => allIds.add(id));
    });

    return this.getActivitiesFromIds(allIds);
  }

  /**
   * Get activities by date range
   */
  async getActivitiesByDateRange(start: Date, end: Date): Promise<AgentActivity[]> {
    const allIds = new Set(this.index.keys());
    const filteredIds = this.filterByDateRange(allIds, start, end);
    return this.getActivitiesFromIds(filteredIds);
  }

  /**
   * Get index statistics
   */
  getStats(): IndexStats {
    const activities = Array.from(this.index.values());
    
    if (activities.length === 0) {
      return {
        totalActivities: 0,
        agentCount: 0,
        serviceCount: 0,
        dateRange: {
          earliest: new Date(),
          latest: new Date()
        },
        byType: {} as Record<ActivityType, number>,
        byStatus: {} as Record<ActivityStatus, number>
      };
    }

    const agents = new Set(activities.map(a => a.agentDID));
    const services = new Set(activities.map(a => a.serviceDID));
    const timestamps = activities.map(a => a.timestamp);
    const earliest = new Date(Math.min(...timestamps.map(t => t.getTime())));
    const latest = new Date(Math.max(...timestamps.map(t => t.getTime())));

    const byType: Record<ActivityType, number> = {} as Record<ActivityType, number>;
    const byStatus: Record<ActivityStatus, number> = {} as Record<ActivityStatus, number>;

    activities.forEach(activity => {
      byType[activity.type] = (byType[activity.type] || 0) + 1;
      byStatus[activity.status] = (byStatus[activity.status] || 0) + 1;
    });

    return {
      totalActivities: activities.length,
      agentCount: agents.size,
      serviceCount: services.size,
      dateRange: { earliest, latest },
      byType,
      byStatus
    };
  }

  /**
   * Remove activity from index
   */
  async removeActivity(activityId: string): Promise<boolean> {
    const entry = this.index.get(activityId);
    if (!entry) {
      return false;
    }

    // Remove from main index
    this.index.delete(activityId);

    // Remove from secondary indexes
    this.removeFromIndex(this.agentIndex, entry.agentDID, activityId);
    this.removeFromIndex(this.serviceIndex, entry.serviceDID, activityId);
    this.removeFromIndex(this.typeIndex, entry.type, activityId);
    this.removeFromIndex(this.statusIndex, entry.status, activityId);

    // Remove from date index
    const dateKey = `${entry.year}-${entry.month.toString().padStart(2, '0')}-${entry.day.toString().padStart(2, '0')}`;
    this.removeFromIndex(this.dateIndex, dateKey, activityId);

    // Remove from scope indexes
    entry.scopes.forEach(scope => {
      this.removeFromIndex(this.scopeIndex, scope, activityId);
    });

    return true;
  }

  /**
   * Clear all indexed data
   */
  clear(): void {
    this.index.clear();
    this.agentIndex.clear();
    this.serviceIndex.clear();
    this.typeIndex.clear();
    this.statusIndex.clear();
    this.dateIndex.clear();
    this.scopeIndex.clear();
  }

  // Helper methods

  private addToIndex(index: Map<string, Set<string>>, key: string, activityId: string): void {
    if (!index.has(key)) {
      index.set(key, new Set());
    }
    index.get(key)!.add(activityId);
  }

  private removeFromIndex(index: Map<string, Set<string>>, key: string, activityId: string): void {
    const set = index.get(key);
    if (set) {
      set.delete(activityId);
      if (set.size === 0) {
        index.delete(key);
      }
    }
  }

  private intersectSets(set1: Set<string>, set2: Set<string>, isFirst: boolean): Set<string> {
    if (isFirst) {
      return new Set(set2);
    }
    
    const result = new Set<string>();
    for (const item of set1) {
      if (set2.has(item)) {
        result.add(item);
      }
    }
    return result;
  }

  private filterByDateRange(ids: Set<string>, start: Date, end: Date): Set<string> {
    const result = new Set<string>();
    
    for (const id of ids) {
      const entry = this.index.get(id);
      if (entry && entry.timestamp >= start && entry.timestamp <= end) {
        result.add(id);
      }
    }
    
    return result;
  }

  private getActivitiesFromIds(ids: Set<string>): AgentActivity[] {
    const activities: AgentActivity[] = [];
    
    for (const id of ids) {
      const entry = this.index.get(id);
      if (entry) {
        // Convert IndexEntry back to AgentActivity
        const activity: AgentActivity = {
          id: entry.id,
          agentDID: entry.agentDID,
          parentDID: entry.parentDID,
          timestamp: entry.timestamp,
          type: entry.type,
          serviceDID: entry.serviceDID,
          status: entry.status,
          scopes: entry.scopes,
          details: {}, // Details not stored in index
          sessionId: entry.sessionId,
          ipfsHash: entry.ipfsHash
        };
        activities.push(activity);
      }
    }
    
    return activities;
  }

  private sortActivities(
    activities: AgentActivity[], 
    sortBy?: 'timestamp' | 'type' | 'service',
    sortOrder?: 'asc' | 'desc'
  ): AgentActivity[] {
    const order = sortOrder || 'desc';
    const field = sortBy || 'timestamp';

    return activities.sort((a, b) => {
      let comparison = 0;
      
      switch (field) {
        case 'timestamp':
          comparison = a.timestamp.getTime() - b.timestamp.getTime();
          break;
        case 'type':
          comparison = a.type.localeCompare(b.type);
          break;
        case 'service':
          comparison = a.serviceDID.localeCompare(b.serviceDID);
          break;
      }
      
      return order === 'asc' ? comparison : -comparison;
    });
  }

  private getPeriodStart(date: Date, period: 'hour' | 'day' | 'week' | 'month' | 'year'): Date {
    const start = new Date(date);
    
    switch (period) {
      case 'hour':
        start.setMinutes(0, 0, 0);
        break;
      case 'day':
        start.setHours(0, 0, 0, 0);
        break;
      case 'week':
        start.setHours(0, 0, 0, 0);
        start.setDate(start.getDate() - start.getDay());
        break;
      case 'month':
        start.setDate(1);
        start.setHours(0, 0, 0, 0);
        break;
      case 'year':
        start.setMonth(0, 1);
        start.setHours(0, 0, 0, 0);
        break;
    }
    
    return start;
  }

  private getPeriodEnd(startDate: Date, period: 'hour' | 'day' | 'week' | 'month' | 'year'): Date {
    const end = new Date(startDate);
    
    switch (period) {
      case 'hour':
        end.setHours(end.getHours() + 1);
        break;
      case 'day':
        end.setDate(end.getDate() + 1);
        break;
      case 'week':
        end.setDate(end.getDate() + 7);
        break;
      case 'month':
        end.setMonth(end.getMonth() + 1);
        break;
      case 'year':
        end.setFullYear(end.getFullYear() + 1);
        break;
    }
    
    return end;
  }
}