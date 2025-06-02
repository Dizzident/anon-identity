import { ActivityIndex } from './activity-index';
import { IPFSActivityStorage } from './ipfs-activity-storage';
import { 
  AgentActivity, 
  ActivityQuery, 
  ActivitySearchResult, 
  ActivitySummary 
} from './types';

export interface SearchServiceConfig {
  enableIPFSFallback?: boolean;
  cacheResults?: boolean;
  maxCacheSize?: number;
  cacheTTL?: number; // milliseconds
}

export interface CachedResult {
  result: ActivitySearchResult;
  timestamp: Date;
  queryHash: string;
}

export class ActivitySearchService {
  private index: ActivityIndex;
  private ipfsStorage?: IPFSActivityStorage;
  private config: SearchServiceConfig;
  private resultCache: Map<string, CachedResult> = new Map();

  constructor(
    index: ActivityIndex,
    ipfsStorage?: IPFSActivityStorage,
    config: SearchServiceConfig = {}
  ) {
    this.index = index;
    this.ipfsStorage = ipfsStorage;
    this.config = {
      enableIPFSFallback: true,
      cacheResults: true,
      maxCacheSize: 1000,
      cacheTTL: 5 * 60 * 1000, // 5 minutes
      ...config
    };
  }

  /**
   * Search activities with advanced querying capabilities
   */
  async searchActivities(query: ActivityQuery): Promise<ActivitySearchResult> {
    // Check cache first
    if (this.config.cacheResults) {
      const cached = this.getCachedResult(query);
      if (cached) {
        return cached.result;
      }
    }

    try {
      // Primary search through index
      const indexResult = await this.index.search(query);
      
      // If we have IPFS storage and results seem incomplete, try IPFS fallback
      if (this.config.enableIPFSFallback && 
          this.ipfsStorage && 
          this.shouldTryIPFSFallback(query, indexResult)) {
        
        const enhancedResult = await this.enhanceWithIPFS(indexResult, query);
        
        // Cache the result
        if (this.config.cacheResults) {
          this.cacheResult(query, enhancedResult);
        }
        
        return enhancedResult;
      }

      // Cache the result
      if (this.config.cacheResults) {
        this.cacheResult(query, indexResult);
      }

      return indexResult;
      
    } catch (error) {
      console.error('Search failed:', error);
      throw new Error(`Activity search failed: ${error}`);
    }
  }

  /**
   * Get activity summary with aggregated statistics
   */
  async getActivitySummary(
    agentDID: string,
    period: 'hour' | 'day' | 'week' | 'month' | 'year',
    startDate?: Date
  ): Promise<ActivitySummary> {
    return this.index.getActivitySummary(agentDID, period, startDate);
  }

  /**
   * Get recent activities for an agent
   */
  async getRecentActivities(
    agentDID: string, 
    limit: number = 50
  ): Promise<AgentActivity[]> {
    const query: ActivityQuery = {
      agentDID,
      limit,
      sortBy: 'timestamp',
      sortOrder: 'desc'
    };

    const result = await this.searchActivities(query);
    return result.activities;
  }

  /**
   * Get activities by session ID
   */
  async getSessionActivities(sessionId: string): Promise<AgentActivity[]> {
    const query: ActivityQuery = {
      sessionId,
      sortBy: 'timestamp',
      sortOrder: 'asc'
    };

    const result = await this.searchActivities(query);
    return result.activities;
  }

  /**
   * Search activities by text content (searches in activity details)
   */
  async searchByText(
    searchText: string,
    agentDID?: string,
    limit: number = 100
  ): Promise<AgentActivity[]> {
    // This is a basic implementation - in production you might want to use
    // a full-text search engine like Elasticsearch
    
    const query: ActivityQuery = {
      agentDID,
      limit: 1000, // Get more results to filter
      sortBy: 'timestamp',
      sortOrder: 'desc'
    };

    const result = await this.searchActivities(query);
    
    // Filter by text content
    const filtered = result.activities.filter(activity => {
      const searchableText = JSON.stringify(activity.details).toLowerCase();
      return searchableText.includes(searchText.toLowerCase());
    });

    return filtered.slice(0, limit);
  }

  /**
   * Get activity trends over time
   */
  async getActivityTrends(
    agentDID: string,
    days: number = 30
  ): Promise<{
    date: string;
    count: number;
    byType: Record<string, number>;
    errorRate: number;
  }[]> {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const query: ActivityQuery = {
      agentDID,
      dateRange: { start: startDate, end: endDate },
      sortBy: 'timestamp',
      sortOrder: 'asc',
      limit: 10000 // Get all activities in range
    };

    const result = await this.searchActivities(query);
    
    // Group by day
    const trends = new Map<string, {
      count: number;
      byType: Record<string, number>;
      errors: number;
    }>();

    result.activities.forEach(activity => {
      const dateKey = activity.timestamp.toISOString().split('T')[0];
      
      if (!trends.has(dateKey)) {
        trends.set(dateKey, {
          count: 0,
          byType: {},
          errors: 0
        });
      }

      const trend = trends.get(dateKey)!;
      trend.count++;
      trend.byType[activity.type] = (trend.byType[activity.type] || 0) + 1;
      
      if (activity.status === 'failed' || activity.status === 'denied') {
        trend.errors++;
      }
    });

    // Convert to array with error rates
    return Array.from(trends.entries()).map(([date, data]) => ({
      date,
      count: data.count,
      byType: data.byType,
      errorRate: data.count > 0 ? data.errors / data.count : 0
    }));
  }

  /**
   * Get comparative statistics between agents
   */
  async compareAgents(
    agentDIDs: string[],
    period: 'day' | 'week' | 'month' = 'week'
  ): Promise<Record<string, ActivitySummary>> {
    const summaries: Record<string, ActivitySummary> = {};
    
    for (const agentDID of agentDIDs) {
      try {
        summaries[agentDID] = await this.getActivitySummary(agentDID, period);
      } catch (error) {
        console.warn(`Failed to get summary for agent ${agentDID}:`, error);
      }
    }
    
    return summaries;
  }

  /**
   * Clear the search cache
   */
  clearCache(): void {
    this.resultCache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): {
    size: number;
    maxSize: number;
    hitRate: number;
  } {
    // This is a simplified implementation
    return {
      size: this.resultCache.size,
      maxSize: this.config.maxCacheSize || 1000,
      hitRate: 0 // Would need to track hits/misses
    };
  }

  // Private helper methods

  private getCachedResult(query: ActivityQuery): CachedResult | null {
    if (!this.config.cacheResults) {
      return null;
    }

    const queryHash = this.hashQuery(query);
    const cached = this.resultCache.get(queryHash);
    
    if (!cached) {
      return null;
    }

    // Check TTL
    const now = new Date();
    const age = now.getTime() - cached.timestamp.getTime();
    
    if (age > (this.config.cacheTTL || 300000)) {
      this.resultCache.delete(queryHash);
      return null;
    }

    return cached;
  }

  private cacheResult(query: ActivityQuery, result: ActivitySearchResult): void {
    if (!this.config.cacheResults) {
      return;
    }

    const queryHash = this.hashQuery(query);
    
    // Check cache size limit
    if (this.resultCache.size >= (this.config.maxCacheSize || 1000)) {
      // Remove oldest entry
      const oldestKey = this.resultCache.keys().next().value;
      if (oldestKey) {
        this.resultCache.delete(oldestKey);
      }
    }

    this.resultCache.set(queryHash, {
      result,
      timestamp: new Date(),
      queryHash
    });
  }

  private hashQuery(query: ActivityQuery): string {
    // Simple hash implementation - in production use a proper hash function
    return Buffer.from(JSON.stringify(query)).toString('base64');
  }

  private shouldTryIPFSFallback(
    query: ActivityQuery, 
    indexResult: ActivitySearchResult
  ): boolean {
    // Try IPFS fallback if:
    // 1. We have few results but no limit was specified
    // 2. We're searching by specific criteria that might not be fully indexed
    // 3. The query asks for activity details (which aren't stored in index)
    
    if (!query.limit && indexResult.total < 10) {
      return true;
    }

    // If searching by date range and got no results, try IPFS
    if (query.dateRange && indexResult.total === 0) {
      return true;
    }

    return false;
  }

  private async enhanceWithIPFS(
    indexResult: ActivitySearchResult,
    query: ActivityQuery
  ): Promise<ActivitySearchResult> {
    // This is a placeholder - in a real implementation, you would:
    // 1. Get IPFS hashes from manifest
    // 2. Retrieve additional activities from IPFS
    // 3. Merge and deduplicate results
    // 4. Apply query filters to the enhanced dataset
    
    console.log('IPFS fallback not yet implemented - returning index results');
    return indexResult;
  }
}