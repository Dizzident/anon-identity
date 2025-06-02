import { ActivityLogger } from './activity-logger';
import { ActivityStreamManager } from './activity-stream-manager';
import { ActivityWebSocketServer } from './websocket-server';
import { ActivitySearchService } from './activity-search-service';
import { IPFSActivityStorage } from './ipfs-activity-storage';
import { ActivityIndex } from './activity-index';
import { 
  AgentActivity, 
  ActivityLoggerConfig, 
  ActivityQuery, 
  ActivitySearchResult,
  ActivitySummary 
} from './types';
import { Server } from 'http';

export interface MonitoringServiceConfig extends ActivityLoggerConfig {
  websocket?: {
    enabled?: boolean;
    port?: number;
    path?: string;
    maxConnections?: number;
  };
  alerts?: {
    enabled?: boolean;
    errorRateThreshold?: number;
    volumeThreshold?: number;
    enableEmail?: boolean;
    enableWebhook?: boolean;
    webhookUrl?: string;
  };
}

export interface MonitoringStats {
  activities: {
    total: number;
    lastHour: number;
    errorRate: number;
  };
  agents: {
    active: number;
    totalSessions: number;
  };
  streaming: {
    connections: number;
    subscriptions: number;
    eventsPublished: number;
  };
  storage: {
    ipfsEnabled: boolean;
    indexEnabled: boolean;
    totalIndexed: number;
  };
}

/**
 * Comprehensive activity monitoring service that integrates all components
 */
export class ActivityMonitoringService {
  private logger!: ActivityLogger;
  private streamManager?: ActivityStreamManager;
  private webSocketServer?: ActivityWebSocketServer;
  private searchService?: ActivitySearchService;
  private config: MonitoringServiceConfig;

  constructor(config: MonitoringServiceConfig = {}) {
    this.config = {
      enableIndexing: true,
      enableStreaming: true,
      enableIPFS: false,
      websocket: {
        enabled: false,
        port: 8080,
        path: '/activity-stream',
        maxConnections: 1000,
        ...config.websocket
      },
      alerts: {
        enabled: true,
        errorRateThreshold: 0.1, // 10%
        volumeThreshold: 1000, // 1000 activities per hour
        enableEmail: false,
        enableWebhook: false,
        ...config.alerts
      },
      ...config
    };

    this.initializeServices();
  }

  /**
   * Start the monitoring service
   */
  async start(httpServer?: Server): Promise<void> {
    // Start WebSocket server if enabled
    if (this.config.websocket?.enabled && this.streamManager) {
      this.webSocketServer = new ActivityWebSocketServer(
        this.streamManager,
        httpServer,
        {
          port: this.config.websocket.port,
          path: this.config.websocket.path,
          maxConnections: this.config.websocket.maxConnections
        }
      );

      console.log(`Activity WebSocket server started on ${this.config.websocket.path}`);
    }

    console.log('Activity Monitoring Service started');
  }

  /**
   * Stop the monitoring service
   */
  async stop(): Promise<void> {
    await this.logger.cleanup();
    
    if (this.webSocketServer) {
      await this.webSocketServer.close();
    }

    console.log('Activity Monitoring Service stopped');
  }

  /**
   * Log an activity
   */
  async logActivity(activity: Partial<AgentActivity>): Promise<AgentActivity> {
    return this.logger.logActivity(activity);
  }

  /**
   * Search activities
   */
  async searchActivities(query: ActivityQuery): Promise<ActivitySearchResult> {
    if (!this.searchService) {
      throw new Error('Search service not initialized - enable indexing');
    }
    return this.searchService.searchActivities(query);
  }

  /**
   * Get activity summary
   */
  async getActivitySummary(
    agentDID: string,
    period: 'hour' | 'day' | 'week' | 'month' | 'year',
    startDate?: Date
  ): Promise<ActivitySummary> {
    if (!this.searchService) {
      throw new Error('Search service not initialized - enable indexing');
    }
    return this.searchService.getActivitySummary(agentDID, period, startDate);
  }

  /**
   * Get recent activities for an agent
   */
  async getRecentActivities(agentDID: string, limit: number = 50): Promise<AgentActivity[]> {
    if (!this.searchService) {
      throw new Error('Search service not initialized - enable indexing');
    }
    return this.searchService.getRecentActivities(agentDID, limit);
  }

  /**
   * Subscribe to real-time activity stream
   */
  subscribeToActivities(
    filters: any,
    callback: (event: any) => void,
    metadata?: Record<string, any>
  ): any {
    if (!this.streamManager) {
      throw new Error('Stream manager not initialized - enable streaming');
    }
    return this.streamManager.subscribe(filters, callback, metadata);
  }

  /**
   * Subscribe to agent activities
   */
  subscribeToAgent(
    agentDID: string,
    callback: (event: any) => void,
    metadata?: Record<string, any>
  ): any {
    if (!this.streamManager) {
      throw new Error('Stream manager not initialized - enable streaming');
    }
    return this.streamManager.subscribeToAgent(agentDID, callback, metadata);
  }

  /**
   * Subscribe to critical events
   */
  subscribeToCriticalEvents(
    callback: (event: any) => void,
    metadata?: Record<string, any>
  ): any {
    if (!this.streamManager) {
      throw new Error('Stream manager not initialized - enable streaming');
    }
    return this.streamManager.subscribeToCriticalEvents(callback, metadata);
  }

  /**
   * Get comprehensive monitoring statistics
   */
  async getMonitoringStats(): Promise<MonitoringStats> {
    const indexStats = this.logger.getActivityIndex()?.getStats();
    const streamStats = this.streamManager?.getMetrics();
    const wsStats = this.webSocketServer?.getStats();

    // Calculate activities in last hour
    let lastHourActivities = 0;
    let totalActivities = 0;
    let errorCount = 0;

    if (indexStats) {
      totalActivities = indexStats.totalActivities;
      
      // Calculate error rate
      Object.entries(indexStats.byStatus).forEach(([status, count]) => {
        if (status === 'failed' || status === 'denied') {
          errorCount += count;
        }
      });

      // Get recent activities for last hour calculation
      if (this.searchService) {
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const recentQuery: ActivityQuery = {
          dateRange: { start: oneHourAgo, end: new Date() }
        };
        
        try {
          const recentResult = await this.searchService.searchActivities(recentQuery);
          lastHourActivities = recentResult.total;
        } catch {
          // Ignore errors in stats calculation
        }
      }
    }

    return {
      activities: {
        total: totalActivities,
        lastHour: lastHourActivities,
        errorRate: totalActivities > 0 ? errorCount / totalActivities : 0
      },
      agents: {
        active: indexStats?.agentCount || 0,
        totalSessions: 0 // Would need to track this separately
      },
      streaming: {
        connections: wsStats?.connectedClients || 0,
        subscriptions: wsStats?.totalSubscriptions || 0,
        eventsPublished: streamStats?.totalEvents || 0
      },
      storage: {
        ipfsEnabled: !!this.logger.getIPFSStorage(),
        indexEnabled: !!this.logger.getActivityIndex(),
        totalIndexed: indexStats?.totalActivities || 0
      }
    };
  }

  /**
   * Get activity trends
   */
  async getActivityTrends(
    agentDID: string,
    days: number = 7
  ): Promise<Array<{
    date: string;
    count: number;
    byType: Record<string, number>;
    errorRate: number;
  }>> {
    if (!this.searchService) {
      throw new Error('Search service not initialized - enable indexing');
    }
    return this.searchService.getActivityTrends(agentDID, days);
  }

  /**
   * Compare multiple agents
   */
  async compareAgents(
    agentDIDs: string[],
    period: 'day' | 'week' | 'month' = 'week'
  ): Promise<Record<string, ActivitySummary>> {
    if (!this.searchService) {
      throw new Error('Search service not initialized - enable indexing');
    }
    return this.searchService.compareAgents(agentDIDs, period);
  }

  /**
   * Force flush all pending activities
   */
  async flush(): Promise<void> {
    await this.logger.flush();
  }

  /**
   * Get the underlying logger instance
   */
  getLogger(): ActivityLogger {
    return this.logger;
  }

  /**
   * Get the stream manager instance
   */
  getStreamManager(): ActivityStreamManager | undefined {
    return this.streamManager;
  }

  /**
   * Get the WebSocket server instance
   */
  getWebSocketServer(): ActivityWebSocketServer | undefined {
    return this.webSocketServer;
  }

  /**
   * Get the search service instance
   */
  getSearchService(): ActivitySearchService | undefined {
    return this.searchService;
  }

  // Private methods

  private initializeServices(): void {
    // Initialize activity logger
    this.logger = new ActivityLogger(this.config);

    // Initialize stream manager if streaming is enabled
    if (this.config.enableStreaming) {
      this.streamManager = this.logger.getStreamManager();
    }

    // Initialize search service if indexing is enabled
    if (this.config.enableIndexing) {
      const index = this.logger.getActivityIndex();
      const ipfsStorage = this.logger.getIPFSStorage();
      
      if (index) {
        this.searchService = new ActivitySearchService(index, ipfsStorage);
      }
    }

    // Setup alert monitoring if enabled
    if (this.config.alerts?.enabled && this.streamManager) {
      this.setupAlertMonitoring();
    }
  }

  private setupAlertMonitoring(): void {
    if (!this.streamManager) return;

    // Subscribe to alerts and handle them
    this.streamManager.subscribeToAlerts(
      async (event) => {
        const alert = event.data as any;
        console.log(`[ALERT] ${alert.severity.toUpperCase()}: ${alert.message}`);
        
        // Handle different alert types
        if (this.config.alerts?.enableWebhook && this.config.alerts?.webhookUrl) {
          await this.sendWebhookAlert(alert);
        }
        
        if (this.config.alerts?.enableEmail) {
          await this.sendEmailAlert(alert);
        }
      },
      undefined,
      { source: 'monitoring-service' }
    );
  }

  private async sendWebhookAlert(alert: any): Promise<void> {
    if (!this.config.alerts?.webhookUrl) return;

    try {
      // This would typically use fetch or axios in a real implementation
      console.log(`Webhook alert would be sent to: ${this.config.alerts.webhookUrl}`);
      console.log('Alert data:', JSON.stringify(alert, null, 2));
    } catch (error) {
      console.error('Failed to send webhook alert:', error);
    }
  }

  private async sendEmailAlert(alert: any): Promise<void> {
    try {
      // This would typically integrate with an email service
      console.log('Email alert would be sent');
      console.log('Alert data:', JSON.stringify(alert, null, 2));
    } catch (error) {
      console.error('Failed to send email alert:', error);
    }
  }
}