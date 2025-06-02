import { v4 as uuidv4 } from 'uuid';
import { 
  AgentActivity, 
  ActivityType, 
  ActivityStatus,
  ActivityBatch,
  ActivityLoggerConfig,
  ActivitySubscription,
  ActivityHook
} from './types';
import { IPFSActivityStorage } from './ipfs-activity-storage';
import { IPFSRedundancyManager, IPFSNode } from './ipfs-redundancy-manager';
import { ActivityIndex } from './activity-index';
import { ActivityStreamManager } from './activity-stream-manager';

/**
 * ActivityLogger - Core service for logging agent activities
 * 
 * Provides activity tracking, batching, and real-time streaming
 */
export class ActivityLogger {
  private config: {
    batchSize: number;
    batchInterval: number;
    enableRealtime: boolean;
    enableBatching: boolean;
    retentionDays: number;
    encryptionKey?: Uint8Array;
    enableIPFS?: boolean;
    ipfsUrl?: string;
    enableRedundancy?: boolean;
    ipfsNodes?: IPFSNode[];
    minReplicas?: number;
    enableIndexing?: boolean;
    enableStreaming?: boolean;
  };
  private activityBuffer: AgentActivity[] = [];
  private batchTimer?: NodeJS.Timeout;
  private subscriptions: Map<string, ActivitySubscription> = new Map();
  private hooks: Map<ActivityType, ActivityHook[]> = new Map();
  private processingBatch: boolean = false;
  private ipfsStorage?: IPFSActivityStorage;
  private redundancyManager?: IPFSRedundancyManager;
  private activityIndex?: ActivityIndex;
  private streamManager?: ActivityStreamManager;

  constructor(config: ActivityLoggerConfig = {}) {
    this.config = {
      batchSize: config.batchSize || 100,
      batchInterval: config.batchInterval || 5000,
      enableRealtime: config.enableRealtime ?? true,
      enableBatching: config.enableBatching ?? true,
      retentionDays: config.retentionDays || 90,
      encryptionKey: config.encryptionKey,
      enableIPFS: config.enableIPFS ?? false,
      ipfsUrl: config.ipfsUrl,
      enableRedundancy: config.enableRedundancy ?? false,
      ipfsNodes: config.ipfsNodes,
      minReplicas: config.minReplicas || 2,
      enableIndexing: config.enableIndexing ?? true,
      enableStreaming: config.enableStreaming ?? false
    };

    if (this.config.enableBatching) {
      this.startBatchTimer();
    }

    // Initialize IPFS storage
    if (this.config.enableIPFS) {
      if (this.config.enableRedundancy && this.config.ipfsNodes) {
        // Use redundancy manager for multiple nodes
        this.redundancyManager = new IPFSRedundancyManager({
          nodes: this.config.ipfsNodes,
          minReplicas: this.config.minReplicas || 2,
          encryptionKey: this.config.encryptionKey
        });
      } else {
        // Use single node storage
        this.ipfsStorage = new IPFSActivityStorage({
          url: this.config.ipfsUrl,
          encryptionKey: this.config.encryptionKey
        });
      }
    }

    // Initialize activity index
    if (this.config.enableIndexing) {
      this.activityIndex = new ActivityIndex();
    }

    // Initialize stream manager
    if (this.config.enableStreaming) {
      this.streamManager = new ActivityStreamManager({
        enableAlerts: true,
        enableMetrics: true
      });
    }
  }

  /**
   * Log a single activity
   */
  async logActivity(activity: Partial<AgentActivity>): Promise<AgentActivity> {
    // Generate ID and timestamp if not provided
    const fullActivity: AgentActivity = {
      id: activity.id || uuidv4(),
      timestamp: activity.timestamp || new Date(),
      scopes: activity.scopes || [],
      details: activity.details || {},
      ...activity
    } as AgentActivity;

    // Run before hooks
    const shouldContinue = await this.runBeforeHooks(fullActivity);
    if (!shouldContinue) {
      throw new Error('Activity rejected by hook');
    }

    // Add to buffer if batching is enabled
    if (this.config.enableBatching) {
      this.activityBuffer.push(fullActivity);
      
      // Check if we should process the batch immediately
      if (this.activityBuffer.length >= this.config.batchSize) {
        await this.processBatch();
      }
    }

    // Notify real-time subscribers
    if (this.config.enableRealtime) {
      await this.notifySubscribers(fullActivity);
    }

    // Index the activity for searching
    if (this.activityIndex) {
      try {
        await this.activityIndex.indexActivity(fullActivity);
      } catch (error) {
        console.error('Failed to index activity:', error);
      }
    }

    // Stream the activity for real-time updates
    if (this.streamManager) {
      try {
        await this.streamManager.publishActivity(fullActivity);
      } catch (error) {
        console.error('Failed to stream activity:', error);
      }
    }

    // Run after hooks
    await this.runAfterHooks(fullActivity);

    return fullActivity;
  }

  /**
   * Log multiple activities at once
   */
  async logActivities(activities: Partial<AgentActivity>[]): Promise<AgentActivity[]> {
    const results: AgentActivity[] = [];
    
    for (const activity of activities) {
      try {
        const logged = await this.logActivity(activity);
        results.push(logged);
      } catch (error) {
        console.error('Failed to log activity:', error);
      }
    }

    return results;
  }

  /**
   * Subscribe to real-time activity updates
   */
  subscribe(
    filter: {
      agentDID?: string;
      parentDID?: string;
      types?: ActivityType[];
    },
    callback: (activity: AgentActivity) => void
  ): ActivitySubscription {
    const subscriptionId = uuidv4();
    
    const subscription: ActivitySubscription = {
      id: subscriptionId,
      agentDID: filter.agentDID,
      parentDID: filter.parentDID,
      types: filter.types,
      callback,
      unsubscribe: () => {
        this.subscriptions.delete(subscriptionId);
      }
    };

    this.subscriptions.set(subscriptionId, subscription);
    return subscription;
  }

  /**
   * Register a hook for activities
   */
  registerHook(hook: ActivityHook): void {
    const hooks = this.hooks.get(hook.type) || [];
    hooks.push(hook);
    this.hooks.set(hook.type, hooks);
  }

  /**
   * Force process the current batch
   */
  async flush(): Promise<void> {
    if (this.activityBuffer.length > 0) {
      await this.processBatch();
    }
  }

  /**
   * Process a batch of activities
   */
  private async processBatch(): Promise<void> {
    if (this.processingBatch || this.activityBuffer.length === 0) {
      return;
    }

    this.processingBatch = true;
    const activities = [...this.activityBuffer];
    this.activityBuffer = [];

    try {
      const batch: ActivityBatch = {
        id: uuidv4(),
        activities,
        startTime: activities[0].timestamp,
        endTime: activities[activities.length - 1].timestamp,
        count: activities.length,
        agentDID: activities[0].agentDID,
        parentDID: activities[0].parentDID
      };

      // Store to IPFS if enabled
      if (this.config.enableIPFS) {
        try {
          if (this.redundancyManager) {
            // Store with redundancy
            const result = await this.redundancyManager.storeBatchWithRedundancy(batch);
            if (result.success) {
              const successfulNode = result.nodes.find(n => n.ipfsHash);
              batch.batchHash = successfulNode?.ipfsHash;
              console.log(`Stored batch with redundancy: ${result.nodes.filter(n => n.ipfsHash).length}/${result.nodes.length} nodes`);
            } else {
              throw new Error('Failed to meet minimum replica requirement');
            }
          } else if (this.ipfsStorage) {
            // Store to single node
            const storedBatch = await this.ipfsStorage.storeActivityBatch(batch);
            console.log(`Stored activity batch to IPFS: ${storedBatch.ipfsHash}`);
            batch.batchHash = storedBatch.ipfsHash;
          }
        } catch (ipfsError) {
          console.error('Failed to store batch to IPFS:', ipfsError);
          // Continue processing even if IPFS storage fails
        }
      } else {
        console.log(`Processing activity batch: ${batch.count} activities`);
      }
      
      // Stream batch processed event
      if (this.streamManager) {
        try {
          await this.streamManager.publishBatch(batch);
        } catch (error) {
          console.error('Failed to stream batch:', error);
        }
      }
      
      // Emit batch processed event
      await this.emitBatchProcessed(batch);
    } catch (error) {
      console.error('Failed to process batch:', error);
      // Re-add activities to buffer for retry
      this.activityBuffer.unshift(...activities);
    } finally {
      this.processingBatch = false;
    }
  }

  /**
   * Start the batch processing timer
   */
  private startBatchTimer(): void {
    this.batchTimer = setInterval(async () => {
      await this.processBatch();
    }, this.config.batchInterval);
  }

  /**
   * Stop the batch processing timer
   */
  stopBatchTimer(): void {
    if (this.batchTimer) {
      clearInterval(this.batchTimer);
      this.batchTimer = undefined;
    }
  }

  /**
   * Notify subscribers of a new activity
   */
  private async notifySubscribers(activity: AgentActivity): Promise<void> {
    const promises = Array.from(this.subscriptions.values())
      .filter(sub => this.matchesSubscription(activity, sub))
      .map(sub => {
        try {
          return Promise.resolve(sub.callback(activity));
        } catch (error) {
          console.error('Subscriber callback error:', error);
          return Promise.resolve();
        }
      });

    await Promise.all(promises);
  }

  /**
   * Check if an activity matches a subscription filter
   */
  private matchesSubscription(
    activity: AgentActivity, 
    subscription: ActivitySubscription
  ): boolean {
    if (subscription.agentDID && activity.agentDID !== subscription.agentDID) {
      return false;
    }

    if (subscription.parentDID && activity.parentDID !== subscription.parentDID) {
      return false;
    }

    if (subscription.types && !subscription.types.includes(activity.type)) {
      return false;
    }

    return true;
  }

  /**
   * Run before hooks for an activity
   */
  private async runBeforeHooks(activity: AgentActivity): Promise<boolean> {
    const hooks = this.hooks.get(activity.type) || [];
    
    for (const hook of hooks) {
      if (hook.beforeActivity) {
        const shouldContinue = await hook.beforeActivity(activity);
        if (!shouldContinue) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Run after hooks for an activity
   */
  private async runAfterHooks(activity: AgentActivity): Promise<void> {
    const hooks = this.hooks.get(activity.type) || [];
    
    const promises = hooks
      .filter(hook => hook.afterActivity)
      .map(hook => hook.afterActivity!(activity));

    await Promise.all(promises);
  }

  /**
   * Emit batch processed event
   */
  private async emitBatchProcessed(batch: ActivityBatch): Promise<void> {
    // This will be extended in future phases
    // For now, just log it
    console.log(`Batch processed: ${batch.id}, Activities: ${batch.count}`);
  }

  /**
   * Get current buffer size
   */
  getBufferSize(): number {
    return this.activityBuffer.length;
  }

  /**
   * Get subscription count
   */
  getSubscriptionCount(): number {
    return this.subscriptions.size;
  }

  /**
   * Retrieve activities from IPFS
   */
  async retrieveActivitiesFromIPFS(ipfsHashes: string[]): Promise<AgentActivity[]> {
    if (!this.ipfsStorage) {
      throw new Error('IPFS storage not enabled');
    }

    const activities: AgentActivity[] = [];
    
    for (const hash of ipfsHashes) {
      try {
        const batch = await this.ipfsStorage.retrieveActivityBatch(hash);
        activities.push(...batch.activities);
      } catch (error) {
        console.error(`Failed to retrieve batch ${hash}:`, error);
      }
    }
    
    return activities;
  }

  /**
   * Get IPFS storage instance
   */
  getIPFSStorage(): IPFSActivityStorage | undefined {
    return this.ipfsStorage;
  }

  /**
   * Get activity index instance
   */
  getActivityIndex(): ActivityIndex | undefined {
    return this.activityIndex;
  }

  /**
   * Get stream manager instance
   */
  getStreamManager(): ActivityStreamManager | undefined {
    return this.streamManager;
  }

  /**
   * Enable or disable IPFS storage
   */
  async setIPFSEnabled(enabled: boolean, ipfsUrl?: string): Promise<void> {
    this.config.enableIPFS = enabled;
    
    if (enabled && !this.ipfsStorage) {
      this.ipfsStorage = new IPFSActivityStorage({
        url: ipfsUrl || this.config.ipfsUrl,
        encryptionKey: this.config.encryptionKey
      });
    } else if (!enabled && this.ipfsStorage) {
      // Flush any pending activities before disabling
      await this.flush();
      this.ipfsStorage = undefined;
    }
  }

  /**
   * Check if IPFS is connected
   */
  async checkIPFSConnection(): Promise<boolean> {
    if (!this.ipfsStorage) {
      return false;
    }
    
    return await this.ipfsStorage.isConnected();
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    // Stop batch timer
    this.stopBatchTimer();

    // Process remaining activities
    await this.flush();

    // Clear subscriptions
    this.subscriptions.clear();

    // Clear hooks
    this.hooks.clear();
  }
}

// Singleton instance for global access
let globalLogger: ActivityLogger | null = null;

/**
 * Get or create the global activity logger instance
 */
export function getActivityLogger(config?: ActivityLoggerConfig): ActivityLogger {
  if (!globalLogger) {
    globalLogger = new ActivityLogger(config);
  }
  return globalLogger;
}

/**
 * Helper function to create a standard activity object
 */
export function createActivity(
  type: ActivityType,
  params: {
    agentDID: string;
    parentDID: string;
    serviceDID: string;
    status: ActivityStatus;
    scopes?: string[];
    details?: any;
    sessionId?: string;
  }
): Partial<AgentActivity> {
  return {
    type,
    agentDID: params.agentDID,
    parentDID: params.parentDID,
    serviceDID: params.serviceDID,
    status: params.status,
    scopes: params.scopes || [],
    details: params.details || {},
    sessionId: params.sessionId
  };
}