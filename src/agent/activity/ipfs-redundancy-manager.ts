import { create } from 'kubo-rpc-client';
import type { KuboRPCClient } from 'kubo-rpc-client';
import { StoredActivity, IPFSActivityStorage } from './ipfs-activity-storage';
import { AgentActivity, ActivityBatch } from './types';

export interface IPFSNode {
  url: string;
  name: string;
  priority: number;
  active: boolean;
}

export interface RedundancyConfig {
  minReplicas: number; // Minimum number of nodes to store data
  nodes: IPFSNode[];
  encryptionKey?: Uint8Array;
  retryAttempts?: number;
  retryDelay?: number;
}

export class IPFSRedundancyManager {
  private storageNodes: Map<string, IPFSActivityStorage> = new Map();
  private config: RedundancyConfig;
  private healthStatus: Map<string, boolean> = new Map();

  constructor(config: RedundancyConfig) {
    this.config = {
      retryAttempts: 3,
      retryDelay: 1000,
      ...config
    };

    // Initialize storage nodes
    this.initializeNodes();
  }

  private initializeNodes(): void {
    for (const node of this.config.nodes) {
      if (node.active) {
        const storage = new IPFSActivityStorage({
          url: node.url,
          encryptionKey: this.config.encryptionKey
        });
        
        this.storageNodes.set(node.name, storage);
        this.healthStatus.set(node.name, true);
      }
    }
  }

  /**
   * Store activity across multiple nodes with redundancy
   */
  async storeActivityWithRedundancy(activity: AgentActivity): Promise<{
    success: boolean;
    nodes: { name: string; ipfsHash?: string; error?: string }[];
  }> {
    const results: { name: string; ipfsHash?: string; error?: string }[] = [];
    const activeNodes = this.getActiveNodes();
    
    if (activeNodes.length < this.config.minReplicas) {
      throw new Error(
        `Insufficient active nodes. Required: ${this.config.minReplicas}, Available: ${activeNodes.length}`
      );
    }

    // Store to all active nodes in parallel
    const storePromises = activeNodes.map(async node => {
      try {
        const storage = this.storageNodes.get(node.name);
        if (!storage) {
          throw new Error(`Storage not found for node: ${node.name}`);
        }

        const result = await this.retryOperation(
          () => storage.storeActivity(activity),
          node.name
        );

        return {
          name: node.name,
          ipfsHash: result.ipfsHash
        };
      } catch (error) {
        this.healthStatus.set(node.name, false);
        return {
          name: node.name,
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    });

    const storeResults = await Promise.all(storePromises);
    
    // Check if minimum replicas were successful
    const successfulNodes = storeResults.filter(r => r.ipfsHash).length;
    
    return {
      success: successfulNodes >= this.config.minReplicas,
      nodes: storeResults
    };
  }

  /**
   * Store activity batch with redundancy
   */
  async storeBatchWithRedundancy(batch: ActivityBatch): Promise<{
    success: boolean;
    nodes: { name: string; ipfsHash?: string; error?: string }[];
  }> {
    const results: { name: string; ipfsHash?: string; error?: string }[] = [];
    const activeNodes = this.getActiveNodes();
    
    if (activeNodes.length < this.config.minReplicas) {
      throw new Error(
        `Insufficient active nodes. Required: ${this.config.minReplicas}, Available: ${activeNodes.length}`
      );
    }

    const storePromises = activeNodes.map(async node => {
      try {
        const storage = this.storageNodes.get(node.name);
        if (!storage) {
          throw new Error(`Storage not found for node: ${node.name}`);
        }

        const result = await this.retryOperation(
          () => storage.storeActivityBatch(batch),
          node.name
        );

        return {
          name: node.name,
          ipfsHash: result.ipfsHash
        };
      } catch (error) {
        this.healthStatus.set(node.name, false);
        return {
          name: node.name,
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    });

    const storeResults = await Promise.all(storePromises);
    const successfulNodes = storeResults.filter(r => r.ipfsHash).length;
    
    return {
      success: successfulNodes >= this.config.minReplicas,
      nodes: storeResults
    };
  }

  /**
   * Retrieve activity from any available node
   */
  async retrieveActivity(ipfsHash: string): Promise<AgentActivity | null> {
    const activeNodes = this.getActiveNodes();
    
    for (const node of activeNodes) {
      try {
        const storage = this.storageNodes.get(node.name);
        if (!storage) continue;

        const activity = await storage.retrieveActivity(ipfsHash);
        return activity;
      } catch (error) {
        console.error(`Failed to retrieve from ${node.name}:`, error);
        continue;
      }
    }
    
    throw new Error(`Failed to retrieve activity from any node: ${ipfsHash}`);
  }

  /**
   * Retrieve batch from any available node
   */
  async retrieveBatch(ipfsHash: string): Promise<ActivityBatch | null> {
    const activeNodes = this.getActiveNodes();
    
    for (const node of activeNodes) {
      try {
        const storage = this.storageNodes.get(node.name);
        if (!storage) continue;

        const batch = await storage.retrieveActivityBatch(ipfsHash);
        return batch;
      } catch (error) {
        console.error(`Failed to retrieve from ${node.name}:`, error);
        continue;
      }
    }
    
    throw new Error(`Failed to retrieve batch from any node: ${ipfsHash}`);
  }

  /**
   * Pin content across minimum required nodes
   */
  async pinWithRedundancy(ipfsHash: string): Promise<{
    success: boolean;
    nodes: { name: string; pinned: boolean; error?: string }[];
  }> {
    const activeNodes = this.getActiveNodes();
    const results: { name: string; pinned: boolean; error?: string }[] = [];

    const pinPromises = activeNodes.slice(0, this.config.minReplicas).map(async node => {
      try {
        const storage = this.storageNodes.get(node.name);
        if (!storage) {
          throw new Error(`Storage not found for node: ${node.name}`);
        }

        await storage.pinActivity(ipfsHash);
        return { name: node.name, pinned: true };
      } catch (error) {
        return {
          name: node.name,
          pinned: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    });

    const pinResults = await Promise.all(pinPromises);
    const successfulPins = pinResults.filter(r => r.pinned).length;
    
    return {
      success: successfulPins >= this.config.minReplicas,
      nodes: pinResults
    };
  }

  /**
   * Check health of all nodes
   */
  async checkNodesHealth(): Promise<Map<string, boolean>> {
    const healthPromises = Array.from(this.storageNodes.entries()).map(
      async ([name, storage]) => {
        try {
          const connected = await storage.isConnected();
          this.healthStatus.set(name, connected);
          return { name, healthy: connected };
        } catch {
          this.healthStatus.set(name, false);
          return { name, healthy: false };
        }
      }
    );

    await Promise.all(healthPromises);
    return new Map(this.healthStatus);
  }

  /**
   * Get active nodes sorted by priority
   */
  private getActiveNodes(): IPFSNode[] {
    return this.config.nodes
      .filter(node => node.active && this.healthStatus.get(node.name) !== false)
      .sort((a, b) => b.priority - a.priority);
  }

  /**
   * Retry operation with exponential backoff
   */
  private async retryOperation<T>(
    operation: () => Promise<T>,
    nodeName: string
  ): Promise<T> {
    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt < this.config.retryAttempts!; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Unknown error');
        
        if (attempt < this.config.retryAttempts! - 1) {
          const delay = this.config.retryDelay! * Math.pow(2, attempt);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    throw lastError || new Error(`Failed after ${this.config.retryAttempts} attempts`);
  }

  /**
   * Sync content between nodes
   */
  async syncContent(ipfsHash: string, fromNode: string, toNodes: string[]): Promise<{
    success: boolean;
    synced: string[];
    failed: string[];
  }> {
    const synced: string[] = [];
    const failed: string[] = [];

    // First retrieve from source node
    const sourceStorage = this.storageNodes.get(fromNode);
    if (!sourceStorage) {
      throw new Error(`Source node not found: ${fromNode}`);
    }

    let content: ActivityBatch | null = null;
    try {
      content = await sourceStorage.retrieveActivityBatch(ipfsHash);
    } catch {
      // Try as single activity
      try {
        const activity = await sourceStorage.retrieveActivity(ipfsHash);
        if (activity) {
          content = {
            id: ipfsHash,
            activities: [activity],
            startTime: activity.timestamp,
            endTime: activity.timestamp,
            count: 1,
            agentDID: activity.agentDID,
            parentDID: activity.parentDID
          };
        }
      } catch (error) {
        throw new Error(`Failed to retrieve content from source: ${error}`);
      }
    }

    if (!content) {
      throw new Error('Content not found on source node');
    }

    // Sync to target nodes
    const syncPromises = toNodes.map(async nodeName => {
      try {
        const targetStorage = this.storageNodes.get(nodeName);
        if (!targetStorage) {
          throw new Error(`Target node not found: ${nodeName}`);
        }

        await targetStorage.storeActivityBatch(content);
        synced.push(nodeName);
      } catch (error) {
        console.error(`Failed to sync to ${nodeName}:`, error);
        failed.push(nodeName);
      }
    });

    await Promise.all(syncPromises);

    return {
      success: synced.length > 0,
      synced,
      failed
    };
  }

  /**
   * Add a new IPFS node
   */
  addNode(node: IPFSNode): void {
    if (node.active) {
      const storage = new IPFSActivityStorage({
        url: node.url,
        encryptionKey: this.config.encryptionKey
      });
      
      this.storageNodes.set(node.name, storage);
      this.healthStatus.set(node.name, true);
      this.config.nodes.push(node);
    }
  }

  /**
   * Remove a node
   */
  removeNode(nodeName: string): void {
    this.storageNodes.delete(nodeName);
    this.healthStatus.delete(nodeName);
    this.config.nodes = this.config.nodes.filter(n => n.name !== nodeName);
  }

  /**
   * Get storage statistics across all nodes
   */
  async getAggregateStats(): Promise<{
    totalNodes: number;
    activeNodes: number;
    totalPinned: number;
    nodeStats: { name: string; pinned: number; healthy: boolean }[];
  }> {
    const nodeStats: { name: string; pinned: number; healthy: boolean }[] = [];
    let totalPinned = 0;

    for (const [name, storage] of this.storageNodes.entries()) {
      try {
        const stats = await storage.getStorageStats();
        nodeStats.push({
          name,
          pinned: stats.totalPinned,
          healthy: this.healthStatus.get(name) || false
        });
        totalPinned += stats.totalPinned;
      } catch {
        nodeStats.push({
          name,
          pinned: 0,
          healthy: false
        });
      }
    }

    return {
      totalNodes: this.config.nodes.length,
      activeNodes: this.getActiveNodes().length,
      totalPinned,
      nodeStats
    };
  }
}