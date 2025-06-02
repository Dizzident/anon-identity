import { create } from 'kubo-rpc-client';
import type { KuboRPCClient } from 'kubo-rpc-client';
import { AgentActivity, ActivityBatch } from './types';
import { ActivityEncryption, EncryptedData } from './activity-encryption';

export interface IPFSStorageConfig {
  url?: string;
  encryptionKey?: Uint8Array;
  pinningServices?: string[];
}

export interface StoredActivity {
  ipfsHash: string;
  encrypted: boolean;
  timestamp: Date;
  checksum: string;
}

export interface ActivityManifest {
  agentDID: string;
  parentDID: string;
  created: Date;
  lastUpdated: Date;
  totalActivities: number;
  ipfsHashes: string[];
  encrypted: boolean;
}

export class IPFSActivityStorage {
  private ipfs: KuboRPCClient;
  private encryption: ActivityEncryption;
  private encryptionKey?: Uint8Array;
  private manifests: Map<string, ActivityManifest> = new Map();

  constructor(config: IPFSStorageConfig = {}) {
    // Default to local IPFS node, can be configured for Infura, Pinata, etc.
    this.ipfs = create({
      url: config.url || 'http://localhost:5001'
    });
    
    this.encryption = new ActivityEncryption();
    this.encryptionKey = config.encryptionKey;
  }

  /**
   * Store a single activity to IPFS
   */
  async storeActivity(activity: AgentActivity): Promise<StoredActivity> {
    try {
      let dataToStore: any;
      let encrypted = false;

      // Add integrity hash
      const activityWithHash = {
        ...activity,
        checksum: ActivityEncryption.createActivityHash(activity)
      };

      if (this.encryptionKey) {
        // Encrypt before storing
        const encryptedData = await this.encryption.encryptActivity(
          activityWithHash,
          this.encryptionKey
        );
        dataToStore = encryptedData;
        encrypted = true;
      } else {
        dataToStore = activityWithHash;
      }

      // Store to IPFS
      const { cid } = await this.ipfs.add(
        JSON.stringify(dataToStore),
        { pin: true }
      );

      const ipfsHash = cid.toString();

      // Update activity with IPFS hash
      activity.ipfsHash = ipfsHash;

      // Update manifest
      await this.updateManifest(activity.agentDID, activity.parentDID, ipfsHash);

      return {
        ipfsHash,
        encrypted,
        timestamp: new Date(),
        checksum: activityWithHash.checksum
      };
    } catch (error) {
      throw new Error(`Failed to store activity: ${error}`);
    }
  }

  /**
   * Store a batch of activities
   */
  async storeActivityBatch(batch: ActivityBatch): Promise<StoredActivity> {
    try {
      let dataToStore: any;
      let encrypted = false;

      // Add merkle root for integrity
      const batchWithProof = {
        ...batch,
        merkleRoot: ActivityEncryption.createBatchMerkleRoot(batch.activities)
      };

      if (this.encryptionKey) {
        // Encrypt before storing
        const encryptedData = await this.encryption.encryptBatch(
          batchWithProof,
          this.encryptionKey
        );
        dataToStore = encryptedData;
        encrypted = true;
      } else {
        dataToStore = batchWithProof;
      }

      // Store to IPFS
      const { cid } = await this.ipfs.add(
        JSON.stringify(dataToStore),
        { pin: true }
      );

      const ipfsHash = cid.toString();

      // Update batch with IPFS hash
      batch.batchHash = ipfsHash;

      // Update all activities in batch with reference
      batch.activities.forEach(activity => {
        activity.ipfsHash = ipfsHash;
      });

      // Update manifest
      await this.updateManifest(batch.agentDID, batch.parentDID, ipfsHash);

      return {
        ipfsHash,
        encrypted,
        timestamp: new Date(),
        checksum: batchWithProof.merkleRoot
      };
    } catch (error) {
      throw new Error(`Failed to store activity batch: ${error}`);
    }
  }

  /**
   * Retrieve an activity from IPFS
   */
  async retrieveActivity(ipfsHash: string): Promise<AgentActivity> {
    try {
      const chunks: Uint8Array[] = [];
      
      for await (const chunk of this.ipfs.cat(ipfsHash)) {
        chunks.push(chunk);
      }
      
      const data = Buffer.concat(chunks).toString('utf8');
      const parsed = JSON.parse(data);

      // Check if data is encrypted
      if (parsed.algorithm && parsed.data && parsed.iv && parsed.tag) {
        if (!this.encryptionKey) {
          throw new Error('Data is encrypted but no encryption key provided');
        }
        
        const decrypted = await this.encryption.decryptActivity(
          parsed as EncryptedData,
          this.encryptionKey
        );
        
        // Verify integrity
        const expectedChecksum = ActivityEncryption.createActivityHash(decrypted);
        if (decrypted.checksum && decrypted.checksum !== expectedChecksum) {
          throw new Error('Activity integrity check failed');
        }
        
        return decrypted;
      }

      // Verify integrity for unencrypted data
      if (parsed.checksum) {
        const expectedChecksum = ActivityEncryption.createActivityHash(parsed);
        if (parsed.checksum !== expectedChecksum) {
          throw new Error('Activity integrity check failed');
        }
      }

      return parsed as AgentActivity;
    } catch (error) {
      throw new Error(`Failed to retrieve activity: ${error}`);
    }
  }

  /**
   * Retrieve a batch of activities
   */
  async retrieveActivityBatch(ipfsHash: string): Promise<ActivityBatch> {
    try {
      const chunks: Uint8Array[] = [];
      
      for await (const chunk of this.ipfs.cat(ipfsHash)) {
        chunks.push(chunk);
      }
      
      const data = Buffer.concat(chunks).toString('utf8');
      const parsed = JSON.parse(data);

      // Check if data is encrypted
      if (parsed.algorithm && parsed.data && parsed.iv && parsed.tag) {
        if (!this.encryptionKey) {
          throw new Error('Data is encrypted but no encryption key provided');
        }
        
        const decrypted = await this.encryption.decryptBatch(
          parsed as EncryptedData,
          this.encryptionKey
        );
        
        // Verify merkle root
        if (decrypted.merkleRoot) {
          const expectedRoot = ActivityEncryption.createBatchMerkleRoot(decrypted.activities);
          if (decrypted.merkleRoot !== expectedRoot) {
            throw new Error('Batch integrity check failed');
          }
        }
        
        return decrypted;
      }

      // Verify merkle root for unencrypted data
      if (parsed.merkleRoot) {
        const expectedRoot = ActivityEncryption.createBatchMerkleRoot(parsed.activities);
        if (parsed.merkleRoot !== expectedRoot) {
          throw new Error('Batch integrity check failed');
        }
      }

      return parsed as ActivityBatch;
    } catch (error) {
      throw new Error(`Failed to retrieve activity batch: ${error}`);
    }
  }

  /**
   * Pin an activity to ensure it stays available
   */
  async pinActivity(ipfsHash: string): Promise<void> {
    try {
      await this.ipfs.pin.add(ipfsHash);
    } catch (error) {
      throw new Error(`Failed to pin activity: ${error}`);
    }
  }

  /**
   * Unpin an activity (for cleanup/archival)
   */
  async unpinActivity(ipfsHash: string): Promise<void> {
    try {
      await this.ipfs.pin.rm(ipfsHash);
    } catch (error) {
      throw new Error(`Failed to unpin activity: ${error}`);
    }
  }

  /**
   * Get all pinned activities
   */
  async getPinnedActivities(): Promise<string[]> {
    try {
      const pins: string[] = [];
      
      for await (const pin of this.ipfs.pin.ls()) {
        pins.push(pin.cid.toString());
      }
      
      return pins;
    } catch (error) {
      throw new Error(`Failed to list pinned activities: ${error}`);
    }
  }

  /**
   * Update the manifest for an agent
   */
  private async updateManifest(
    agentDID: string,
    parentDID: string,
    ipfsHash: string
  ): Promise<void> {
    const manifestKey = `${parentDID}:${agentDID}`;
    let manifest = this.manifests.get(manifestKey);

    if (!manifest) {
      manifest = {
        agentDID,
        parentDID,
        created: new Date(),
        lastUpdated: new Date(),
        totalActivities: 0,
        ipfsHashes: [],
        encrypted: !!this.encryptionKey
      };
    }

    manifest.ipfsHashes.push(ipfsHash);
    manifest.totalActivities++;
    manifest.lastUpdated = new Date();

    this.manifests.set(manifestKey, manifest);

    // Store updated manifest to IPFS
    await this.storeManifest(manifest);
  }

  /**
   * Store manifest to IPFS
   */
  private async storeManifest(manifest: ActivityManifest): Promise<string> {
    try {
      const { cid } = await this.ipfs.add(
        JSON.stringify(manifest),
        { pin: true }
      );
      
      return cid.toString();
    } catch (error) {
      throw new Error(`Failed to store manifest: ${error}`);
    }
  }

  /**
   * Get manifest for an agent
   */
  async getManifest(agentDID: string, parentDID: string): Promise<ActivityManifest | null> {
    const manifestKey = `${parentDID}:${agentDID}`;
    return this.manifests.get(manifestKey) || null;
  }

  /**
   * Get storage statistics
   */
  async getStorageStats(): Promise<{
    totalPinned: number;
    totalSize: number;
    manifests: number;
  }> {
    try {
      const pins = await this.getPinnedActivities();
      let totalSize = 0;

      // Note: Getting actual size requires additional IPFS API calls
      // This is a simplified version
      
      return {
        totalPinned: pins.length,
        totalSize,
        manifests: this.manifests.size
      };
    } catch (error) {
      throw new Error(`Failed to get storage stats: ${error}`);
    }
  }

  /**
   * Check if IPFS node is connected
   */
  async isConnected(): Promise<boolean> {
    try {
      const id = await this.ipfs.id();
      return !!id;
    } catch {
      return false;
    }
  }

  /**
   * Set or update encryption key
   */
  setEncryptionKey(key: Uint8Array): void {
    this.encryptionKey = key;
  }
}