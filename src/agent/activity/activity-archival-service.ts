import { AgentActivity, ActivityQuery } from './types';
import { ActivitySearchService } from './activity-search-service';
import { ActivityExporter, ExportFormat, AuditProof } from './activity-exporter';
import { ActivityIndex } from './activity-index';
import { IPFSActivityStorage } from './ipfs-activity-storage';

export interface ArchivalPolicy {
  id: string;
  name: string;
  description: string;
  retentionPeriod: number; // days
  archiveAfter: number; // days
  autoDelete: boolean;
  compressionEnabled: boolean;
  encryptionRequired: boolean;
  complianceStandard?: 'gdpr' | 'hipaa' | 'sox' | 'iso27001';
  triggers: ArchivalTrigger[];
}

export interface ArchivalTrigger {
  type: 'time' | 'size' | 'count' | 'compliance';
  condition: any;
  action: 'archive' | 'delete' | 'export' | 'notify';
}

export interface ArchivalRule {
  agentDID?: string;
  parentDID?: string;
  serviceDID?: string;
  activityTypes?: string[];
  policy: ArchivalPolicy;
  priority: number;
  active: boolean;
}

export interface ArchivalRecord {
  id: string;
  originalActivityIds: string[];
  archiveDate: Date;
  policy: string;
  location: string; // IPFS hash or file path
  checksum: string;
  proof: AuditProof;
  metadata: {
    totalActivities: number;
    dateRange: {
      start: Date;
      end: Date;
    };
    format: ExportFormat;
    compressed: boolean;
    encrypted: boolean;
  };
}

export interface DataRetentionConfig {
  defaultRetentionDays: number;
  maxRetentionDays: number;
  complianceMode: boolean;
  auditLogging: boolean;
  autoArchival: boolean;
  notificationEnabled: boolean;
  warningDays: number; // Days before deletion to warn
}

export interface GDPRComplianceInfo {
  dataSubject: string; // Parent DID
  processingBasis: 'consent' | 'contract' | 'legal_obligation' | 'vital_interests' | 'public_task' | 'legitimate_interests';
  categories: string[]; // Data categories
  recipients: string[]; // Who has access
  retentionPeriod: string;
  rightsInformed: boolean;
  consentWithdrawable: boolean;
}

export class ActivityArchivalService {
  private searchService: ActivitySearchService;
  private exporter: ActivityExporter;
  private index: ActivityIndex;
  private ipfsStorage?: IPFSActivityStorage;
  private config: DataRetentionConfig;
  private policies: Map<string, ArchivalPolicy> = new Map();
  private rules: ArchivalRule[] = [];
  private archivalRecords: Map<string, ArchivalRecord> = new Map();
  private gdprRecords: Map<string, GDPRComplianceInfo> = new Map();

  constructor(
    searchService: ActivitySearchService,
    exporter: ActivityExporter,
    index: ActivityIndex,
    ipfsStorage?: IPFSActivityStorage,
    config: Partial<DataRetentionConfig> = {}
  ) {
    this.searchService = searchService;
    this.exporter = exporter;
    this.index = index;
    this.ipfsStorage = ipfsStorage;
    
    this.config = {
      defaultRetentionDays: 90,
      maxRetentionDays: 2555, // 7 years for compliance
      complianceMode: false,
      auditLogging: true,
      autoArchival: true,
      notificationEnabled: true,
      warningDays: 30,
      ...config
    };

    this.initializeDefaultPolicies();
    this.startArchivalScheduler();
  }

  /**
   * Add archival policy
   */
  addPolicy(policy: ArchivalPolicy): void {
    this.policies.set(policy.id, policy);
  }

  /**
   * Add archival rule
   */
  addRule(rule: ArchivalRule): void {
    this.rules.push(rule);
    this.rules.sort((a, b) => b.priority - a.priority); // Higher priority first
  }

  /**
   * Archive activities based on criteria
   */
  async archiveActivities(
    query: ActivityQuery,
    policyId: string,
    options: {
      deleteOriginals?: boolean;
      createProof?: boolean;
      encryptionKey?: Uint8Array;
    } = {}
  ): Promise<ArchivalRecord> {
    const policy = this.policies.get(policyId);
    if (!policy) {
      throw new Error(`Archival policy not found: ${policyId}`);
    }

    // Get activities to archive
    const searchResult = await this.searchService.searchActivities({
      ...query,
      limit: 50000 // High limit for archival
    });

    if (searchResult.activities.length === 0) {
      throw new Error('No activities found matching archival criteria');
    }

    const activities = searchResult.activities;

    // Export activities for archival
    const exportResult = await this.exporter.exportActivities(query, {
      format: ExportFormat.JSON,
      includeDetails: true,
      includeMetadata: true,
      compression: policy.compressionEnabled,
      encryption: policy.encryptionRequired ? {
        enabled: true,
        key: options.encryptionKey
      } : undefined
    });

    // Store archived data
    let location: string;
    if (this.ipfsStorage) {
      // Store in IPFS
      const ipfsResult = await this.storeInIPFS(exportResult.data);
      location = ipfsResult;
    } else {
      // Store locally (simplified)
      location = `local://archive-${Date.now()}.json`;
    }

    // Create audit proof if requested
    let proof: AuditProof;
    if (options.createProof) {
      proof = await this.exporter.createAuditProof(activities, options.encryptionKey);
    } else {
      // Create minimal proof
      proof = await this.exporter.createAuditProof(activities);
    }

    // Create archival record
    const archivalRecord: ArchivalRecord = {
      id: this.generateId('archive'),
      originalActivityIds: activities.map(a => a.id),
      archiveDate: new Date(),
      policy: policyId,
      location,
      checksum: exportResult.checksum,
      proof,
      metadata: {
        totalActivities: activities.length,
        dateRange: {
          start: activities[activities.length - 1].timestamp, // Oldest first
          end: activities[0].timestamp // Newest first
        },
        format: exportResult.metadata.format,
        compressed: exportResult.metadata.compressed,
        encrypted: exportResult.metadata.encrypted
      }
    };

    this.archivalRecords.set(archivalRecord.id, archivalRecord);

    // Remove original activities if requested
    if (options.deleteOriginals) {
      await this.deleteActivitiesFromIndex(activities.map(a => a.id));
    }

    // Log archival action if audit logging is enabled
    if (this.config.auditLogging) {
      console.log(`Archived ${activities.length} activities using policy ${policyId}`);
    }

    return archivalRecord;
  }

  /**
   * Restore activities from archive
   */
  async restoreActivities(archivalRecordId: string): Promise<AgentActivity[]> {
    const record = this.archivalRecords.get(archivalRecordId);
    if (!record) {
      throw new Error(`Archival record not found: ${archivalRecordId}`);
    }

    // Retrieve archived data
    let archivedData: Buffer | string;
    if (record.location.startsWith('ipfs://') || record.location.length === 46) {
      // IPFS storage
      if (!this.ipfsStorage) {
        throw new Error('IPFS storage not available for restoration');
      }
      archivedData = await this.retrieveFromIPFS(record.location);
    } else {
      // Local storage (simplified)
      throw new Error('Local archive restoration not implemented');
    }

    // Parse activities
    let activities: AgentActivity[];
    try {
      const parsedData = JSON.parse(archivedData.toString());
      
      if (record.metadata.encrypted) {
        throw new Error('Cannot restore encrypted archive without decryption key');
      }

      activities = parsedData.activities || parsedData;
    } catch (error) {
      throw new Error(`Failed to parse archived data: ${error}`);
    }

    // Verify integrity using audit proof
    const verification = await this.exporter.verifyAuditProof(record.proof, activities);
    if (!verification.valid) {
      throw new Error(`Archive integrity verification failed: ${verification.errors.join(', ')}`);
    }

    // Log restoration if audit logging is enabled
    if (this.config.auditLogging) {
      console.log(`Restored ${activities.length} activities from archive ${archivalRecordId}`);
    }

    return activities;
  }

  /**
   * Delete expired activities based on retention policies
   */
  async deleteExpiredActivities(): Promise<{
    deleted: number;
    archived: number;
    warned: number;
  }> {
    const results = { deleted: 0, archived: 0, warned: 0 };
    const now = new Date();

    // Process each active rule
    for (const rule of this.rules.filter(r => r.active)) {
      const policy = this.policies.get(rule.policy.id);
      if (!policy) continue;

      const cutoffDate = new Date(now.getTime() - policy.retentionPeriod * 24 * 60 * 60 * 1000);
      const warningDate = new Date(now.getTime() - (policy.retentionPeriod - this.config.warningDays) * 24 * 60 * 60 * 1000);

      const query: ActivityQuery = {
        agentDID: rule.agentDID,
        parentDID: rule.parentDID,
        serviceDID: rule.serviceDID,
        types: rule.activityTypes as any[],
        dateRange: {
          start: new Date(0), // Beginning of time
          end: cutoffDate
        },
        limit: 10000
      };

      const expiredActivities = await this.searchService.searchActivities(query);

      if (expiredActivities.activities.length > 0) {
        if (policy.autoDelete) {
          // Delete immediately
          await this.deleteActivitiesFromIndex(expiredActivities.activities.map(a => a.id));
          results.deleted += expiredActivities.activities.length;
        } else {
          // Archive before deletion
          await this.archiveActivities(query, policy.id, { deleteOriginals: true });
          results.archived += expiredActivities.activities.length;
        }
      }

      // Check for activities approaching expiration
      if (this.config.notificationEnabled) {
        const warningQuery: ActivityQuery = {
          ...query,
          dateRange: {
            start: new Date(0),
            end: warningDate
          }
        };

        const warningActivities = await this.searchService.searchActivities(warningQuery);
        if (warningActivities.activities.length > 0) {
          results.warned += warningActivities.activities.length;
          await this.sendExpirationWarning(rule, warningActivities.activities);
        }
      }
    }

    return results;
  }

  /**
   * Register GDPR compliance information
   */
  registerGDPRCompliance(parentDID: string, info: GDPRComplianceInfo): void {
    this.gdprRecords.set(parentDID, info);
  }

  /**
   * Handle GDPR data subject request (right to be forgotten)
   */
  async handleGDPRDataDeletion(parentDID: string): Promise<{
    activitiesDeleted: number;
    archivesDeleted: number;
  }> {
    const gdprInfo = this.gdprRecords.get(parentDID);
    if (!gdprInfo) {
      throw new Error(`No GDPR compliance information found for ${parentDID}`);
    }

    // Delete all activities for this data subject
    const query: ActivityQuery = {
      parentDID,
      limit: 50000
    };

    const activities = await this.searchService.searchActivities(query);
    await this.deleteActivitiesFromIndex(activities.activities.map(a => a.id));

    // Delete related archives
    const relatedArchives = Array.from(this.archivalRecords.values())
      .filter(record => record.originalActivityIds.some(id => 
        activities.activities.some(a => a.id === id)
      ));

    for (const archive of relatedArchives) {
      await this.deleteArchive(archive.id);
    }

    // Log GDPR deletion
    if (this.config.auditLogging) {
      console.log(`GDPR deletion completed for ${parentDID}: ${activities.total} activities, ${relatedArchives.length} archives`);
    }

    return {
      activitiesDeleted: activities.total,
      archivesDeleted: relatedArchives.length
    };
  }

  /**
   * Generate data retention report
   */
  async generateRetentionReport(): Promise<{
    totalActivities: number;
    activitiesByAge: Record<string, number>;
    archivalRecords: number;
    upcomingExpirations: number;
    complianceStatus: string;
  }> {
    const stats = this.index.getStats();
    const now = new Date();

    // Calculate activities by age
    const activitiesByAge: Record<string, number> = {
      '0-30 days': 0,
      '31-90 days': 0,
      '91-365 days': 0,
      '1+ years': 0
    };

    // This would need to query the index for age-based counts
    // Simplified for now
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
    const oneYearAgo = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);

    const recentQuery = await this.searchService.searchActivities({
      dateRange: { start: thirtyDaysAgo, end: now },
      limit: 10000
    });
    activitiesByAge['0-30 days'] = recentQuery.total;

    // Calculate upcoming expirations
    let upcomingExpirations = 0;
    for (const rule of this.rules.filter(r => r.active)) {
      const policy = this.policies.get(rule.policy.id);
      if (!policy) continue;

      const expirationDate = new Date(now.getTime() + this.config.warningDays * 24 * 60 * 60 * 1000);
      const cutoffDate = new Date(expirationDate.getTime() - policy.retentionPeriod * 24 * 60 * 60 * 1000);

      const expiringQuery = await this.searchService.searchActivities({
        agentDID: rule.agentDID,
        parentDID: rule.parentDID,
        dateRange: { start: new Date(0), end: cutoffDate },
        limit: 1000
      });

      upcomingExpirations += expiringQuery.total;
    }

    return {
      totalActivities: stats.totalActivities,
      activitiesByAge,
      archivalRecords: this.archivalRecords.size,
      upcomingExpirations,
      complianceStatus: this.config.complianceMode ? 'enabled' : 'disabled'
    };
  }

  // Private helper methods

  private initializeDefaultPolicies(): void {
    // GDPR compliance policy
    this.addPolicy({
      id: 'gdpr-default',
      name: 'GDPR Default Retention',
      description: 'Default GDPR-compliant data retention policy',
      retentionPeriod: 90, // 3 months
      archiveAfter: 60,
      autoDelete: false,
      compressionEnabled: true,
      encryptionRequired: true,
      complianceStandard: 'gdpr',
      triggers: [
        {
          type: 'time',
          condition: { days: 90 },
          action: 'archive'
        }
      ]
    });

    // Standard policy
    this.addPolicy({
      id: 'standard',
      name: 'Standard Retention',
      description: 'Standard data retention policy',
      retentionPeriod: 365, // 1 year
      archiveAfter: 180,
      autoDelete: false,
      compressionEnabled: true,
      encryptionRequired: false,
      triggers: [
        {
          type: 'time',
          condition: { days: 180 },
          action: 'archive'
        }
      ]
    });

    // Long-term policy
    this.addPolicy({
      id: 'long-term',
      name: 'Long-term Retention',
      description: 'Long-term data retention for compliance',
      retentionPeriod: 2555, // 7 years
      archiveAfter: 365,
      autoDelete: false,
      compressionEnabled: true,
      encryptionRequired: true,
      triggers: [
        {
          type: 'time',
          condition: { days: 365 },
          action: 'archive'
        }
      ]
    });
  }

  private startArchivalScheduler(): void {
    if (!this.config.autoArchival) return;

    // Run archival check every day
    setInterval(async () => {
      try {
        await this.deleteExpiredActivities();
      } catch (error) {
        console.error('Archival scheduler error:', error);
      }
    }, 24 * 60 * 60 * 1000); // 24 hours
  }

  private async deleteActivitiesFromIndex(activityIds: string[]): Promise<void> {
    for (const id of activityIds) {
      await this.index.removeActivity(id);
    }
  }

  private async storeInIPFS(data: Buffer | string): Promise<string> {
    if (!this.ipfsStorage) {
      throw new Error('IPFS storage not available');
    }

    // Create a temporary activity to use IPFS storage
    const tempActivity = {
      id: 'archive-temp',
      data: Buffer.isBuffer(data) ? data.toString() : data
    } as any;

    const result = await this.ipfsStorage.storeActivity(tempActivity);
    return result.ipfsHash;
  }

  private async retrieveFromIPFS(hash: string): Promise<Buffer> {
    if (!this.ipfsStorage) {
      throw new Error('IPFS storage not available');
    }

    const activity = await this.ipfsStorage.retrieveActivity(hash);
    return Buffer.from((activity as any).data);
  }

  private async deleteArchive(archiveId: string): Promise<void> {
    const record = this.archivalRecords.get(archiveId);
    if (!record) return;

    // Delete from IPFS if stored there
    if (this.ipfsStorage && (record.location.startsWith('ipfs://') || record.location.length === 46)) {
      // IPFS doesn't support deletion, but we can unpin
      try {
        await this.ipfsStorage.unpinActivity(record.location);
      } catch (error) {
        console.warn(`Failed to unpin IPFS content: ${error}`);
      }
    }

    this.archivalRecords.delete(archiveId);
  }

  private async sendExpirationWarning(rule: ArchivalRule, activities: AgentActivity[]): Promise<void> {
    // Simplified warning - in production would send email/notification
    console.log(`Warning: ${activities.length} activities will expire soon for rule ${rule.policy.name}`);
  }

  private generateId(prefix: string): string {
    return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}