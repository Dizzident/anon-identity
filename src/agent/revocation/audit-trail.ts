import { RevocationAuditEntry } from './cascading-revocation-manager';
import { AgentIdentity, DelegationCredential } from '../types';
import { ActivityLogger, createActivity } from '../activity/activity-logger';
import { ActivityType, ActivityStatus } from '../activity/types';

export interface AuditQuery {
  agentDID?: string;
  revokedBy?: string;
  serviceDID?: string;
  reason?: string;
  status?: 'pending' | 'completed' | 'failed' | 'partial';
  dateRange?: {
    start: Date;
    end: Date;
  };
  cascading?: boolean;
  limit?: number;
  offset?: number;
  sortBy?: 'timestamp' | 'agentDID' | 'status';
  sortOrder?: 'asc' | 'desc';
}

export interface AuditAnalytics {
  totalRevocations: number;
  revocationsByReason: Map<string, number>;
  revocationsByService: Map<string, number>;
  revocationsByUser: Map<string, number>;
  revocationsByStatus: Map<string, number>;
  cascadingPercentage: number;
  averageChildRevocations: number;
  peakRevocationHours: number[];
  revocationTrends: {
    daily: Map<string, number>;
    weekly: Map<string, number>;
    monthly: Map<string, number>;
  };
  complianceMetrics: {
    auditCompleteness: number;
    notificationSuccessRate: number;
    avgProcessingTime: number;
  };
}

export interface AuditAlert {
  id: string;
  type: 'high_volume' | 'cascade_failure' | 'notification_failure' | 'suspicious_pattern';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: Date;
  affectedAgents: string[];
  metadata: Record<string, any>;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
}

/**
 * Enhanced audit trail system for delegation revocations
 * Provides advanced querying, analytics, and monitoring capabilities
 */
export class EnhancedAuditTrail {
  private auditEntries: Map<string, RevocationAuditEntry> = new Map();
  private alertSubscribers: Map<string, (alert: AuditAlert) => void> = new Map();
  private alerts: Map<string, AuditAlert> = new Map();
  private lastAnalyticsUpdate: Date = new Date();
  private cachedAnalytics: AuditAnalytics | null = null;

  constructor(
    private activityLogger: ActivityLogger,
    private config: {
      maxEntries: number;
      alertThresholds: {
        highVolumeMinutes: number;
        highVolumeCount: number;
        cascadeFailureThreshold: number;
        notificationFailureThreshold: number;
      };
      retentionDays: number;
    } = {
      maxEntries: 10000,
      alertThresholds: {
        highVolumeMinutes: 60,
        highVolumeCount: 50,
        cascadeFailureThreshold: 0.8,
        notificationFailureThreshold: 0.7
      },
      retentionDays: 365
    }
  ) {}

  /**
   * Adds a revocation audit entry to the trail
   */
  async addAuditEntry(entry: RevocationAuditEntry): Promise<void> {
    this.auditEntries.set(entry.id, entry);

    // Log audit entry creation
    await this.activityLogger.logActivity(createActivity(
      ActivityType.REVOCATION,
      {
        agentDID: entry.targetAgentDID,
        parentDID: '',
        serviceDID: entry.serviceDID || 'all',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {
          action: 'audit_entry_created',
          auditId: entry.id,
          cascading: entry.cascading,
          childCount: entry.childRevocations.length
        }
      }
    ));

    // Check for alerts
    await this.checkAlerts(entry);

    // Invalidate cached analytics
    this.cachedAnalytics = null;

    // Clean up old entries if needed
    await this.cleanupOldEntries();
  }

  /**
   * Updates an existing audit entry
   */
  async updateAuditEntry(id: string, updates: Partial<RevocationAuditEntry>): Promise<boolean> {
    const entry = this.auditEntries.get(id);
    if (!entry) {
      return false;
    }

    const updatedEntry = { ...entry, ...updates };
    this.auditEntries.set(id, updatedEntry);

    // Log audit entry update
    await this.activityLogger.logActivity(createActivity(
      ActivityType.REVOCATION,
      {
        agentDID: entry.targetAgentDID,
        parentDID: '',
        serviceDID: entry.serviceDID || 'all',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {
          action: 'audit_entry_updated',
          auditId: id,
          updatedFields: Object.keys(updates)
        }
      }
    ));

    // Invalidate cached analytics
    this.cachedAnalytics = null;

    return true;
  }

  /**
   * Queries audit entries with advanced filtering
   */
  queryAuditEntries(query: AuditQuery = {}): RevocationAuditEntry[] {
    let entries = Array.from(this.auditEntries.values());

    // Apply filters
    if (query.agentDID) {
      entries = entries.filter(entry => 
        entry.targetAgentDID === query.agentDID || 
        entry.childRevocations.includes(query.agentDID!)
      );
    }

    if (query.revokedBy) {
      entries = entries.filter(entry => entry.revokedBy === query.revokedBy);
    }

    if (query.serviceDID) {
      entries = entries.filter(entry => entry.serviceDID === query.serviceDID);
    }

    if (query.reason) {
      entries = entries.filter(entry => 
        entry.reason.toLowerCase().includes(query.reason!.toLowerCase())
      );
    }

    if (query.status) {
      entries = entries.filter(entry => entry.status === query.status);
    }

    if (query.dateRange) {
      entries = entries.filter(entry => 
        entry.timestamp >= query.dateRange!.start && 
        entry.timestamp <= query.dateRange!.end
      );
    }

    if (query.cascading !== undefined) {
      entries = entries.filter(entry => entry.cascading === query.cascading);
    }

    // Sort entries
    const sortField = query.sortBy || 'timestamp';
    const sortOrder = query.sortOrder || 'desc';
    
    entries.sort((a, b) => {
      let aVal: any, bVal: any;
      
      switch (sortField) {
        case 'timestamp':
          aVal = a.timestamp.getTime();
          bVal = b.timestamp.getTime();
          break;
        case 'agentDID':
          aVal = a.targetAgentDID;
          bVal = b.targetAgentDID;
          break;
        case 'status':
          aVal = a.status;
          bVal = b.status;
          break;
        default:
          aVal = a.timestamp.getTime();
          bVal = b.timestamp.getTime();
      }

      if (sortOrder === 'asc') {
        return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
      } else {
        return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
      }
    });

    // Apply pagination
    if (query.offset) {
      entries = entries.slice(query.offset);
    }

    if (query.limit) {
      entries = entries.slice(0, query.limit);
    }

    return entries;
  }

  /**
   * Generates comprehensive analytics from audit data
   */
  generateAnalytics(forceRefresh: boolean = false): AuditAnalytics {
    const cacheValidityMinutes = 15;
    const cacheAge = Date.now() - this.lastAnalyticsUpdate.getTime();
    
    if (!forceRefresh && this.cachedAnalytics && cacheAge < cacheValidityMinutes * 60 * 1000) {
      return this.cachedAnalytics;
    }

    const entries = Array.from(this.auditEntries.values());
    const analytics: AuditAnalytics = {
      totalRevocations: entries.length,
      revocationsByReason: new Map(),
      revocationsByService: new Map(),
      revocationsByUser: new Map(),
      revocationsByStatus: new Map(),
      cascadingPercentage: 0,
      averageChildRevocations: 0,
      peakRevocationHours: [],
      revocationTrends: {
        daily: new Map(),
        weekly: new Map(),
        monthly: new Map()
      },
      complianceMetrics: {
        auditCompleteness: 0,
        notificationSuccessRate: 0,
        avgProcessingTime: 0
      }
    };

    if (entries.length === 0) {
      this.cachedAnalytics = analytics;
      this.lastAnalyticsUpdate = new Date();
      return analytics;
    }

    // Basic aggregations
    let totalChildRevocations = 0;
    let totalNotificationsSent = 0;
    let totalNotificationsAttempted = 0;
    let totalProcessingTime = 0;
    const hourCounts = new Array(24).fill(0);

    entries.forEach(entry => {
      // Reason analysis
      const count = analytics.revocationsByReason.get(entry.reason) || 0;
      analytics.revocationsByReason.set(entry.reason, count + 1);

      // Service analysis
      const serviceKey = entry.serviceDID || 'global';
      const serviceCount = analytics.revocationsByService.get(serviceKey) || 0;
      analytics.revocationsByService.set(serviceKey, serviceCount + 1);

      // User analysis
      const userCount = analytics.revocationsByUser.get(entry.revokedBy) || 0;
      analytics.revocationsByUser.set(entry.revokedBy, userCount + 1);

      // Status analysis
      const statusCount = analytics.revocationsByStatus.get(entry.status) || 0;
      analytics.revocationsByStatus.set(entry.status, statusCount + 1);

      // Child revocations
      totalChildRevocations += entry.childRevocations.length;

      // Notifications
      totalNotificationsSent += entry.notificationsSent.length;
      if (entry.childRevocations.length > 0 || entry.targetAgentDID) {
        totalNotificationsAttempted += 1; // Estimate
      }

      // Time analysis
      const hour = entry.timestamp.getHours();
      hourCounts[hour]++;

      // Processing time (estimate based on complexity)
      const complexity = 1 + entry.childRevocations.length * 0.5;
      totalProcessingTime += complexity;

      // Trends
      const dateKey = entry.timestamp.toISOString().split('T')[0];
      const weekKey = this.getWeekKey(entry.timestamp);
      const monthKey = entry.timestamp.toISOString().substring(0, 7);

      analytics.revocationTrends.daily.set(dateKey, (analytics.revocationTrends.daily.get(dateKey) || 0) + 1);
      analytics.revocationTrends.weekly.set(weekKey, (analytics.revocationTrends.weekly.get(weekKey) || 0) + 1);
      analytics.revocationTrends.monthly.set(monthKey, (analytics.revocationTrends.monthly.get(monthKey) || 0) + 1);
    });

    // Calculate derived metrics
    const cascadingCount = entries.filter(e => e.cascading).length;
    analytics.cascadingPercentage = entries.length > 0 ? (cascadingCount / entries.length) * 100 : 0;
    analytics.averageChildRevocations = entries.length > 0 ? totalChildRevocations / entries.length : 0;

    // Find peak hours (top 3)
    const hourIndices = Array.from({ length: 24 }, (_, i) => i);
    analytics.peakRevocationHours = hourIndices
      .sort((a, b) => hourCounts[b] - hourCounts[a])
      .slice(0, 3);

    // Compliance metrics
    const completedEntries = entries.filter(e => e.status === 'completed' || e.status === 'partial');
    analytics.complianceMetrics.auditCompleteness = entries.length > 0 ? (completedEntries.length / entries.length) * 100 : 100;
    analytics.complianceMetrics.notificationSuccessRate = totalNotificationsAttempted > 0 ? (totalNotificationsSent / totalNotificationsAttempted) * 100 : 100;
    analytics.complianceMetrics.avgProcessingTime = entries.length > 0 ? totalProcessingTime / entries.length : 0;

    this.cachedAnalytics = analytics;
    this.lastAnalyticsUpdate = new Date();
    return analytics;
  }

  /**
   * Subscribes to audit alerts
   */
  subscribeToAlerts(subscriberId: string, callback: (alert: AuditAlert) => void): void {
    this.alertSubscribers.set(subscriberId, callback);
  }

  /**
   * Unsubscribes from audit alerts
   */
  unsubscribeFromAlerts(subscriberId: string): void {
    this.alertSubscribers.delete(subscriberId);
  }

  /**
   * Gets all active alerts
   */
  getActiveAlerts(): AuditAlert[] {
    return Array.from(this.alerts.values()).filter(alert => !alert.acknowledged);
  }

  /**
   * Acknowledges an alert
   */
  async acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<boolean> {
    const alert = this.alerts.get(alertId);
    if (!alert) {
      return false;
    }

    alert.acknowledged = true;
    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date();

    // Log alert acknowledgment
    await this.activityLogger.logActivity(createActivity(
      ActivityType.REVOCATION,
      {
        agentDID: 'system',
        parentDID: '',
        serviceDID: 'monitoring',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {
          action: 'alert_acknowledged',
          alertId,
          alertType: alert.type,
          acknowledgedBy
        }
      }
    ));

    return true;
  }

  /**
   * Exports audit data in various formats
   */
  exportAuditData(format: 'json' | 'csv' | 'xml', query: AuditQuery = {}): string {
    const entries = this.queryAuditEntries(query);

    switch (format) {
      case 'json':
        return JSON.stringify(entries, null, 2);

      case 'csv':
        return this.exportToCsv(entries);

      case 'xml':
        return this.exportToXml(entries);

      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Generates compliance report
   */
  generateComplianceReport(period: { start: Date; end: Date }): {
    summary: {
      totalRevocations: number;
      successfulRevocations: number;
      failedRevocations: number;
      partialRevocations: number;
      complianceScore: number;
    };
    details: {
      auditCompleteness: number;
      notificationDelivery: number;
      processingTime: number;
      errorRate: number;
    };
    recommendations: string[];
    violations: Array<{
      type: string;
      severity: 'low' | 'medium' | 'high';
      description: string;
      affectedEntries: string[];
    }>;
  } {
    const entries = this.queryAuditEntries({
      dateRange: period
    });

    const successful = entries.filter(e => e.status === 'completed').length;
    const failed = entries.filter(e => e.status === 'failed').length;
    const partial = entries.filter(e => e.status === 'partial').length;

    const analytics = this.generateAnalytics(true);
    
    const complianceScore = entries.length > 0 ? 
      ((successful + partial * 0.5) / entries.length) * 100 : 100;

    const recommendations: string[] = [];
    const violations: Array<{
      type: string;
      severity: 'low' | 'medium' | 'high';
      description: string;
      affectedEntries: string[];
    }> = [];

    // Generate recommendations based on analytics
    if (analytics.complianceMetrics.notificationSuccessRate < 90) {
      recommendations.push('Improve notification delivery reliability');
    }

    if (analytics.cascadingPercentage > 70) {
      recommendations.push('Review delegation depth policies to reduce excessive cascading');
    }

    if (failed > entries.length * 0.1) {
      recommendations.push('Investigate high failure rate in revocations');
      violations.push({
        type: 'high_failure_rate',
        severity: 'high',
        description: `Failure rate exceeds 10% (${(failed/entries.length*100).toFixed(1)}%)`,
        affectedEntries: entries.filter(e => e.status === 'failed').map(e => e.id)
      });
    }

    return {
      summary: {
        totalRevocations: entries.length,
        successfulRevocations: successful,
        failedRevocations: failed,
        partialRevocations: partial,
        complianceScore
      },
      details: {
        auditCompleteness: analytics.complianceMetrics.auditCompleteness,
        notificationDelivery: analytics.complianceMetrics.notificationSuccessRate,
        processingTime: analytics.complianceMetrics.avgProcessingTime,
        errorRate: entries.length > 0 ? (failed / entries.length) * 100 : 0
      },
      recommendations,
      violations
    };
  }

  // Private helper methods

  private async checkAlerts(entry: RevocationAuditEntry): Promise<void> {
    const now = new Date();
    const recentWindow = new Date(now.getTime() - this.config.alertThresholds.highVolumeMinutes * 60 * 1000);
    
    // Check for high volume
    const recentEntries = Array.from(this.auditEntries.values())
      .filter(e => e.timestamp >= recentWindow);
      
    if (recentEntries.length >= this.config.alertThresholds.highVolumeCount) {
      await this.createAlert('high_volume', 'medium', 
        `High revocation volume: ${recentEntries.length} revocations in ${this.config.alertThresholds.highVolumeMinutes} minutes`,
        recentEntries.map(e => e.targetAgentDID)
      );
    }

    // Check for cascade failures
    if (entry.cascading && entry.status === 'failed') {
      await this.createAlert('cascade_failure', 'high',
        `Cascading revocation failed for agent ${entry.targetAgentDID}`,
        [entry.targetAgentDID, ...entry.childRevocations]
      );
    }

    // Check for notification failures
    const expectedNotifications = entry.childRevocations.length + 1; // +1 for parent chain
    const actualNotifications = entry.notificationsSent.length;
    
    if (expectedNotifications > 0 && (actualNotifications / expectedNotifications) < this.config.alertThresholds.notificationFailureThreshold) {
      await this.createAlert('notification_failure', 'medium',
        `Notification delivery below threshold for revocation ${entry.id}`,
        [entry.targetAgentDID]
      );
    }
  }

  private async createAlert(
    type: AuditAlert['type'],
    severity: AuditAlert['severity'],
    message: string,
    affectedAgents: string[]
  ): Promise<void> {
    const alert: AuditAlert = {
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type,
      severity,
      message,
      timestamp: new Date(),
      affectedAgents,
      metadata: {},
      acknowledged: false
    };

    this.alerts.set(alert.id, alert);

    // Notify subscribers
    this.alertSubscribers.forEach(callback => {
      try {
        callback(alert);
      } catch (error) {
        console.error('Error notifying alert subscriber:', error);
      }
    });

    // Log alert creation
    await this.activityLogger.logActivity(createActivity(
      ActivityType.REVOCATION,
      {
        agentDID: 'system',
        parentDID: '',
        serviceDID: 'monitoring',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {
          action: 'alert_created',
          alertId: alert.id,
          alertType: type,
          severity,
          affectedCount: affectedAgents.length
        }
      }
    ));
  }

  private async cleanupOldEntries(): Promise<void> {
    if (this.auditEntries.size <= this.config.maxEntries) {
      return;
    }

    const cutoffDate = new Date(Date.now() - this.config.retentionDays * 24 * 60 * 60 * 1000);
    const entriesToDelete: string[] = [];

    for (const [id, entry] of this.auditEntries.entries()) {
      if (entry.timestamp < cutoffDate || this.auditEntries.size - entriesToDelete.length > this.config.maxEntries) {
        entriesToDelete.push(id);
      }
    }

    entriesToDelete.forEach(id => this.auditEntries.delete(id));

    if (entriesToDelete.length > 0) {
      await this.activityLogger.logActivity(createActivity(
        ActivityType.REVOCATION,
        {
          agentDID: 'system',
          parentDID: '',
          serviceDID: 'audit',
          status: ActivityStatus.SUCCESS,
          scopes: [],
          details: {
            action: 'audit_cleanup',
            deletedCount: entriesToDelete.length,
            remainingCount: this.auditEntries.size
          }
        }
      ));
    }
  }

  private exportToCsv(entries: RevocationAuditEntry[]): string {
    const headers = [
      'id', 'targetAgentDID', 'revokedBy', 'reason', 'timestamp',
      'cascading', 'serviceDID', 'effectiveDate', 'childRevocationsCount',
      'notificationsSentCount', 'status'
    ];

    const rows = entries.map(entry => [
      entry.id,
      entry.targetAgentDID,
      entry.revokedBy,
      entry.reason,
      entry.timestamp.toISOString(),
      entry.cascading.toString(),
      entry.serviceDID || '',
      entry.effectiveDate.toISOString(),
      entry.childRevocations.length.toString(),
      entry.notificationsSent.length.toString(),
      entry.status
    ]);

    return [headers, ...rows].map(row => row.join(',')).join('\n');
  }

  private exportToXml(entries: RevocationAuditEntry[]): string {
    const xmlHeader = '<?xml version="1.0" encoding="UTF-8"?>\n<auditTrail>\n';
    const xmlFooter = '</auditTrail>';

    const xmlEntries = entries.map(entry => {
      return `  <entry>
    <id>${this.escapeXml(entry.id)}</id>
    <targetAgentDID>${this.escapeXml(entry.targetAgentDID)}</targetAgentDID>
    <revokedBy>${this.escapeXml(entry.revokedBy)}</revokedBy>
    <reason>${this.escapeXml(entry.reason)}</reason>
    <timestamp>${entry.timestamp.toISOString()}</timestamp>
    <cascading>${entry.cascading}</cascading>
    <serviceDID>${this.escapeXml(entry.serviceDID || '')}</serviceDID>
    <effectiveDate>${entry.effectiveDate.toISOString()}</effectiveDate>
    <childRevocationsCount>${entry.childRevocations.length}</childRevocationsCount>
    <notificationsSentCount>${entry.notificationsSent.length}</notificationsSentCount>
    <status>${entry.status}</status>
  </entry>`;
    }).join('\n');

    return xmlHeader + xmlEntries + '\n' + xmlFooter;
  }

  private escapeXml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  private getWeekKey(date: Date): string {
    const year = date.getFullYear();
    const week = this.getWeekNumber(date);
    return `${year}-W${week.toString().padStart(2, '0')}`;
  }

  private getWeekNumber(date: Date): number {
    const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
    const dayNum = d.getUTCDay() || 7;
    d.setUTCDate(d.getUTCDate() + 4 - dayNum);
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil((((d.getTime() - yearStart.getTime()) / 86400000) + 1) / 7);
  }
}