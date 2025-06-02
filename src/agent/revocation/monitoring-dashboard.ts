import { EnhancedAuditTrail, AuditAnalytics, AuditAlert, AuditQuery } from './audit-trail';
import { CascadingRevocationManager } from './cascading-revocation-manager';
import { AgentIdentityManager } from '../agent-identity';
import { AgentIdentity } from '../types';
import { ActivityLogger } from '../activity/activity-logger';

export interface DashboardConfig {
  refreshInterval: number; // milliseconds
  alertRetentionDays: number;
  maxDisplayItems: number;
  enableRealTimeUpdates: boolean;
  alertNotifications: {
    email?: string[];
    webhook?: string;
    slack?: string;
  };
}

export interface DashboardMetrics {
  realTime: {
    activeAgents: number;
    ongoingRevocations: number;
    alertsInLast24h: number;
    systemHealth: 'healthy' | 'warning' | 'critical';
  };
  historical: {
    totalRevocations: number;
    successRate: number;
    avgProcessingTime: number;
    peakRevocationTime: string;
  };
  trends: {
    dailyRevocations: Array<{ date: string; count: number }>;
    revocationReasons: Array<{ reason: string; count: number; percentage: number }>;
    serviceImpact: Array<{ service: string; revocations: number; agents: number }>;
  };
  alerts: {
    active: AuditAlert[];
    recent: AuditAlert[];
    summary: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
}

export interface DashboardFilter {
  timeRange: '1h' | '24h' | '7d' | '30d' | 'custom';
  customRange?: { start: Date; end: Date };
  services?: string[];
  users?: string[];
  statuses?: string[];
  alertTypes?: string[];
}

/**
 * Monitoring dashboard for revocation and delegation audit trail
 * Provides real-time metrics, analytics, and alerting capabilities
 */
export class RevocationMonitoringDashboard {
  private metrics: DashboardMetrics | null = null;
  private lastUpdate: Date = new Date(0);
  private subscribers: Map<string, (metrics: DashboardMetrics) => void> = new Map();
  private refreshTimer: NodeJS.Timeout | null = null;

  constructor(
    private auditTrail: EnhancedAuditTrail,
    private revocationManager: CascadingRevocationManager,
    private agentManager: AgentIdentityManager,
    private activityLogger: ActivityLogger,
    private config: DashboardConfig = {
      refreshInterval: 30000, // 30 seconds
      alertRetentionDays: 30,
      maxDisplayItems: 100,
      enableRealTimeUpdates: true,
      alertNotifications: {}
    }
  ) {
    this.startAutoRefresh();
    this.subscribeToAlerts();
  }

  /**
   * Gets current dashboard metrics
   */
  async getMetrics(filter: DashboardFilter = { timeRange: '24h' }): Promise<DashboardMetrics> {
    const shouldRefresh = this.shouldRefreshMetrics();
    
    if (!this.metrics || shouldRefresh) {
      await this.refreshMetrics(filter);
    }

    return this.metrics!;
  }

  /**
   * Subscribes to real-time dashboard updates
   */
  subscribe(subscriberId: string, callback: (metrics: DashboardMetrics) => void): void {
    this.subscribers.set(subscriberId, callback);
  }

  /**
   * Unsubscribes from dashboard updates
   */
  unsubscribe(subscriberId: string): void {
    this.subscribers.delete(subscriberId);
  }

  /**
   * Forces a refresh of dashboard metrics
   */
  async refreshMetrics(filter: DashboardFilter = { timeRange: '24h' }): Promise<DashboardMetrics> {
    const timeRange = this.calculateTimeRange(filter);
    const analytics = this.auditTrail.generateAnalytics(true);
    const activeAlerts = this.auditTrail.getActiveAlerts();
    
    // Get recent alerts
    const recentAlerts = this.getRecentAlerts(filter);
    
    // Calculate real-time metrics
    const realTimeMetrics = await this.calculateRealTimeMetrics();
    
    // Calculate historical metrics
    const historicalMetrics = this.calculateHistoricalMetrics(analytics, timeRange);
    
    // Calculate trends
    const trends = this.calculateTrends(analytics, timeRange);
    
    // Alert summary
    const alertSummary = this.calculateAlertSummary(activeAlerts);

    this.metrics = {
      realTime: realTimeMetrics,
      historical: historicalMetrics,
      trends,
      alerts: {
        active: activeAlerts,
        recent: recentAlerts,
        summary: alertSummary
      }
    };

    this.lastUpdate = new Date();
    
    // Notify subscribers
    this.notifySubscribers(this.metrics);
    
    return this.metrics;
  }

  /**
   * Gets revocation statistics for a specific time period
   */
  getRevocationStats(filter: DashboardFilter): {
    totalRevocations: number;
    successfulRevocations: number;
    failedRevocations: number;
    averageProcessingTime: number;
    topReasons: Array<{ reason: string; count: number }>;
    topServices: Array<{ service: string; count: number }>;
  } {
    const timeRange = this.calculateTimeRange(filter);
    const query: AuditQuery = { dateRange: timeRange };
    
    const entries = this.auditTrail.queryAuditEntries(query);
    
    const successful = entries.filter(e => e.status === 'completed').length;
    const failed = entries.filter(e => e.status === 'failed').length;
    
    // Count reasons
    const reasonCounts = new Map<string, number>();
    const serviceCounts = new Map<string, number>();
    
    entries.forEach(entry => {
      reasonCounts.set(entry.reason, (reasonCounts.get(entry.reason) || 0) + 1);
      const service = entry.serviceDID || 'global';
      serviceCounts.set(service, (serviceCounts.get(service) || 0) + 1);
    });

    const topReasons = Array.from(reasonCounts.entries())
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([reason, count]) => ({ reason, count }));

    const topServices = Array.from(serviceCounts.entries())
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([service, count]) => ({ service, count }));

    return {
      totalRevocations: entries.length,
      successfulRevocations: successful,
      failedRevocations: failed,
      averageProcessingTime: entries.length > 0 ? entries.length * 0.5 : 0, // Estimate
      topReasons,
      topServices
    };
  }

  /**
   * Gets agent health overview
   */
  getAgentHealthOverview(): {
    totalAgents: number;
    activeAgents: number;
    revokedAgents: number;
    agentsWithIssues: number;
    delegationDepthDistribution: Map<number, number>;
    recentlyCreated: number;
    recentlyRevoked: number;
  } {
    const allAgents = this.agentManager.getAllAgents();
    const now = new Date();
    const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    
    const depthDistribution = new Map<number, number>();
    let revokedCount = 0;
    let issuesCount = 0;
    let recentlyCreated = 0;
    let recentlyRevoked = 0;

    allAgents.forEach((agent: AgentIdentity) => {
      // Depth distribution
      const depth = agent.delegationDepth || 0;
      depthDistribution.set(depth, (depthDistribution.get(depth) || 0) + 1);
      
      // Check if revoked
      if (this.revocationManager.isAgentRevoked(agent.did)) {
        revokedCount++;
        
        // Check if recently revoked
        const auditEntries = this.revocationManager.getRevocationAudit(agent.did);
        if (auditEntries.some(entry => entry.timestamp >= last24h)) {
          recentlyRevoked++;
        }
      }
      
      // Check for issues (example: approaching max depth)
      if (agent.delegationDepth >= (agent.maxDelegationDepth || 3) - 1) {
        issuesCount++;
      }
    });

    return {
      totalAgents: allAgents.length,
      activeAgents: allAgents.length - revokedCount,
      revokedAgents: revokedCount,
      agentsWithIssues: issuesCount,
      delegationDepthDistribution: depthDistribution,
      recentlyCreated: 0, // Would need creation timestamps
      recentlyRevoked
    };
  }

  /**
   * Generates dashboard report
   */
  generateReport(filter: DashboardFilter, format: 'json' | 'html' | 'pdf' = 'json'): string {
    const metrics = this.metrics;
    if (!metrics) {
      throw new Error('No metrics available. Call refreshMetrics() first.');
    }

    const stats = this.getRevocationStats(filter);
    const healthOverview = this.getAgentHealthOverview();
    
    const report = {
      generatedAt: new Date().toISOString(),
      filter,
      summary: {
        systemHealth: metrics.realTime.systemHealth,
        totalRevocations: stats.totalRevocations,
        successRate: stats.totalRevocations > 0 ? (stats.successfulRevocations / stats.totalRevocations) * 100 : 100,
        activeAlerts: metrics.alerts.active.length,
        agentHealth: healthOverview
      },
      metrics,
      statistics: stats,
      recommendations: this.generateRecommendations(metrics, stats, healthOverview)
    };

    switch (format) {
      case 'json':
        return JSON.stringify(report, null, 2);
      case 'html':
        return this.generateHtmlReport(report);
      case 'pdf':
        throw new Error('PDF format not implemented yet');
      default:
        return JSON.stringify(report, null, 2);
    }
  }

  /**
   * Stops the dashboard and cleans up resources
   */
  stop(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.subscribers.clear();
  }

  // Private helper methods

  private startAutoRefresh(): void {
    if (!this.config.enableRealTimeUpdates) {
      return;
    }

    this.refreshTimer = setInterval(async () => {
      try {
        await this.refreshMetrics();
      } catch (error) {
        console.error('Dashboard auto-refresh error:', error);
      }
    }, this.config.refreshInterval);
  }

  private subscribeToAlerts(): void {
    this.auditTrail.subscribeToAlerts('dashboard', (alert) => {
      // Handle new alerts for notifications
      this.handleNewAlert(alert);
    });
  }

  private async handleNewAlert(alert: AuditAlert): Promise<void> {
    // Send notifications if configured
    if (this.config.alertNotifications.email && alert.severity === 'critical') {
      // Email notification logic would go here
      console.log(`Critical alert: ${alert.message}`);
    }

    if (this.config.alertNotifications.webhook) {
      // Webhook notification logic would go here
      console.log(`Webhook alert: ${alert.message}`);
    }

    // Refresh metrics to include new alert
    await this.refreshMetrics();
  }

  private shouldRefreshMetrics(): boolean {
    const refreshAge = Date.now() - this.lastUpdate.getTime();
    return refreshAge > this.config.refreshInterval;
  }

  private calculateTimeRange(filter: DashboardFilter): { start: Date; end: Date } {
    const now = new Date();
    let start: Date;

    switch (filter.timeRange) {
      case '1h':
        start = new Date(now.getTime() - 60 * 60 * 1000);
        break;
      case '24h':
        start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      case 'custom':
        if (!filter.customRange) {
          throw new Error('Custom range requires start and end dates');
        }
        return filter.customRange;
      default:
        start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }

    return { start, end: now };
  }

  private async calculateRealTimeMetrics(): Promise<DashboardMetrics['realTime']> {
    const allAgents = this.agentManager.getAllAgents();
    const activeAgents = allAgents.filter((agent: AgentIdentity) => !this.revocationManager.isAgentRevoked(agent.did));
    
    const now = new Date();
    const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const recentAlerts = this.auditTrail.getActiveAlerts()
      .filter(alert => alert.timestamp >= last24h);

    // Determine system health
    let systemHealth: 'healthy' | 'warning' | 'critical' = 'healthy';
    const criticalAlerts = recentAlerts.filter(a => a.severity === 'critical').length;
    const highAlerts = recentAlerts.filter(a => a.severity === 'high').length;
    
    if (criticalAlerts > 0) {
      systemHealth = 'critical';
    } else if (highAlerts > 2 || recentAlerts.length > 10) {
      systemHealth = 'warning';
    }

    return {
      activeAgents: activeAgents.length,
      ongoingRevocations: 0, // Would track active revocation processes
      alertsInLast24h: recentAlerts.length,
      systemHealth
    };
  }

  private calculateHistoricalMetrics(analytics: AuditAnalytics, timeRange: { start: Date; end: Date }): DashboardMetrics['historical'] {
    const peakHour = analytics.peakRevocationHours[0] || 12;
    const peakTime = `${peakHour.toString().padStart(2, '0')}:00`;

    return {
      totalRevocations: analytics.totalRevocations,
      successRate: analytics.complianceMetrics.auditCompleteness,
      avgProcessingTime: analytics.complianceMetrics.avgProcessingTime,
      peakRevocationTime: peakTime
    };
  }

  private calculateTrends(analytics: AuditAnalytics, timeRange: { start: Date; end: Date }): DashboardMetrics['trends'] {
    // Daily revocations trend
    const dailyRevocations = Array.from(analytics.revocationTrends.daily.entries())
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => a.date.localeCompare(b.date))
      .slice(-30); // Last 30 days

    // Revocation reasons
    const totalRevocations = analytics.totalRevocations;
    const revocationReasons = Array.from(analytics.revocationsByReason.entries())
      .map(([reason, count]) => ({
        reason,
        count,
        percentage: totalRevocations > 0 ? (count / totalRevocations) * 100 : 0
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Service impact
    const serviceImpact = Array.from(analytics.revocationsByService.entries())
      .map(([service, revocations]) => ({
        service,
        revocations,
        agents: revocations // Simplified - would need actual agent count per service
      }))
      .sort((a, b) => b.revocations - a.revocations)
      .slice(0, 10);

    return {
      dailyRevocations,
      revocationReasons,
      serviceImpact
    };
  }

  private calculateAlertSummary(alerts: AuditAlert[]): DashboardMetrics['alerts']['summary'] {
    return {
      critical: alerts.filter(a => a.severity === 'critical').length,
      high: alerts.filter(a => a.severity === 'high').length,
      medium: alerts.filter(a => a.severity === 'medium').length,
      low: alerts.filter(a => a.severity === 'low').length
    };
  }

  private getRecentAlerts(filter: DashboardFilter): AuditAlert[] {
    const timeRange = this.calculateTimeRange(filter);
    return this.auditTrail.getActiveAlerts()
      .filter(alert => alert.timestamp >= timeRange.start && alert.timestamp <= timeRange.end)
      .slice(0, this.config.maxDisplayItems);
  }

  private notifySubscribers(metrics: DashboardMetrics): void {
    this.subscribers.forEach(callback => {
      try {
        callback(metrics);
      } catch (error) {
        console.error('Error notifying dashboard subscriber:', error);
      }
    });
  }

  private generateRecommendations(
    metrics: DashboardMetrics,
    stats: any,
    healthOverview: any
  ): string[] {
    const recommendations: string[] = [];

    if (metrics.realTime.systemHealth === 'critical') {
      recommendations.push('URGENT: System health is critical - investigate active alerts immediately');
    }

    if (metrics.alerts.summary.critical > 0) {
      recommendations.push(`Address ${metrics.alerts.summary.critical} critical alerts`);
    }

    if (stats.totalRevocations > 0 && stats.successfulRevocations / stats.totalRevocations < 0.9) {
      recommendations.push('Investigate high revocation failure rate');
    }

    if (healthOverview.agentsWithIssues > healthOverview.totalAgents * 0.1) {
      recommendations.push('Review agent delegation depth policies');
    }

    if (metrics.trends.dailyRevocations.length > 7) {
      const recent = metrics.trends.dailyRevocations.slice(-7);
      const totalRecent = recent.reduce((sum, day) => sum + day.count, 0);
      if (totalRecent > recent.length * 10) {
        recommendations.push('High revocation volume detected - review security policies');
      }
    }

    return recommendations;
  }

  private generateHtmlReport(report: any): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Revocation Monitoring Dashboard Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: #e9ecef; border-radius: 5px; }
        .alert { padding: 10px; margin: 5px 0; border-radius: 3px; }
        .alert.critical { background: #f8d7da; border: 1px solid #f5c6cb; }
        .alert.high { background: #fff3cd; border: 1px solid #ffeaa7; }
        .alert.medium { background: #d1ecf1; border: 1px solid #bee5eb; }
        .alert.low { background: #d4edda; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Revocation Monitoring Dashboard Report</h1>
        <p>Generated: ${report.generatedAt}</p>
        <p>System Health: <strong>${report.summary.systemHealth}</strong></p>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <div class="metric">Total Revocations: ${report.summary.totalRevocations}</div>
        <div class="metric">Success Rate: ${report.summary.successRate.toFixed(1)}%</div>
        <div class="metric">Active Alerts: ${report.summary.activeAlerts}</div>
        <div class="metric">Active Agents: ${report.summary.agentHealth.activeAgents}</div>
    </div>
    
    <div class="section">
        <h2>Active Alerts</h2>
        ${report.metrics.alerts.active.map((alert: AuditAlert) => `
        <div class="alert ${alert.severity}">
            <strong>${alert.severity.toUpperCase()}</strong>: ${alert.message}
            <br><small>${alert.timestamp}</small>
        </div>
        `).join('')}
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            ${report.recommendations.map((rec: string) => `<li>${rec}</li>`).join('')}
        </ul>
    </div>
</body>
</html>`;
  }
}