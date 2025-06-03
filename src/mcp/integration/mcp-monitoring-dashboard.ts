/**
 * MCP Monitoring Dashboard
 * 
 * Comprehensive monitoring and analytics for LLM interactions
 */

import { EventEmitter } from 'events';
import {
  ProviderHealth,
  ProviderMetrics,
  UsageInfo,
  RequestPriority,
  LLMRequestType,
  MCPError,
  MCPErrorCode
} from '../types';
import { MessageRouter } from '../routing/message-router';
import { ProviderSelector } from '../providers/provider-selector';
import { ContextManager } from '../context/context-manager';
import { StreamManager } from '../streaming/stream-manager';
import { AgentMatcher } from '../matching/agent-matcher';
import { AuditLogger } from '../security/audit-logger';
import { RateLimiterManager } from '../security/rate-limiter';

/**
 * Dashboard metric types
 */
export interface DashboardMetrics {
  // Overall statistics
  totalRequests: number;
  totalTokens: number;
  totalCost: number;
  averageLatency: number;
  errorRate: number;
  
  // Provider metrics
  providerHealth: ProviderHealth[];
  providerUsage: Record<string, ProviderMetrics>;
  
  // Request breakdown
  requestsByType: Record<LLMRequestType, number>;
  requestsByPriority: Record<RequestPriority, number>;
  requestsByAgent: Record<string, number>;
  
  // Performance metrics
  latencyPercentiles: {
    p50: number;
    p90: number;
    p95: number;
    p99: number;
  };
  
  // Cost analysis
  costByProvider: Record<string, number>;
  costByAgent: Record<string, number>;
  costByRequestType: Record<LLMRequestType, number>;
  
  // Context metrics
  activeContexts: number;
  totalContextTokens: number;
  compressionsSaved: number;
  
  // Streaming metrics
  activeStreams: number;
  totalStreamedTokens: number;
  averageStreamLatency: number;
  
  // Agent matching metrics
  totalMatches: number;
  matchSuccessRate: number;
  averageMatchScore: number;
}

/**
 * Time series data point
 */
export interface TimeSeriesDataPoint {
  timestamp: Date;
  value: number;
  metadata?: Record<string, any>;
}

/**
 * Alert configuration
 */
export interface AlertConfig {
  metric: string;
  threshold: number;
  operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  windowSize: number; // milliseconds
  cooldown: number; // milliseconds
}

/**
 * Dashboard configuration
 */
export interface DashboardConfig {
  refreshInterval: number;
  retentionPeriod: number;
  alerts: AlertConfig[];
  enableRealTimeUpdates: boolean;
  enableHistoricalAnalysis: boolean;
  exportFormats: ('json' | 'csv' | 'prometheus')[];
}

/**
 * MCP Monitoring Dashboard
 */
export class MCPMonitoringDashboard extends EventEmitter {
  private metrics: DashboardMetrics;
  private timeSeries: Map<string, TimeSeriesDataPoint[]> = new Map();
  private activeAlerts: Map<string, { triggered: Date; alert: AlertConfig }> = new Map();
  private refreshTimer?: NodeJS.Timeout;
  private metricsHistory: DashboardMetrics[] = [];

  constructor(
    private messageRouter: MessageRouter,
    private providerSelector: ProviderSelector | null,
    private contextManager: ContextManager,
    private streamManager: StreamManager,
    private agentMatcher: AgentMatcher,
    private auditLogger: AuditLogger,
    private rateLimiter: RateLimiterManager,
    private config: DashboardConfig = {
      refreshInterval: 30000, // 30 seconds
      retentionPeriod: 86400000 * 7, // 7 days
      alerts: [],
      enableRealTimeUpdates: true,
      enableHistoricalAnalysis: true,
      exportFormats: ['json', 'prometheus']
    }
  ) {
    super();
    this.metrics = this.initializeMetrics();
    this.setupEventListeners();
    this.startMetricsCollection();
  }

  /**
   * Initialize empty metrics
   */
  private initializeMetrics(): DashboardMetrics {
    return {
      totalRequests: 0,
      totalTokens: 0,
      totalCost: 0,
      averageLatency: 0,
      errorRate: 0,
      providerHealth: [],
      providerUsage: {},
      requestsByType: {
        [LLMRequestType.COMPLETION]: 0,
        [LLMRequestType.FUNCTION_CALL]: 0,
        [LLMRequestType.EMBEDDING]: 0,
        [LLMRequestType.MODERATION]: 0,
        [LLMRequestType.STREAMING]: 0
      },
      requestsByPriority: {
        [RequestPriority.LOW]: 0,
        [RequestPriority.MEDIUM]: 0,
        [RequestPriority.HIGH]: 0,
        [RequestPriority.URGENT]: 0,
        [RequestPriority.CRITICAL]: 0
      },
      requestsByAgent: {},
      latencyPercentiles: {
        p50: 0,
        p90: 0,
        p95: 0,
        p99: 0
      },
      costByProvider: {},
      costByAgent: {},
      costByRequestType: {
        [LLMRequestType.COMPLETION]: 0,
        [LLMRequestType.FUNCTION_CALL]: 0,
        [LLMRequestType.EMBEDDING]: 0,
        [LLMRequestType.MODERATION]: 0,
        [LLMRequestType.STREAMING]: 0
      },
      activeContexts: 0,
      totalContextTokens: 0,
      compressionsSaved: 0,
      activeStreams: 0,
      totalStreamedTokens: 0,
      averageStreamLatency: 0,
      totalMatches: 0,
      matchSuccessRate: 0,
      averageMatchScore: 0
    };
  }

  /**
   * Setup event listeners
   */
  private setupEventListeners(): void {
    // Router events
    this.messageRouter.on('request_queued', (event) => {
      this.updateMetric('totalRequests', 1, 'increment');
      this.updateRequestBreakdown(event.request);
    });

    this.messageRouter.on('request_completed', (event) => {
      this.updateLatencyMetrics(event.latency);
      this.updateCostMetrics(event.request, event.response);
    });

    this.messageRouter.on('request_failed', (event) => {
      this.updateErrorRate();
    });

    // Provider events
    if (this.providerSelector) {
      this.providerSelector.on('provider_selected', (event) => {
        this.updateProviderUsage(event.result.primaryProvider.id);
      });

      this.providerSelector.on('performance_recorded', (event) => {
        this.updateProviderPerformance(event.providerId, event.performance);
      });
    }

    // Context events
    this.contextManager.on('context_created', () => {
      this.updateMetric('activeContexts', 1, 'increment');
    });

    this.contextManager.on('context_compressed', (event) => {
      this.updateMetric('compressionsSaved', 1, 'increment');
      this.recordCompressionSavings(event.result);
    });

    this.contextManager.on('context_deleted', () => {
      this.updateMetric('activeContexts', 1, 'decrement');
    });

    // Stream events
    this.streamManager.on('stream_started', () => {
      this.updateMetric('activeStreams', 1, 'increment');
    });

    this.streamManager.on('chunk_received', (event) => {
      this.updateMetric('totalStreamedTokens', event.tokens || 0, 'increment');
      this.updateStreamLatency(event.latency);
    });

    this.streamManager.on('stream_completed', () => {
      this.updateMetric('activeStreams', 1, 'decrement');
    });

    // Agent matcher events
    this.agentMatcher.on('matches_found', (event) => {
      this.updateMetric('totalMatches', 1, 'increment');
      this.updateMatchMetrics(event.matches);
    });

    this.agentMatcher.on('match_outcome_recorded', (event) => {
      this.updateMatchSuccessRate(event.outcome);
    });
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    // Collect metrics periodically
    this.refreshTimer = setInterval(() => {
      this.collectMetrics();
    }, this.config.refreshInterval);

    // Initial collection
    this.collectMetrics();
  }

  /**
   * Collect current metrics
   */
  private async collectMetrics(): Promise<void> {
    try {
      // Get router statistics
      const routerStats = this.messageRouter.getStatistics();
      // Convert router stats provider health to expected format
      this.metrics.providerHealth = (routerStats.providerHealth || []).map(health => ({
        providerId: health.providerId,
        status: health.status === 'connected' ? 'healthy' : 
                health.status === 'error' ? 'unhealthy' : 'degraded',
        lastCheck: new Date(),
        responseTime: health.averageLatency || 0,
        uptime: 0.99, // Default uptime
        errorRate: 0.01, // Default error rate
        connectionCount: 1,
        version: '1.0.0'
      }));

      // Get context statistics
      const contextStats = this.contextManager.getStatistics();
      this.metrics.activeContexts = contextStats.activeContexts;
      this.metrics.totalContextTokens = contextStats.totalTokens;
      this.metrics.compressionsSaved = contextStats.compressionsSaved;

      // Get streaming statistics
      const activeStreams = this.streamManager.getActiveSessions();
      this.metrics.activeStreams = activeStreams.length;

      // Get agent matcher statistics
      const matcherStats = this.agentMatcher.getStatistics();
      this.metrics.matchSuccessRate = matcherStats.successRate;

      // Get rate limiter statistics
      const rateLimiterStats = await this.getRateLimiterStats();
      
      // Calculate derived metrics
      this.calculateDerivedMetrics();

      // Check alerts
      this.checkAlerts();

      // Store historical data
      if (this.config.enableHistoricalAnalysis) {
        this.storeHistoricalData();
      }

      // Emit update event
      this.emit('metrics_updated', this.metrics);

    } catch (error) {
      console.error('Failed to collect metrics:', error);
      this.emit('error', error);
    }
  }

  /**
   * Update metric value
   */
  private updateMetric(
    metric: keyof DashboardMetrics,
    value: number,
    operation: 'set' | 'increment' | 'decrement' = 'set'
  ): void {
    const current = this.metrics[metric] as number;
    
    switch (operation) {
      case 'set':
        (this.metrics[metric] as number) = value;
        break;
      case 'increment':
        (this.metrics[metric] as number) = current + value;
        break;
      case 'decrement':
        (this.metrics[metric] as number) = Math.max(0, current - value);
        break;
    }

    // Record time series data
    this.recordTimeSeries(metric, this.metrics[metric] as number);
  }

  /**
   * Update request breakdown
   */
  private updateRequestBreakdown(request: any): void {
    // By type
    if (request.type && request.type in this.metrics.requestsByType) {
      (this.metrics.requestsByType as any)[request.type]++;
    }

    // By priority
    if (request.metadata?.priority && request.metadata.priority in this.metrics.requestsByPriority) {
      (this.metrics.requestsByPriority as any)[request.metadata.priority]++;
    }

    // By agent
    if (request.agentDID) {
      this.metrics.requestsByAgent[request.agentDID] = 
        (this.metrics.requestsByAgent[request.agentDID] || 0) + 1;
    }
  }

  /**
   * Update latency metrics
   */
  private updateLatencyMetrics(latency: number): void {
    // Update running average
    const totalRequests = this.metrics.totalRequests || 1;
    this.metrics.averageLatency = 
      (this.metrics.averageLatency * (totalRequests - 1) + latency) / totalRequests;

    // Store for percentile calculation
    this.recordTimeSeries('latency', latency);
  }

  /**
   * Update cost metrics
   */
  private updateCostMetrics(request: any, response: any): void {
    const cost = response.usage?.cost || 0;
    this.metrics.totalCost += cost;

    // By provider
    if (response.provider) {
      this.metrics.costByProvider[response.provider] = 
        (this.metrics.costByProvider[response.provider] || 0) + cost;
    }

    // By agent
    if (request.agentDID) {
      this.metrics.costByAgent[request.agentDID] = 
        (this.metrics.costByAgent[request.agentDID] || 0) + cost;
    }

    // By request type
    if (request.type && request.type in this.metrics.costByRequestType) {
      (this.metrics.costByRequestType as any)[request.type] += cost;
    }

    // Update tokens
    if (response.usage?.totalTokens) {
      this.metrics.totalTokens += response.usage.totalTokens;
    }
  }

  /**
   * Update error rate
   */
  private updateErrorRate(): void {
    const totalRequests = this.metrics.totalRequests || 1;
    const currentErrors = Math.round(this.metrics.errorRate * totalRequests);
    this.metrics.errorRate = (currentErrors + 1) / totalRequests;
  }

  /**
   * Update provider usage
   */
  private updateProviderUsage(providerId: string): void {
    if (!this.metrics.providerUsage[providerId]) {
      this.metrics.providerUsage[providerId] = {
        providerId,
        requestCount: 0,
        successCount: 0,
        errorCount: 0,
        totalLatency: 0,
        averageLatency: 0,
        successRate: 1,
        requestsPerSecond: 0,
        tokensPerSecond: 0,
        costPer1kTokens: 0,
        lastUpdated: new Date()
      };
    }
    
    this.metrics.providerUsage[providerId].requestCount++;
    this.metrics.providerUsage[providerId].lastUpdated = new Date();
  }

  /**
   * Update provider performance
   */
  private updateProviderPerformance(
    providerId: string,
    performance: { latency: number; success: boolean; cost: number }
  ): void {
    const usage = this.metrics.providerUsage[providerId];
    if (!usage) return;

    if (performance.success) {
      usage.successCount++;
    } else {
      usage.errorCount++;
    }

    usage.totalLatency += performance.latency;
    usage.averageLatency = usage.totalLatency / usage.requestCount;
    usage.successRate = usage.successCount / usage.requestCount;
  }

  /**
   * Update stream latency
   */
  private updateStreamLatency(latency: number): void {
    const currentTotal = this.metrics.averageStreamLatency * this.metrics.totalStreamedTokens;
    const newTotal = this.metrics.totalStreamedTokens + 1;
    this.metrics.averageStreamLatency = (currentTotal + latency) / newTotal;
  }

  /**
   * Record compression savings
   */
  private recordCompressionSavings(result: any): void {
    const savedTokens = result.originalTokens - result.compressedTokens;
    this.recordTimeSeries('compressionSavings', savedTokens);
  }

  /**
   * Update match metrics
   */
  private updateMatchMetrics(matches: any[]): void {
    if (matches.length > 0) {
      const avgScore = matches.reduce((sum, m) => sum + m.score, 0) / matches.length;
      const currentAvg = this.metrics.averageMatchScore;
      const totalMatches = this.metrics.totalMatches;
      
      this.metrics.averageMatchScore = 
        (currentAvg * (totalMatches - 1) + avgScore) / totalMatches;
    }
  }

  /**
   * Update match success rate
   */
  private updateMatchSuccessRate(outcome: string): void {
    const successful = outcome === 'success';
    const totalMatches = this.metrics.totalMatches;
    const currentSuccessful = Math.round(this.metrics.matchSuccessRate * totalMatches);
    
    this.metrics.matchSuccessRate = 
      (currentSuccessful + (successful ? 1 : 0)) / totalMatches;
  }

  /**
   * Get rate limiter statistics
   */
  private async getRateLimiterStats(): Promise<any> {
    // TODO: Implement getStatistics on RateLimiterManager
    // const stats = await this.rateLimiter.getStatistics();
    return {
      totalRequests: 0,
      blockedRequests: 0,
      averageResponseTime: 0
    };
  }

  /**
   * Calculate derived metrics
   */
  private calculateDerivedMetrics(): void {
    // Calculate latency percentiles from time series
    const latencyData = this.timeSeries.get('latency') || [];
    if (latencyData.length > 0) {
      const sortedLatencies = latencyData
        .map(d => d.value)
        .sort((a, b) => a - b);
      
      this.metrics.latencyPercentiles = {
        p50: this.getPercentile(sortedLatencies, 0.5),
        p90: this.getPercentile(sortedLatencies, 0.9),
        p95: this.getPercentile(sortedLatencies, 0.95),
        p99: this.getPercentile(sortedLatencies, 0.99)
      };
    }
  }

  /**
   * Get percentile value
   */
  private getPercentile(sortedArray: number[], percentile: number): number {
    const index = Math.ceil(sortedArray.length * percentile) - 1;
    return sortedArray[Math.max(0, index)] || 0;
  }

  /**
   * Record time series data
   */
  private recordTimeSeries(metric: string, value: number): void {
    if (!this.timeSeries.has(metric)) {
      this.timeSeries.set(metric, []);
    }

    const series = this.timeSeries.get(metric)!;
    series.push({
      timestamp: new Date(),
      value
    });

    // Clean old data
    const cutoff = Date.now() - this.config.retentionPeriod;
    const filtered = series.filter(d => d.timestamp.getTime() > cutoff);
    this.timeSeries.set(metric, filtered);
  }

  /**
   * Check alerts
   */
  private checkAlerts(): void {
    for (const alert of this.config.alerts) {
      const metricValue = this.getMetricValue(alert.metric);
      if (metricValue === null) continue;

      const shouldTrigger = this.evaluateAlertCondition(metricValue, alert);
      const existingAlert = this.activeAlerts.get(alert.metric);

      if (shouldTrigger && !existingAlert) {
        // Trigger new alert
        this.activeAlerts.set(alert.metric, {
          triggered: new Date(),
          alert
        });

        this.emit('alert_triggered', {
          alert,
          value: metricValue,
          timestamp: new Date()
        });

      } else if (!shouldTrigger && existingAlert) {
        // Clear alert
        const duration = Date.now() - existingAlert.triggered.getTime();
        if (duration > alert.cooldown) {
          this.activeAlerts.delete(alert.metric);
          
          this.emit('alert_cleared', {
            alert,
            duration,
            timestamp: new Date()
          });
        }
      }
    }
  }

  /**
   * Get metric value by path
   */
  private getMetricValue(metricPath: string): number | null {
    const parts = metricPath.split('.');
    let value: any = this.metrics;

    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return null;
      }
    }

    return typeof value === 'number' ? value : null;
  }

  /**
   * Evaluate alert condition
   */
  private evaluateAlertCondition(value: number, alert: AlertConfig): boolean {
    switch (alert.operator) {
      case 'gt': return value > alert.threshold;
      case 'lt': return value < alert.threshold;
      case 'eq': return value === alert.threshold;
      case 'gte': return value >= alert.threshold;
      case 'lte': return value <= alert.threshold;
      default: return false;
    }
  }

  /**
   * Store historical data
   */
  private storeHistoricalData(): void {
    const snapshot = JSON.parse(JSON.stringify(this.metrics));
    this.metricsHistory.push(snapshot);

    // Keep only recent history
    const maxHistory = Math.floor(this.config.retentionPeriod / this.config.refreshInterval);
    if (this.metricsHistory.length > maxHistory) {
      this.metricsHistory = this.metricsHistory.slice(-maxHistory);
    }
  }

  /**
   * Get current metrics
   */
  getMetrics(): DashboardMetrics {
    return { ...this.metrics };
  }

  /**
   * Get time series data
   */
  getTimeSeries(metric: string, duration?: number): TimeSeriesDataPoint[] {
    const series = this.timeSeries.get(metric) || [];
    
    if (duration) {
      const cutoff = Date.now() - duration;
      return series.filter(d => d.timestamp.getTime() > cutoff);
    }

    return [...series];
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Array<{ alert: AlertConfig; triggered: Date }> {
    return Array.from(this.activeAlerts.values());
  }

  /**
   * Export metrics
   */
  exportMetrics(format: 'json' | 'csv' | 'prometheus' = 'json'): string {
    switch (format) {
      case 'json':
        return JSON.stringify(this.metrics, null, 2);
      
      case 'csv':
        return this.exportAsCSV();
      
      case 'prometheus':
        return this.exportAsPrometheus();
      
      default:
        throw new MCPError({
          code: MCPErrorCode.INVALID_REQUEST,
          message: `Unsupported export format: ${format}`,
          timestamp: new Date(),
          retryable: false
        });
    }
  }

  /**
   * Export as CSV
   */
  private exportAsCSV(): string {
    const rows: string[] = ['metric,value,timestamp'];
    const timestamp = new Date().toISOString();

    const addRow = (key: string, value: any) => {
      if (typeof value === 'number') {
        rows.push(`${key},${value},${timestamp}`);
      }
    };

    // Flatten metrics
    Object.entries(this.metrics).forEach(([key, value]) => {
      if (typeof value === 'object' && !Array.isArray(value)) {
        Object.entries(value).forEach(([subKey, subValue]) => {
          addRow(`${key}.${subKey}`, subValue);
        });
      } else {
        addRow(key, value);
      }
    });

    return rows.join('\n');
  }

  /**
   * Export as Prometheus metrics
   */
  private exportAsPrometheus(): string {
    const lines: string[] = [];
    const timestamp = Date.now();

    const addMetric = (name: string, value: number, labels?: Record<string, string>) => {
      const labelStr = labels 
        ? '{' + Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(',') + '}'
        : '';
      lines.push(`mcp_${name}${labelStr} ${value} ${timestamp}`);
    };

    // Export key metrics
    addMetric('total_requests', this.metrics.totalRequests);
    addMetric('total_tokens', this.metrics.totalTokens);
    addMetric('total_cost', this.metrics.totalCost);
    addMetric('average_latency_ms', this.metrics.averageLatency);
    addMetric('error_rate', this.metrics.errorRate);
    addMetric('active_contexts', this.metrics.activeContexts);
    addMetric('active_streams', this.metrics.activeStreams);

    // Export provider metrics
    Object.entries(this.metrics.providerUsage).forEach(([provider, usage]) => {
      addMetric('provider_requests', usage.requestCount, { provider });
      addMetric('provider_success_rate', usage.successRate, { provider });
      addMetric('provider_latency_ms', usage.averageLatency, { provider });
    });

    // Export request type breakdown
    Object.entries(this.metrics.requestsByType).forEach(([type, count]) => {
      addMetric('requests_by_type', count, { type });
    });

    return lines.join('\n');
  }

  /**
   * Add custom alert
   */
  addAlert(alert: AlertConfig): void {
    this.config.alerts.push(alert);
  }

  /**
   * Remove alert
   */
  removeAlert(metric: string): void {
    this.config.alerts = this.config.alerts.filter(a => a.metric !== metric);
    this.activeAlerts.delete(metric);
  }

  /**
   * Get historical metrics
   */
  getHistoricalMetrics(duration?: number): DashboardMetrics[] {
    if (!duration) {
      return [...this.metricsHistory];
    }

    const cutoff = Date.now() - duration;
    const cutoffIndex = this.metricsHistory.findIndex((m: any) => 
      (m.timestamp || Date.now()) > cutoff
    );

    return cutoffIndex >= 0 
      ? this.metricsHistory.slice(cutoffIndex)
      : this.metricsHistory;
  }

  /**
   * Reset metrics
   */
  resetMetrics(): void {
    this.metrics = this.initializeMetrics();
    this.timeSeries.clear();
    this.activeAlerts.clear();
    this.metricsHistory = [];
    
    this.emit('metrics_reset');
  }

  /**
   * Shutdown dashboard
   */
  shutdown(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
    }

    this.removeAllListeners();
  }
}

export default MCPMonitoringDashboard;