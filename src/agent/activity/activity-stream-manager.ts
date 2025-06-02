import { EventEmitter } from 'events';
import { AgentActivity, ActivityType, ActivityStatus, ActivityBatch } from './types';

export interface StreamSubscription {
  id: string;
  filters: StreamFilter;
  callback: (event: StreamEvent) => void;
  metadata?: Record<string, any>;
  createdAt: Date;
  lastActivity?: Date;
  unsubscribe: () => void;
}

export interface StreamFilter {
  agentDID?: string | string[];
  parentDID?: string | string[];
  serviceDID?: string | string[];
  types?: ActivityType[];
  status?: ActivityStatus[];
  scopes?: string[];
  critical?: boolean; // Only critical events
  minDuration?: number; // Only activities taking longer than X ms
  errorOnly?: boolean; // Only failed/denied activities
}

export interface StreamEvent {
  id: string;
  timestamp: Date;
  type: StreamEventType;
  data: AgentActivity | ActivityBatch | ActivityAlert;
  metadata?: Record<string, any>;
}

export enum StreamEventType {
  ACTIVITY_LOGGED = 'activity_logged',
  BATCH_PROCESSED = 'batch_processed',
  ACTIVITY_ALERT = 'activity_alert',
  AGENT_SESSION_START = 'agent_session_start',
  AGENT_SESSION_END = 'agent_session_end',
  SYSTEM_ALERT = 'system_alert'
}

export interface ActivityAlert {
  id: string;
  agentDID: string;
  parentDID: string;
  alertType: AlertType;
  severity: AlertSeverity;
  message: string;
  timestamp: Date;
  relatedActivityId?: string;
  details?: Record<string, any>;
}

export enum AlertType {
  HIGH_ERROR_RATE = 'high_error_rate',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  PERMISSION_ESCALATION = 'permission_escalation',
  UNUSUAL_PATTERN = 'unusual_pattern',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  SYSTEM_ERROR = 'system_error'
}

export enum AlertSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface StreamManagerConfig {
  maxSubscriptions?: number;
  eventRetentionMs?: number;
  alertThresholds?: {
    errorRateThreshold?: number; // Trigger alert if error rate > X%
    suspiciousVolumeThreshold?: number; // Activities per minute
    unusualHoursThreshold?: number; // Activities outside 8AM-6PM
  };
  enableAlerts?: boolean;
  enableMetrics?: boolean;
}

export class ActivityStreamManager extends EventEmitter {
  private subscriptions: Map<string, StreamSubscription> = new Map();
  private recentEvents: StreamEvent[] = [];
  private config: Required<StreamManagerConfig>;
  private metrics: {
    totalEvents: number;
    totalSubscriptions: number;
    eventsByType: Record<StreamEventType, number>;
    alertsGenerated: number;
  };

  constructor(config: StreamManagerConfig = {}) {
    super();
    
    this.config = {
      maxSubscriptions: config.maxSubscriptions || 1000,
      eventRetentionMs: config.eventRetentionMs || 60 * 60 * 1000, // 1 hour
      alertThresholds: {
        errorRateThreshold: 0.2, // 20%
        suspiciousVolumeThreshold: 100, // 100 activities per minute
        unusualHoursThreshold: 50, // 50 activities outside business hours
        ...config.alertThresholds
      },
      enableAlerts: config.enableAlerts ?? true,
      enableMetrics: config.enableMetrics ?? true
    };

    this.metrics = {
      totalEvents: 0,
      totalSubscriptions: 0,
      eventsByType: {} as Record<StreamEventType, number>,
      alertsGenerated: 0
    };

    // Initialize event type counters
    Object.values(StreamEventType).forEach(type => {
      this.metrics.eventsByType[type] = 0;
    });

    // Start cleanup timer
    this.startCleanupTimer();
  }

  /**
   * Subscribe to activity stream with filters
   */
  subscribe(
    filters: StreamFilter,
    callback: (event: StreamEvent) => void,
    metadata?: Record<string, any>
  ): StreamSubscription {
    if (this.subscriptions.size >= this.config.maxSubscriptions) {
      throw new Error('Maximum subscription limit reached');
    }

    const subscriptionId = this.generateId('sub');
    
    const subscription: StreamSubscription = {
      id: subscriptionId,
      filters,
      callback,
      metadata,
      createdAt: new Date(),
      unsubscribe: () => {
        this.subscriptions.delete(subscriptionId);
        this.metrics.totalSubscriptions--;
      }
    };

    this.subscriptions.set(subscriptionId, subscription);
    this.metrics.totalSubscriptions++;

    return subscription;
  }

  /**
   * Subscribe to specific agent activities
   */
  subscribeToAgent(
    agentDID: string,
    callback: (event: StreamEvent) => void,
    metadata?: Record<string, any>
  ): StreamSubscription {
    return this.subscribe({ agentDID }, callback, metadata);
  }

  /**
   * Subscribe to user activities (all agents under a parent DID)
   */
  subscribeToUser(
    parentDID: string,
    callback: (event: StreamEvent) => void,
    metadata?: Record<string, any>
  ): StreamSubscription {
    return this.subscribe({ parentDID }, callback, metadata);
  }

  /**
   * Subscribe to critical events only
   */
  subscribeToCriticalEvents(
    callback: (event: StreamEvent) => void,
    metadata?: Record<string, any>
  ): StreamSubscription {
    return this.subscribe(
      { 
        critical: true,
        status: [ActivityStatus.FAILED, ActivityStatus.DENIED]
      }, 
      callback, 
      metadata
    );
  }

  /**
   * Subscribe to alerts
   */
  subscribeToAlerts(
    callback: (event: StreamEvent) => void,
    severity?: AlertSeverity[],
    metadata?: Record<string, any>
  ): StreamSubscription {
    const filters: StreamFilter = {};
    if (severity) {
      filters.critical = severity.includes(AlertSeverity.CRITICAL);
    }

    const subscription = this.subscribe(filters, callback, metadata);
    
    // Also listen for alert events specifically
    const alertCallback = (event: StreamEvent) => {
      if (event.type === StreamEventType.ACTIVITY_ALERT) {
        const alert = event.data as ActivityAlert;
        if (!severity || severity.includes(alert.severity)) {
          callback(event);
        }
      }
    };

    // Override callback to handle alerts
    subscription.callback = (event: StreamEvent) => {
      if (event.type === StreamEventType.ACTIVITY_ALERT) {
        alertCallback(event);
      } else {
        callback(event);
      }
    };

    return subscription;
  }

  /**
   * Publish an activity to subscribers
   */
  async publishActivity(activity: AgentActivity): Promise<void> {
    const event: StreamEvent = {
      id: this.generateId('evt'),
      timestamp: new Date(),
      type: StreamEventType.ACTIVITY_LOGGED,
      data: activity
    };

    await this.publishEvent(event);

    // Check for alerts if enabled
    if (this.config.enableAlerts) {
      await this.checkForAlerts(activity);
    }
  }

  /**
   * Publish a batch processed event
   */
  async publishBatch(batch: ActivityBatch): Promise<void> {
    const event: StreamEvent = {
      id: this.generateId('evt'),
      timestamp: new Date(),
      type: StreamEventType.BATCH_PROCESSED,
      data: batch,
      metadata: {
        activityCount: batch.count,
        batchSize: batch.activities.length
      }
    };

    await this.publishEvent(event);
  }

  /**
   * Publish an alert
   */
  async publishAlert(alert: ActivityAlert): Promise<void> {
    const event: StreamEvent = {
      id: this.generateId('evt'),
      timestamp: new Date(),
      type: StreamEventType.ACTIVITY_ALERT,
      data: alert,
      metadata: {
        severity: alert.severity,
        alertType: alert.alertType
      }
    };

    await this.publishEvent(event);
    this.metrics.alertsGenerated++;
  }

  /**
   * Get recent events (for replay/catch-up)
   */
  getRecentEvents(
    filters?: Partial<StreamFilter>,
    limit: number = 100
  ): StreamEvent[] {
    let events = [...this.recentEvents];

    // Apply filters if provided
    if (filters) {
      events = events.filter(event => this.matchesFilter(event, filters));
    }

    return events
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Get subscription statistics
   */
  getSubscriptionStats(): {
    total: number;
    byFilter: Record<string, number>;
    active: number;
  } {
    const byFilter: Record<string, number> = {};
    let active = 0;

    this.subscriptions.forEach(sub => {
      const now = new Date();
      const timeSinceActivity = sub.lastActivity ? 
        now.getTime() - sub.lastActivity.getTime() : 
        now.getTime() - sub.createdAt.getTime();

      if (timeSinceActivity < 5 * 60 * 1000) { // Active in last 5 minutes
        active++;
      }

      // Categorize by main filter type
      if (sub.filters.agentDID) {
        byFilter['agent'] = (byFilter['agent'] || 0) + 1;
      } else if (sub.filters.parentDID) {
        byFilter['user'] = (byFilter['user'] || 0) + 1;
      } else if (sub.filters.critical) {
        byFilter['critical'] = (byFilter['critical'] || 0) + 1;
      } else {
        byFilter['general'] = (byFilter['general'] || 0) + 1;
      }
    });

    return {
      total: this.subscriptions.size,
      byFilter,
      active
    };
  }

  /**
   * Get streaming metrics
   */
  getMetrics(): typeof this.metrics {
    return { ...this.metrics };
  }

  /**
   * Clear old events and inactive subscriptions
   */
  cleanup(): void {
    const now = new Date();
    const cutoff = now.getTime() - this.config.eventRetentionMs;

    // Remove old events
    this.recentEvents = this.recentEvents.filter(
      event => event.timestamp.getTime() > cutoff
    );

    // Remove inactive subscriptions (no activity for 1 hour)
    const inactivityThreshold = 60 * 60 * 1000; // 1 hour
    const toRemove: string[] = [];

    this.subscriptions.forEach((sub, id) => {
      const timeSinceActivity = sub.lastActivity ? 
        now.getTime() - sub.lastActivity.getTime() : 
        now.getTime() - sub.createdAt.getTime();

      if (timeSinceActivity > inactivityThreshold) {
        toRemove.push(id);
      }
    });

    toRemove.forEach(id => {
      this.subscriptions.delete(id);
      this.metrics.totalSubscriptions--;
    });
  }

  // Private methods

  private async publishEvent(event: StreamEvent): Promise<void> {
    // Store event for replay
    this.recentEvents.push(event);
    
    // Update metrics
    this.metrics.totalEvents++;
    this.metrics.eventsByType[event.type]++;

    // Notify matching subscriptions
    const matchingSubscriptions = Array.from(this.subscriptions.values())
      .filter(sub => this.matchesFilter(event, sub.filters));

    const promises = matchingSubscriptions.map(async sub => {
      try {
        sub.lastActivity = new Date();
        await Promise.resolve(sub.callback(event));
      } catch (error) {
        console.error('Subscription callback error:', error);
      }
    });

    await Promise.all(promises);

    // Emit to EventEmitter listeners
    this.emit('event', event);
    this.emit(event.type, event);
  }

  private matchesFilter(event: StreamEvent, filters: Partial<StreamFilter>): boolean {
    const activity = event.data as AgentActivity;

    // Only process activity events for most filters
    if (event.type !== StreamEventType.ACTIVITY_LOGGED && 
        event.type !== StreamEventType.ACTIVITY_ALERT) {
      return true; // Allow all non-activity events through
    }

    if (filters.agentDID) {
      const agentDIDs = Array.isArray(filters.agentDID) ? filters.agentDID : [filters.agentDID];
      if (!agentDIDs.includes(activity.agentDID)) {
        return false;
      }
    }

    if (filters.parentDID) {
      const parentDIDs = Array.isArray(filters.parentDID) ? filters.parentDID : [filters.parentDID];
      if (!parentDIDs.includes(activity.parentDID)) {
        return false;
      }
    }

    if (filters.serviceDID) {
      const serviceDIDs = Array.isArray(filters.serviceDID) ? filters.serviceDID : [filters.serviceDID];
      if (!serviceDIDs.includes(activity.serviceDID)) {
        return false;
      }
    }

    if (filters.types && !filters.types.includes(activity.type)) {
      return false;
    }

    if (filters.status && !filters.status.includes(activity.status)) {
      return false;
    }

    if (filters.scopes) {
      const hasScope = filters.scopes.some(scope => activity.scopes.includes(scope));
      if (!hasScope) {
        return false;
      }
    }

    if (filters.critical) {
      // Critical events: failures, high duration, or specific types
      const isCritical = 
        activity.status === ActivityStatus.FAILED ||
        activity.status === ActivityStatus.DENIED ||
        (activity.duration && activity.duration > 5000) ||
        activity.type === ActivityType.ERROR;
      
      if (!isCritical) {
        return false;
      }
    }

    if (filters.minDuration && activity.duration && activity.duration < filters.minDuration) {
      return false;
    }

    if (filters.errorOnly) {
      const isError = 
        activity.status === ActivityStatus.FAILED ||
        activity.status === ActivityStatus.DENIED;
      
      if (!isError) {
        return false;
      }
    }

    return true;
  }

  private async checkForAlerts(activity: AgentActivity): Promise<void> {
    // Check for high error rate
    if (activity.status === ActivityStatus.FAILED || activity.status === ActivityStatus.DENIED) {
      const recentActivities = this.getRecentActivityCount(activity.agentDID, 5 * 60 * 1000); // 5 minutes
      const recentErrors = this.getRecentErrorCount(activity.agentDID, 5 * 60 * 1000);
      
      if (recentActivities > 10 && recentErrors / recentActivities > this.config.alertThresholds.errorRateThreshold!) {
        await this.publishAlert({
          id: this.generateId('alert'),
          agentDID: activity.agentDID,
          parentDID: activity.parentDID,
          alertType: AlertType.HIGH_ERROR_RATE,
          severity: AlertSeverity.HIGH,
          message: `High error rate detected: ${Math.round(recentErrors / recentActivities * 100)}% (${recentErrors}/${recentActivities})`,
          timestamp: new Date(),
          relatedActivityId: activity.id,
          details: {
            errorRate: recentErrors / recentActivities,
            totalActivities: recentActivities,
            totalErrors: recentErrors
          }
        });
      }
    }

    // Check for suspicious volume
    const recentCount = this.getRecentActivityCount(activity.agentDID, 60 * 1000); // 1 minute
    if (recentCount > this.config.alertThresholds.suspiciousVolumeThreshold!) {
      await this.publishAlert({
        id: this.generateId('alert'),
        agentDID: activity.agentDID,
        parentDID: activity.parentDID,
        alertType: AlertType.SUSPICIOUS_ACTIVITY,
        severity: AlertSeverity.MEDIUM,
        message: `Suspicious activity volume: ${recentCount} activities in the last minute`,
        timestamp: new Date(),
        relatedActivityId: activity.id,
        details: {
          activityCount: recentCount,
          timeWindow: '1 minute'
        }
      });
    }

    // Check for unusual hours (outside 8 AM - 6 PM)
    const hour = activity.timestamp.getHours();
    if (hour < 8 || hour > 18) {
      const unusualHoursCount = this.getRecentUnusualHoursCount(activity.agentDID, 24 * 60 * 60 * 1000); // 24 hours
      if (unusualHoursCount > this.config.alertThresholds.unusualHoursThreshold!) {
        await this.publishAlert({
          id: this.generateId('alert'),
          agentDID: activity.agentDID,
          parentDID: activity.parentDID,
          alertType: AlertType.UNUSUAL_PATTERN,
          severity: AlertSeverity.LOW,
          message: `Unusual activity pattern: ${unusualHoursCount} activities outside business hours in the last 24 hours`,
          timestamp: new Date(),
          relatedActivityId: activity.id,
          details: {
            unusualHoursCount,
            currentHour: hour,
            timeWindow: '24 hours'
          }
        });
      }
    }
  }

  private getRecentActivityCount(agentDID: string, timeWindowMs: number): number {
    const cutoff = Date.now() - timeWindowMs;
    return this.recentEvents.filter(event => 
      event.type === StreamEventType.ACTIVITY_LOGGED &&
      event.timestamp.getTime() > cutoff &&
      (event.data as AgentActivity).agentDID === agentDID
    ).length;
  }

  private getRecentErrorCount(agentDID: string, timeWindowMs: number): number {
    const cutoff = Date.now() - timeWindowMs;
    return this.recentEvents.filter(event => 
      event.type === StreamEventType.ACTIVITY_LOGGED &&
      event.timestamp.getTime() > cutoff &&
      (event.data as AgentActivity).agentDID === agentDID &&
      [ActivityStatus.FAILED, ActivityStatus.DENIED].includes((event.data as AgentActivity).status)
    ).length;
  }

  private getRecentUnusualHoursCount(agentDID: string, timeWindowMs: number): number {
    const cutoff = Date.now() - timeWindowMs;
    return this.recentEvents.filter(event => 
      event.type === StreamEventType.ACTIVITY_LOGGED &&
      event.timestamp.getTime() > cutoff &&
      (event.data as AgentActivity).agentDID === agentDID &&
      (event.timestamp.getHours() < 8 || event.timestamp.getHours() > 18)
    ).length;
  }

  private generateId(prefix: string): string {
    return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private startCleanupTimer(): void {
    // Run cleanup every 5 minutes
    setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000);
  }
}