/**
 * Audit Logger for MCP
 * 
 * Comprehensive audit logging for all LLM interactions with compliance support
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import {
  AuditConfig,
  AuditExportFormat,
  LLMRequest,
  LLMResponse,
  MCPError,
  MCPErrorCode,
  UsageInfo,
  RequestMetadata,
  FunctionCall
} from '../types';
// Using MemoryStorageProvider directly for audit log storage
import { MemoryStorageProvider } from '../../storage/providers/memory-storage-provider';

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  eventType: AuditEventType;
  agentDID: string;
  sessionId?: string;
  requestId?: string;
  provider?: string;
  model?: string;
  action: string;
  resource?: string;
  status: 'success' | 'failure' | 'error';
  duration?: number;
  metadata: {
    ip?: string;
    userAgent?: string;
    requestSize?: number;
    responseSize?: number;
    error?: string;
    usage?: UsageInfo;
    functionCalls?: FunctionCall[];
    tags?: string[];
  };
  hash?: string;
  previousHash?: string;
}

/**
 * Audit event types
 */
export enum AuditEventType {
  // Authentication events
  AUTH_SUCCESS = 'auth.success',
  AUTH_FAILURE = 'auth.failure',
  AUTH_TOKEN_CREATED = 'auth.token.created',
  AUTH_TOKEN_REFRESHED = 'auth.token.refreshed',
  AUTH_SESSION_CREATED = 'auth.session.created',
  AUTH_SESSION_EXPIRED = 'auth.session.expired',
  
  // Authorization events
  AUTHZ_GRANTED = 'authz.granted',
  AUTHZ_DENIED = 'authz.denied',
  PERMISSION_CHANGED = 'permission.changed',
  
  // LLM interaction events
  LLM_REQUEST = 'llm.request',
  LLM_RESPONSE = 'llm.response',
  LLM_ERROR = 'llm.error',
  LLM_FUNCTION_CALL = 'llm.function_call',
  LLM_STREAMING_START = 'llm.streaming.start',
  LLM_STREAMING_END = 'llm.streaming.end',
  
  // Provider events
  PROVIDER_CONNECTED = 'provider.connected',
  PROVIDER_DISCONNECTED = 'provider.disconnected',
  PROVIDER_ERROR = 'provider.error',
  PROVIDER_FAILOVER = 'provider.failover',
  
  // Security events
  SECURITY_ALERT = 'security.alert',
  RATE_LIMIT_EXCEEDED = 'rate_limit.exceeded',
  CREDENTIAL_ACCESSED = 'credential.accessed',
  CREDENTIAL_ROTATED = 'credential.rotated',
  
  // System events
  SYSTEM_START = 'system.start',
  SYSTEM_SHUTDOWN = 'system.shutdown',
  CONFIG_CHANGED = 'config.changed'
}

/**
 * Audit query options
 */
export interface AuditQueryOptions {
  startDate?: Date;
  endDate?: Date;
  agentDID?: string;
  sessionId?: string;
  eventTypes?: AuditEventType[];
  status?: string;
  provider?: string;
  limit?: number;
  offset?: number;
  sortBy?: 'timestamp' | 'duration' | 'requestSize';
  sortOrder?: 'asc' | 'desc';
}

/**
 * Audit statistics
 */
export interface AuditStatistics {
  totalEvents: number;
  eventsByType: Record<AuditEventType, number>;
  eventsByStatus: Record<string, number>;
  eventsByProvider: Record<string, number>;
  eventsByAgent: Record<string, number>;
  averageResponseTime: number;
  totalTokensUsed: number;
  totalCost: number;
  errorRate: number;
}

/**
 * Compliance report
 */
export interface ComplianceReport {
  period: {
    start: Date;
    end: Date;
  };
  summary: {
    totalRequests: number;
    successRate: number;
    averageResponseTime: number;
    totalCost: number;
    uniqueAgents: number;
    topAgents: Array<{ agentDID: string; requests: number }>;
    topModels: Array<{ model: string; requests: number }>;
  };
  security: {
    authFailures: number;
    authzDenials: number;
    securityAlerts: number;
    rateLimitViolations: number;
  };
  usage: {
    totalTokens: number;
    tokensByProvider: Record<string, number>;
    costByProvider: Record<string, number>;
    functionCalls: number;
  };
  compliance: {
    dataRetentionCompliant: boolean;
    auditTrailIntegrity: boolean;
    unauthorizedAccessAttempts: number;
  };
}

/**
 * Audit Logger
 */
export class AuditLogger extends EventEmitter {
  private logs: Map<string, AuditLogEntry> = new Map();
  private indexByAgent: Map<string, Set<string>> = new Map();
  private indexBySession: Map<string, Set<string>> = new Map();
  private indexByDate: Map<string, Set<string>> = new Map();
  private storageProvider: MemoryStorageProvider;
  private hashChain: string | null = null;
  private retentionTimer?: NodeJS.Timeout;

  constructor(
    private config: AuditConfig,
    storageProvider?: MemoryStorageProvider
  ) {
    super();
    this.storageProvider = storageProvider || new MemoryStorageProvider();
    this.loadLogs();
    this.startRetentionCleanup();
  }

  /**
   * Log LLM request
   */
  async logRequest(
    request: LLMRequest,
    agentDID: string,
    sessionId?: string
  ): Promise<string> {
    const entry: AuditLogEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      eventType: AuditEventType.LLM_REQUEST,
      agentDID,
      sessionId,
      requestId: request.id,
      provider: request.metadata?.source,
      model: request.parameters?.model,
      action: request.type,
      status: 'success',
      metadata: {
        requestSize: JSON.stringify(request).length,
        tags: request.metadata?.tags
      }
    };

    // Log sensitive data only if configured
    if (this.config.logSensitiveData) {
      (entry.metadata as any).prompt = request.prompt;
      if (request.functions) {
        entry.metadata.functionCalls = request.functions.map(f => ({
          name: f.name,
          arguments: {},
          id: `func-${f.name}`
        }));
      }
    }

    return this.addLogEntry(entry);
  }

  /**
   * Log LLM response
   */
  async logResponse(
    response: LLMResponse,
    request: LLMRequest,
    duration: number
  ): Promise<string> {
    const entry: AuditLogEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      eventType: AuditEventType.LLM_RESPONSE,
      agentDID: request.agentDID,
      sessionId: request.sessionId,
      requestId: request.id,
      provider: response.provider,
      model: response.model,
      action: request.type,
      status: response.status === 'success' ? 'success' : 'failure',
      duration,
      metadata: {
        responseSize: response.content ? response.content.length : 0,
        usage: response.usage,
        error: response.error?.message
      }
    };

    // Log response content if configured
    if (this.config.logResponses && this.config.logSensitiveData) {
      (entry.metadata as any).content = response.content;
    }

    if (response.functionCall) {
      entry.metadata.functionCalls = [response.functionCall];
    }

    return this.addLogEntry(entry);
  }

  /**
   * Log authentication event
   */
  async logAuthentication(
    agentDID: string,
    success: boolean,
    method: string,
    error?: string
  ): Promise<string> {
    const entry: AuditLogEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      eventType: success ? AuditEventType.AUTH_SUCCESS : AuditEventType.AUTH_FAILURE,
      agentDID,
      action: `auth.${method}`,
      status: success ? 'success' : 'failure',
      metadata: {
        error
      }
    };

    return this.addLogEntry(entry);
  }

  /**
   * Log authorization event
   */
  async logAuthorization(
    agentDID: string,
    resource: string,
    action: string,
    granted: boolean,
    reasons?: string[]
  ): Promise<string> {
    const entry: AuditLogEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      eventType: granted ? AuditEventType.AUTHZ_GRANTED : AuditEventType.AUTHZ_DENIED,
      agentDID,
      action,
      resource,
      status: granted ? 'success' : 'failure',
      metadata: {
        error: reasons?.join(', ')
      }
    };

    return this.addLogEntry(entry);
  }

  /**
   * Log security alert
   */
  async logSecurityAlert(
    type: string,
    agentDID: string,
    details: any
  ): Promise<string> {
    const entry: AuditLogEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      eventType: AuditEventType.SECURITY_ALERT,
      agentDID,
      action: `security.${type}`,
      status: 'error',
      metadata: {
        error: JSON.stringify(details)
      }
    };

    this.emit('security_alert', entry);
    return this.addLogEntry(entry);
  }

  /**
   * Add log entry
   */
  private async addLogEntry(entry: AuditLogEntry): Promise<string> {
    // Add hash chain for integrity
    if (this.hashChain) {
      entry.previousHash = this.hashChain;
    }
    entry.hash = this.calculateHash(entry);
    this.hashChain = entry.hash;

    // Store in memory
    this.logs.set(entry.id, entry);

    // Update indices
    this.updateIndices(entry);

    // Persist to storage
    await this.persistLog(entry);

    // Emit event
    this.emit('log_added', entry);

    return entry.id;
  }

  /**
   * Update indices
   */
  private updateIndices(entry: AuditLogEntry): void {
    // Agent index
    if (!this.indexByAgent.has(entry.agentDID)) {
      this.indexByAgent.set(entry.agentDID, new Set());
    }
    this.indexByAgent.get(entry.agentDID)!.add(entry.id);

    // Session index
    if (entry.sessionId) {
      if (!this.indexBySession.has(entry.sessionId)) {
        this.indexBySession.set(entry.sessionId, new Set());
      }
      this.indexBySession.get(entry.sessionId)!.add(entry.id);
    }

    // Date index
    const dateKey = entry.timestamp.toISOString().split('T')[0];
    if (!this.indexByDate.has(dateKey)) {
      this.indexByDate.set(dateKey, new Set());
    }
    this.indexByDate.get(dateKey)!.add(entry.id);
  }

  /**
   * Calculate hash for log entry
   */
  private calculateHash(entry: AuditLogEntry): string {
    const data = JSON.stringify({
      id: entry.id,
      timestamp: entry.timestamp,
      eventType: entry.eventType,
      agentDID: entry.agentDID,
      action: entry.action,
      status: entry.status,
      previousHash: entry.previousHash
    });

    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Query audit logs
   */
  async query(options: AuditQueryOptions = {}): Promise<AuditLogEntry[]> {
    let results: AuditLogEntry[] = [];

    // Start with all logs or filtered by indices
    if (options.agentDID) {
      const agentLogs = this.indexByAgent.get(options.agentDID) || new Set();
      results = Array.from(agentLogs).map(id => this.logs.get(id)!).filter(Boolean);
    } else if (options.sessionId) {
      const sessionLogs = this.indexBySession.get(options.sessionId) || new Set();
      results = Array.from(sessionLogs).map(id => this.logs.get(id)!).filter(Boolean);
    } else {
      results = Array.from(this.logs.values());
    }

    // Apply filters
    if (options.startDate) {
      results = results.filter(log => log.timestamp >= options.startDate!);
    }
    if (options.endDate) {
      results = results.filter(log => log.timestamp <= options.endDate!);
    }
    if (options.eventTypes && options.eventTypes.length > 0) {
      results = results.filter(log => options.eventTypes!.includes(log.eventType));
    }
    if (options.status) {
      results = results.filter(log => log.status === options.status);
    }
    if (options.provider) {
      results = results.filter(log => log.provider === options.provider);
    }

    // Sort
    const sortBy = options.sortBy || 'timestamp';
    const sortOrder = options.sortOrder || 'desc';
    results.sort((a, b) => {
      let aVal: any, bVal: any;
      
      switch (sortBy) {
        case 'timestamp':
          aVal = a.timestamp.getTime();
          bVal = b.timestamp.getTime();
          break;
        case 'duration':
          aVal = a.duration || 0;
          bVal = b.duration || 0;
          break;
        case 'requestSize':
          aVal = a.metadata.requestSize || 0;
          bVal = b.metadata.requestSize || 0;
          break;
      }

      return sortOrder === 'asc' ? aVal - bVal : bVal - aVal;
    });

    // Apply pagination
    if (options.offset) {
      results = results.slice(options.offset);
    }
    if (options.limit) {
      results = results.slice(0, options.limit);
    }

    return results;
  }

  /**
   * Get statistics
   */
  async getStatistics(options: AuditQueryOptions = {}): Promise<AuditStatistics> {
    const logs = await this.query(options);
    
    const stats: AuditStatistics = {
      totalEvents: logs.length,
      eventsByType: {} as Record<AuditEventType, number>,
      eventsByStatus: {},
      eventsByProvider: {},
      eventsByAgent: {},
      averageResponseTime: 0,
      totalTokensUsed: 0,
      totalCost: 0,
      errorRate: 0
    };

    let totalDuration = 0;
    let durationCount = 0;
    let errorCount = 0;

    for (const log of logs) {
      // Count by type
      stats.eventsByType[log.eventType] = (stats.eventsByType[log.eventType] || 0) + 1;

      // Count by status
      stats.eventsByStatus[log.status] = (stats.eventsByStatus[log.status] || 0) + 1;

      // Count by provider
      if (log.provider) {
        stats.eventsByProvider[log.provider] = (stats.eventsByProvider[log.provider] || 0) + 1;
      }

      // Count by agent
      stats.eventsByAgent[log.agentDID] = (stats.eventsByAgent[log.agentDID] || 0) + 1;

      // Calculate averages
      if (log.duration) {
        totalDuration += log.duration;
        durationCount++;
      }

      // Sum usage
      if (log.metadata.usage) {
        stats.totalTokensUsed += log.metadata.usage.totalTokens || 0;
        stats.totalCost += log.metadata.usage.cost || 0;
      }

      // Count errors
      if (log.status === 'error' || log.status === 'failure') {
        errorCount++;
      }
    }

    stats.averageResponseTime = durationCount > 0 ? totalDuration / durationCount : 0;
    stats.errorRate = logs.length > 0 ? errorCount / logs.length : 0;

    return stats;
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(startDate: Date, endDate: Date): Promise<ComplianceReport> {
    const logs = await this.query({ startDate, endDate });
    
    const report: ComplianceReport = {
      period: { start: startDate, end: endDate },
      summary: {
        totalRequests: 0,
        successRate: 0,
        averageResponseTime: 0,
        totalCost: 0,
        uniqueAgents: new Set<string>() as any,
        topAgents: [],
        topModels: []
      },
      security: {
        authFailures: 0,
        authzDenials: 0,
        securityAlerts: 0,
        rateLimitViolations: 0
      },
      usage: {
        totalTokens: 0,
        tokensByProvider: {},
        costByProvider: {},
        functionCalls: 0
      },
      compliance: {
        dataRetentionCompliant: true,
        auditTrailIntegrity: true,
        unauthorizedAccessAttempts: 0
      }
    };

    const agentCounts = new Map<string, number>();
    const modelCounts = new Map<string, number>();
    let successCount = 0;
    let totalDuration = 0;
    let durationCount = 0;

    for (const log of logs) {
      // Count requests
      if (log.eventType === AuditEventType.LLM_REQUEST) {
        report.summary.totalRequests++;
      }

      // Track unique agents
      (report.summary.uniqueAgents as any).add(log.agentDID);
      agentCounts.set(log.agentDID, (agentCounts.get(log.agentDID) || 0) + 1);

      // Track models
      if (log.model) {
        modelCounts.set(log.model, (modelCounts.get(log.model) || 0) + 1);
      }

      // Count successes
      if (log.status === 'success') {
        successCount++;
      }

      // Calculate response times
      if (log.duration) {
        totalDuration += log.duration;
        durationCount++;
      }

      // Sum costs
      if (log.metadata.usage?.cost) {
        report.summary.totalCost += log.metadata.usage.cost;
        if (log.provider) {
          report.usage.costByProvider[log.provider] = 
            (report.usage.costByProvider[log.provider] || 0) + log.metadata.usage.cost;
        }
      }

      // Count tokens
      if (log.metadata.usage?.totalTokens) {
        report.usage.totalTokens += log.metadata.usage.totalTokens;
        if (log.provider) {
          report.usage.tokensByProvider[log.provider] = 
            (report.usage.tokensByProvider[log.provider] || 0) + log.metadata.usage.totalTokens;
        }
      }

      // Count function calls
      if (log.metadata.functionCalls) {
        report.usage.functionCalls += log.metadata.functionCalls.length;
      }

      // Security events
      switch (log.eventType) {
        case AuditEventType.AUTH_FAILURE:
          report.security.authFailures++;
          report.compliance.unauthorizedAccessAttempts++;
          break;
        case AuditEventType.AUTHZ_DENIED:
          report.security.authzDenials++;
          break;
        case AuditEventType.SECURITY_ALERT:
          report.security.securityAlerts++;
          break;
        case AuditEventType.RATE_LIMIT_EXCEEDED:
          report.security.rateLimitViolations++;
          break;
      }

      // Check audit trail integrity
      if (log.hash && log.previousHash) {
        // Verify hash chain
        const calculatedHash = this.calculateHash({ ...log, hash: undefined });
        if (calculatedHash !== log.hash) {
          report.compliance.auditTrailIntegrity = false;
        }
      }
    }

    // Finalize summary
    report.summary.uniqueAgents = (report.summary.uniqueAgents as any).size;
    report.summary.successRate = report.summary.totalRequests > 0 
      ? successCount / report.summary.totalRequests 
      : 0;
    report.summary.averageResponseTime = durationCount > 0 
      ? totalDuration / durationCount 
      : 0;

    // Top agents
    report.summary.topAgents = Array.from(agentCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([agentDID, requests]) => ({ agentDID, requests }));

    // Top models
    report.summary.topModels = Array.from(modelCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([model, requests]) => ({ model, requests }));

    // Check retention compliance
    const oldestLog = logs.reduce((oldest, log) => 
      log.timestamp < oldest.timestamp ? log : oldest, 
      logs[0] || { timestamp: new Date() }
    );
    const retentionDays = (Date.now() - oldestLog.timestamp.getTime()) / (1000 * 60 * 60 * 24);
    report.compliance.dataRetentionCompliant = retentionDays <= (this.config.retentionPeriod / (1000 * 60 * 60 * 24));

    return report;
  }

  /**
   * Export logs
   */
  async export(
    format: AuditExportFormat,
    options: AuditQueryOptions = {}
  ): Promise<string> {
    const logs = await this.query(options);

    switch (format) {
      case AuditExportFormat.JSON:
        return JSON.stringify(logs, null, 2);

      case AuditExportFormat.CSV:
        return this.exportCSV(logs);

      case AuditExportFormat.SYSLOG:
        return this.exportSyslog(logs);

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
  private exportCSV(logs: AuditLogEntry[]): string {
    const headers = [
      'ID',
      'Timestamp',
      'Event Type',
      'Agent DID',
      'Session ID',
      'Action',
      'Resource',
      'Status',
      'Duration',
      'Provider',
      'Model',
      'Error'
    ];

    const rows = logs.map(log => [
      log.id,
      log.timestamp.toISOString(),
      log.eventType,
      log.agentDID,
      log.sessionId || '',
      log.action,
      log.resource || '',
      log.status,
      log.duration || '',
      log.provider || '',
      log.model || '',
      log.metadata.error || ''
    ]);

    return [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    ].join('\n');
  }

  /**
   * Export as Syslog
   */
  private exportSyslog(logs: AuditLogEntry[]): string {
    return logs.map(log => {
      const severity = log.status === 'error' ? 3 : log.status === 'failure' ? 4 : 6;
      const facility = 16; // Local0
      const priority = facility * 8 + severity;
      
      return `<${priority}>${log.timestamp.toISOString()} ${log.agentDID} ${log.eventType} - ${JSON.stringify(log)}`;
    }).join('\n');
  }

  /**
   * Load logs from storage
   */
  private async loadLogs(): Promise<void> {
    try {
      // Use internal storage for audit logs
      const storedLogs = (this.storageProvider as any)._storage?.get('mcp:audit:logs');
      if (storedLogs) {
        const logs = JSON.parse(storedLogs);
        for (const log of logs) {
          // Convert dates
          log.timestamp = new Date(log.timestamp);
          
          this.logs.set(log.id, log);
          this.updateIndices(log);
          
          // Update hash chain
          if (log.hash) {
            this.hashChain = log.hash;
          }
        }
      }
    } catch (error) {
      this.emit('error', new MCPError({
        code: MCPErrorCode.INVALID_CONFIG,
        message: `Failed to load audit logs: ${(error as Error).message}`,
        timestamp: new Date(),
        retryable: false
      }));
    }
  }

  /**
   * Persist log to storage
   */
  private async persistLog(entry: AuditLogEntry): Promise<void> {
    if (!this.config.enabled) return;

    try {
      // Get all logs for persistence
      const allLogs = Array.from(this.logs.values());
      
      // Limit to retention period
      const cutoffDate = new Date(Date.now() - this.config.retentionPeriod);
      const logsToKeep = allLogs.filter(log => log.timestamp > cutoffDate);
      
      // Use internal storage for audit logs
      (this.storageProvider as any)._storage = (this.storageProvider as any)._storage || new Map();
      (this.storageProvider as any)._storage.set('mcp:audit:logs', JSON.stringify(logsToKeep));
    } catch (error) {
      this.emit('error', new MCPError({
        code: MCPErrorCode.PROVIDER_ERROR,
        message: `Failed to persist audit log: ${(error as Error).message}`,
        timestamp: new Date(),
        retryable: true
      }));
    }
  }

  /**
   * Start retention cleanup timer
   */
  private startRetentionCleanup(): void {
    if (!this.config.retentionPeriod) return;

    this.retentionTimer = setInterval(() => {
      this.cleanupOldLogs();
    }, 60 * 60 * 1000); // Run every hour
  }

  /**
   * Clean up old logs
   */
  private cleanupOldLogs(): void {
    const cutoffDate = new Date(Date.now() - this.config.retentionPeriod);
    const logsToDelete: string[] = [];

    for (const [id, log] of this.logs.entries()) {
      if (log.timestamp < cutoffDate) {
        logsToDelete.push(id);
      }
    }

    for (const id of logsToDelete) {
      const log = this.logs.get(id)!;
      this.logs.delete(id);
      
      // Remove from indices
      this.indexByAgent.get(log.agentDID)?.delete(id);
      if (log.sessionId) {
        this.indexBySession.get(log.sessionId)?.delete(id);
      }
      const dateKey = log.timestamp.toISOString().split('T')[0];
      this.indexByDate.get(dateKey)?.delete(id);
    }

    if (logsToDelete.length > 0) {
      this.emit('logs_cleaned', logsToDelete.length);
    }
  }

  /**
   * Verify audit trail integrity
   */
  async verifyIntegrity(): Promise<{
    valid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];
    let previousHash: string | null = null;

    const sortedLogs = Array.from(this.logs.values())
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    for (const log of sortedLogs) {
      // Check hash chain
      if (log.previousHash !== previousHash) {
        errors.push(`Hash chain broken at log ${log.id}`);
      }

      // Verify hash
      const calculatedHash = this.calculateHash({ ...log, hash: undefined });
      if (calculatedHash !== log.hash) {
        errors.push(`Invalid hash for log ${log.id}`);
      }

      previousHash = log.hash || null;
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Shutdown audit logger
   */
  shutdown(): void {
    if (this.retentionTimer) {
      clearInterval(this.retentionTimer);
    }

    // Final persist
    this.persistLog({} as AuditLogEntry).catch(() => {});

    this.logs.clear();
    this.indexByAgent.clear();
    this.indexBySession.clear();
    this.indexByDate.clear();

    this.removeAllListeners();
  }
}

export default AuditLogger;