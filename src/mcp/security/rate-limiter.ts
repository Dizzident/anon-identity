/**
 * Enhanced Rate Limiter and Quota Manager for MCP
 * 
 * Implements sophisticated rate limiting and quota management for LLM interactions
 */

import { EventEmitter } from 'events';
import {
  RateLimitInfo,
  LLMRequest,
  MCPError,
  MCPErrorCode,
  UsageInfo
} from '../types';

/**
 * Rate limit window types
 */
export enum RateLimitWindow {
  SECOND = 1000,
  MINUTE = 60000,
  HOUR = 3600000,
  DAY = 86400000,
  WEEK = 604800000,
  MONTH = 2592000000
}

/**
 * Rate limit rule
 */
export interface RateLimitRule {
  id: string;
  name: string;
  description?: string;
  window: RateLimitWindow;
  limit: number;
  resource?: string;
  action?: string;
  scope: 'global' | 'agent' | 'provider' | 'model';
  priority: number;
  burst?: number;
  cooldown?: number;
}

/**
 * Token bucket for rate limiting
 */
interface TokenBucket {
  tokens: number;
  capacity: number;
  refillRate: number;
  lastRefill: number;
}

/**
 * Quota definition
 */
export interface Quota {
  id: string;
  name: string;
  agentDID?: string;
  provider?: string;
  model?: string;
  window: RateLimitWindow;
  limits: {
    requests?: number;
    tokens?: number;
    cost?: number;
  };
  usage: {
    requests: number;
    tokens: number;
    cost: number;
  };
  resetAt: Date;
  warningThreshold?: number;
  hardLimit: boolean;
}

/**
 * Rate limit result
 */
export interface RateLimitResult {
  allowed: boolean;
  limit?: number;
  remaining?: number;
  resetAt?: Date;
  retryAfter?: number;
  reason?: string;
  violatedRules?: RateLimitRule[];
}

/**
 * Quota status
 */
export interface QuotaStatus {
  quota: Quota;
  percentageUsed: number;
  remaining: {
    requests?: number;
    tokens?: number;
    cost?: number;
  };
  willReset: Date;
  isWarning: boolean;
  isExceeded: boolean;
}

/**
 * Usage tracking entry
 */
interface UsageEntry {
  timestamp: number;
  agentDID: string;
  provider?: string;
  model?: string;
  requests: number;
  tokens: number;
  cost: number;
}

/**
 * Enhanced Rate Limiter and Quota Manager
 */
export class RateLimiterManager extends EventEmitter {
  private rules: Map<string, RateLimitRule> = new Map();
  private quotas: Map<string, Quota> = new Map();
  private tokenBuckets: Map<string, TokenBucket> = new Map();
  private usageHistory: UsageEntry[] = [];
  private slidingWindows: Map<string, number[]> = new Map();
  private cooldowns: Map<string, number> = new Map();
  private cleanupInterval?: NodeJS.Timeout;

  constructor() {
    super();
    this.initializeDefaultRules();
    this.startCleanupTimer();
  }

  /**
   * Initialize default rate limit rules
   */
  private initializeDefaultRules(): void {
    // Global rate limits
    this.addRule({
      id: 'global-requests-per-second',
      name: 'Global requests per second',
      window: RateLimitWindow.SECOND,
      limit: 10,
      scope: 'global',
      priority: 100,
      burst: 20
    });

    this.addRule({
      id: 'global-requests-per-minute',
      name: 'Global requests per minute',
      window: RateLimitWindow.MINUTE,
      limit: 100,
      scope: 'global',
      priority: 90
    });

    // Per-agent rate limits
    this.addRule({
      id: 'agent-requests-per-minute',
      name: 'Agent requests per minute',
      window: RateLimitWindow.MINUTE,
      limit: 60,
      scope: 'agent',
      priority: 80
    });

    this.addRule({
      id: 'agent-requests-per-hour',
      name: 'Agent requests per hour',
      window: RateLimitWindow.HOUR,
      limit: 1000,
      scope: 'agent',
      priority: 70
    });

    // Per-provider rate limits
    this.addRule({
      id: 'provider-requests-per-minute',
      name: 'Provider requests per minute',
      window: RateLimitWindow.MINUTE,
      limit: 50,
      scope: 'provider',
      priority: 60
    });
  }

  /**
   * Check rate limit
   */
  async checkRateLimit(
    request: LLMRequest,
    provider?: string,
    model?: string
  ): Promise<RateLimitResult> {
    const agentDID = request.agentDID;
    const violatedRules: RateLimitRule[] = [];
    let mostRestrictive: RateLimitResult | null = null;

    // Check all applicable rules
    const applicableRules = this.getApplicableRules(request, provider, model);
    
    for (const rule of applicableRules) {
      const key = this.getRateLimitKey(rule, agentDID, provider, model);
      const result = this.checkRule(rule, key);
      
      if (!result.allowed) {
        violatedRules.push(rule);
        
        // Track most restrictive rule
        if (!mostRestrictive || (result.retryAfter || 0) > (mostRestrictive.retryAfter || 0)) {
          mostRestrictive = result;
        }
      }
    }

    // If any rule violated, return the most restrictive
    if (mostRestrictive) {
      return {
        ...mostRestrictive,
        violatedRules
      };
    }

    // All rules passed - consume tokens
    for (const rule of applicableRules) {
      const key = this.getRateLimitKey(rule, agentDID, provider, model);
      this.consumeToken(rule, key);
    }

    return { allowed: true };
  }

  /**
   * Check quota
   */
  async checkQuota(
    agentDID: string,
    usage: UsageInfo,
    provider?: string,
    model?: string
  ): Promise<RateLimitResult> {
    const applicableQuotas = this.getApplicableQuotas(agentDID, provider, model);
    
    for (const quota of applicableQuotas) {
      // Check if quota would be exceeded
      const wouldExceed = this.wouldExceedQuota(quota, usage);
      
      if (wouldExceed && quota.hardLimit) {
        return {
          allowed: false,
          reason: `Quota exceeded: ${quota.name}`,
          resetAt: quota.resetAt,
          retryAfter: Math.ceil((quota.resetAt.getTime() - Date.now()) / 1000)
        };
      }

      // Check warning threshold
      if (quota.warningThreshold) {
        const percentageAfter = this.calculateQuotaPercentage(quota, usage);
        if (percentageAfter >= quota.warningThreshold) {
          this.emit('quota_warning', {
            quota,
            percentageUsed: percentageAfter,
            agentDID
          });
        }
      }
    }

    return { allowed: true };
  }

  /**
   * Record usage
   */
  async recordUsage(
    agentDID: string,
    usage: UsageInfo,
    provider?: string,
    model?: string
  ): Promise<void> {
    // Record in history
    const entry: UsageEntry = {
      timestamp: Date.now(),
      agentDID,
      provider,
      model,
      requests: 1,
      tokens: usage.totalTokens || 0,
      cost: usage.cost || 0
    };
    
    this.usageHistory.push(entry);

    // Update quotas
    const applicableQuotas = this.getApplicableQuotas(agentDID, provider, model);
    for (const quota of applicableQuotas) {
      quota.usage.requests += 1;
      quota.usage.tokens += usage.totalTokens || 0;
      quota.usage.cost += usage.cost || 0;

      // Check if quota exceeded
      if (this.isQuotaExceeded(quota)) {
        this.emit('quota_exceeded', {
          quota,
          agentDID,
          provider,
          model
        });
      }
    }

    // Emit usage event
    this.emit('usage_recorded', entry);
  }

  /**
   * Add rate limit rule
   */
  addRule(rule: RateLimitRule): void {
    this.rules.set(rule.id, rule);
    
    // Initialize token bucket if using burst
    if (rule.burst) {
      const key = this.getRateLimitKey(rule, '*', '*', '*');
      this.tokenBuckets.set(key, {
        tokens: rule.burst,
        capacity: rule.burst,
        refillRate: rule.limit / (rule.window / 1000),
        lastRefill: Date.now()
      });
    }
  }

  /**
   * Remove rate limit rule
   */
  removeRule(ruleId: string): void {
    this.rules.delete(ruleId);
  }

  /**
   * Add quota
   */
  addQuota(quota: Quota): void {
    // Set reset time
    quota.resetAt = new Date(Date.now() + quota.window);
    
    // Initialize usage if not set
    if (!quota.usage) {
      quota.usage = {
        requests: 0,
        tokens: 0,
        cost: 0
      };
    }

    this.quotas.set(quota.id, quota);
    
    // Schedule quota reset
    this.scheduleQuotaReset(quota);
  }

  /**
   * Remove quota
   */
  removeQuota(quotaId: string): void {
    this.quotas.delete(quotaId);
  }

  /**
   * Get quota status
   */
  getQuotaStatus(quotaId: string): QuotaStatus | null {
    const quota = this.quotas.get(quotaId);
    if (!quota) return null;

    const percentageUsed = this.calculateQuotaPercentage(quota);
    const isWarning = quota.warningThreshold ? percentageUsed >= quota.warningThreshold : false;
    const isExceeded = this.isQuotaExceeded(quota);

    return {
      quota,
      percentageUsed,
      remaining: {
        requests: quota.limits.requests ? Math.max(0, quota.limits.requests - quota.usage.requests) : undefined,
        tokens: quota.limits.tokens ? Math.max(0, quota.limits.tokens - quota.usage.tokens) : undefined,
        cost: quota.limits.cost ? Math.max(0, quota.limits.cost - quota.usage.cost) : undefined
      },
      willReset: quota.resetAt,
      isWarning,
      isExceeded
    };
  }

  /**
   * Get all quota statuses for agent
   */
  getAgentQuotaStatuses(agentDID: string): QuotaStatus[] {
    const statuses: QuotaStatus[] = [];
    
    for (const quota of this.quotas.values()) {
      if (!quota.agentDID || quota.agentDID === agentDID) {
        const status = this.getQuotaStatus(quota.id);
        if (status) {
          statuses.push(status);
        }
      }
    }

    return statuses;
  }

  /**
   * Get usage statistics
   */
  getUsageStatistics(
    window: RateLimitWindow,
    agentDID?: string,
    provider?: string
  ): {
    requests: number;
    tokens: number;
    cost: number;
    averageTokensPerRequest: number;
    peakRequestsPerMinute: number;
  } {
    const cutoff = Date.now() - window;
    const relevantEntries = this.usageHistory.filter(entry => {
      if (entry.timestamp < cutoff) return false;
      if (agentDID && entry.agentDID !== agentDID) return false;
      if (provider && entry.provider !== provider) return false;
      return true;
    });

    const stats = {
      requests: 0,
      tokens: 0,
      cost: 0,
      averageTokensPerRequest: 0,
      peakRequestsPerMinute: 0
    };

    // Sum up usage
    for (const entry of relevantEntries) {
      stats.requests += entry.requests;
      stats.tokens += entry.tokens;
      stats.cost += entry.cost;
    }

    // Calculate averages
    if (stats.requests > 0) {
      stats.averageTokensPerRequest = stats.tokens / stats.requests;
    }

    // Calculate peak requests per minute
    const minuteBuckets = new Map<number, number>();
    for (const entry of relevantEntries) {
      const minute = Math.floor(entry.timestamp / 60000);
      minuteBuckets.set(minute, (minuteBuckets.get(minute) || 0) + entry.requests);
    }
    stats.peakRequestsPerMinute = Math.max(...Array.from(minuteBuckets.values()), 0);

    return stats;
  }

  /**
   * Get applicable rules
   */
  private getApplicableRules(
    request: LLMRequest,
    provider?: string,
    model?: string
  ): RateLimitRule[] {
    const rules = Array.from(this.rules.values());
    
    return rules
      .filter(rule => {
        // Check resource match
        if (rule.resource && rule.resource !== request.type) return false;
        
        // Check action match
        if (rule.action && rule.action !== request.type) return false;
        
        return true;
      })
      .sort((a, b) => b.priority - a.priority);
  }

  /**
   * Get applicable quotas
   */
  private getApplicableQuotas(
    agentDID: string,
    provider?: string,
    model?: string
  ): Quota[] {
    const quotas: Quota[] = [];
    
    for (const quota of this.quotas.values()) {
      // Check if quota applies
      if (quota.agentDID && quota.agentDID !== agentDID) continue;
      if (quota.provider && quota.provider !== provider) continue;
      if (quota.model && quota.model !== model) continue;
      
      quotas.push(quota);
    }

    return quotas;
  }

  /**
   * Get rate limit key
   */
  private getRateLimitKey(
    rule: RateLimitRule,
    agentDID: string,
    provider?: string,
    model?: string
  ): string {
    const parts = [`rule:${rule.id}`];
    
    switch (rule.scope) {
      case 'global':
        parts.push('global');
        break;
      case 'agent':
        parts.push(`agent:${agentDID}`);
        break;
      case 'provider':
        parts.push(`provider:${provider || 'unknown'}`);
        break;
      case 'model':
        parts.push(`model:${model || 'unknown'}`);
        break;
    }

    return parts.join(':');
  }

  /**
   * Check rule using sliding window
   */
  private checkRule(rule: RateLimitRule, key: string): RateLimitResult {
    // Check cooldown first
    const cooldownUntil = this.cooldowns.get(key);
    if (cooldownUntil && cooldownUntil > Date.now()) {
      return {
        allowed: false,
        limit: rule.limit,
        remaining: 0,
        retryAfter: Math.ceil((cooldownUntil - Date.now()) / 1000),
        reason: `Rate limit cooldown for ${rule.name}`
      };
    }

    // Use token bucket if configured
    if (rule.burst) {
      return this.checkTokenBucket(rule, key);
    }

    // Use sliding window
    const now = Date.now();
    const window = rule.window;
    const windowStart = now - window;

    // Get or create sliding window
    let timestamps = this.slidingWindows.get(key) || [];
    
    // Remove old entries
    timestamps = timestamps.filter(t => t > windowStart);
    this.slidingWindows.set(key, timestamps);

    // Check if limit exceeded
    if (timestamps.length >= rule.limit) {
      const oldestTimestamp = timestamps[0];
      const resetAt = new Date(oldestTimestamp + window);
      
      // Apply cooldown if configured
      if (rule.cooldown) {
        this.cooldowns.set(key, now + rule.cooldown);
      }

      return {
        allowed: false,
        limit: rule.limit,
        remaining: 0,
        resetAt,
        retryAfter: Math.ceil((resetAt.getTime() - now) / 1000),
        reason: `Rate limit exceeded for ${rule.name}`
      };
    }

    return {
      allowed: true,
      limit: rule.limit,
      remaining: rule.limit - timestamps.length
    };
  }

  /**
   * Check token bucket
   */
  private checkTokenBucket(rule: RateLimitRule, key: string): RateLimitResult {
    let bucket = this.tokenBuckets.get(key);
    
    if (!bucket) {
      bucket = {
        tokens: rule.burst!,
        capacity: rule.burst!,
        refillRate: rule.limit / (rule.window / 1000),
        lastRefill: Date.now()
      };
      this.tokenBuckets.set(key, bucket);
    }

    // Refill tokens
    const now = Date.now();
    const timePassed = (now - bucket.lastRefill) / 1000;
    const tokensToAdd = timePassed * bucket.refillRate;
    
    bucket.tokens = Math.min(bucket.capacity, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;

    // Check if token available
    if (bucket.tokens < 1) {
      const timeToNextToken = (1 - bucket.tokens) / bucket.refillRate;
      
      return {
        allowed: false,
        limit: rule.limit,
        remaining: Math.floor(bucket.tokens),
        retryAfter: Math.ceil(timeToNextToken),
        reason: `Rate limit exceeded for ${rule.name} (token bucket)`
      };
    }

    return {
      allowed: true,
      limit: rule.limit,
      remaining: Math.floor(bucket.tokens)
    };
  }

  /**
   * Consume token
   */
  private consumeToken(rule: RateLimitRule, key: string): void {
    if (rule.burst) {
      // Consume from token bucket
      const bucket = this.tokenBuckets.get(key);
      if (bucket) {
        bucket.tokens = Math.max(0, bucket.tokens - 1);
      }
    } else {
      // Add to sliding window
      const timestamps = this.slidingWindows.get(key) || [];
      timestamps.push(Date.now());
      this.slidingWindows.set(key, timestamps);
    }
  }

  /**
   * Calculate quota percentage used
   */
  private calculateQuotaPercentage(quota: Quota, additionalUsage?: UsageInfo): number {
    let percentage = 0;
    let count = 0;

    if (quota.limits.requests) {
      const used = quota.usage.requests + (additionalUsage ? 1 : 0);
      percentage += (used / quota.limits.requests) * 100;
      count++;
    }

    if (quota.limits.tokens) {
      const used = quota.usage.tokens + (additionalUsage?.totalTokens || 0);
      percentage += (used / quota.limits.tokens) * 100;
      count++;
    }

    if (quota.limits.cost) {
      const used = quota.usage.cost + (additionalUsage?.cost || 0);
      percentage += (used / quota.limits.cost) * 100;
      count++;
    }

    return count > 0 ? percentage / count : 0;
  }

  /**
   * Check if quota would be exceeded
   */
  private wouldExceedQuota(quota: Quota, usage: UsageInfo): boolean {
    if (quota.limits.requests && quota.usage.requests + 1 > quota.limits.requests) {
      return true;
    }

    if (quota.limits.tokens && quota.usage.tokens + (usage.totalTokens || 0) > quota.limits.tokens) {
      return true;
    }

    if (quota.limits.cost && quota.usage.cost + (usage.cost || 0) > quota.limits.cost) {
      return true;
    }

    return false;
  }

  /**
   * Check if quota is exceeded
   */
  private isQuotaExceeded(quota: Quota): boolean {
    if (quota.limits.requests && quota.usage.requests > quota.limits.requests) {
      return true;
    }

    if (quota.limits.tokens && quota.usage.tokens > quota.limits.tokens) {
      return true;
    }

    if (quota.limits.cost && quota.usage.cost > quota.limits.cost) {
      return true;
    }

    return false;
  }

  /**
   * Schedule quota reset
   */
  private scheduleQuotaReset(quota: Quota): void {
    const timeUntilReset = quota.resetAt.getTime() - Date.now();
    
    if (timeUntilReset > 0) {
      setTimeout(() => {
        this.resetQuota(quota);
      }, timeUntilReset);
    }
  }

  /**
   * Reset quota
   */
  private resetQuota(quota: Quota): void {
    quota.usage = {
      requests: 0,
      tokens: 0,
      cost: 0
    };
    
    quota.resetAt = new Date(Date.now() + quota.window);
    
    this.emit('quota_reset', quota);
    
    // Schedule next reset
    this.scheduleQuotaReset(quota);
  }

  /**
   * Start cleanup timer
   */
  private startCleanupTimer(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000); // Run every minute
  }

  /**
   * Clean up old data
   */
  private cleanup(): void {
    const now = Date.now();
    
    // Clean old usage history (keep 24 hours)
    const historyAge = 24 * 60 * 60 * 1000;
    this.usageHistory = this.usageHistory.filter(entry => entry.timestamp > now - historyAge);

    // Clean expired cooldowns
    for (const [key, expiry] of this.cooldowns.entries()) {
      if (expiry < now) {
        this.cooldowns.delete(key);
      }
    }

    // Clean old sliding window entries
    for (const [key, timestamps] of this.slidingWindows.entries()) {
      // Keep entries for the longest window (1 month)
      const maxAge = RateLimitWindow.MONTH;
      const filtered = timestamps.filter(t => t > now - maxAge);
      
      if (filtered.length === 0) {
        this.slidingWindows.delete(key);
      } else if (filtered.length < timestamps.length) {
        this.slidingWindows.set(key, filtered);
      }
    }
  }

  /**
   * Export rate limit configuration
   */
  exportConfiguration(): {
    rules: RateLimitRule[];
    quotas: Quota[];
  } {
    return {
      rules: Array.from(this.rules.values()),
      quotas: Array.from(this.quotas.values())
    };
  }

  /**
   * Import rate limit configuration
   */
  importConfiguration(config: {
    rules?: RateLimitRule[];
    quotas?: Quota[];
  }): void {
    if (config.rules) {
      for (const rule of config.rules) {
        this.addRule(rule);
      }
    }

    if (config.quotas) {
      for (const quota of config.quotas) {
        this.addQuota(quota);
      }
    }
  }

  /**
   * Shutdown rate limiter
   */
  shutdown(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    this.rules.clear();
    this.quotas.clear();
    this.tokenBuckets.clear();
    this.usageHistory = [];
    this.slidingWindows.clear();
    this.cooldowns.clear();

    this.removeAllListeners();
  }
}

export default RateLimiterManager;