# Agent-to-Agent Delegation Best Practices

This guide provides best practices, patterns, and recommendations for implementing secure and effective agent-to-agent delegation using the Anonymous Identity Framework.

## Table of Contents

1. [Security Principles](#security-principles)
2. [Delegation Design Patterns](#delegation-design-patterns)
3. [Scope Management](#scope-management)
4. [Policy Configuration](#policy-configuration)
5. [Monitoring and Auditing](#monitoring-and-auditing)
6. [Performance Optimization](#performance-optimization)
7. [Error Handling](#error-handling)
8. [Common Pitfalls](#common-pitfalls)
9. [Testing Strategies](#testing-strategies)
10. [Production Deployment](#production-deployment)

## Security Principles

### 1. Principle of Least Privilege

Always grant the minimum scopes necessary for an agent to perform its intended function.

**✅ Good Practice:**
```typescript
// Specific scopes for specific tasks
const calendarAgent = await agentManager.createSubAgent(parentAgent.did, {
  name: 'Calendar Manager',
  requestedScopes: ['read:calendar', 'write:calendar'], // Only calendar operations
  maxDelegationDepth: 1 // Prevent further delegation
});
```

**❌ Bad Practice:**
```typescript
// Overly broad scopes
const agent = await agentManager.createSubAgent(parentAgent.did, {
  name: 'Helper Agent',
  requestedScopes: ['*', 'admin:all', 'delete:everything'], // Too permissive
  maxDelegationDepth: 10 // Excessive depth
});
```

### 2. Zero-Trust Delegation

Always verify delegation chains and never trust delegation claims without cryptographic proof.

**✅ Good Practice:**
```typescript
// Always validate chains before granting access
const validation = await chainValidator.validateChain(agentDID, serviceDID);
if (!validation.valid) {
  throw new Error(`Invalid delegation chain: ${validation.errors.join(', ')}`);
}

// Verify signatures and expiration
const isValid = await delegationManager.validateDelegation(credential);
const isExpired = delegationManager.isExpired(credential);

if (!isValid || isExpired) {
  return { verified: false, error: 'Invalid or expired credential' };
}
```

### 3. Time-Bounded Delegations

Set appropriate expiration times for all delegations.

**✅ Good Practice:**
```typescript
const shortTermCredential = await delegationManager.createDelegationCredential(
  issuerDID,
  issuerKeyPair,
  subjectDID,
  subjectName,
  {
    serviceDID: 'temp-service',
    scopes: ['read:data'],
    expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000) // 2 hours for temporary access
  }
);

const regularCredential = await delegationManager.createDelegationCredential(
  issuerDID,
  issuerKeyPair,
  subjectDID,
  subjectName,
  {
    serviceDID: 'regular-service',
    scopes: ['read:profile'],
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours for regular access
  }
);
```

### 4. Depth Control

Implement and enforce delegation depth limits to prevent unauthorized privilege escalation.

**✅ Good Practice:**
```typescript
// Configure appropriate depth limits based on organizational structure
const organizationConfig = {
  ceoAgent: { maxDelegationDepth: 5 }, // Can delegate deep for large org
  departmentHead: { maxDelegationDepth: 3 }, // Limited to team structure
  teamLead: { maxDelegationDepth: 2 }, // Can create sub-agents for team members
  teamMember: { maxDelegationDepth: 1 }, // Can only create task-specific agents
  contractor: { maxDelegationDepth: 0 } // No delegation allowed
};

// Validate depth before creating sub-agents
if (!agentManager.validateDelegationDepth(parentAgent.did)) {
  throw new Error('Maximum delegation depth reached');
}
```

## Delegation Design Patterns

### 1. Hierarchical Organization Pattern

Model organizational structures with appropriate delegation flows.

```typescript
class OrganizationalDelegation {
  private agentManager: AgentIdentityManager;
  private policyEngine: DelegationPolicyEngine;
  
  async createDepartmentStructure(ceoDID: string, department: string) {
    // Department head with broad departmental access
    const deptHead = await this.agentManager.createAgent(ceoDID, {
      name: `${department} Head`,
      description: `Head of ${department} department`,
      canDelegate: true,
      maxDelegationDepth: 3
    });
    
    // Team leads with specific team access
    const teamLead = await this.agentManager.createSubAgent(deptHead.did, {
      name: `${department} Team Lead`,
      parentAgentDID: deptHead.did,
      requestedScopes: [`manage:${department}-team`, `read:${department}`, `write:${department}`]
    });
    
    // Team members with limited operational access
    const teamMember = await this.agentManager.createSubAgent(teamLead.did, {
      name: `${department} Team Member`,
      parentAgentDID: teamLead.did,
      requestedScopes: [`read:${department}`, `write:${department}`]
    });
    
    return { deptHead, teamLead, teamMember };
  }
}
```

### 2. Service-Specific Delegation Pattern

Create specialized agents for different services.

```typescript
class ServiceSpecificDelegation {
  async createServiceAgents(parentDID: string, services: string[]) {
    const serviceAgents = new Map();
    
    for (const service of services) {
      const agent = await this.agentManager.createSubAgent(parentDID, {
        name: `${service} Specialist`,
        description: `Specialized agent for ${service} operations`,
        parentAgentDID: parentDID,
        requestedScopes: this.getServiceScopes(service)
      });
      
      // Create service-specific credential
      const credential = await this.delegationManager.createDelegationCredential(
        parentDID,
        parentAgent.keyPair,
        agent.did,
        agent.name,
        {
          serviceDID: service,
          scopes: this.getServiceScopes(service),
          expiresAt: this.calculateServiceExpiration(service)
        }
      );
      
      serviceAgents.set(service, { agent, credential });
    }
    
    return serviceAgents;
  }
  
  private getServiceScopes(service: string): string[] {
    const scopeMap = {
      'email-service': ['read:emails', 'write:emails', 'manage:folders'],
      'calendar-service': ['read:calendar', 'write:calendar', 'manage:invites'],
      'file-service': ['read:files', 'write:files', 'share:files']
    };
    return scopeMap[service] || [`read:${service}`, `write:${service}`];
  }
}
```

### 3. Temporary Task Pattern

Create short-lived agents for specific tasks.

```typescript
class TemporaryTaskDelegation {
  async createTaskAgent(
    parentDID: string, 
    taskType: string, 
    duration: number
  ) {
    const taskAgent = await this.agentManager.createSubAgent(parentDID, {
      name: `${taskType} Task Agent`,
      description: `Temporary agent for ${taskType}`,
      parentAgentDID: parentDID,
      requestedScopes: this.getTaskScopes(taskType),
      maxDelegationDepth: 0 // No further delegation
    });
    
    // Create short-lived credential
    const credential = await this.delegationManager.createDelegationCredential(
      parentDID,
      parentAgent.keyPair,
      taskAgent.did,
      taskAgent.name,
      {
        serviceDID: `${taskType}-service`,
        scopes: this.getTaskScopes(taskType),
        expiresAt: new Date(Date.now() + duration)
      }
    );
    
    // Schedule automatic cleanup
    setTimeout(async () => {
      await this.cleanupTaskAgent(taskAgent.did);
    }, duration);
    
    return { taskAgent, credential };
  }
  
  private async cleanupTaskAgent(agentDID: string) {
    // Revoke agent when task is complete
    await this.revocationManager.revokeAgent({
      targetAgentDID: agentDID,
      reason: 'Task completion - automatic cleanup',
      revokedBy: 'system',
      timestamp: new Date(),
      cascading: false
    });
  }
}
```

## Scope Management

### 1. Scope Categorization

Organize scopes into logical categories for better management.

```typescript
interface ScopeCategory {
  category: string;
  scopes: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  requiresApproval: boolean;
}

const scopeCategories: ScopeCategory[] = [
  {
    category: 'read-only',
    scopes: ['read:profile', 'read:calendar', 'read:files'],
    riskLevel: 'low',
    requiresApproval: false
  },
  {
    category: 'operational',
    scopes: ['write:calendar', 'write:emails', 'manage:tasks'],
    riskLevel: 'medium',
    requiresApproval: true
  },
  {
    category: 'administrative',
    scopes: ['admin:users', 'manage:permissions', 'delete:data'],
    riskLevel: 'high',
    requiresApproval: true
  },
  {
    category: 'system',
    scopes: ['admin:system', 'delete:all', 'backup:create'],
    riskLevel: 'critical',
    requiresApproval: true
  }
];
```

### 2. Dynamic Scope Reduction

Implement intelligent scope reduction based on context.

```typescript
class ContextualScopeReducer {
  reduceScopes(
    parentScopes: string[],
    requestedScopes: string[],
    context: DelegationContext
  ): string[] {
    const timeBasedReduction = this.applyTimeRestrictions(requestedScopes, context.timestamp);
    const riskBasedReduction = this.applyRiskReduction(timeBasedReduction, context.riskProfile);
    const depthBasedReduction = this.applyDepthReduction(riskBasedReduction, context.delegationDepth);
    
    // Ensure all scopes are subset of parent
    return depthBasedReduction.filter(scope => parentScopes.includes(scope));
  }
  
  private applyTimeRestrictions(scopes: string[], timestamp: Date): string[] {
    const businessHours = this.isBusinessHours(timestamp);
    
    if (!businessHours) {
      // Remove sensitive operations outside business hours
      return scopes.filter(scope => 
        !scope.includes('delete') && 
        !scope.includes('admin') && 
        !scope.includes('transfer')
      );
    }
    
    return scopes;
  }
  
  private applyRiskReduction(scopes: string[], riskProfile: string): string[] {
    const highRiskScopes = ['delete:', 'admin:', 'transfer:', 'backup:'];
    
    if (riskProfile === 'high-risk') {
      return scopes.filter(scope => 
        !highRiskScopes.some(risk => scope.includes(risk))
      );
    }
    
    return scopes;
  }
}
```

### 3. Scope Validation

Implement comprehensive scope validation.

```typescript
class ScopeValidator {
  validateScopes(scopes: string[], context: ValidationContext): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    
    // Check scope format
    for (const scope of scopes) {
      if (!this.isValidScopeFormat(scope)) {
        errors.push(`Invalid scope format: ${scope}`);
      }
    }
    
    // Check scope combinations
    const conflicts = this.findScopeConflicts(scopes);
    errors.push(...conflicts);
    
    // Check risk levels
    const riskyScopes = this.findRiskyScopes(scopes);
    warnings.push(...riskyScopes.map(scope => `High-risk scope: ${scope}`));
    
    // Check business rules
    const businessViolations = this.validateBusinessRules(scopes, context);
    errors.push(...businessViolations);
    
    return {
      valid: errors.length === 0,
      errors,
      warnings,
      filteredScopes: this.filterValidScopes(scopes)
    };
  }
  
  private findScopeConflicts(scopes: string[]): string[] {
    const conflicts: string[] = [];
    
    // Example: read-only and write conflicts
    const hasReadOnly = scopes.some(s => s.includes('readonly:'));
    const hasWrite = scopes.some(s => s.includes('write:'));
    
    if (hasReadOnly && hasWrite) {
      conflicts.push('Conflicting scopes: readonly and write operations');
    }
    
    return conflicts;
  }
}
```

## Policy Configuration

### 1. Environment-Specific Policies

Configure different policies for different environments.

```typescript
class PolicyManager {
  private policies: Map<string, DelegationPolicy> = new Map();
  
  constructor(environment: 'development' | 'staging' | 'production') {
    this.initializePolicies(environment);
  }
  
  private initializePolicies(environment: string) {
    switch (environment) {
      case 'development':
        this.policies.set('default', this.createDevelopmentPolicy());
        break;
      case 'staging':
        this.policies.set('default', this.createStagingPolicy());
        break;
      case 'production':
        this.policies.set('default', this.createProductionPolicy());
        break;
    }
  }
  
  private createProductionPolicy(): DelegationPolicy {
    return {
      name: 'production-default',
      description: 'Strict policy for production environment',
      maxDelegationDepth: 3,
      allowedServices: ['email-service', 'calendar-service', 'file-service'],
      maxScopes: 5,
      scopeReduction: { strategy: 'intersection' },
      expirationPolicy: { strategy: 'fixed', duration: 8 * 60 * 60 * 1000 }, // 8 hours
      constraints: [
        { type: 'time_limit', value: { start: '09:00', end: '17:00' } },
        { type: 'scope_limit', value: { forbidden: ['delete:', 'admin:'] } }
      ]
    };
  }
  
  private createDevelopmentPolicy(): DelegationPolicy {
    return {
      name: 'development-default',
      description: 'Relaxed policy for development',
      maxDelegationDepth: 5,
      allowedServices: ['*'], // All services allowed
      maxScopes: 20,
      scopeReduction: { strategy: 'subset' },
      expirationPolicy: { strategy: 'inherit' },
      constraints: [] // No constraints in development
    };
  }
}
```

### 2. Role-Based Policies

Create policies based on roles and responsibilities.

```typescript
class RoleBasedPolicyEngine extends DelegationPolicyEngine {
  private rolePolicies: Map<string, DelegationPolicy> = new Map();
  
  constructor(agentManager: AgentIdentityManager) {
    super(agentManager);
    this.initializeRolePolicies();
  }
  
  private initializeRolePolicies() {
    // Executive role - high privileges, high security
    this.rolePolicies.set('executive', {
      name: 'executive-policy',
      maxDelegationDepth: 4,
      allowedServices: ['*'],
      maxScopes: 15,
      scopeReduction: { strategy: 'hierarchical' },
      expirationPolicy: { strategy: 'reduced', factor: 0.5 },
      constraints: [
        { type: 'scope_limit', value: { required_approval: ['admin:', 'delete:'] } }
      ]
    });
    
    // Manager role - moderate privileges
    this.rolePolicies.set('manager', {
      name: 'manager-policy',
      maxDelegationDepth: 3,
      allowedServices: ['team-services'],
      maxScopes: 10,
      scopeReduction: { strategy: 'intersection' },
      expirationPolicy: { strategy: 'fixed', duration: 12 * 60 * 60 * 1000 },
      constraints: [
        { type: 'time_limit', value: { business_hours_only: true } }
      ]
    });
    
    // Employee role - limited privileges
    this.rolePolicies.set('employee', {
      name: 'employee-policy',
      maxDelegationDepth: 2,
      allowedServices: ['basic-services'],
      maxScopes: 5,
      scopeReduction: { strategy: 'intersection' },
      expirationPolicy: { strategy: 'fixed', duration: 4 * 60 * 60 * 1000 },
      constraints: [
        { type: 'scope_limit', value: { forbidden: ['admin:', 'delete:', 'transfer:'] } }
      ]
    });
    
    // Contractor role - minimal privileges
    this.rolePolicies.set('contractor', {
      name: 'contractor-policy',
      maxDelegationDepth: 1,
      allowedServices: ['public-services'],
      maxScopes: 3,
      scopeReduction: { strategy: 'intersection' },
      expirationPolicy: { strategy: 'fixed', duration: 2 * 60 * 60 * 1000 },
      constraints: [
        { type: 'scope_limit', value: { whitelist: ['read:assigned-project'] } }
      ]
    });
  }
  
  getPolicyForRole(role: string): DelegationPolicy | undefined {
    return this.rolePolicies.get(role) || this.getBuiltInPolicy('default');
  }
}
```

## Monitoring and Auditing

### 1. Comprehensive Logging

Implement detailed logging for all delegation operations.

```typescript
class DelegationAuditor {
  constructor(private activityLogger: ActivityLogger) {}
  
  async logDelegationCreation(
    issuer: string,
    subject: string,
    scopes: string[],
    context: any
  ) {
    await this.activityLogger.logActivity(createActivity(
      ActivityType.DELEGATION,
      {
        agentDID: issuer,
        parentDID: '',
        serviceDID: context.serviceDID || 'unknown',
        status: ActivityStatus.SUCCESS,
        scopes,
        details: {
          action: 'delegation_created',
          subjectDID: subject,
          grantedScopes: scopes,
          expiresAt: context.expiresAt,
          delegationDepth: context.delegationDepth,
          policy: context.policyUsed
        }
      }
    ));
  }
  
  async logDelegationValidation(
    agentDID: string,
    serviceDID: string,
    result: ChainValidationResult
  ) {
    await this.activityLogger.logActivity(createActivity(
      ActivityType.DELEGATION,
      {
        agentDID,
        parentDID: '',
        serviceDID,
        status: result.valid ? ActivityStatus.SUCCESS : ActivityStatus.FAILED,
        scopes: [],
        details: {
          action: 'delegation_validated',
          chainLength: result.chain?.agents.length || 0,
          errors: result.errors,
          warnings: result.warnings
        }
      }
    ));
  }
}
```

### 2. Real-Time Monitoring

Set up real-time monitoring for delegation activities.

```typescript
class DelegationMonitor {
  private alerts: Map<string, AlertRule> = new Map();
  
  constructor(
    private dashboard: RevocationMonitoringDashboard,
    private auditTrail: EnhancedAuditTrail
  ) {
    this.setupAlertRules();
    this.startMonitoring();
  }
  
  private setupAlertRules() {
    // High frequency delegation alert
    this.alerts.set('high-frequency', {
      name: 'High Frequency Delegation',
      condition: (metrics) => metrics.delegationsPerHour > 100,
      severity: 'medium',
      action: (alert) => this.handleHighFrequencyAlert(alert)
    });
    
    // Unusual depth alert
    this.alerts.set('unusual-depth', {
      name: 'Unusual Delegation Depth',
      condition: (metrics) => metrics.maxDelegationDepth > 5,
      severity: 'high',
      action: (alert) => this.handleUnusualDepthAlert(alert)
    });
    
    // Failed validation spike
    this.alerts.set('validation-failures', {
      name: 'High Validation Failure Rate',
      condition: (metrics) => metrics.validationFailureRate > 0.2,
      severity: 'critical',
      action: (alert) => this.handleValidationFailures(alert)
    });
  }
  
  private startMonitoring() {
    setInterval(async () => {
      const metrics = await this.dashboard.getMetrics();
      
      for (const [id, rule] of this.alerts.entries()) {
        if (rule.condition(metrics)) {
          await rule.action({
            id,
            rule,
            metrics,
            timestamp: new Date()
          });
        }
      }
    }, 60000); // Check every minute
  }
}
```

### 3. Audit Trail Analysis

Implement sophisticated audit trail analysis.

```typescript
class AuditAnalyzer {
  analyzePatterns(entries: RevocationAuditEntry[]): AnalysisReport {
    const patterns = {
      timePatterns: this.analyzeTimePatterns(entries),
      agentPatterns: this.analyzeAgentPatterns(entries),
      servicePatterns: this.analyzeServicePatterns(entries),
      anomalies: this.detectAnomalies(entries)
    };
    
    return {
      patterns,
      recommendations: this.generateRecommendations(patterns),
      riskScore: this.calculateRiskScore(patterns)
    };
  }
  
  private analyzeTimePatterns(entries: RevocationAuditEntry[]) {
    const hourlyDistribution = new Map<number, number>();
    const dailyDistribution = new Map<string, number>();
    
    entries.forEach(entry => {
      const hour = entry.timestamp.getHours();
      const day = entry.timestamp.toDateString();
      
      hourlyDistribution.set(hour, (hourlyDistribution.get(hour) || 0) + 1);
      dailyDistribution.set(day, (dailyDistribution.get(day) || 0) + 1);
    });
    
    return {
      peakHours: this.findPeakHours(hourlyDistribution),
      peakDays: this.findPeakDays(dailyDistribution),
      offHoursActivity: this.calculateOffHoursActivity(hourlyDistribution)
    };
  }
  
  private detectAnomalies(entries: RevocationAuditEntry[]): Anomaly[] {
    const anomalies: Anomaly[] = [];
    
    // Detect bulk operations
    const bulkThreshold = 10;
    const timeWindow = 5 * 60 * 1000; // 5 minutes
    
    for (let i = 0; i < entries.length; i++) {
      const windowEntries = entries.filter(entry => 
        Math.abs(entry.timestamp.getTime() - entries[i].timestamp.getTime()) < timeWindow
      );
      
      if (windowEntries.length >= bulkThreshold) {
        anomalies.push({
          type: 'bulk_operation',
          severity: 'medium',
          description: `${windowEntries.length} operations in 5-minute window`,
          entries: windowEntries.map(e => e.id)
        });
      }
    }
    
    return anomalies;
  }
}
```

## Performance Optimization

### 1. Chain Validation Caching

Implement efficient caching for delegation chain validation.

```typescript
class OptimizedChainValidator extends DelegationChainValidator {
  private cacheStrategy: CacheStrategy;
  
  constructor(
    delegationManager: DelegationManager,
    agentManager: AgentIdentityManager,
    cacheStrategy: CacheStrategy = new LRUCacheStrategy(1000)
  ) {
    super(delegationManager, agentManager);
    this.cacheStrategy = cacheStrategy;
  }
  
  async validateChain(
    targetAgentDID: string,
    serviceDID: string
  ): Promise<ChainValidationResult> {
    const cacheKey = `${targetAgentDID}:${serviceDID}`;
    
    // Check cache first
    const cached = this.cacheStrategy.get(cacheKey);
    if (cached && !this.isCacheExpired(cached)) {
      return cached.result;
    }
    
    // Validate and cache result
    const result = await super.validateChain(targetAgentDID, serviceDID);
    
    this.cacheStrategy.set(cacheKey, {
      result,
      timestamp: new Date(),
      ttl: this.calculateTTL(result)
    });
    
    return result;
  }
  
  private calculateTTL(result: ChainValidationResult): number {
    // Shorter TTL for failed validations
    if (!result.valid) return 5 * 60 * 1000; // 5 minutes
    
    // Longer TTL for valid chains
    return 30 * 60 * 1000; // 30 minutes
  }
}
```

### 2. Batch Operations

Implement efficient batch operations for bulk delegation management.

```typescript
class BatchDelegationManager {
  constructor(
    private agentManager: AgentIdentityManager,
    private delegationManager: DelegationManager
  ) {}
  
  async createBulkDelegations(
    requests: BulkDelegationRequest[]
  ): Promise<BulkDelegationResult> {
    const results: DelegationResult[] = [];
    const batchSize = 10;
    
    // Process in batches to avoid overwhelming the system
    for (let i = 0; i < requests.length; i += batchSize) {
      const batch = requests.slice(i, i + batchSize);
      const batchPromises = batch.map(request => this.processSingleRequest(request));
      
      const batchResults = await Promise.allSettled(batchPromises);
      results.push(...this.processBatchResults(batchResults));
      
      // Add delay between batches to prevent rate limiting
      if (i + batchSize < requests.length) {
        await this.delay(100);
      }
    }
    
    return {
      total: requests.length,
      successful: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length,
      results
    };
  }
  
  private async processSingleRequest(
    request: BulkDelegationRequest
  ): Promise<DelegationResult> {
    try {
      const subAgent = await this.agentManager.createSubAgent(
        request.parentAgentDID,
        request.config
      );
      
      const credential = await this.delegationManager.createDelegationCredential(
        request.parentAgentDID,
        request.parentKeyPair,
        subAgent.did,
        subAgent.name,
        request.grant
      );
      
      return {
        success: true,
        agentDID: subAgent.did,
        credential
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }
}
```

### 3. Memory Management

Implement proper memory management for large-scale deployments.

```typescript
class MemoryEfficientAgentManager extends AgentIdentityManager {
  private readonly maxCacheSize = 10000;
  private cacheEvictionStrategy = new LRUEvictionStrategy();
  
  constructor() {
    super();
    this.setupMemoryManagement();
  }
  
  private setupMemoryManagement() {
    // Periodic cleanup of expired credentials
    setInterval(() => {
      this.cleanupExpiredCredentials();
    }, 60 * 60 * 1000); // Every hour
    
    // Memory pressure monitoring
    setInterval(() => {
      if (this.agents.size > this.maxCacheSize) {
        this.evictLeastRecentlyUsed();
      }
    }, 5 * 60 * 1000); // Every 5 minutes
  }
  
  private cleanupExpiredCredentials() {
    for (const [agentDID, credentials] of this.delegationCredentials.entries()) {
      const validCredentials = credentials.filter(cred => 
        !this.delegationManager.isExpired(cred)
      );
      
      if (validCredentials.length !== credentials.length) {
        this.delegationCredentials.set(agentDID, validCredentials);
      }
    }
  }
  
  private evictLeastRecentlyUsed() {
    const toEvict = this.cacheEvictionStrategy.selectForEviction(
      this.agents,
      this.agents.size - this.maxCacheSize
    );
    
    toEvict.forEach(agentDID => {
      this.agents.delete(agentDID);
      this.delegationCredentials.delete(agentDID);
      this.accessGrants.delete(agentDID);
    });
  }
}
```

## Error Handling

### 1. Graceful Degradation

Implement graceful degradation for delegation failures.

```typescript
class ResilientDelegationService {
  constructor(
    private primaryDelegationManager: DelegationManager,
    private fallbackDelegationManager?: DelegationManager
  ) {}
  
  async createDelegationWithFallback(
    request: DelegationRequest
  ): Promise<DelegationResult> {
    try {
      // Try primary delegation service
      return await this.primaryDelegationManager.createDelegationCredential(
        request.issuerDID,
        request.issuerKeyPair,
        request.subjectDID,
        request.subjectName,
        request.grant
      );
    } catch (primaryError) {
      console.warn('Primary delegation failed, trying fallback:', primaryError);
      
      if (this.fallbackDelegationManager) {
        try {
          return await this.fallbackDelegationManager.createDelegationCredential(
            request.issuerDID,
            request.issuerKeyPair,
            request.subjectDID,
            request.subjectName,
            this.adjustGrantForFallback(request.grant)
          );
        } catch (fallbackError) {
          throw new AggregateError(
            [primaryError, fallbackError],
            'Both primary and fallback delegation failed'
          );
        }
      }
      
      throw primaryError;
    }
  }
  
  private adjustGrantForFallback(grant: AccessGrant): AccessGrant {
    // Reduce scope and duration for fallback
    return {
      ...grant,
      scopes: grant.scopes.filter(scope => !scope.includes('admin')),
      expiresAt: new Date(Math.min(
        grant.expiresAt.getTime(),
        Date.now() + 2 * 60 * 60 * 1000 // Max 2 hours for fallback
      ))
    };
  }
}
```

### 2. Circuit Breaker Pattern

Implement circuit breaker for external dependencies.

```typescript
class CircuitBreakerDelegationManager {
  private circuitBreaker: CircuitBreaker;
  
  constructor(private delegationManager: DelegationManager) {
    this.circuitBreaker = new CircuitBreaker({
      threshold: 5, // Failures before opening
      timeout: 60000, // Reset timeout
      monitor: true
    });
  }
  
  async createDelegationCredential(...args: any[]): Promise<DelegationCredential> {
    return this.circuitBreaker.fire(() => 
      this.delegationManager.createDelegationCredential(...args)
    );
  }
  
  async validateDelegation(credential: DelegationCredential): Promise<boolean> {
    return this.circuitBreaker.fire(() => 
      this.delegationManager.validateDelegation(credential)
    );
  }
}
```

## Common Pitfalls

### 1. Avoid Over-Delegation

**❌ Problem:**
```typescript
// Creating too many agents with overlapping purposes
const emailAgent = await createSubAgent(parent, { scopes: ['read:emails', 'write:emails'] });
const inboxAgent = await createSubAgent(parent, { scopes: ['read:emails'] });
const sentAgent = await createSubAgent(parent, { scopes: ['read:emails'] });
const draftAgent = await createSubAgent(parent, { scopes: ['write:emails'] });
```

**✅ Solution:**
```typescript
// Create a single, well-scoped agent
const emailManager = await createSubAgent(parent, {
  name: 'Email Manager',
  scopes: ['read:emails', 'write:emails', 'manage:folders'],
  description: 'Comprehensive email management'
});
```

### 2. Avoid Scope Creep

**❌ Problem:**
```typescript
// Gradually adding more scopes than necessary
const agent = await createSubAgent(parent, { scopes: ['read:calendar'] });
// Later...
agent.scopes.push('write:calendar', 'delete:events', 'admin:calendar');
```

**✅ Solution:**
```typescript
// Define clear scope requirements upfront
const calendarAgent = await createSubAgent(parent, {
  scopes: ['read:calendar', 'write:calendar'], // Only what's needed
  maxDelegationDepth: 1 // Prevent further scope expansion
});
```

### 3. Avoid Circular Dependencies

**❌ Problem:**
```typescript
// Agent A delegates to Agent B, which delegates back to A
const agentA = await createSubAgent(parent, { name: 'Agent A' });
const agentB = await createSubAgent(agentA.did, { name: 'Agent B' });
// Don't do this:
const agentC = await createSubAgent(agentB.did, { parentDID: agentA.did });
```

**✅ Solution:**
```typescript
// Maintain clear hierarchical structure
const agentA = await createSubAgent(parent, { name: 'Agent A' });
const agentB = await createSubAgent(agentA.did, { name: 'Agent B' });
const agentC = await createSubAgent(agentB.did, { name: 'Agent C' });
// Clear parent-child relationship maintained
```

## Testing Strategies

### 1. Unit Testing

```typescript
describe('DelegationManager', () => {
  let delegationManager: DelegationManager;
  let agentManager: AgentIdentityManager;
  
  beforeEach(() => {
    delegationManager = new DelegationManager();
    agentManager = new AgentIdentityManager();
  });
  
  it('should create valid delegation credential', async () => {
    const parent = await agentManager.createAgent(userDID, {
      name: 'Parent Agent',
      canDelegate: true
    });
    
    const child = await agentManager.createSubAgent(parent.did, {
      name: 'Child Agent',
      parentAgentDID: parent.did,
      requestedScopes: ['read:data']
    });
    
    const credential = await delegationManager.createDelegationCredential(
      parent.did,
      parent.keyPair,
      child.did,
      child.name,
      {
        serviceDID: 'test-service',
        scopes: ['read:data'],
        expiresAt: new Date(Date.now() + 60000)
      }
    );
    
    expect(credential).toBeDefined();
    expect(credential.credentialSubject.scopes).toEqual(['read:data']);
    expect(await delegationManager.validateDelegation(credential)).toBe(true);
  });
});
```

### 2. Integration Testing

```typescript
describe('End-to-End Delegation Flow', () => {
  it('should handle complete delegation and verification flow', async () => {
    // Setup
    const agentManager = new AgentIdentityManager();
    const delegationManager = new DelegationManager();
    const chainValidator = new DelegationChainValidator(delegationManager, agentManager);
    const serviceProvider = new ServiceProviderAgent(['test-service'], chainValidator);
    
    // Create delegation hierarchy
    const parent = await agentManager.createAgent(userDID, { /* config */ });
    const child = await agentManager.createSubAgent(parent.did, { /* config */ });
    
    // Create credentials
    const credential = await delegationManager.createDelegationCredential(/* args */);
    agentManager.addDelegationCredential(child.did, credential);
    
    // Create presentation
    const presentation = await delegationManager.createPresentation(/* args */);
    
    // Verify with service provider
    const verification = await serviceProvider.verifyPresentation(presentation);
    
    expect(verification.verified).toBe(true);
    expect(verification.grantedScopes).toContain('read:data');
  });
});
```

### 3. Load Testing

```typescript
describe('Delegation Performance', () => {
  it('should handle high-volume delegation creation', async () => {
    const agentManager = new AgentIdentityManager();
    const delegationManager = new DelegationManager();
    
    const parent = await agentManager.createAgent(userDID, {
      name: 'Load Test Parent',
      maxDelegationDepth: 5
    });
    
    const promises = Array.from({ length: 1000 }, async (_, i) => {
      const child = await agentManager.createSubAgent(parent.did, {
        name: `Load Test Child ${i}`,
        parentAgentDID: parent.did,
        requestedScopes: ['read:data']
      });
      
      return delegationManager.createDelegationCredential(
        parent.did,
        parent.keyPair,
        child.did,
        child.name,
        {
          serviceDID: 'load-test-service',
          scopes: ['read:data'],
          expiresAt: new Date(Date.now() + 60000)
        }
      );
    });
    
    const startTime = Date.now();
    const results = await Promise.all(promises);
    const endTime = Date.now();
    
    expect(results.length).toBe(1000);
    expect(endTime - startTime).toBeLessThan(10000); // Should complete in under 10 seconds
  });
});
```

## Production Deployment

### 1. Configuration Management

```typescript
interface DelegationConfig {
  environment: 'development' | 'staging' | 'production';
  defaultPolicy: string;
  maxAgentsPerUser: number;
  maxDelegationDepth: number;
  credentialTTL: number;
  auditRetention: number;
  monitoring: {
    enabled: boolean;
    alertThresholds: AlertThresholds;
  };
  storage: {
    provider: 'memory' | 'redis' | 'database';
    connectionString?: string;
  };
}

class DelegationService {
  constructor(private config: DelegationConfig) {
    this.validateConfig(config);
    this.initializeComponents(config);
  }
  
  private validateConfig(config: DelegationConfig) {
    if (config.environment === 'production' && config.storage.provider === 'memory') {
      throw new Error('Memory storage not suitable for production');
    }
    
    if (config.maxDelegationDepth > 10) {
      console.warn('High delegation depth may impact performance');
    }
  }
}
```

### 2. Health Checks

```typescript
class DelegationHealthCheck {
  constructor(
    private agentManager: AgentIdentityManager,
    private delegationManager: DelegationManager,
    private chainValidator: DelegationChainValidator
  ) {}
  
  async checkHealth(): Promise<HealthStatus> {
    const checks = await Promise.allSettled([
      this.checkAgentManager(),
      this.checkDelegationManager(),
      this.checkChainValidator(),
      this.checkMemoryUsage(),
      this.checkPerformance()
    ]);
    
    const results = checks.map((check, index) => ({
      name: ['agentManager', 'delegationManager', 'chainValidator', 'memory', 'performance'][index],
      status: check.status === 'fulfilled' ? 'healthy' : 'unhealthy',
      details: check.status === 'fulfilled' ? check.value : check.reason
    }));
    
    const overall = results.every(r => r.status === 'healthy') ? 'healthy' : 'unhealthy';
    
    return { overall, checks: results, timestamp: new Date() };
  }
  
  private async checkPerformance(): Promise<PerformanceMetrics> {
    const start = Date.now();
    
    // Test delegation creation
    const testAgent = await this.agentManager.createAgent('test:user', {
      name: 'Health Check Agent'
    });
    
    const creationTime = Date.now() - start;
    
    // Cleanup
    this.agentManager.deleteAgent(testAgent.did);
    
    return {
      delegationCreationTime: creationTime,
      healthy: creationTime < 1000 // Should complete in under 1 second
    };
  }
}
```

### 3. Monitoring Integration

```typescript
class ProductionDelegationMonitor {
  constructor(
    private metricsCollector: MetricsCollector,
    private alertManager: AlertManager
  ) {}
  
  startMonitoring() {
    // Collect metrics every minute
    setInterval(() => {
      this.collectMetrics();
    }, 60000);
    
    // Check alerts every 30 seconds
    setInterval(() => {
      this.checkAlerts();
    }, 30000);
  }
  
  private async collectMetrics() {
    const metrics = {
      activeAgents: this.agentManager.getAllAgents().length,
      delegationsPerMinute: this.getDelegationsPerMinute(),
      validationSuccessRate: this.getValidationSuccessRate(),
      averageChainLength: this.getAverageChainLength(),
      memoryUsage: process.memoryUsage(),
      responseTime: await this.measureResponseTime()
    };
    
    this.metricsCollector.record(metrics);
  }
  
  private async checkAlerts() {
    const metrics = await this.getLatestMetrics();
    
    if (metrics.delegationsPerMinute > 500) {
      this.alertManager.trigger({
        severity: 'warning',
        message: 'High delegation rate detected',
        metrics
      });
    }
    
    if (metrics.validationSuccessRate < 0.95) {
      this.alertManager.trigger({
        severity: 'critical',
        message: 'Low validation success rate',
        metrics
      });
    }
  }
}
```

## Conclusion

Following these best practices will help you build a secure, scalable, and maintainable agent-to-agent delegation system. Key takeaways:

1. **Security First**: Always apply the principle of least privilege and implement proper validation
2. **Monitor Everything**: Comprehensive logging and monitoring are essential for production systems
3. **Plan for Scale**: Design with performance and memory management in mind
4. **Test Thoroughly**: Implement comprehensive testing strategies including load testing
5. **Handle Errors Gracefully**: Implement proper error handling and fallback mechanisms

Remember that delegation systems are complex and security-critical. Regular security audits and penetration testing are recommended for production deployments.