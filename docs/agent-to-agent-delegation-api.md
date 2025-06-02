# Agent-to-Agent Delegation API Reference

This document provides a comprehensive API reference for the agent-to-agent delegation system implemented in the Anonymous Identity Framework.

## Table of Contents

1. [Core Classes](#core-classes)
2. [Agent Management](#agent-management)
3. [Delegation Operations](#delegation-operations)
4. [Chain Validation](#chain-validation)
5. [Policy Management](#policy-management)
6. [Communication Protocol](#communication-protocol)
7. [Revocation System](#revocation-system)
8. [Monitoring and Analytics](#monitoring-and-analytics)
9. [Types and Interfaces](#types-and-interfaces)
10. [Error Handling](#error-handling)

## Core Classes

### AgentIdentityManager

Main class for managing agent identities and their delegation relationships.

```typescript
class AgentIdentityManager {
  constructor()
  
  // Core agent management
  async createAgent(parentDID: string, config: AgentConfig): Promise<AgentIdentity>
  async createSubAgent(parentAgentDID: string, config: SubAgentConfig): Promise<AgentIdentity>
  
  // Agent access
  getAgent(agentDID: string): AgentIdentity | undefined
  getAllAgents(): AgentIdentity[]
  listAgents(parentDID: string): AgentIdentity[]
  deleteAgent(agentDID: string): boolean
  
  // Delegation credentials
  addDelegationCredential(agentDID: string, credential: DelegationCredential): void
  getDelegationCredentials(agentDID: string): DelegationCredential[]
  
  // Access control
  addAccessGrant(agentDID: string, grant: AccessGrant): void
  getAccessGrants(agentDID: string): AccessGrant[]
  revokeServiceAccess(agentDID: string, serviceDID: string): boolean
  
  // Scope management
  reduceScopesForDelegation(
    parentScopes: string[], 
    requestedScopes: string[], 
    policy?: ScopeReductionPolicy
  ): string[]
  
  // Validation
  validateDelegationDepth(agentDID: string): boolean
}
```

#### Methods

##### `createAgent(parentDID: string, config: AgentConfig): Promise<AgentIdentity>`

Creates a new agent under a user or another agent.

**Parameters:**
- `parentDID`: DID of the parent (user or agent)
- `config`: Agent configuration options

**Returns:** Promise resolving to the created `AgentIdentity`

**Example:**
```typescript
const agent = await agentManager.createAgent(userDID, {
  name: 'Assistant Agent',
  description: 'General purpose assistant',
  canDelegate: true,
  maxDelegationDepth: 3
});
```

##### `createSubAgent(parentAgentDID: string, config: SubAgentConfig): Promise<AgentIdentity>`

Creates a sub-agent under an existing agent with reduced permissions.

**Parameters:**
- `parentAgentDID`: DID of the parent agent
- `config`: Sub-agent configuration with requested scopes

**Returns:** Promise resolving to the created sub-agent

**Example:**
```typescript
const subAgent = await agentManager.createSubAgent(parentAgent.did, {
  name: 'Calendar Agent',
  description: 'Specialized calendar management',
  parentAgentDID: parentAgent.did,
  requestedScopes: ['read:calendar', 'write:calendar']
});
```

### DelegationManager

Handles delegation credential creation and verification.

```typescript
class DelegationManager {
  constructor()
  
  async createDelegationCredential(
    issuerDID: string,
    issuerKeyPair: any,
    subjectDID: string,
    subjectName: string,
    grant: AccessGrant,
    metadata?: DelegationMetadata
  ): Promise<DelegationCredential>
  
  async createPresentation(
    holderDID: string,
    holderKeyPair: any,
    serviceDID: string,
    requestedScopes: string[],
    options?: PresentationOptions
  ): Promise<VerifiablePresentation>
  
  async validateDelegation(credential: DelegationCredential): Promise<boolean>
  extractScopes(credential: DelegationCredential): string[]
  isExpired(credential: DelegationCredential): boolean
}
```

### DelegationChainValidator

Validates delegation chains and ensures proper authorization flow.

```typescript
class DelegationChainValidator {
  constructor(delegationManager: DelegationManager, agentManager: AgentIdentityManager)
  
  async validateChain(
    targetAgentDID: string, 
    serviceDID: string
  ): Promise<ChainValidationResult>
  
  async buildChain(targetAgentDID: string): Promise<DelegationChain | null>
  validateChainSignatures(chain: DelegationChain): Promise<boolean>
  validateScopeInheritance(chain: DelegationChain): boolean
  validateChainProperties(chain: DelegationChain): string[]
  
  // Caching
  getCachedChain(agentDID: string): DelegationChain | null
  invalidateCache(agentDID?: string): void
}
```

## Agent Management

### AgentConfig Interface

Configuration for creating new agents.

```typescript
interface AgentConfig {
  name: string;
  description: string;
  canDelegate?: boolean;              // Default: true
  maxDelegationDepth?: number;        // Default: 3
}
```

### SubAgentConfig Interface

Configuration for creating sub-agents with delegation.

```typescript
interface SubAgentConfig {
  name: string;
  description: string;
  parentAgentDID: string;
  requestedScopes: string[];
  maxDelegationDepth?: number;
  scopeReduction?: ScopeReductionPolicy;
}
```

### AgentIdentity Interface

Represents an agent in the system.

```typescript
interface AgentIdentity {
  did: string;
  name: string;
  description: string;
  parentDID: string;
  createdAt: Date;
  keyPair: any;
  maxDelegationDepth: number;
  delegationDepth: number;
  canDelegate: boolean;
  delegatedBy?: string;
}
```

## Delegation Operations

### Creating Delegation Credentials

```typescript
// Create delegation credential
const credential = await delegationManager.createDelegationCredential(
  parentDID,
  parentKeyPair,
  subjectDID,
  subjectName,
  {
    serviceDID: 'example-service',
    scopes: ['read:data', 'write:data'],
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
  }
);

// Add to agent's credential store
agentManager.addDelegationCredential(subjectDID, credential);
```

### Creating Presentations

```typescript
// Create verifiable presentation
const presentation = await delegationManager.createPresentation(
  agentDID,
  agentKeyPair,
  'target-service',
  ['read:data'],
  { 
    challenge: 'service-challenge-123',
    domain: 'https://service.example.com'
  }
);
```

## Chain Validation

### ChainValidationResult

```typescript
interface ChainValidationResult {
  valid: boolean;
  chain?: DelegationChain;
  errors: string[];
  warnings: string[];
}
```

### Validating Delegation Chains

```typescript
// Validate complete delegation chain
const result = await chainValidator.validateChain(agentDID, 'service-id');

if (result.valid) {
  console.log('Chain is valid');
  console.log('Chain length:', result.chain?.agents.length);
} else {
  console.log('Validation errors:', result.errors);
  console.log('Warnings:', result.warnings);
}
```

## Policy Management

### DelegationPolicyEngine

Manages and evaluates delegation policies.

```typescript
class DelegationPolicyEngine {
  constructor(agentManager: AgentIdentityManager)
  
  async evaluatePolicy(
    request: DelegationRequest,
    policy?: DelegationPolicy
  ): Promise<PolicyEvaluationResult>
  
  // Built-in policies
  getBuiltInPolicy(name: 'default' | 'high-security' | 'development' | 'business-hours'): DelegationPolicy
  
  // Policy management
  addPolicy(name: string, policy: DelegationPolicy): void
  getPolicy(name: string): DelegationPolicy | undefined
  listPolicies(): string[]
  
  // Utilities
  calculateExpiration(policy: DelegationPolicy, defaultExpiration: Date): Date
}
```

### Policy Evaluation

```typescript
// Evaluate delegation request against policy
const evaluation = await policyEngine.evaluatePolicy({
  parentAgent: parentAgent,
  requestedScopes: ['read:data', 'write:data'],
  serviceDID: 'example-service',
  metadata: { purpose: 'data analysis' }
});

if (evaluation.allowed) {
  // Proceed with delegation
  console.log('Applied constraints:', evaluation.appliedConstraints);
} else {
  console.log('Policy violations:', evaluation.violations);
}
```

## Communication Protocol

### CommunicationManager

Manages inter-agent communication.

```typescript
class CommunicationManager {
  constructor(
    agentIdentity: AgentIdentity,
    agentManager: AgentIdentityManager,
    delegationManager: DelegationManager,
    policyEngine: DelegationPolicyEngine,
    activityLogger: ActivityLogger,
    config?: CommunicationConfig
  )
  
  // Channel management
  addChannel(channel: CommunicationChannel): void
  removeChannel(channelId: string): Promise<void>
  connectAll(): Promise<void>
  disconnectAll(): Promise<void>
  
  // Messaging
  async sendMessage(message: AgentMessage): Promise<void>
  registerMessageHandler(type: AgentMessageType, handler: MessageHandler): void
  
  // Delegation operations
  async requestDelegation(
    targetAgentDID: string,
    requestedScopes: string[],
    options?: DelegationRequestOptions
  ): Promise<void>
  
  async pingAgent(targetAgentDID: string): Promise<void>
  async queryAgentStatus(
    targetAgentDID: string,
    options?: StatusQueryOptions
  ): Promise<void>
  
  // Statistics
  getStats(channelId?: string): CommunicationStats | Map<string, CommunicationStats>
}
```

### Message Types

```typescript
enum AgentMessageType {
  // Delegation messages
  DELEGATION_REQUEST = 'delegation_request',
  DELEGATION_GRANT = 'delegation_grant',
  DELEGATION_DENY = 'delegation_deny',
  DELEGATION_REVOKE = 'delegation_revoke',
  
  // Status messages
  QUERY_STATUS = 'query_status',
  RESPONSE_STATUS = 'response_status',
  
  // System messages
  PING = 'ping',
  PONG = 'pong',
  ACK = 'ack',
  ERROR = 'error',
  
  // Notification messages
  NOTIFY_REVOCATION = 'notify_revocation',
  NOTIFY_EXPIRATION = 'notify_expiration',
  NOTIFY_POLICY_CHANGE = 'notify_policy_change'
}
```

## Revocation System

### CascadingRevocationManager

Handles agent revocation with cascading support.

```typescript
class CascadingRevocationManager {
  constructor(
    agentManager: AgentIdentityManager,
    chainValidator: DelegationChainValidator,
    communicationManager: CommunicationManager,
    activityLogger: ActivityLogger
  )
  
  async revokeAgent(request: RevocationRequest): Promise<RevocationResult>
  
  // Status checking
  isAgentRevoked(agentDID: string, serviceDID?: string): boolean
  getRevocationAudit(agentDID?: string): RevocationAuditEntry[]
  
  // Statistics
  getRevocationStats(): RevocationStats
  
  // Maintenance
  purgeOldAuditEntries(olderThan: Date): number
  exportAuditTrail(format: 'json' | 'csv'): string
}
```

### Revocation Operations

```typescript
// Individual revocation
const result = await revocationManager.revokeAgent({
  targetAgentDID: 'did:key:agent123',
  reason: 'Security violation',
  revokedBy: 'did:key:admin456',
  timestamp: new Date(),
  cascading: false
});

// Cascading revocation
const cascadingResult = await revocationManager.revokeAgent({
  targetAgentDID: 'did:key:parentAgent',
  reason: 'Department restructuring',
  revokedBy: 'did:key:admin456',
  timestamp: new Date(),
  cascading: true
});

// Service-specific revocation
const serviceResult = await revocationManager.revokeAgent({
  targetAgentDID: 'did:key:agent789',
  reason: 'Service audit',
  revokedBy: 'did:key:admin456',
  timestamp: new Date(),
  cascading: false,
  serviceDID: 'email-service'
});
```

## Monitoring and Analytics

### RevocationMonitoringDashboard

Provides real-time monitoring and analytics.

```typescript
class RevocationMonitoringDashboard {
  constructor(
    auditTrail: EnhancedAuditTrail,
    revocationManager: CascadingRevocationManager,
    agentManager: AgentIdentityManager,
    activityLogger: ActivityLogger,
    config?: DashboardConfig
  )
  
  async getMetrics(filter?: DashboardFilter): Promise<DashboardMetrics>
  async refreshMetrics(filter?: DashboardFilter): Promise<DashboardMetrics>
  
  // Subscriptions
  subscribe(subscriberId: string, callback: (metrics: DashboardMetrics) => void): void
  unsubscribe(subscriberId: string): void
  
  // Reports
  generateReport(filter: DashboardFilter, format?: 'json' | 'html' | 'pdf'): string
  getRevocationStats(filter: DashboardFilter): RevocationStatsReport
  getAgentHealthOverview(): AgentHealthOverview
  
  // Lifecycle
  stop(): void
}
```

### EnhancedAuditTrail

Advanced audit trail with analytics capabilities.

```typescript
class EnhancedAuditTrail {
  constructor(activityLogger: ActivityLogger, config?: AuditConfig)
  
  // Entry management
  async addAuditEntry(entry: RevocationAuditEntry): Promise<void>
  async updateAuditEntry(id: string, updates: Partial<RevocationAuditEntry>): Promise<boolean>
  
  // Querying
  queryAuditEntries(query?: AuditQuery): RevocationAuditEntry[]
  
  // Analytics
  generateAnalytics(forceRefresh?: boolean): AuditAnalytics
  
  // Alerts
  subscribeToAlerts(subscriberId: string, callback: (alert: AuditAlert) => void): void
  unsubscribeFromAlerts(subscriberId: string): void
  getActiveAlerts(): AuditAlert[]
  acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<boolean>
  
  // Export
  exportAuditData(format: 'json' | 'csv' | 'xml', query?: AuditQuery): string
  
  // Compliance
  generateComplianceReport(period: { start: Date; end: Date }): ComplianceReport
}
```

## Types and Interfaces

### Core Types

```typescript
interface DelegationCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: {
    id: string;
    name: string;
    serviceDID: string;
    scopes: string[];
    services: Record<string, any>;
  };
  proof: any;
  metadata?: DelegationMetadata;
}

interface DelegationMetadata {
  delegationDepth?: number;
  maxDelegationDepth?: number;
  canDelegate?: boolean;
  scopeReduction?: ScopeReductionPolicy;
  expirationPolicy?: ExpirationPolicy;
  auditLevel?: 'basic' | 'detailed' | 'comprehensive';
}

interface AccessGrant {
  serviceDID: string;
  scopes: string[];
  expiresAt: Date;
}
```

### Policy Types

```typescript
interface DelegationPolicy {
  name: string;
  description: string;
  maxDelegationDepth: number;
  allowedServices: string[];
  maxScopes: number;
  scopeReduction: ScopeReductionPolicy;
  expirationPolicy: ExpirationPolicy;
  constraints: PolicyConstraint[];
  timeRestrictions?: TimeRestriction[];
}

interface PolicyConstraint {
  type: 'scope_limit' | 'service_restriction' | 'time_limit' | 'custom';
  value: any;
  message?: string;
}

interface ScopeReductionPolicy {
  strategy: 'intersection' | 'subset' | 'hierarchical' | 'category' | 'risk' | 'time' | 'composite' | 'custom';
  customReducer?: (parentScopes: string[], requestedScopes: string[]) => string[];
  parameters?: Record<string, any>;
}
```

### Revocation Types

```typescript
interface RevocationRequest {
  targetAgentDID: string;
  reason: string;
  revokedBy: string;
  timestamp: Date;
  cascading: boolean;
  serviceDID?: string;
  effectiveDate?: Date;
}

interface RevocationResult {
  success: boolean;
  revokedAgents: string[];
  failedRevocations: Array<{
    agentDID: string;
    error: string;
  }>;
  notificationsSent: number;
  auditEntries: number;
}

interface RevocationAuditEntry {
  id: string;
  targetAgentDID: string;
  revokedBy: string;
  reason: string;
  timestamp: Date;
  cascading: boolean;
  serviceDID?: string;
  effectiveDate: Date;
  childRevocations: string[];
  notificationsSent: string[];
  status: 'pending' | 'completed' | 'failed' | 'partial';
}
```

### Communication Types

```typescript
interface AgentMessage {
  id: string;
  type: AgentMessageType;
  from: string;
  to: string;
  timestamp: Date;
  version: string;
  payload: any;
  expiresAt?: Date;
  replyTo?: string;
  metadata?: Record<string, any>;
  signature?: string;
}

interface DelegationRequestMessage extends AgentMessage {
  type: AgentMessageType.DELEGATION_REQUEST;
  payload: {
    requestedScopes: string[];
    serviceDID?: string;
    duration?: number;
    purpose?: string;
    constraints?: Record<string, any>;
  };
}

interface MessageHandler {
  (message: AgentMessage, context: MessageHandlerContext): Promise<AgentMessage | void>;
}

interface MessageHandlerContext {
  agentIdentity: AgentIdentity;
  sendMessage: (message: AgentMessage) => Promise<void>;
  getAgent: (did: string) => AgentIdentity | undefined;
  validateCredential: (credential: DelegationCredential) => Promise<boolean>;
}
```

## Error Handling

### Common Error Types

```typescript
class DelegationError extends Error {
  constructor(message: string, public code: string, public details?: any) {
    super(message);
    this.name = 'DelegationError';
  }
}

class ValidationError extends DelegationError {
  constructor(message: string, details?: any) {
    super(message, 'VALIDATION_ERROR', details);
    this.name = 'ValidationError';
  }
}

class DepthLimitError extends DelegationError {
  constructor(currentDepth: number, maxDepth: number) {
    super(`Delegation depth limit exceeded: ${currentDepth} > ${maxDepth}`, 'DEPTH_LIMIT_ERROR');
    this.name = 'DepthLimitError';
  }
}

class RevocationError extends DelegationError {
  constructor(message: string, agentDID: string) {
    super(message, 'REVOCATION_ERROR', { agentDID });
    this.name = 'RevocationError';
  }
}
```

### Error Handling Best Practices

```typescript
try {
  const subAgent = await agentManager.createSubAgent(parentDID, config);
  const credential = await delegationManager.createDelegationCredential(/*...*/);
  
} catch (error) {
  if (error instanceof DepthLimitError) {
    console.log('Delegation depth limit reached');
  } else if (error instanceof ValidationError) {
    console.log('Validation failed:', error.details);
  } else if (error instanceof DelegationError) {
    console.log('Delegation error:', error.code, error.message);
  } else {
    console.log('Unexpected error:', error);
  }
}
```

## Usage Examples

### Basic Agent Creation and Delegation

```typescript
import { 
  AgentIdentityManager, 
  DelegationManager, 
  DelegationChainValidator 
} from '../src/agent';

// Initialize managers
const agentManager = new AgentIdentityManager();
const delegationManager = new DelegationManager();
const chainValidator = new DelegationChainValidator(delegationManager, agentManager);

// Create parent agent
const parentAgent = await agentManager.createAgent(userDID, {
  name: 'Assistant Agent',
  description: 'General assistant',
  canDelegate: true,
  maxDelegationDepth: 3
});

// Create sub-agent
const subAgent = await agentManager.createSubAgent(parentAgent.did, {
  name: 'Calendar Agent',
  description: 'Calendar specialist',
  parentAgentDID: parentAgent.did,
  requestedScopes: ['read:calendar', 'write:calendar']
});

// Validate delegation chain
const validation = await chainValidator.validateChain(subAgent.did, 'calendar-service');
console.log('Chain valid:', validation.valid);
```

### Complete Workflow Example

```typescript
// 1. Setup
const agentManager = new AgentIdentityManager();
const delegationManager = new DelegationManager();
const chainValidator = new DelegationChainValidator(delegationManager, agentManager);
const policyEngine = new DelegationPolicyEngine(agentManager);

// 2. Create delegation hierarchy
const ceoAgent = await agentManager.createAgent(ceoDID, {
  name: 'CEO Agent',
  description: 'Executive level agent',
  canDelegate: true,
  maxDelegationDepth: 4
});

const deptAgent = await agentManager.createSubAgent(ceoAgent.did, {
  name: 'Department Head',
  description: 'Department level agent',
  parentAgentDID: ceoAgent.did,
  requestedScopes: ['read:dept', 'write:dept', 'manage:dept']
});

// 3. Apply policies
const policy = policyEngine.getBuiltInPolicy('high-security');
const evaluation = await policyEngine.evaluatePolicy({
  parentAgent: deptAgent,
  requestedScopes: ['read:sensitive'],
  serviceDID: 'secure-service'
}, policy);

// 4. Create credential if allowed
if (evaluation.allowed) {
  const credential = await delegationManager.createDelegationCredential(
    deptAgent.did,
    deptAgent.keyPair,
    teamMemberDID,
    'Team Member',
    {
      serviceDID: 'secure-service',
      scopes: evaluation.reducedScopes || ['read:sensitive'],
      expiresAt: policyEngine.calculateExpiration(policy, new Date())
    }
  );
}
```

This API reference provides comprehensive documentation for implementing agent-to-agent delegation in your applications. For complete working examples, see the example files in the `/examples` directory.