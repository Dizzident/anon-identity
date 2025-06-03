# MCP Integration API Reference

## Overview

The Model Context Protocol (MCP) integration provides a unified interface for all LLM communications within the Anonymous Identity Framework. This document provides comprehensive API reference for all MCP components.

## Table of Contents

- [Core MCP Components](#core-mcp-components)
- [Integration Components](#integration-components)
- [Security Components](#security-components)
- [Providers and Routing](#providers-and-routing)
- [Context Management](#context-management)
- [Streaming and Real-time](#streaming-and-real-time)
- [Monitoring and Analytics](#monitoring-and-analytics)
- [Error Handling](#error-handling)
- [Configuration](#configuration)

## Core MCP Components

### MCPClient

The main client for interacting with MCP servers.

```typescript
class MCPClient {
  constructor(config: MCPClientConfig)
  
  // Connection management
  connect(): Promise<void>
  disconnect(): Promise<void>
  isConnected(): boolean
  
  // Provider management
  getProviders(): Map<string, LLMProvider>
  getProvider(id: string): LLMProvider | null
  
  // Core operations
  request(request: LLMRequest): Promise<LLMResponse>
  stream(request: LLMRequest): AsyncIterable<LLMResponseChunk>
  health(): Promise<HealthStatus>
}

interface MCPClientConfig {
  serverUrl: string
  apiKey: string
  providers: Record<string, ProviderConfig>
  options?: {
    reconnectAttempts?: number
    heartbeatInterval?: number
    requestTimeout?: number
  }
}
```

### MessageRouter

Routes LLM requests to appropriate providers with intelligent selection.

```typescript
class MessageRouter {
  constructor(
    mcpClient: MCPClient,
    authManager: AuthManager,
    auditLogger: AuditLogger,
    rateLimiter: RateLimiterManager,
    credentialManager: CredentialManager
  )
  
  // Request routing
  routeMessage(request: LLMRequest): Promise<LLMResponse>
  routeStreamingMessage(request: LLMRequest): AsyncIterable<LLMResponseChunk>
  
  // Statistics and monitoring
  getStatistics(): RouterStatistics
  
  // Lifecycle
  shutdown(): void
}

interface RouterStatistics {
  activeRequests: number
  totalRequests: number
  averageLatency: number
  providerHealth: ProviderHealth[]
  errorRate: number
}
```

### LLM Request/Response Types

Core types for LLM interactions.

```typescript
interface LLMRequest {
  id: string
  type: LLMRequestType
  prompt: string
  agentDID: string
  sessionId: string
  functions?: FunctionDefinition[]
  streaming?: boolean
  parameters?: LLMParameters
  metadata: RequestMetadata
}

interface LLMResponse {
  id: string
  content?: string
  provider: string
  model?: string
  usage?: UsageInfo
  functionCall?: FunctionCall
  timestamp: Date
  metadata?: ResponseMetadata
}

enum LLMRequestType {
  COMPLETION = 'completion',
  FUNCTION_CALL = 'function_call',
  EMBEDDING = 'embedding',
  MODERATION = 'moderation',
  STREAMING = 'streaming'
}
```

## Integration Components

### MCPEnabledCommunicationManager

Extends the existing CommunicationManager with MCP capabilities.

```typescript
class MCPEnabledCommunicationManager extends CommunicationManager {
  constructor(
    agentIdentity: AgentIdentity,
    agentManager: AgentIdentityManager,
    delegationManager: DelegationManager,
    policyEngine: DelegationPolicyEngine,
    activityLogger: ActivityLogger,
    options: MCPCommunicationManagerOptions,
    authManager: AuthManager,
    rateLimiter: RateLimiterManager,
    credentialManager: CredentialManager
  )
  
  // Natural language processing
  processNaturalLanguageMessage(
    message: string,
    targetAgent?: string,
    options?: {
      streaming?: boolean
      priority?: RequestPriority
      onChunk?: (chunk: string) => void
    }
  ): Promise<AgentMessage>
  
  // LLM-assisted delegation
  evaluateDelegationWithLLM(
    requestingAgent: string,
    targetAgent: string,
    requestedScopes: string[],
    purpose: string,
    duration?: number
  ): Promise<DelegationEvaluation>
  
  // Agent matching
  findAgentsForTask(
    taskDescription: string,
    requiredCapabilities: string[],
    options?: AgentMatchingOptions
  ): Promise<AgentMatch[]>
  
  // Context sharing
  shareContextWithAgent(
    targetAgentDID: string,
    options?: ContextSharingOptions
  ): Promise<void>
  
  // Usage statistics
  getLLMUsageStatistics(): Promise<LLMUsageStatistics>
  
  // Cleanup
  cleanup(): Promise<void>
}

interface DelegationEvaluation {
  decision: 'approve' | 'deny' | 'approve_with_modifications' | 'request_more_info'
  confidence: number
  reasoning: string
  suggestedScopes?: string[]
  warnings: string[]
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
}
```

### MCPMonitoringDashboard

Comprehensive monitoring and analytics for LLM interactions.

```typescript
class MCPMonitoringDashboard extends EventEmitter {
  constructor(
    messageRouter: MessageRouter,
    providerSelector: ProviderSelector | null,
    contextManager: ContextManager,
    streamManager: StreamManager,
    agentMatcher: AgentMatcher,
    auditLogger: AuditLogger,
    rateLimiter: RateLimiterManager,
    config?: DashboardConfig
  )
  
  // Metrics access
  getMetrics(): DashboardMetrics
  getTimeSeries(metric: string, duration?: number): TimeSeriesDataPoint[]
  getHistoricalMetrics(duration?: number): DashboardMetrics[]
  
  // Alerts
  addAlert(alert: AlertConfig): void
  removeAlert(metric: string): void
  getActiveAlerts(): Array<{ alert: AlertConfig; triggered: Date }>
  
  // Export capabilities
  exportMetrics(format: 'json' | 'csv' | 'prometheus'): string
  
  // Lifecycle
  resetMetrics(): void
  shutdown(): void
}

interface DashboardMetrics {
  totalRequests: number
  totalTokens: number
  totalCost: number
  averageLatency: number
  errorRate: number
  providerHealth: ProviderHealth[]
  providerUsage: Record<string, ProviderMetrics>
  requestsByType: Record<LLMRequestType, number>
  requestsByPriority: Record<RequestPriority, number>
  latencyPercentiles: {
    p50: number
    p90: number
    p95: number
    p99: number
  }
  activeContexts: number
  activeStreams: number
  totalMatches: number
  matchSuccessRate: number
}
```

### MCPSecurityIntegration

LLM-based security threat detection and automated response.

```typescript
class MCPSecurityIntegration extends EventEmitter {
  constructor(
    messageRouter: MessageRouter,
    authManager: AuthManager,
    auditLogger: AuditLogger,
    rateLimiter: RateLimiterManager,
    credentialManager: CredentialManager,
    config?: SecurityConfig
  )
  
  // Threat analysis
  analyzeRequest(request: LLMRequest): Promise<SecurityThreat[]>
  analyzeResponse(
    response: LLMResponse,
    originalRequest: LLMRequest
  ): Promise<SecurityThreat[]>
  analyzeAgentBehavior(
    agentDID: string,
    recentActivity: any[],
    historicalPatterns?: any
  ): Promise<SecurityThreat[]>
  
  // Policy evaluation
  evaluatePolicies(request: LLMRequest): Promise<PolicyEvaluation>
  
  // Threat management
  getActiveThreats(filters?: ThreatFilters): SecurityThreat[]
  clearThreat(threatId: string): void
  
  // Security policies
  addSecurityPolicy(policy: SecurityPolicy): void
  removeSecurityPolicy(policyId: string): void
  
  // Statistics and reporting
  getStatistics(): SecurityStatistics
  exportThreatReport(format: 'json' | 'csv'): string
  
  // Lifecycle
  shutdown(): void
}

interface SecurityThreat {
  id: string
  type: ThreatType
  severity: ThreatSeverity
  confidence: number
  timestamp: Date
  source: string
  targetAgent?: string
  description: string
  evidence: Record<string, any>
  recommendations: string[]
  automatedResponse?: SecurityResponse
}
```

## Security Components

### AuthManager

Handles authentication and authorization for MCP requests.

```typescript
class AuthManager {
  constructor(config: AuthConfig)
  
  // Authentication
  authenticate(credentials: AuthCredentials): Promise<boolean>
  
  // Authorization
  authorize(request: AuthorizationRequest): Promise<boolean>
  
  // Session management
  createSession(agentDID: string): Promise<Session>
  validateSession(sessionId: string): Promise<boolean>
  revokeSession(sessionId: string): Promise<void>
  
  // Security operations
  revokeAccess(agentDID: string, reason: string): Promise<void>
  quarantineAgent(agentDID: string, reason: string): Promise<void>
}

interface AuthCredentials {
  method: 'api-key' | 'did-auth' | 'oauth'
  credentials: Record<string, any>
}

interface AuthorizationRequest {
  agentDID: string
  resource: string
  action: string
  context: Record<string, any>
}
```

### CredentialManager

Secure storage and management of provider credentials.

```typescript
class CredentialManager {
  constructor(config: CredentialConfig)
  
  // Credential operations
  storeCredentials(providerId: string, credentials: any): Promise<void>
  getCredentials(providerId: string): Promise<any>
  rotateCredentials(providerId: string, newCredentials: any): Promise<void>
  deleteCredentials(providerId: string): Promise<void>
  
  // Security features
  encryptCredentials(credentials: any): string
  decryptCredentials(encrypted: string): any
  validateCredentials(providerId: string): Promise<boolean>
}
```

### RateLimiterManager

Manages rate limiting and quota enforcement.

```typescript
class RateLimiterManager {
  constructor(authManager: AuthManager, config?: RateLimiterConfig)
  
  // Rate limiting
  checkLimit(agentDID: string): Promise<boolean>
  setLimit(agentDID: string, limit: number, window: number): Promise<void>
  applyPenalty(agentDID: string, duration: number, reason: string): Promise<void>
  
  // Statistics
  getStatistics(): Promise<RateLimitStatistics>
  getUsage(agentDID: string): Promise<UsageStats>
}
```

## Providers and Routing

### ProviderSelector

Intelligent provider selection based on various criteria.

```typescript
class ProviderSelector {
  constructor(providers: Map<string, LLMProvider>)
  
  // Provider selection
  selectProvider(
    request: LLMRequest,
    criteria: SelectionCriteria,
    strategy: SelectionStrategy
  ): Promise<ProviderSelection>
  
  // Provider management
  updateProviderHealth(providerId: string, health: ProviderHealth): void
  getProviderPerformance(providerId: string): ProviderMetrics
  
  // Lifecycle
  shutdown(): void
}

interface SelectionCriteria {
  requestType: LLMRequestType
  priority: RequestPriority
  requirements: {
    maxLatency?: number
    minReliability?: number
    maxCost?: number
    capabilities?: string[]
  }
  context: {
    agentDID: string
    domain?: string
    sensitiveData?: boolean
  }
}

enum SelectionStrategy {
  RELIABILITY = 'reliability',
  COST_OPTIMIZED = 'cost_optimized',
  LATENCY = 'latency',
  CAPABILITY_MATCH = 'capability_match',
  ROUND_ROBIN = 'round_robin',
  BALANCED = 'balanced'
}
```

## Context Management

### ContextManager

Manages conversation contexts with compression and sharing.

```typescript
class ContextManager {
  constructor(config: ContextConfig)
  
  // Context operations
  createContext(
    agentDID: string,
    sessionId: string,
    metadata: ContextMetadata
  ): Promise<ConversationContext>
  
  addMessage(
    conversationId: string,
    message: ConversationMessage
  ): Promise<void>
  
  getContext(conversationId: string): Promise<ConversationContext>
  
  // Context sharing
  shareContext(
    conversationId: string,
    targetAgentDID: string,
    options: ContextSharingOptions
  ): Promise<void>
  
  // Compression and optimization
  compressContext(conversationId: string): Promise<CompressionResult>
  
  // Statistics
  getStatistics(): ContextStatistics
  
  // Lifecycle
  deleteContext(conversationId: string): Promise<void>
  shutdown(): void
}

interface ConversationContext {
  conversationId: string
  agentDID: string
  sessionId: string
  messages: ConversationMessage[]
  metadata: ContextMetadata
  summary?: string
  lastUpdated: Date
}
```

## Streaming and Real-time

### StreamManager

Manages streaming LLM responses with real-time capabilities.

```typescript
class StreamManager {
  constructor(
    messageRouter: MessageRouter,
    authManager: AuthManager,
    auditLogger: AuditLogger
  )
  
  // Stream management
  startStream(
    request: LLMRequest,
    options: StreamOptions
  ): Promise<StreamSession>
  
  getActiveStreams(): StreamSession[]
  getStream(streamId: string): StreamSession | null
  terminateStream(streamId: string): Promise<void>
  
  // Lifecycle
  shutdown(): void
}

interface StreamOptions {
  priority: 'low' | 'medium' | 'high'
  onChunk: (chunk: LLMResponseChunk) => void
  onComplete: (response: LLMResponse) => void
  onError?: (error: Error) => void
  timeout?: number
}

interface StreamSession {
  id: string
  request: LLMRequest
  status: 'active' | 'completed' | 'error' | 'terminated'
  startTime: Date
  endTime?: Date
  chunksReceived: number
  bytesReceived: number
}
```

## Error Handling

### MCPError

Standardized error handling across all MCP components.

```typescript
class MCPError extends Error {
  constructor(details: MCPErrorDetails)
  
  code: MCPErrorCode
  timestamp: Date
  retryable: boolean
  provider?: string
  requestId?: string
  context?: Record<string, any>
}

enum MCPErrorCode {
  // Connection errors
  CONNECTION_FAILED = 'CONNECTION_FAILED',
  CONNECTION_TIMEOUT = 'CONNECTION_TIMEOUT',
  
  // Authentication/Authorization errors
  AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',
  AUTHORIZATION_DENIED = 'AUTHORIZATION_DENIED',
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  
  // Request errors
  INVALID_REQUEST = 'INVALID_REQUEST',
  REQUEST_TOO_LARGE = 'REQUEST_TOO_LARGE',
  MALFORMED_REQUEST = 'MALFORMED_REQUEST',
  
  // Provider errors
  PROVIDER_ERROR = 'PROVIDER_ERROR',
  PROVIDER_UNAVAILABLE = 'PROVIDER_UNAVAILABLE',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  
  // System errors
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  CIRCUIT_BREAKER_OPEN = 'CIRCUIT_BREAKER_OPEN',
  
  // Security errors
  SECURITY_VIOLATION = 'SECURITY_VIOLATION',
  THREAT_DETECTED = 'THREAT_DETECTED',
  ACCESS_DENIED = 'ACCESS_DENIED'
}
```

## Configuration

### Complete Configuration Reference

```typescript
interface MCPIntegrationConfig {
  // Core MCP client configuration
  client: MCPClientConfig
  
  // Communication manager options
  communication: MCPCommunicationManagerOptions
  
  // Security configuration
  security: {
    auth: AuthConfig
    credentials: CredentialConfig
    rateLimiting: RateLimiterConfig
    threatDetection: SecurityConfig
  }
  
  // Monitoring and analytics
  monitoring: DashboardConfig
  
  // Provider configuration
  providers: Record<string, ProviderConfig>
  
  // Context management
  context: ContextConfig
  
  // Streaming configuration
  streaming: StreamConfig
}

// Example complete configuration
const mcpConfig: MCPIntegrationConfig = {
  client: {
    serverUrl: 'ws://localhost:8080',
    apiKey: process.env.MCP_API_KEY!,
    providers: {
      openai: {
        apiKey: process.env.OPENAI_API_KEY!,
        models: ['gpt-4', 'gpt-3.5-turbo']
      },
      anthropic: {
        apiKey: process.env.ANTHROPIC_API_KEY!,
        models: ['claude-3-sonnet', 'claude-3-haiku']
      }
    },
    options: {
      reconnectAttempts: 3,
      heartbeatInterval: 30000,
      requestTimeout: 60000
    }
  },
  communication: {
    llmIntegration: {
      enableNaturalLanguage: true,
      enablePolicyEvaluation: true,
      enableAgentMatching: true,
      enableStreaming: true,
      defaultProvider: 'openai',
      defaultModel: 'gpt-4'
    },
    contextSettings: {
      maxTokensPerContext: 4000,
      compressionStrategy: 'importance',
      shareContextBetweenAgents: true
    }
  },
  security: {
    auth: {
      authMethods: ['api-key', 'did-auth'],
      sessionTimeout: 3600000,
      maxFailedAttempts: 3
    },
    credentials: {
      encryptionKey: process.env.CREDENTIAL_ENCRYPTION_KEY!,
      rotationInterval: 86400000 * 7
    },
    rateLimiting: {
      windowSize: 60000,
      defaultLimit: 100,
      burstLimit: 20
    },
    threatDetection: {
      enableThreatDetection: true,
      enableAutomatedResponse: true,
      threatRetentionPeriod: 86400000 * 30,
      analysisTimeout: 10000
    }
  },
  monitoring: {
    refreshInterval: 30000,
    retentionPeriod: 86400000 * 7,
    enableRealTimeUpdates: true,
    enableHistoricalAnalysis: true,
    alerts: [
      {
        metric: 'errorRate',
        threshold: 0.05,
        operator: 'gt',
        windowSize: 300000,
        cooldown: 600000
      }
    ],
    exportFormats: ['json', 'prometheus']
  },
  context: {
    maxTokensPerContext: 4000,
    compressionThreshold: 0.8,
    compressionStrategy: 'importance',
    retentionCheckInterval: 3600000,
    sharing: {
      allowSharing: true,
      requireConsent: true,
      maxShareDepth: 2
    }
  },
  streaming: {
    maxConcurrentStreams: 10,
    bufferSize: 1024,
    flushInterval: 100,
    timeout: 300000
  }
}
```

## Usage Examples

### Basic Setup

```typescript
import { 
  MCPClient, 
  MCPEnabledCommunicationManager,
  AuthManager,
  RateLimiterManager,
  CredentialManager
} from './mcp'

// Initialize MCP infrastructure
const mcpClient = new MCPClient(config.client)
const authManager = new AuthManager(config.security.auth)
const rateLimiter = new RateLimiterManager(authManager, config.security.rateLimiting)
const credentialManager = new CredentialManager(config.security.credentials)

// Create enhanced communication manager
const communicationManager = new MCPEnabledCommunicationManager(
  agentIdentity,
  agentManager,
  delegationManager,
  policyEngine,
  activityLogger,
  config.communication,
  authManager,
  rateLimiter,
  credentialManager
)

// Process natural language request
const response = await communicationManager.processNaturalLanguageMessage(
  'Find an agent to help with data analysis',
  undefined,
  { streaming: true, priority: RequestPriority.HIGH }
)
```

### Advanced Usage with Monitoring

```typescript
import { MCPMonitoringDashboard, MCPSecurityIntegration } from './mcp'

// Setup monitoring
const dashboard = new MCPMonitoringDashboard(
  messageRouter,
  providerSelector,
  contextManager,
  streamManager,
  agentMatcher,
  auditLogger,
  rateLimiter,
  config.monitoring
)

// Setup security
const security = new MCPSecurityIntegration(
  messageRouter,
  authManager,
  auditLogger,
  rateLimiter,
  credentialManager,
  config.security.threatDetection
)

// Monitor events
dashboard.on('alert_triggered', (alert) => {
  console.log('Alert triggered:', alert.alert.metric)
})

security.on('threat_detected', (threat) => {
  console.log('Security threat detected:', threat.type)
})

// Get real-time metrics
const metrics = dashboard.getMetrics()
console.log('Current error rate:', metrics.errorRate)

// Export for external monitoring
const prometheusMetrics = dashboard.exportMetrics('prometheus')
```

## Migration from Direct API Usage

See the [Migration Guide](./mcp-migration-guide.md) for detailed information on migrating from direct LLM API usage to the MCP integration.

## Best Practices

1. **Always use the MCPEnabledCommunicationManager** instead of direct API calls
2. **Enable monitoring and security** for production deployments
3. **Configure appropriate rate limits** based on your usage patterns
4. **Use streaming for real-time interactions** when possible
5. **Monitor provider health** and configure failover strategies
6. **Implement proper error handling** using MCPError types
7. **Regularly rotate credentials** using the CredentialManager
8. **Review security alerts** and threat reports regularly

## Support and Troubleshooting

For common issues and troubleshooting steps, see the [Troubleshooting Guide](./mcp-troubleshooting.md).

For configuration examples and setup guides, see the [Configuration Guide](./mcp-configuration-guide.md).