# MCP Configuration Guide

## Overview

This guide provides comprehensive instructions for configuring the Model Context Protocol (MCP) integration within the Anonymous Identity Framework. It covers all aspects of setup, provider configuration, security settings, and optimization.

## Table of Contents

- [Quick Start](#quick-start)
- [Basic Configuration](#basic-configuration)
- [Provider Setup](#provider-setup)
- [Security Configuration](#security-configuration)
- [Monitoring Setup](#monitoring-setup)
- [Performance Optimization](#performance-optimization)
- [Advanced Configuration](#advanced-configuration)
- [Environment-Specific Configurations](#environment-specific-configurations)
- [Configuration Validation](#configuration-validation)

## Quick Start

### Minimal Configuration

The simplest MCP setup requires just a few essential settings:

```typescript
import { MCPClient, MCPEnabledCommunicationManager } from './mcp'

const minimalConfig = {
  client: {
    serverUrl: 'ws://localhost:8080',
    apiKey: process.env.MCP_API_KEY!,
    providers: {
      openai: {
        apiKey: process.env.OPENAI_API_KEY!,
        models: ['gpt-4']
      }
    }
  }
}

// Initialize with minimal config
const mcpClient = new MCPClient(minimalConfig.client)
```

### Quick Setup Script

```bash
#!/bin/bash
# quick-mcp-setup.sh

# Set required environment variables
export MCP_API_KEY="your-mcp-api-key"
export OPENAI_API_KEY="your-openai-api-key"
export ANTHROPIC_API_KEY="your-anthropic-api-key"

# Optional: Set encryption key for credentials
export CREDENTIAL_ENCRYPTION_KEY=$(openssl rand -hex 32)

echo "MCP environment configured! Run your application now."
```

## Basic Configuration

### Core MCP Client Setup

```typescript
interface MCPClientConfig {
  // Required: MCP server connection
  serverUrl: string              // WebSocket URL for MCP server
  apiKey: string                // Authentication key for MCP server
  
  // Required: Provider configurations
  providers: Record<string, ProviderConfig>
  
  // Optional: Connection options
  options?: {
    reconnectAttempts?: number   // Default: 3
    heartbeatInterval?: number   // Default: 30000ms
    requestTimeout?: number      // Default: 60000ms
    maxConcurrentRequests?: number // Default: 10
  }
}

// Example basic configuration
const basicConfig: MCPClientConfig = {
  serverUrl: process.env.MCP_SERVER_URL || 'ws://localhost:8080',
  apiKey: process.env.MCP_API_KEY!,
  providers: {
    openai: {
      apiKey: process.env.OPENAI_API_KEY!,
      models: ['gpt-4', 'gpt-3.5-turbo'],
      endpoint: 'https://api.openai.com/v1',
      timeout: 30000
    },
    anthropic: {
      apiKey: process.env.ANTHROPIC_API_KEY!,
      models: ['claude-3-sonnet', 'claude-3-haiku'],
      endpoint: 'https://api.anthropic.com/v1',
      timeout: 30000
    }
  },
  options: {
    reconnectAttempts: 5,
    heartbeatInterval: 30000,
    requestTimeout: 60000,
    maxConcurrentRequests: 20
  }
}
```

### Communication Manager Configuration

```typescript
interface MCPCommunicationManagerOptions {
  mcpClient: MCPClient
  
  // LLM integration settings
  llmIntegration?: {
    enableNaturalLanguage?: boolean     // Default: false
    enablePolicyEvaluation?: boolean    // Default: false
    enableAgentMatching?: boolean       // Default: false
    enableStreaming?: boolean           // Default: false
    defaultProvider?: string            // Default: first provider
    defaultModel?: string               // Default: first model
    timeout?: number                    // Default: 30000ms
  }
  
  // Context management settings
  contextSettings?: {
    maxTokensPerContext?: number        // Default: 4000
    compressionStrategy?: 'summary' | 'sliding-window' | 'importance' // Default: 'importance'
    shareContextBetweenAgents?: boolean // Default: false
    retentionPeriod?: number           // Default: 7 days
  }
}

// Example communication configuration
const communicationConfig: MCPCommunicationManagerOptions = {
  mcpClient,
  llmIntegration: {
    enableNaturalLanguage: true,
    enablePolicyEvaluation: true,
    enableAgentMatching: true,
    enableStreaming: true,
    defaultProvider: 'openai',
    defaultModel: 'gpt-4',
    timeout: 45000
  },
  contextSettings: {
    maxTokensPerContext: 8000,
    compressionStrategy: 'importance',
    shareContextBetweenAgents: true,
    retentionPeriod: 86400000 * 14 // 14 days
  }
}
```

## Provider Setup

### OpenAI Configuration

```typescript
const openaiConfig = {
  apiKey: process.env.OPENAI_API_KEY!,
  organization: process.env.OPENAI_ORG_ID, // Optional
  models: [
    'gpt-4',
    'gpt-4-turbo-preview',
    'gpt-3.5-turbo',
    'gpt-3.5-turbo-16k'
  ],
  endpoint: 'https://api.openai.com/v1',
  timeout: 30000,
  rateLimits: {
    requestsPerMinute: 100,
    tokensPerMinute: 150000,
    requestsPerDay: 10000,
    tokensPerDay: 2000000
  },
  costs: {
    'gpt-4': { input: 0.00003, output: 0.00006 }, // per token
    'gpt-3.5-turbo': { input: 0.000001, output: 0.000002 }
  },
  capabilities: {
    completion: true,
    streaming: true,
    functionCalling: true,
    embeddings: false,  // Use text-embedding-ada-002 separately
    moderation: true
  }
}
```

### Anthropic Configuration

```typescript
const anthropicConfig = {
  apiKey: process.env.ANTHROPIC_API_KEY!,
  models: [
    'claude-3-sonnet-20240229',
    'claude-3-haiku-20240307',
    'claude-3-opus-20240229'
  ],
  endpoint: 'https://api.anthropic.com/v1',
  timeout: 45000,
  rateLimits: {
    requestsPerMinute: 50,
    tokensPerMinute: 100000,
    requestsPerDay: 5000,
    tokensPerDay: 1000000
  },
  costs: {
    'claude-3-sonnet': { input: 0.000015, output: 0.000075 },
    'claude-3-haiku': { input: 0.00000025, output: 0.00000125 },
    'claude-3-opus': { input: 0.000015, output: 0.000075 }
  },
  capabilities: {
    completion: true,
    streaming: true,
    functionCalling: true,
    embeddings: false,
    moderation: false
  }
}
```

### Custom Provider Configuration

```typescript
const customProviderConfig = {
  apiKey: process.env.CUSTOM_API_KEY!,
  models: ['custom-model-v1', 'custom-model-v2'],
  endpoint: 'https://api.customprovider.com/v1',
  timeout: 20000,
  
  // Custom authentication
  authentication: {
    type: 'bearer', // or 'api-key', 'oauth'
    headerName: 'Authorization',
    prefix: 'Bearer '
  },
  
  // Request/response transformation
  transforms: {
    request: (mcpRequest) => ({
      prompt: mcpRequest.prompt,
      model: mcpRequest.parameters?.model || 'custom-model-v1',
      max_tokens: mcpRequest.parameters?.maxTokens || 1000,
      temperature: mcpRequest.parameters?.temperature || 0.7
    }),
    response: (providerResponse) => ({
      content: providerResponse.text,
      usage: {
        promptTokens: providerResponse.usage.input_tokens,
        completionTokens: providerResponse.usage.output_tokens,
        totalTokens: providerResponse.usage.total_tokens
      }
    })
  },
  
  rateLimits: {
    requestsPerMinute: 30,
    tokensPerMinute: 50000
  },
  
  capabilities: {
    completion: true,
    streaming: false,
    functionCalling: false,
    embeddings: true,
    moderation: false
  }
}
```

## Security Configuration

### Authentication Setup

```typescript
const authConfig = {
  // Supported authentication methods
  authMethods: ['api-key', 'did-auth', 'oauth'],
  
  // Session management
  sessionTimeout: 3600000, // 1 hour
  maxFailedAttempts: 3,
  lockoutDuration: 300000, // 5 minutes
  
  // API key settings
  apiKey: {
    length: 32,
    algorithm: 'HS256',
    expirationTime: 86400000 * 30 // 30 days
  },
  
  // DID authentication
  didAuth: {
    supportedMethods: ['ed25519', 'secp256k1'],
    challengeTimeout: 300000, // 5 minutes
    requireSignature: true
  },
  
  // OAuth settings
  oauth: {
    providers: ['google', 'github'],
    scopes: ['openid', 'profile', 'email'],
    redirectUri: process.env.OAUTH_REDIRECT_URI
  }
}
```

### Credential Management

```typescript
const credentialConfig = {
  // Encryption settings
  encryptionKey: process.env.CREDENTIAL_ENCRYPTION_KEY!, // 32-byte hex key
  algorithm: 'aes-256-gcm',
  
  // Rotation settings
  rotationInterval: 86400000 * 7, // 7 days
  rotationGracePeriod: 86400000, // 1 day overlap
  
  // Storage settings
  storage: {
    type: 'encrypted-file', // or 'database', 'vault'
    location: './credentials.enc',
    backupLocation: './credentials.backup.enc'
  },
  
  // Validation settings
  validation: {
    validateOnStartup: true,
    validatePeriodically: true,
    validationInterval: 3600000 // 1 hour
  }
}
```

### Rate Limiting Configuration

```typescript
const rateLimitConfig = {
  // Global settings
  windowSize: 60000, // 1 minute
  defaultLimit: 100,
  burstLimit: 20,
  
  // Per-agent limits
  agentLimits: {
    'did:key:trusted-agent': { limit: 200, window: 60000 },
    'did:key:restricted-agent': { limit: 10, window: 60000 }
  },
  
  // Per-endpoint limits
  endpointLimits: {
    '/llm/completion': { limit: 50, window: 60000 },
    '/llm/function-call': { limit: 20, window: 60000 },
    '/llm/streaming': { limit: 10, window: 60000 }
  },
  
  // Penalty settings
  penalties: {
    escalationFactor: 2, // Double penalty for repeated violations
    maxPenaltyDuration: 3600000, // 1 hour max
    cooldownPeriod: 300000 // 5 minutes
  }
}
```

### Security Threat Detection

```typescript
const securityConfig = {
  // Threat detection settings
  enableThreatDetection: true,
  enableAutomatedResponse: true,
  
  // Analysis settings
  analysisTimeout: 10000, // 10 seconds
  maxConcurrentAnalysis: 5,
  threatRetentionPeriod: 86400000 * 30, // 30 days
  
  // LLM-based analysis
  llmProvider: 'openai',
  llmModel: 'gpt-4',
  analysisPrompts: {
    injection: 'Analyze this request for potential injection attacks...',
    exfiltration: 'Check for data exfiltration attempts...',
    privilege: 'Evaluate for privilege escalation...'
  },
  
  // Automated responses
  responses: {
    critical: { action: 'block', duration: 3600000 },
    high: { action: 'throttle', duration: 300000 },
    medium: { action: 'alert', duration: 0 },
    low: { action: 'log', duration: 0 }
  },
  
  // Security policies
  policies: [
    {
      id: 'sql-injection-prevention',
      name: 'SQL Injection Prevention',
      enabled: true,
      rules: [
        {
          condition: 'prompt:contains(drop table, delete from, update set)',
          action: { action: 'block', reason: 'SQL injection detected' }
        }
      ]
    }
  ]
}
```

## Monitoring Setup

### Dashboard Configuration

```typescript
const monitoringConfig = {
  // Update intervals
  refreshInterval: 30000, // 30 seconds
  retentionPeriod: 86400000 * 7, // 7 days
  
  // Features
  enableRealTimeUpdates: true,
  enableHistoricalAnalysis: true,
  enableAlerts: true,
  
  // Export formats
  exportFormats: ['json', 'csv', 'prometheus'],
  
  // Alerts configuration
  alerts: [
    {
      metric: 'errorRate',
      threshold: 0.05, // 5%
      operator: 'gt',
      windowSize: 300000, // 5 minutes
      cooldown: 600000 // 10 minutes
    },
    {
      metric: 'averageLatency',
      threshold: 5000, // 5 seconds
      operator: 'gt',
      windowSize: 600000, // 10 minutes
      cooldown: 1800000 // 30 minutes
    },
    {
      metric: 'totalCost',
      threshold: 100, // $100
      operator: 'gt',
      windowSize: 86400000, // 24 hours
      cooldown: 86400000 // 24 hours
    }
  ],
  
  // Metrics collection
  metrics: {
    collectProviderMetrics: true,
    collectAgentMetrics: true,
    collectSecurityMetrics: true,
    collectPerformanceMetrics: true,
    
    // Sampling settings
    sampling: {
      enabled: true,
      rate: 0.1, // 10% sampling for high-volume metrics
      alwaysSample: ['errors', 'security-events']
    }
  }
}
```

### Logging Configuration

```typescript
const loggingConfig = {
  // Audit logging
  audit: {
    enabled: true,
    logAllRequests: true,
    logResponses: true,
    logSensitiveData: false, // Important: keep false in production
    
    // Retention
    retentionPeriod: 86400000 * 90, // 90 days
    archiveAfter: 86400000 * 30, // 30 days
    
    // Export settings
    exportFormat: ['json', 'csv'],
    exportSchedule: 'daily',
    exportLocation: './audit-logs/'
  },
  
  // Application logging
  application: {
    level: 'info', // 'debug', 'info', 'warn', 'error'
    format: 'json',
    output: ['console', 'file'],
    
    // File settings
    file: {
      location: './logs/mcp.log',
      maxSize: '100MB',
      maxFiles: 10,
      rotation: 'daily'
    }
  }
}
```

## Performance Optimization

### Provider Selection Optimization

```typescript
const providerOptimization = {
  // Selection strategies
  strategies: {
    default: 'balanced',
    lowLatency: 'latency',
    costOptimized: 'cost_optimized',
    highReliability: 'reliability'
  },
  
  // Performance targets
  targets: {
    maxLatency: 2000, // 2 seconds
    minReliability: 0.99, // 99%
    maxCostPerRequest: 0.01, // $0.01
    maxErrorRate: 0.01 // 1%
  },
  
  // Load balancing
  loadBalancing: {
    algorithm: 'weighted_round_robin',
    weights: {
      openai: 0.6,
      anthropic: 0.3,
      custom: 0.1
    },
    healthCheckInterval: 30000,
    failureThreshold: 3
  },
  
  // Circuit breaker
  circuitBreaker: {
    enabled: true,
    failureThreshold: 5,
    recoveryTimeout: 60000,
    halfOpenRequests: 3
  }
}
```

### Context Management Optimization

```typescript
const contextOptimization = {
  // Compression settings
  compression: {
    strategy: 'importance', // 'summary', 'sliding-window', 'importance'
    threshold: 0.8, // Compress when 80% full
    targetReduction: 0.5, // Reduce by 50%
    
    // Importance-based compression
    importance: {
      recentMessageWeight: 0.4,
      userMessageWeight: 0.3,
      systemMessageWeight: 0.2,
      contextualRelevanceWeight: 0.1
    }
  },
  
  // Caching
  cache: {
    enabled: true,
    maxSize: 1000, // Number of contexts
    ttl: 3600000, // 1 hour
    compressionCacheEnabled: true
  },
  
  // Cleanup
  cleanup: {
    interval: 3600000, // 1 hour
    maxAge: 86400000 * 7, // 7 days
    maxInactiveTime: 86400000 // 1 day
  }
}
```

### Streaming Optimization

```typescript
const streamingOptimization = {
  // Buffer settings
  bufferSize: 1024, // bytes
  flushInterval: 50, // milliseconds
  
  // Connection settings
  maxConcurrentStreams: 20,
  streamTimeout: 300000, // 5 minutes
  keepAliveInterval: 30000, // 30 seconds
  
  // Quality of service
  qos: {
    priorityQueues: true,
    highPriorityBufferSize: 2048,
    normalPriorityBufferSize: 1024,
    lowPriorityBufferSize: 512
  },
  
  // Adaptive streaming
  adaptive: {
    enabled: true,
    monitorLatency: true,
    adjustBufferSize: true,
    minBufferSize: 256,
    maxBufferSize: 4096
  }
}
```

## Advanced Configuration

### Custom Provider Integration

```typescript
class CustomProvider implements LLMProvider {
  constructor(private config: CustomProviderConfig) {}
  
  async completion(request: LLMRequest): Promise<LLMResponse> {
    // Custom implementation
    const response = await this.callCustomAPI(request)
    return this.transformResponse(response)
  }
  
  async stream(request: LLMRequest): AsyncIterable<LLMResponseChunk> {
    // Custom streaming implementation
    const stream = await this.createCustomStream(request)
    yield* this.transformStreamChunks(stream)
  }
  
  async health(): Promise<ProviderHealth> {
    // Custom health check
    return {
      providerId: this.config.id,
      status: 'healthy',
      lastCheck: new Date(),
      responseTime: await this.measureResponseTime(),
      uptime: this.calculateUptime(),
      errorRate: this.getErrorRate(),
      requestCount: this.getRequestCount()
    }
  }
}

// Register custom provider
const customProvider = new CustomProvider(customConfig)
mcpClient.registerProvider('custom', customProvider)
```

### Plugin System

```typescript
interface MCPPlugin {
  name: string
  version: string
  initialize(mcp: MCPClient): Promise<void>
  shutdown(): Promise<void>
}

class CostOptimizationPlugin implements MCPPlugin {
  name = 'cost-optimization'
  version = '1.0.0'
  
  async initialize(mcp: MCPClient): Promise<void> {
    // Add cost optimization middleware
    mcp.use(this.costOptimizationMiddleware)
  }
  
  private costOptimizationMiddleware = async (request: LLMRequest, next: Function) => {
    // Analyze request for cost optimization
    const optimizedRequest = await this.optimizeForCost(request)
    return next(optimizedRequest)
  }
  
  private async optimizeForCost(request: LLMRequest): Promise<LLMRequest> {
    // Implementation
    return request
  }
  
  async shutdown(): Promise<void> {
    // Cleanup
  }
}

// Use plugin
const plugin = new CostOptimizationPlugin()
await mcpClient.use(plugin)
```

## Environment-Specific Configurations

### Development Environment

```typescript
const developmentConfig = {
  client: {
    serverUrl: 'ws://localhost:8080',
    apiKey: 'dev-api-key',
    providers: {
      openai: {
        apiKey: process.env.OPENAI_API_KEY_DEV!,
        models: ['gpt-3.5-turbo'] // Cheaper for development
      }
    },
    options: {
      requestTimeout: 120000, // Longer timeout for debugging
      reconnectAttempts: 1 // Fail fast in development
    }
  },
  security: {
    auth: {
      authMethods: ['api-key'], // Simplified auth
      sessionTimeout: 7200000 // 2 hours
    },
    threatDetection: {
      enableThreatDetection: false, // Disable for development
      enableAutomatedResponse: false
    }
  },
  monitoring: {
    refreshInterval: 10000, // More frequent updates
    enableRealTimeUpdates: true,
    alerts: [] // No alerts in development
  },
  logging: {
    level: 'debug',
    output: ['console'],
    logSensitiveData: true // OK for development
  }
}
```

### Production Environment

```typescript
const productionConfig = {
  client: {
    serverUrl: process.env.MCP_SERVER_URL!,
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
      requestTimeout: 60000,
      reconnectAttempts: 5,
      maxConcurrentRequests: 50
    }
  },
  security: {
    auth: {
      authMethods: ['did-auth', 'oauth'],
      sessionTimeout: 3600000, // 1 hour
      maxFailedAttempts: 3
    },
    threatDetection: {
      enableThreatDetection: true,
      enableAutomatedResponse: true,
      analysisTimeout: 5000 // Faster analysis in production
    },
    credentials: {
      encryptionKey: process.env.CREDENTIAL_ENCRYPTION_KEY!,
      rotationInterval: 86400000 * 7 // Weekly rotation
    }
  },
  monitoring: {
    refreshInterval: 30000,
    retentionPeriod: 86400000 * 30, // 30 days
    enableRealTimeUpdates: true,
    alerts: [
      // Production alerts configuration
    ]
  },
  logging: {
    level: 'info',
    output: ['file', 'syslog'],
    logSensitiveData: false // Never in production
  }
}
```

### Staging Environment

```typescript
const stagingConfig = {
  // Similar to production but with:
  client: {
    // ... production settings
    providers: {
      openai: {
        apiKey: process.env.OPENAI_API_KEY_STAGING!,
        models: ['gpt-3.5-turbo'] // Cheaper models for staging
      }
    }
  },
  security: {
    // ... production security settings
    threatDetection: {
      enableThreatDetection: true,
      enableAutomatedResponse: false // Alert only, don't block
    }
  },
  monitoring: {
    // ... production monitoring
    retentionPeriod: 86400000 * 7, // Shorter retention
    alerts: [] // Reduced alerts for staging
  }
}
```

## Configuration Validation

### Validation Schema

```typescript
import Joi from 'joi'

const configSchema = Joi.object({
  client: Joi.object({
    serverUrl: Joi.string().uri().required(),
    apiKey: Joi.string().min(16).required(),
    providers: Joi.object().pattern(
      Joi.string(),
      Joi.object({
        apiKey: Joi.string().required(),
        models: Joi.array().items(Joi.string()).min(1).required(),
        endpoint: Joi.string().uri(),
        timeout: Joi.number().min(1000).max(300000)
      })
    ).min(1).required(),
    options: Joi.object({
      reconnectAttempts: Joi.number().min(0).max(10),
      heartbeatInterval: Joi.number().min(5000),
      requestTimeout: Joi.number().min(5000),
      maxConcurrentRequests: Joi.number().min(1).max(100)
    })
  }).required(),
  
  security: Joi.object({
    auth: Joi.object({
      authMethods: Joi.array().items(
        Joi.string().valid('api-key', 'did-auth', 'oauth')
      ).min(1).required(),
      sessionTimeout: Joi.number().min(60000),
      maxFailedAttempts: Joi.number().min(1).max(10)
    }),
    
    credentials: Joi.object({
      encryptionKey: Joi.string().length(64).required(), // 32 bytes hex
      rotationInterval: Joi.number().min(86400000) // At least 1 day
    }),
    
    rateLimiting: Joi.object({
      windowSize: Joi.number().min(1000),
      defaultLimit: Joi.number().min(1),
      burstLimit: Joi.number().min(1)
    })
  }),
  
  monitoring: Joi.object({
    refreshInterval: Joi.number().min(1000),
    retentionPeriod: Joi.number().min(3600000), // At least 1 hour
    enableRealTimeUpdates: Joi.boolean(),
    alerts: Joi.array().items(
      Joi.object({
        metric: Joi.string().required(),
        threshold: Joi.number().required(),
        operator: Joi.string().valid('gt', 'lt', 'eq', 'gte', 'lte').required(),
        windowSize: Joi.number().min(1000).required(),
        cooldown: Joi.number().min(0).required()
      })
    )
  })
})

// Validation function
export function validateConfig(config: any): { valid: boolean; errors?: string[] } {
  const { error } = configSchema.validate(config, { abortEarly: false })
  
  if (error) {
    return {
      valid: false,
      errors: error.details.map(detail => detail.message)
    }
  }
  
  return { valid: true }
}
```

### Configuration Testing

```typescript
export function testConfiguration(config: any): Promise<ConfigTestResult> {
  return new Promise(async (resolve) => {
    const results = {
      overall: true,
      tests: {}
    }
    
    // Test MCP server connectivity
    try {
      const client = new MCPClient(config.client)
      await client.connect()
      results.tests.serverConnection = true
      await client.disconnect()
    } catch (error) {
      results.tests.serverConnection = false
      results.overall = false
    }
    
    // Test provider connectivity
    for (const [providerId, providerConfig] of Object.entries(config.client.providers)) {
      try {
        const response = await testProviderConnection(providerConfig)
        results.tests[`provider_${providerId}`] = response.success
        if (!response.success) results.overall = false
      } catch (error) {
        results.tests[`provider_${providerId}`] = false
        results.overall = false
      }
    }
    
    // Test credential encryption
    try {
      const credManager = new CredentialManager(config.security.credentials)
      const testData = { test: 'data' }
      const encrypted = credManager.encryptCredentials(testData)
      const decrypted = credManager.decryptCredentials(encrypted)
      results.tests.credentialEncryption = JSON.stringify(testData) === JSON.stringify(decrypted)
    } catch (error) {
      results.tests.credentialEncryption = false
      results.overall = false
    }
    
    resolve(results)
  })
}
```

## Configuration Best Practices

1. **Use Environment Variables**: Never hardcode sensitive values like API keys
2. **Validate Configuration**: Always validate configuration before startup
3. **Environment-Specific Configs**: Use different configurations for dev/staging/prod
4. **Monitor Configuration**: Track configuration changes and their impact
5. **Secure Credential Storage**: Use proper encryption for stored credentials
6. **Regular Rotation**: Implement regular credential rotation
7. **Audit Configuration Changes**: Log all configuration modifications
8. **Test Configuration**: Validate configuration with connectivity tests
9. **Documentation**: Keep configuration documentation up to date
10. **Backup Configuration**: Maintain backups of working configurations

## Troubleshooting Configuration Issues

Common configuration problems and solutions:

### Connection Issues
```bash
# Check MCP server status
curl -f http://localhost:8080/health

# Verify WebSocket connectivity
wscat -c ws://localhost:8080

# Test provider API keys
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

### Provider Authentication Failures
```bash
# Verify API key format
echo $OPENAI_API_KEY | wc -c  # Should be 51 characters

# Test with minimal request
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"test"}],"max_tokens":1}'
```

### Configuration Validation
```typescript
// Run validation
const validation = validateConfig(yourConfig)
if (!validation.valid) {
  console.error('Configuration errors:', validation.errors)
  process.exit(1)
}

// Run connectivity test
const testResult = await testConfiguration(yourConfig)
if (!testResult.overall) {
  console.error('Configuration test failures:', testResult.tests)
}
```

For more troubleshooting help, see the [Troubleshooting Guide](./mcp-troubleshooting.md).