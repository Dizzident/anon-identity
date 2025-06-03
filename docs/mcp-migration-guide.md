# MCP Migration Guide

## Overview

This guide provides step-by-step instructions for migrating from direct LLM API usage to the Model Context Protocol (MCP) integration within the Anonymous Identity Framework. It includes code examples, breaking changes, and best practices for a smooth transition.

## Table of Contents

- [Migration Overview](#migration-overview)
- [Pre-Migration Assessment](#pre-migration-assessment)
- [Step-by-Step Migration](#step-by-step-migration)
- [Code Examples](#code-examples)
- [Breaking Changes](#breaking-changes)
- [Compatibility Shims](#compatibility-shims)
- [Testing Migration](#testing-migration)
- [Performance Considerations](#performance-considerations)
- [Rollback Strategy](#rollback-strategy)
- [Post-Migration Optimization](#post-migration-optimization)

## Migration Overview

### What's Changing

**Before (Direct API):**
- Direct HTTP calls to OpenAI, Anthropic, etc.
- Manual error handling per provider
- Provider-specific response parsing
- Inconsistent authentication patterns
- Limited observability and monitoring

**After (MCP Integration):**
- Unified MCP interface for all providers
- Standardized error handling
- Automatic response normalization
- Centralized authentication and security
- Comprehensive monitoring and analytics

### Migration Benefits

1. **Standardization**: Consistent interface across all LLM providers
2. **Reliability**: Built-in failover and circuit breaker patterns
3. **Security**: Centralized credential management and threat detection
4. **Observability**: Real-time monitoring and comprehensive analytics
5. **Performance**: Intelligent provider selection and caching
6. **Cost Optimization**: Usage tracking and cost optimization algorithms

### Migration Phases

1. **Assessment**: Analyze current LLM usage patterns
2. **Preparation**: Install MCP infrastructure and configure providers
3. **Implementation**: Migrate code to use MCP interfaces
4. **Testing**: Validate functionality and performance
5. **Deployment**: Gradual rollout with monitoring
6. **Optimization**: Fine-tune configuration based on usage patterns

## Pre-Migration Assessment

### Inventory Current LLM Usage

Before starting migration, identify all current LLM integrations:

```bash
# Find direct API calls in codebase
grep -r "openai\|anthropic\|api\.openai\|api\.anthropic" src/ --include="*.ts" --include="*.js"

# Find environment variables
grep -r "OPENAI_API_KEY\|ANTHROPIC_API_KEY" . --include="*.env*" --include="*.ts" --include="*.js"

# Find configuration files
find . -name "*.json" -o -name "*.yaml" -o -name "*.yml" | xargs grep -l "openai\|anthropic"
```

### Document Current Patterns

Create an inventory of your current LLM usage:

```typescript
// Example current usage inventory
const currentUsage = {
  providers: ['openai', 'anthropic'],
  usagePatterns: [
    {
      location: 'src/delegation/natural-language.ts',
      provider: 'openai',
      method: 'chat completions',
      frequency: 'high',
      critical: true
    },
    {
      location: 'src/agent/decision-making.ts',
      provider: 'anthropic',
      method: 'message API',
      frequency: 'medium',
      critical: false
    }
  ],
  dependencies: [
    'openai@4.x',
    'anthropic@0.x'
  ],
  errorHandling: 'manual per provider',
  monitoring: 'basic logging'
}
```

### Assess Migration Complexity

Rate each integration by complexity:

- **Low**: Simple completion requests with basic error handling
- **Medium**: Function calling, streaming, or custom error handling
- **High**: Complex workflows, custom authentication, or extensive customization

## Step-by-Step Migration

### Step 1: Install MCP Infrastructure

1. **Install Dependencies:**
   ```bash
   npm install @mcp/client @mcp/types
   # Keep existing dependencies for compatibility during migration
   ```

2. **Set Up Configuration:**
   ```typescript
   // config/mcp.ts
   import { MCPIntegrationConfig } from '../src/mcp/types'
   
   export const mcpConfig: MCPIntegrationConfig = {
     client: {
       serverUrl: process.env.MCP_SERVER_URL || 'ws://localhost:8080',
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
       }
     },
     // ... rest of configuration
   }
   ```

3. **Initialize MCP Components:**
   ```typescript
   // src/mcp-setup.ts
   import { MCPClient, MCPEnabledCommunicationManager } from './mcp'
   import { mcpConfig } from '../config/mcp'
   
   // Initialize infrastructure
   export const mcpClient = new MCPClient(mcpConfig.client)
   export const authManager = new AuthManager(mcpConfig.security.auth)
   export const rateLimiter = new RateLimiterManager(authManager)
   export const credentialManager = new CredentialManager(mcpConfig.security.credentials)
   
   // Create enhanced communication manager
   export const communicationManager = new MCPEnabledCommunicationManager(
     agentIdentity,
     agentManager,
     delegationManager,
     policyEngine,
     activityLogger,
     mcpConfig.communication,
     authManager,
     rateLimiter,
     credentialManager
   )
   ```

### Step 2: Create Compatibility Layer

Create a compatibility layer to ease migration:

```typescript
// src/compatibility/llm-adapter.ts
import { mcpClient } from '../mcp-setup'
import { LLMRequest, LLMResponse } from '../mcp/types'

/**
 * Compatibility adapter for existing OpenAI usage
 */
export class OpenAIAdapter {
  static async chatCompletion(params: {
    model: string
    messages: Array<{ role: string; content: string }>
    temperature?: number
    max_tokens?: number
  }): Promise<any> {
    const request: LLMRequest = {
      id: `compat-${Date.now()}`,
      type: 'completion',
      prompt: this.messagesToPrompt(params.messages),
      agentDID: 'compatibility-layer',
      sessionId: 'compat-session',
      parameters: {
        model: params.model,
        temperature: params.temperature,
        maxTokens: params.max_tokens
      },
      metadata: {
        timestamp: new Date(),
        source: 'compatibility-adapter'
      }
    }

    const response = await mcpClient.request(request)
    
    // Convert MCP response to OpenAI format
    return {
      id: response.id,
      object: 'chat.completion',
      choices: [{
        message: {
          role: 'assistant',
          content: response.content
        },
        finish_reason: 'stop'
      }],
      usage: response.usage,
      model: response.model
    }
  }

  private static messagesToPrompt(messages: Array<{ role: string; content: string }>): string {
    return messages.map(m => `${m.role}: ${m.content}`).join('\n')
  }
}

/**
 * Compatibility adapter for existing Anthropic usage
 */
export class AnthropicAdapter {
  static async messages(params: {
    model: string
    messages: Array<{ role: string; content: string }>
    max_tokens: number
  }): Promise<any> {
    const request: LLMRequest = {
      id: `compat-anthropic-${Date.now()}`,
      type: 'completion',
      prompt: this.messagesToPrompt(params.messages),
      agentDID: 'compatibility-layer',
      sessionId: 'compat-session',
      parameters: {
        model: params.model,
        maxTokens: params.max_tokens,
        provider: 'anthropic'
      },
      metadata: {
        timestamp: new Date(),
        source: 'compatibility-adapter'
      }
    }

    const response = await mcpClient.request(request)
    
    // Convert MCP response to Anthropic format
    return {
      id: response.id,
      type: 'message',
      content: [{ type: 'text', text: response.content }],
      usage: {
        input_tokens: response.usage?.promptTokens || 0,
        output_tokens: response.usage?.completionTokens || 0
      },
      model: response.model
    }
  }

  private static messagesToPrompt(messages: Array<{ role: string; content: string }>): string {
    return messages.map(m => `${m.role}: ${m.content}`).join('\n')
  }
}
```

### Step 3: Migrate Individual Components

#### Example 1: Simple Completion Migration

**Before (Direct OpenAI):**
```typescript
// src/delegation/natural-language.ts (BEFORE)
import OpenAI from 'openai'

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
})

export async function processNaturalLanguageRequest(
  request: string
): Promise<string> {
  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'system', content: 'You are a delegation assistant.' },
        { role: 'user', content: request }
      ],
      temperature: 0.7,
      max_tokens: 500
    })

    return completion.choices[0].message.content || ''
  } catch (error) {
    console.error('OpenAI error:', error)
    throw new Error('Failed to process request')
  }
}
```

**After (MCP Integration):**
```typescript
// src/delegation/natural-language.ts (AFTER)
import { communicationManager } from '../mcp-setup'

export async function processNaturalLanguageRequest(
  request: string
): Promise<string> {
  try {
    const response = await communicationManager.processNaturalLanguageMessage(
      request,
      undefined,
      {
        streaming: false,
        priority: 'high'
      }
    )

    return response.content
  } catch (error) {
    // MCP provides standardized error handling
    console.error('MCP error:', error)
    throw error
  }
}
```

#### Example 2: Function Calling Migration

**Before (Direct OpenAI):**
```typescript
// src/agent/decision-making.ts (BEFORE)
import OpenAI from 'openai'

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
})

const functions = [
  {
    name: 'evaluate_delegation',
    description: 'Evaluate a delegation request',
    parameters: {
      type: 'object',
      properties: {
        requester: { type: 'string' },
        scopes: { type: 'array', items: { type: 'string' } },
        reason: { type: 'string' }
      },
      required: ['requester', 'scopes', 'reason']
    }
  }
]

export async function makeDelegationDecision(
  context: DelegationContext
): Promise<DelegationDecision> {
  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'system', content: 'You are a delegation decision engine.' },
        { role: 'user', content: `Evaluate: ${JSON.stringify(context)}` }
      ],
      functions,
      function_call: { name: 'evaluate_delegation' }
    })

    const functionCall = completion.choices[0].message.function_call
    if (functionCall) {
      const args = JSON.parse(functionCall.arguments)
      return processDelegationDecision(args)
    }

    throw new Error('No function call returned')
  } catch (error) {
    console.error('Function call error:', error)
    throw error
  }
}
```

**After (MCP Integration):**
```typescript
// src/agent/decision-making.ts (AFTER)
import { communicationManager } from '../mcp-setup'

export async function makeDelegationDecision(
  context: DelegationContext
): Promise<DelegationDecision> {
  try {
    // MCP handles function calling automatically
    const evaluation = await communicationManager.evaluateDelegationWithLLM(
      context.requester,
      context.targetAgent,
      context.scopes,
      context.reason,
      context.duration
    )

    return {
      decision: evaluation.decision,
      confidence: evaluation.confidence,
      reasoning: evaluation.reasoning,
      suggestedScopes: evaluation.suggestedScopes,
      warnings: evaluation.warnings,
      riskLevel: evaluation.riskLevel
    }
  } catch (error) {
    console.error('Delegation evaluation error:', error)
    throw error
  }
}
```

#### Example 3: Streaming Migration

**Before (Direct OpenAI):**
```typescript
// src/real-time/streaming.ts (BEFORE)
import OpenAI from 'openai'

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
})

export async function streamResponse(
  prompt: string,
  onChunk: (chunk: string) => void
): Promise<string> {
  const stream = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }],
    stream: true
  })

  let fullResponse = ''

  for await (const chunk of stream) {
    const content = chunk.choices[0]?.delta?.content || ''
    if (content) {
      fullResponse += content
      onChunk(content)
    }
  }

  return fullResponse
}
```

**After (MCP Integration):**
```typescript
// src/real-time/streaming.ts (AFTER)
import { communicationManager } from '../mcp-setup'

export async function streamResponse(
  prompt: string,
  onChunk: (chunk: string) => void
): Promise<string> {
  try {
    const response = await communicationManager.processNaturalLanguageMessage(
      prompt,
      undefined,
      {
        streaming: true,
        priority: 'medium',
        onChunk
      }
    )

    return response.content
  } catch (error) {
    console.error('Streaming error:', error)
    throw error
  }
}
```

### Step 4: Update Error Handling

**Before (Provider-Specific):**
```typescript
// Error handling per provider
try {
  const response = await openai.chat.completions.create(params)
} catch (error: any) {
  if (error.status === 429) {
    // Rate limit handling
    await new Promise(resolve => setTimeout(resolve, 1000))
    // Retry logic
  } else if (error.status === 401) {
    // Auth error
    throw new Error('Invalid API key')
  } else {
    throw error
  }
}
```

**After (Standardized MCP):**
```typescript
// Standardized error handling
import { MCPError, MCPErrorCode } from '../mcp/types'

try {
  const response = await communicationManager.processNaturalLanguageMessage(request)
} catch (error: any) {
  if (error instanceof MCPError) {
    switch (error.code) {
      case MCPErrorCode.RATE_LIMIT_EXCEEDED:
        // MCP handles rate limiting and failover automatically
        console.warn('Rate limit exceeded, failover initiated')
        break
      case MCPErrorCode.AUTHENTICATION_FAILED:
        console.error('Authentication failed:', error.message)
        break
      case MCPErrorCode.PROVIDER_ERROR:
        console.error('Provider error:', error.message, 'Provider:', error.provider)
        break
      default:
        console.error('MCP error:', error)
    }
  }
  throw error
}
```

### Step 5: Update Configuration Management

**Before (Multiple Configurations):**
```typescript
// Multiple provider configurations
const openaiConfig = {
  apiKey: process.env.OPENAI_API_KEY,
  organization: process.env.OPENAI_ORG_ID
}

const anthropicConfig = {
  apiKey: process.env.ANTHROPIC_API_KEY
}
```

**After (Unified MCP Configuration):**
```typescript
// Single MCP configuration
import { mcpConfig } from '../config/mcp'

// All provider configurations are centralized
// Automatic failover, load balancing, and cost optimization
```

## Breaking Changes

### Removed Direct Dependencies

After migration, you can remove direct provider dependencies:

```bash
# Remove old dependencies
npm uninstall openai anthropic

# Add MCP dependencies (if not already added)
npm install @mcp/client @mcp/types
```

### Changed Response Formats

**Response Structure Changes:**
```typescript
// Before: OpenAI-specific response
interface OpenAIResponse {
  id: string
  object: string
  choices: Array<{
    message: { role: string; content: string }
    finish_reason: string
  }>
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number }
}

// After: Standardized MCP response
interface LLMResponse {
  id: string
  content?: string
  provider: string
  model?: string
  usage?: UsageInfo
  timestamp: Date
  metadata?: ResponseMetadata
}
```

### API Method Changes

| Before (Direct API) | After (MCP) |
|-------------------|-------------|
| `openai.chat.completions.create()` | `communicationManager.processNaturalLanguageMessage()` |
| `anthropic.messages.create()` | `communicationManager.processNaturalLanguageMessage()` |
| Manual provider selection | `providerSelector.selectProvider()` |
| Manual error handling | Automatic error handling with MCPError |
| Manual retry logic | Built-in circuit breaker and failover |

### Environment Variable Changes

Add new MCP-specific environment variables:
```bash
# New required variables
MCP_API_KEY=your-mcp-api-key
CREDENTIAL_ENCRYPTION_KEY=$(openssl rand -hex 32)

# Existing variables (still needed)
OPENAI_API_KEY=your-openai-key
ANTHROPIC_API_KEY=your-anthropic-key
```

## Compatibility Shims

For gradual migration, use compatibility shims:

```typescript
// src/compatibility/openai-shim.ts
import { OpenAIAdapter } from './llm-adapter'

export const openai = {
  chat: {
    completions: {
      create: OpenAIAdapter.chatCompletion.bind(OpenAIAdapter)
    }
  }
}

// Usage in existing code (minimal changes required)
import { openai } from '../compatibility/openai-shim'

// Existing code continues to work
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello' }]
})
```

```typescript
// src/compatibility/anthropic-shim.ts
import { AnthropicAdapter } from './llm-adapter'

export const anthropic = {
  messages: {
    create: AnthropicAdapter.messages.bind(AnthropicAdapter)
  }
}
```

## Testing Migration

### Unit Tests

Update existing tests to use MCP:

```typescript
// tests/delegation.test.ts (AFTER)
import { communicationManager } from '../src/mcp-setup'
import { jest } from '@jest/globals'

describe('Natural Language Processing', () => {
  beforeEach(() => {
    // Mock MCP communication manager
    jest.spyOn(communicationManager, 'processNaturalLanguageMessage')
      .mockResolvedValue({
        id: 'test-response',
        content: 'Test delegation response',
        type: 'delegation',
        timestamp: new Date(),
        metadata: { source: 'test' }
      })
  })

  it('should process natural language requests', async () => {
    const response = await processNaturalLanguageRequest('Create a delegation for email access')
    
    expect(response).toBe('Test delegation response')
    expect(communicationManager.processNaturalLanguageMessage).toHaveBeenCalledWith(
      'Create a delegation for email access',
      undefined,
      expect.objectContaining({
        streaming: false,
        priority: 'high'
      })
    )
  })
})
```

### Integration Tests

Test MCP integration end-to-end:

```typescript
// tests/mcp-integration.test.ts
import { mcpClient, communicationManager } from '../src/mcp-setup'

describe('MCP Integration', () => {
  beforeAll(async () => {
    await mcpClient.connect()
  })

  afterAll(async () => {
    await mcpClient.disconnect()
  })

  it('should handle real requests through MCP', async () => {
    const response = await communicationManager.processNaturalLanguageMessage(
      'Test MCP integration',
      undefined,
      { streaming: false, priority: 'medium' }
    )

    expect(response).toBeDefined()
    expect(response.content).toBeTruthy()
    expect(response.metadata?.source).toBe('mcp')
  })

  it('should handle provider failover', async () => {
    // Test with simulated provider failure
    const response = await communicationManager.processNaturalLanguageMessage(
      'Test failover functionality',
      undefined,
      { streaming: false, priority: 'high' }
    )

    expect(response).toBeDefined()
    // Response should succeed even if primary provider fails
  })
})
```

### Performance Testing

Compare performance before and after migration:

```typescript
// tests/performance-comparison.test.ts
import { performance } from 'perf_hooks'

describe('Performance Comparison', () => {
  it('should maintain acceptable performance with MCP', async () => {
    const startTime = performance.now()
    
    const response = await communicationManager.processNaturalLanguageMessage(
      'Performance test request',
      undefined,
      { streaming: false, priority: 'medium' }
    )
    
    const endTime = performance.now()
    const duration = endTime - startTime

    expect(response).toBeDefined()
    expect(duration).toBeLessThan(5000) // 5 second max
  })
})
```

## Performance Considerations

### Expected Overhead

MCP introduces minimal overhead:
- **Latency**: +50-100ms for request routing and processing
- **Memory**: +10-20MB for MCP infrastructure
- **CPU**: +5-10% for provider selection and monitoring

### Optimization Opportunities

MCP provides several optimization features:

1. **Intelligent Provider Selection:**
   ```typescript
   // Automatically selects best provider based on latency/cost/reliability
   const response = await communicationManager.processNaturalLanguageMessage(
     request,
     undefined,
     { priority: 'high' }  // High priority = low latency providers
   )
   ```

2. **Context Caching:**
   ```typescript
   // Context is automatically cached and compressed
   // Reduces token usage for follow-up requests
   ```

3. **Connection Pooling:**
   ```typescript
   // MCP maintains connection pools to providers
   // Reduces connection overhead
   ```

4. **Request Batching:**
   ```typescript
   // Future enhancement: automatic request batching
   // for compatible providers
   ```

## Rollback Strategy

### Gradual Rollback

If issues arise, you can gradually rollback:

1. **Feature Flags:**
   ```typescript
   const USE_MCP = process.env.USE_MCP === 'true'
   
   if (USE_MCP) {
     return await communicationManager.processNaturalLanguageMessage(request)
   } else {
     return await legacyOpenAIHandler(request)
   }
   ```

2. **Component-by-Component:**
   ```typescript
   // Rollback specific components while keeping others on MCP
   const MCP_COMPONENTS = process.env.MCP_COMPONENTS?.split(',') || []
   
   if (MCP_COMPONENTS.includes('delegation')) {
     // Use MCP for delegation
   } else {
     // Use legacy implementation
   }
   ```

### Emergency Rollback

For emergency situations:

1. **Environment Variable:**
   ```bash
   export EMERGENCY_DISABLE_MCP=true
   ```

2. **Code Switch:**
   ```typescript
   if (process.env.EMERGENCY_DISABLE_MCP === 'true') {
     // Use all legacy implementations
     return await legacyHandler(request)
   }
   ```

3. **Configuration Rollback:**
   ```bash
   # Restore previous configuration
   cp config/pre-mcp-backup.json config/current.json
   npm restart
   ```

## Post-Migration Optimization

### Monitor Performance

After migration, monitor key metrics:

```typescript
// Monitor MCP performance
const metrics = dashboard.getMetrics()
console.log('MCP Performance:', {
  averageLatency: metrics.averageLatency,
  errorRate: metrics.errorRate,
  costSavings: metrics.totalCost, // vs previous period
  providerHealth: metrics.providerHealth
})
```

### Optimize Configuration

Based on usage patterns, optimize:

1. **Provider Selection Strategy:**
   ```typescript
   // Adjust based on your priorities
   const strategy = costSensitive ? 
     SelectionStrategy.COST_OPTIMIZED : 
     SelectionStrategy.RELIABILITY
   ```

2. **Rate Limits:**
   ```typescript
   // Adjust based on actual usage
   const config = {
     rateLimiting: {
       windowSize: 60000,
       defaultLimit: actualUsagePattern * 1.2  // 20% buffer
     }
   }
   ```

3. **Context Management:**
   ```typescript
   // Optimize based on conversation patterns
   const config = {
     context: {
       maxTokensPerContext: optimalContextSize,
       compressionStrategy: bestCompressionForYourUseCase
     }
   }
   ```

### Enable Advanced Features

After successful migration, enable advanced MCP features:

1. **Security Monitoring:**
   ```typescript
   const security = new MCPSecurityIntegration(/* ... */)
   security.on('threat_detected', (threat) => {
     // Handle security threats
   })
   ```

2. **Cost Optimization:**
   ```typescript
   // Enable cost tracking and optimization
   const costOptimizer = new CostOptimizer(dashboard)
   await costOptimizer.analyzeCostPatterns()
   ```

3. **Performance Analytics:**
   ```typescript
   // Enable detailed performance monitoring
   const analytics = new PerformanceAnalytics(dashboard)
   await analytics.generateOptimizationRecommendations()
   ```

## Migration Checklist

### Pre-Migration
- [ ] Inventory all current LLM usage
- [ ] Assess migration complexity for each component
- [ ] Set up MCP infrastructure and configuration
- [ ] Create backup of current implementation
- [ ] Plan rollback strategy

### During Migration
- [ ] Install MCP dependencies
- [ ] Create compatibility shims
- [ ] Migrate components one by one
- [ ] Update error handling
- [ ] Update tests
- [ ] Monitor performance during migration

### Post-Migration
- [ ] Remove old dependencies
- [ ] Remove compatibility shims (when no longer needed)
- [ ] Optimize MCP configuration
- [ ] Enable advanced features
- [ ] Monitor and analyze performance
- [ ] Document lessons learned

### Validation
- [ ] All existing functionality works
- [ ] Performance is acceptable
- [ ] Error handling is improved
- [ ] Monitoring provides better visibility
- [ ] Cost optimization is working
- [ ] Security monitoring is active

## Common Migration Issues

### Issue: Type Errors After Migration

**Problem:** TypeScript compilation errors due to changed interfaces.

**Solution:**
```typescript
// Update type imports
import { LLMResponse, LLMRequest } from '../mcp/types'

// Use type assertions for compatibility
const legacyResponse = mcpResponse as any as LegacyResponseType
```

### Issue: Performance Regression

**Problem:** Increased latency after migration.

**Solution:**
```typescript
// Optimize provider selection
const criteria = {
  requirements: {
    maxLatency: 1000  // Strict latency requirements
  }
}

// Enable caching
const config = {
  context: {
    cache: { enabled: true, ttl: 3600000 }
  }
}
```

### Issue: Unexpected Costs

**Problem:** Higher than expected costs after migration.

**Solution:**
```typescript
// Enable cost monitoring
dashboard.addAlert({
  metric: 'totalCost',
  threshold: dailyBudget,
  operator: 'gt',
  windowSize: 86400000  // 24 hours
})

// Use cost-optimized strategy
const strategy = SelectionStrategy.COST_OPTIMIZED
```

For additional support during migration, refer to the [Troubleshooting Guide](./mcp-troubleshooting.md) or contact the development team.