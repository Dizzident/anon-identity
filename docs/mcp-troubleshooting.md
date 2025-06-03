# MCP Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting information for the Model Context Protocol (MCP) integration within the Anonymous Identity Framework. It covers common issues, diagnostic procedures, and solutions for various MCP-related problems.

## Table of Contents

- [Quick Diagnostic Steps](#quick-diagnostic-steps)
- [Connection Issues](#connection-issues)
- [Provider Problems](#provider-problems)
- [Authentication and Security](#authentication-and-security)
- [Performance Issues](#performance-issues)
- [Error Handling](#error-handling)
- [Configuration Problems](#configuration-problems)
- [Monitoring and Debugging](#monitoring-and-debugging)
- [Common Error Codes](#common-error-codes)
- [Diagnostic Tools](#diagnostic-tools)
- [Support and Resources](#support-and-resources)

## Quick Diagnostic Steps

When experiencing MCP issues, start with these basic diagnostic steps:

### 1. Check System Status
```bash
# Verify MCP server is running
curl -f http://localhost:8080/health

# Check WebSocket connectivity
wscat -c ws://localhost:8080

# Verify environment variables
echo $MCP_API_KEY
echo $OPENAI_API_KEY
echo $ANTHROPIC_API_KEY
```

### 2. Test Configuration
```typescript
import { validateConfig, testConfiguration } from './mcp-configuration-guide'

// Validate configuration structure
const validation = validateConfig(yourConfig)
if (!validation.valid) {
  console.error('Configuration errors:', validation.errors)
}

// Test connectivity
const testResult = await testConfiguration(yourConfig)
if (!testResult.overall) {
  console.error('Connectivity failures:', testResult.tests)
}
```

### 3. Check Logs
```bash
# Application logs
tail -f ./logs/mcp.log

# System logs (if using systemd)
journalctl -u mcp-server -f

# Docker logs (if containerized)
docker logs mcp-server --follow
```

## Connection Issues

### Problem: MCP Server Connection Failed

**Symptoms:**
- `CONNECTION_FAILED` errors
- Timeouts during initialization
- WebSocket connection errors

**Diagnostics:**
```bash
# Check if MCP server is running
netstat -tlnp | grep 8080

# Test direct connection
telnet localhost 8080

# Check firewall rules
sudo ufw status
```

**Solutions:**

1. **Server Not Running:**
   ```bash
   # Start MCP server
   npm run mcp:server
   
   # Or using Docker
   docker-compose up mcp-server
   ```

2. **Port Conflicts:**
   ```yaml
   # Update docker-compose.yml or config
   mcp_server:
     ports:
       - "8081:8080"  # Use different port
   ```

3. **Network Configuration:**
   ```typescript
   const config = {
     client: {
       serverUrl: 'ws://0.0.0.0:8080',  // Bind to all interfaces
       options: {
         reconnectAttempts: 5,
         heartbeatInterval: 30000
       }
     }
   }
   ```

### Problem: Intermittent Connection Drops

**Symptoms:**
- Random connection failures
- Heartbeat timeout errors
- Reconnection attempts

**Solutions:**

1. **Adjust Heartbeat Settings:**
   ```typescript
   const config = {
     client: {
       options: {
         heartbeatInterval: 15000,  // More frequent heartbeats
         requestTimeout: 90000,     // Longer timeout
         reconnectAttempts: 10      // More retry attempts
       }
     }
   }
   ```

2. **Implement Connection Monitoring:**
   ```typescript
   mcpClient.on('disconnect', () => {
     console.log('MCP connection lost, attempting reconnection...')
   })
   
   mcpClient.on('reconnect', () => {
     console.log('MCP connection restored')
   })
   ```

## Provider Problems

### Problem: Provider Authentication Failures

**Symptoms:**
- `AUTHENTICATION_FAILED` errors
- 401/403 HTTP status codes
- Invalid API key messages

**Diagnostics:**
```bash
# Test OpenAI API key
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  https://api.openai.com/v1/models

# Test Anthropic API key
curl -H "x-api-key: $ANTHROPIC_API_KEY" \
  https://api.anthropic.com/v1/messages \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"test"}]}'
```

**Solutions:**

1. **Verify API Keys:**
   ```bash
   # Check key format and length
   echo $OPENAI_API_KEY | wc -c  # Should be ~51 characters
   echo $ANTHROPIC_API_KEY | wc -c  # Should be ~108 characters
   ```

2. **Update Configuration:**
   ```typescript
   const config = {
     providers: {
       openai: {
         apiKey: process.env.OPENAI_API_KEY!,
         organization: process.env.OPENAI_ORG_ID, // If using org
         endpoint: 'https://api.openai.com/v1'
       },
       anthropic: {
         apiKey: process.env.ANTHROPIC_API_KEY!,
         endpoint: 'https://api.anthropic.com/v1'
       }
     }
   }
   ```

3. **Credential Rotation:**
   ```typescript
   await credentialManager.rotateCredentials('openai', {
     apiKey: newApiKey,
     rotatedAt: new Date()
   })
   ```

### Problem: Provider Rate Limiting

**Symptoms:**
- `RATE_LIMIT_EXCEEDED` errors
- 429 HTTP status codes
- Temporary provider unavailability

**Solutions:**

1. **Implement Backoff Strategy:**
   ```typescript
   const config = {
     providers: {
       openai: {
         rateLimits: {
           requestsPerMinute: 60,    // Reduce from default
           tokensPerMinute: 90000,   // Conservative limit
           backoffStrategy: 'exponential',
           maxRetries: 3
         }
       }
     }
   }
   ```

2. **Enable Provider Failover:**
   ```typescript
   const selection = await providerSelector.selectProvider(
     request,
     criteria,
     SelectionStrategy.RELIABILITY
   )
   
   // Automatically switches to backup provider on rate limits
   ```

3. **Monitor Usage:**
   ```typescript
   const metrics = dashboard.getMetrics()
   console.log('Provider usage:', metrics.providerUsage)
   
   if (metrics.providerUsage.openai.requestsPerMinute > 50) {
     console.warn('Approaching OpenAI rate limit')
   }
   ```

### Problem: Provider Response Errors

**Symptoms:**
- Malformed response data
- Unexpected response format
- Model not found errors

**Diagnostics:**
```typescript
// Enable debug logging
const mcpClient = new MCPClient({
  ...config,
  debug: true,
  logLevel: 'debug'
})

// Monitor raw responses
mcpClient.on('response', (response) => {
  console.log('Raw provider response:', response)
})
```

**Solutions:**

1. **Verify Model Availability:**
   ```typescript
   const providers = mcpClient.getProviders()
   providers.forEach(provider => {
     console.log(`${provider.id} models:`, provider.models)
   })
   ```

2. **Handle Provider-Specific Formats:**
   ```typescript
   // Response normalization is handled automatically
   // Check configuration if issues persist
   const normalizedResponse = await messageRouter.routeMessage(request)
   ```

## Authentication and Security

### Problem: DID Authentication Failures

**Symptoms:**
- Invalid DID format errors
- Signature verification failures
- Authentication timeouts

**Solutions:**

1. **Verify DID Format:**
   ```typescript
   import { validateDID } from '../core/did'
   
   const isValid = validateDID('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')
   if (!isValid) {
     throw new Error('Invalid DID format')
   }
   ```

2. **Check Signature Process:**
   ```typescript
   // Ensure proper key pair usage
   const keyPair = await generateKeyPair()
   const signature = await signMessage(message, keyPair.privateKey)
   const verified = await verifySignature(message, signature, keyPair.publicKey)
   ```

3. **Session Management:**
   ```typescript
   const session = await authManager.createSession(agentDID)
   
   // Verify session is valid
   const isValidSession = await authManager.validateSession(session.id)
   ```

### Problem: Credential Encryption Issues

**Symptoms:**
- Decryption failures
- Corrupt credential data
- Key rotation errors

**Solutions:**

1. **Verify Encryption Key:**
   ```bash
   # Generate new encryption key if needed
   export CREDENTIAL_ENCRYPTION_KEY=$(openssl rand -hex 32)
   ```

2. **Test Encryption/Decryption:**
   ```typescript
   const testData = { test: 'data' }
   const encrypted = credentialManager.encryptCredentials(testData)
   const decrypted = credentialManager.decryptCredentials(encrypted)
   
   console.log('Encryption test:', JSON.stringify(testData) === JSON.stringify(decrypted))
   ```

3. **Credential Recovery:**
   ```typescript
   // Backup and restore credentials
   const backup = await credentialManager.exportCredentials()
   await credentialManager.importCredentials(backup)
   ```

## Performance Issues

### Problem: High Latency

**Symptoms:**
- Slow response times
- Timeout errors
- Poor user experience

**Diagnostics:**
```typescript
// Monitor latency metrics
const metrics = dashboard.getMetrics()
console.log('Average latency:', metrics.averageLatency)
console.log('P95 latency:', metrics.latencyPercentiles.p95)

// Provider-specific latency
Object.entries(metrics.providerUsage).forEach(([provider, usage]) => {
  console.log(`${provider} latency:`, usage.averageLatency)
})
```

**Solutions:**

1. **Optimize Provider Selection:**
   ```typescript
   const selection = await providerSelector.selectProvider(
     request,
     {
       requirements: {
         maxLatency: 1000  // 1 second max
       }
     },
     SelectionStrategy.LATENCY
   )
   ```

2. **Enable Caching:**
   ```typescript
   const config = {
     context: {
       cache: {
         enabled: true,
         maxSize: 1000,
         ttl: 3600000  // 1 hour
       }
     }
   }
   ```

3. **Connection Pooling:**
   ```typescript
   const config = {
     client: {
       options: {
         maxConcurrentRequests: 20,
         connectionPoolSize: 10
       }
     }
   }
   ```

### Problem: Memory Leaks

**Symptoms:**
- Increasing memory usage over time
- Node.js heap out of memory errors
- Degraded performance

**Solutions:**

1. **Context Cleanup:**
   ```typescript
   // Regular cleanup
   setInterval(() => {
     contextManager.cleanup()
   }, 3600000)  // Every hour
   
   // Manual cleanup
   await contextManager.deleteContext(conversationId)
   ```

2. **Monitor Memory Usage:**
   ```typescript
   const usage = process.memoryUsage()
   console.log('Memory usage:', {
     rss: Math.round(usage.rss / 1024 / 1024) + ' MB',
     heapUsed: Math.round(usage.heapUsed / 1024 / 1024) + ' MB',
     heapTotal: Math.round(usage.heapTotal / 1024 / 1024) + ' MB'
   })
   ```

3. **Streaming Cleanup:**
   ```typescript
   // Ensure streams are properly closed
   stream.on('end', () => {
     stream.destroy()
   })
   
   stream.on('error', (error) => {
     console.error('Stream error:', error)
     stream.destroy()
   })
   ```

## Error Handling

### Problem: Unhandled Promise Rejections

**Symptoms:**
- Node.js warning messages
- Application crashes
- Inconsistent error states

**Solutions:**

1. **Global Error Handling:**
   ```typescript
   process.on('unhandledRejection', (reason, promise) => {
     console.error('Unhandled Rejection at:', promise, 'reason:', reason)
     // Log to monitoring system
   })
   
   process.on('uncaughtException', (error) => {
     console.error('Uncaught Exception:', error)
     process.exit(1)
   })
   ```

2. **Proper Async/Await Usage:**
   ```typescript
   // Bad
   someAsyncFunction()  // Missing await
   
   // Good
   try {
     const result = await someAsyncFunction()
   } catch (error) {
     console.error('Error:', error)
   }
   ```

3. **Error Boundaries:**
   ```typescript
   class MCPErrorHandler {
     static async handleError(error: MCPError, context: any): Promise<void> {
       // Log error
       console.error('MCP Error:', error)
       
       // Report to monitoring
       await monitoringDashboard.reportError(error, context)
       
       // Take appropriate action
       if (error.retryable) {
         // Implement retry logic
       } else {
         // Escalate or fail gracefully
       }
     }
   }
   ```

## Configuration Problems

### Problem: Invalid Configuration Schema

**Symptoms:**
- Configuration validation errors
- Startup failures
- Missing required properties

**Solutions:**

1. **Use Configuration Validation:**
   ```typescript
   import { validateConfig } from './mcp-configuration-guide'
   
   const validation = validateConfig(config)
   if (!validation.valid) {
     console.error('Configuration errors:')
     validation.errors?.forEach(error => console.error('-', error))
     process.exit(1)
   }
   ```

2. **Configuration Templates:**
   ```typescript
   // Use provided configuration templates
   const config = {
     ...developmentConfig,  // or productionConfig
     // Override specific settings
     client: {
       ...developmentConfig.client,
       apiKey: process.env.MCP_API_KEY
     }
   }
   ```

3. **Environment-Specific Configs:**
   ```typescript
   const environment = process.env.NODE_ENV || 'development'
   const configFile = `./config/mcp-${environment}.json`
   const config = JSON.parse(fs.readFileSync(configFile, 'utf8'))
   ```

### Problem: Environment Variable Issues

**Symptoms:**
- Missing environment variables
- Configuration defaults not working
- Runtime errors

**Solutions:**

1. **Environment Validation:**
   ```typescript
   const requiredEnvVars = [
     'MCP_API_KEY',
     'OPENAI_API_KEY',
     'ANTHROPIC_API_KEY',
     'CREDENTIAL_ENCRYPTION_KEY'
   ]
   
   requiredEnvVars.forEach(varName => {
     if (!process.env[varName]) {
       throw new Error(`Missing required environment variable: ${varName}`)
     }
   })
   ```

2. **Use dotenv for Development:**
   ```bash
   # .env file
   MCP_API_KEY=your-mcp-api-key
   OPENAI_API_KEY=your-openai-key
   ANTHROPIC_API_KEY=your-anthropic-key
   CREDENTIAL_ENCRYPTION_KEY=64-char-hex-string
   ```

3. **Default Value Handling:**
   ```typescript
   const config = {
     serverUrl: process.env.MCP_SERVER_URL || 'ws://localhost:8080',
     retryAttempts: parseInt(process.env.MCP_RETRY_ATTEMPTS || '3'),
     timeout: parseInt(process.env.MCP_TIMEOUT || '60000')
   }
   ```

## Monitoring and Debugging

### Enable Debug Logging

```typescript
const config = {
  client: {
    debug: true,
    logLevel: 'debug'
  },
  monitoring: {
    enableRealTimeUpdates: true,
    refreshInterval: 5000  // 5 seconds for debugging
  }
}
```

### Real-time Monitoring

```typescript
// Monitor metrics continuously
const monitor = setInterval(() => {
  const metrics = dashboard.getMetrics()
  console.log('Current metrics:', {
    requests: metrics.totalRequests,
    errors: metrics.errorRate,
    latency: metrics.averageLatency
  })
}, 10000)

// Stop monitoring
clearInterval(monitor)
```

### Debug Specific Components

```typescript
// Enable component-specific debugging
const messageRouter = new MessageRouter(mcpClient, authManager, auditLogger, rateLimiter, credentialManager, {
  debug: true,
  debugComponents: ['routing', 'selection', 'failover']
})

// Monitor events
messageRouter.on('debug', (event) => {
  console.log('Router debug:', event)
})
```

### Export Debug Information

```typescript
// Export comprehensive debug info
const debugInfo = {
  config: config,
  metrics: dashboard.getMetrics(),
  providers: Array.from(mcpClient.getProviders().values()),
  health: await Promise.all(
    Array.from(mcpClient.getProviders().values()).map(p => p.health())
  ),
  logs: auditLogger.getRecentLogs(100)
}

fs.writeFileSync('debug-info.json', JSON.stringify(debugInfo, null, 2))
```

## Common Error Codes

### MCPErrorCode.CONNECTION_FAILED
- **Cause:** MCP server unreachable
- **Solution:** Check server status and network connectivity

### MCPErrorCode.AUTHENTICATION_FAILED
- **Cause:** Invalid credentials or expired tokens
- **Solution:** Verify API keys and refresh authentication

### MCPErrorCode.RATE_LIMIT_EXCEEDED
- **Cause:** Too many requests to provider
- **Solution:** Implement backoff strategy or use different provider

### MCPErrorCode.PROVIDER_ERROR
- **Cause:** Provider-specific error
- **Solution:** Check provider status and error details

### MCPErrorCode.CIRCUIT_BREAKER_OPEN
- **Cause:** Provider marked as unhealthy due to repeated failures
- **Solution:** Wait for circuit breaker timeout or use alternative provider

### MCPErrorCode.SECURITY_VIOLATION
- **Cause:** Security threat detected
- **Solution:** Review request content and security policies

### MCPErrorCode.INVALID_REQUEST
- **Cause:** Malformed or invalid request format
- **Solution:** Validate request structure and parameters

## Diagnostic Tools

### MCP Health Check Tool

```typescript
async function mcpHealthCheck(): Promise<HealthReport> {
  const report: HealthReport = {
    timestamp: new Date(),
    overall: true,
    components: {}
  }

  // Check MCP server
  try {
    const serverHealth = await mcpClient.health()
    report.components.server = { status: 'healthy', details: serverHealth }
  } catch (error) {
    report.components.server = { status: 'unhealthy', error: error.message }
    report.overall = false
  }

  // Check providers
  const providers = mcpClient.getProviders()
  for (const [id, provider] of providers.entries()) {
    try {
      const health = await provider.health()
      report.components[`provider_${id}`] = { status: health.status, details: health }
      if (health.status !== 'healthy') report.overall = false
    } catch (error) {
      report.components[`provider_${id}`] = { status: 'unhealthy', error: error.message }
      report.overall = false
    }
  }

  return report
}
```

### Performance Benchmark Tool

```typescript
async function benchmarkMCP(): Promise<BenchmarkResult> {
  const requests = Array.from({ length: 100 }, (_, i) => 
    MCPTestUtils.createMockLLMRequest({
      id: `benchmark-${i}`,
      prompt: `Benchmark test ${i}`
    })
  )

  const startTime = performance.now()
  const results = await Promise.allSettled(
    requests.map(req => messageRouter.routeMessage(req))
  )
  const endTime = performance.now()

  const successful = results.filter(r => r.status === 'fulfilled').length
  const failed = results.filter(r => r.status === 'rejected').length

  return {
    totalRequests: requests.length,
    successful,
    failed,
    totalTime: endTime - startTime,
    averageLatency: (endTime - startTime) / requests.length,
    successRate: successful / requests.length
  }
}
```

### Configuration Validator Tool

```typescript
function validateMCPSetup(): ValidationResult {
  const issues: string[] = []
  const warnings: string[] = []

  // Check environment variables
  const requiredEnvVars = ['MCP_API_KEY', 'OPENAI_API_KEY']
  requiredEnvVars.forEach(varName => {
    if (!process.env[varName]) {
      issues.push(`Missing environment variable: ${varName}`)
    }
  })

  // Check configuration
  try {
    const validation = validateConfig(config)
    if (!validation.valid) {
      issues.push(...(validation.errors || []))
    }
  } catch (error) {
    issues.push(`Configuration validation error: ${error.message}`)
  }

  // Check connectivity
  // ... connectivity tests

  return {
    valid: issues.length === 0,
    issues,
    warnings
  }
}
```

## Support and Resources

### Documentation Links
- [MCP API Reference](./mcp-api-reference.md)
- [Configuration Guide](./mcp-configuration-guide.md)
- [Migration Guide](./mcp-migration-guide.md)

### Community and Support
- GitHub Issues: https://github.com/your-org/anon-identity/issues
- Documentation: https://docs.your-org.com/mcp
- Community Forum: https://forum.your-org.com

### Emergency Procedures

#### System Recovery
1. **Backup Current State**
   ```bash
   # Backup configuration
   cp config/mcp.json config/mcp.backup.json
   
   # Export current metrics
   curl -o metrics-backup.json http://localhost:8080/metrics
   ```

2. **Restore to Known Good State**
   ```bash
   # Restore configuration
   cp config/mcp.known-good.json config/mcp.json
   
   # Restart services
   npm run mcp:restart
   ```

3. **Gradual Recovery**
   ```typescript
   // Disable non-essential features
   const recoveryConfig = {
     ...config,
     security: {
       ...config.security,
       threatDetection: { enableThreatDetection: false }
     },
     monitoring: {
       ...config.monitoring,
       enableRealTimeUpdates: false
     }
   }
   ```

#### Contact Information
- **Emergency Contact:** ops@your-org.com
- **Technical Support:** support@your-org.com
- **Documentation Issues:** docs@your-org.com

### Logs and Monitoring
Always include the following information when reporting issues:

1. **Configuration (sanitized)**
2. **Error logs and stack traces**
3. **MCP metrics at time of issue**
4. **Provider health status**
5. **System resource usage**
6. **Steps to reproduce**

Example issue report:
```
Issue: MCP provider failover not working

Environment: Production
Version: 1.0.12
Timestamp: 2025-01-06T15:30:00Z

Error: MCPError: Provider selection failed after all attempts
Stack trace: [attach full stack trace]

Configuration: [attach sanitized config]
Metrics: [attach metrics export]
Health: [attach health check results]

Steps to reproduce:
1. Send request with OpenAI primary provider down
2. Observe failover attempt to Anthropic
3. Error occurs instead of successful failover
```

This troubleshooting guide should help resolve most common MCP integration issues. For complex problems not covered here, please refer to the documentation links or contact support with detailed information about your specific issue.