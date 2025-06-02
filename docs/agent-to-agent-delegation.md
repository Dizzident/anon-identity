# Agent-to-Agent Delegation Documentation

The Anonymous Identity Framework includes a comprehensive agent-to-agent delegation system that enables AI agents to create and manage sub-agents with hierarchical permission structures.

## Overview

Agent-to-agent delegation allows agents to:
- Create sub-agents with restricted permissions
- Delegate specific scopes to other agents
- Maintain hierarchical delegation chains
- Communicate securely between agents
- Monitor and revoke delegations

## Quick Start

```typescript
import { 
  AgentIdentityManager, 
  DelegationManager, 
  DelegationChainValidator 
} from 'anon-identity';

// Initialize managers
const agentManager = new AgentIdentityManager();
const delegationManager = new DelegationManager();
const chainValidator = new DelegationChainValidator(delegationManager, agentManager);

// Create primary agent
const primaryAgent = await agentManager.createAgent(userDID, {
  name: 'Assistant Agent',
  description: 'Main AI assistant',
  canDelegate: true,
  maxDelegationDepth: 3
});

// Create specialized sub-agent
const calendarAgent = await agentManager.createSubAgent(primaryAgent.did, {
  name: 'Calendar Agent',
  description: 'Calendar management specialist',
  parentAgentDID: primaryAgent.did,
  requestedScopes: ['read:calendar', 'write:calendar']
});

// Validate delegation chain
const validation = await chainValidator.validateChain(calendarAgent.did, 'calendar-service');
console.log('Chain valid:', validation.valid);
```

## Core Components

### AgentIdentityManager

Manages agent creation, delegation hierarchies, and credential storage.

**Key Methods:**
- `createAgent(parentDID, config)` - Create new agent
- `createSubAgent(parentDID, config)` - Create sub-agent with delegation
- `getAgent(agentDID)` - Retrieve agent by DID
- `listAgents(parentDID)` - List child agents
- `deleteAgent(agentDID)` - Remove agent

### DelegationChainValidator

Validates delegation chains and ensures proper authorization flow.

**Key Methods:**
- `validateChain(targetAgentDID, serviceDID)` - Validate complete chain
- `buildChain(targetAgentDID)` - Build delegation chain
- `validateSignatures(chain)` - Verify cryptographic signatures

### CommunicationManager

Handles secure inter-agent communication.

**Key Methods:**
- `requestDelegation(targetDID, scopes, options)` - Request delegation
- `sendMessage(message)` - Send secure message
- `pingAgent(targetDID)` - Test agent connectivity

### CascadingRevocationManager

Manages agent revocation with cascading support.

**Key Methods:**
- `revokeAgent(request)` - Revoke agent (with optional cascade)
- `isAgentRevoked(agentDID, serviceDID?)` - Check revocation status
- `getRevocationAudit(agentDID?)` - Get audit trail

## Examples

### Basic Delegation

See [basic delegation example](../examples/agent-to-agent-delegation-example.ts) for a complete walkthrough.

### Multi-Level Hierarchies

See [multi-level delegation example](../examples/multi-level-delegation-example.ts) for corporate hierarchy patterns.

### Cross-Service Delegation

See [cross-service example](../examples/cross-service-delegation-example.ts) for multi-service access patterns.

### Revocation Scenarios

See [revocation scenarios example](../examples/revocation-scenarios-example.ts) for comprehensive revocation testing.

## Integration Guides

### Framework Integrations

See [integration examples](../examples/integration-examples.ts) for:
- LangChain AI agent workflows
- Express.js API integration
- WebSocket real-time communication
- React frontend components
- OpenAI function calling

## Best Practices

See [delegation best practices guide](./delegation-best-practices.md) for:
- Security principles
- Delegation design patterns
- Scope management strategies
- Performance optimization
- Testing approaches

## Security Considerations

See [security considerations document](./delegation-security-considerations.md) for:
- Threat models and attack vectors
- Cryptographic security measures
- Access control strategies
- Incident response procedures

## API Reference

See [complete API reference](./agent-to-agent-delegation-api.md) for detailed documentation of all classes, methods, and interfaces.

## Monitoring and Analytics

The system includes comprehensive monitoring capabilities:

```typescript
import { RevocationMonitoringDashboard, EnhancedAuditTrail } from 'anon-identity';

// Set up monitoring
const auditTrail = new EnhancedAuditTrail(activityLogger);
const dashboard = new RevocationMonitoringDashboard(
  auditTrail, 
  revocationManager, 
  agentManager, 
  activityLogger
);

// Get real-time metrics
const metrics = await dashboard.getMetrics();
console.log('System health:', metrics.realTime.systemHealth);
console.log('Active agents:', metrics.realTime.activeAgents);

// Generate compliance report
const report = auditTrail.generateComplianceReport({
  start: new Date(Date.now() - 24 * 60 * 60 * 1000),
  end: new Date()
});
```

## Configuration

### Policy Configuration

```typescript
import { DelegationPolicyEngine } from 'anon-identity';

const policyEngine = new DelegationPolicyEngine(agentManager);

// Use built-in policies
const policy = policyEngine.getBuiltInPolicy('high-security');

// Or create custom policy
const customPolicy = {
  name: 'custom-policy',
  maxDelegationDepth: 2,
  allowedServices: ['email-service', 'calendar-service'],
  maxScopes: 5,
  scopeReduction: { strategy: 'intersection' },
  constraints: [
    { type: 'time_limit', value: { business_hours_only: true } }
  ]
};
```

### Communication Configuration

```typescript
import { CommunicationManager, DirectChannel, WebSocketChannel } from 'anon-identity';

const commManager = new CommunicationManager(
  agentIdentity,
  agentManager,
  delegationManager,
  policyEngine,
  activityLogger,
  {
    maxRetries: 3,
    retryDelay: 1000,
    timeout: 30000
  }
);

// Add communication channels
commManager.addChannel(new DirectChannel('local'));
commManager.addChannel(new WebSocketChannel('ws://localhost:8080', {
  autoReconnect: true,
  heartbeatInterval: 30000
}));
```

## Troubleshooting

### Common Issues

1. **Delegation Depth Exceeded**
   ```typescript
   // Check current depth
   const agent = agentManager.getAgent(agentDID);
   console.log(`Current depth: ${agent.delegationDepth}/${agent.maxDelegationDepth}`);
   
   // Increase max depth if needed
   agent.maxDelegationDepth = 5;
   ```

2. **Chain Validation Failed**
   ```typescript
   const result = await chainValidator.validateChain(agentDID, serviceDID);
   if (!result.valid) {
     console.log('Validation errors:', result.errors);
     console.log('Warnings:', result.warnings);
   }
   ```

3. **Scope Inheritance Issues**
   ```typescript
   // Check parent scopes
   const parentAgent = agentManager.getAgent(parentDID);
   const parentCredentials = agentManager.getDelegationCredentials(parentDID);
   const parentScopes = parentCredentials.flatMap(cred => cred.credentialSubject.scopes);
   
   // Verify requested scopes are subset of parent scopes
   const validScopes = requestedScopes.filter(scope => parentScopes.includes(scope));
   ```

### Debug Mode

Enable debug logging for detailed information:

```typescript
process.env.DEBUG = 'anon-identity:delegation:*';
```

## Performance Considerations

- Use caching for delegation chain validation
- Implement batch operations for multiple agent creation
- Monitor memory usage with large agent hierarchies
- Consider async processing for revocation cascades

## Limitations

- Maximum delegation depth: 10 levels (configurable)
- Chain validation cache TTL: 30 minutes (configurable)
- Communication message size limit: 1MB
- Concurrent revocation limit: 100 agents

## Migration Guide

When upgrading to the delegation system:

1. Existing agent identities remain compatible
2. Add delegation capabilities to existing agents:
   ```typescript
   agent.canDelegate = true;
   agent.maxDelegationDepth = 3;
   agent.delegationDepth = 0;
   ```
3. Update service providers to support chain validation
4. Implement proper error handling for delegation operations

## Contributing

To contribute to the delegation system:

1. Follow the existing code patterns
2. Add comprehensive tests for new features
3. Update documentation for API changes
4. Ensure security reviews for delegation logic

For questions or issues, see the main project documentation or create an issue in the repository.