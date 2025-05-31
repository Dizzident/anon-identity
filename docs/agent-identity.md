# Agent Sub-Identity Documentation

## Overview

The Agent Sub-Identity feature allows users to create delegated identities for AI agents and automated systems. These sub-identities operate with limited, scoped permissions granted by the parent identity owner, enabling secure delegation of tasks while maintaining control and revocability.

## Key Concepts

### Agent Identity
A derived identity created by a user that can act on their behalf within defined boundaries. Each agent has:
- Its own DID (Decentralized Identifier)
- A unique key pair for cryptographic operations
- A parent-child relationship with the creating user
- Scoped permissions for specific services

### Delegation Credentials
Special Verifiable Credentials that grant agents authority to act on behalf of users. They contain:
- Agent and parent DIDs
- Granted scopes (permissions)
- Service-specific access rights
- Expiration times
- Cryptographic proof from the parent identity

### Scopes
Fine-grained permissions following the format `action:resource:constraint`. Examples:
- `read:profile:basic` - Read basic profile information
- `write:posts:own` - Write posts owned by the user
- `execute:payments:limit:100` - Execute payments up to $100

## Getting Started

### Creating an Agent

```typescript
import { UserWallet } from 'anon-identity';

// Create or restore a user wallet
const userWallet = await UserWallet.create();

// Create an agent
const agent = await userWallet.createAgent({
  name: 'Shopping Assistant',
  description: 'AI agent for online shopping tasks',
  maxValidityPeriod: 30 * 24 * 60 * 60 * 1000 // 30 days
});

console.log(`Agent DID: ${agent.did}`);
```

### Granting Agent Access

```typescript
// Grant agent access to a service with specific scopes
const delegationCredential = await userWallet.grantAgentAccess(agent.did, {
  serviceDID: 'did:key:shopping-service',
  scopes: [
    'read:products:all',
    'write:cart:add',
    'execute:payments:limit:100'
  ],
  constraints: {
    maxPurchaseAmount: 100,
    requireApprovalAbove: 50
  },
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
});
```

### Service Provider Integration

Services need to be updated to support agent validation:

```typescript
import { AgentEnabledServiceProvider, ServiceManifestBuilder } from 'anon-identity';

// Define service requirements
const manifest = new ServiceManifestBuilder(
  'did:key:my-service',
  'E-Commerce Platform'
)
  .addRequiredScope('read:profile:basic')
  .addRequiredScope('read:products:all')
  .addOptionalScope('write:cart:add')
  .addOptionalScope('execute:payments:limit:100')
  .build();

// Create agent-enabled service provider
const serviceProvider = new AgentEnabledServiceProvider(
  'E-Commerce Platform',
  'did:key:my-service',
  ['did:key:trusted-issuer'],
  { serviceManifest: manifest }
);
```

### Agent Authentication Flow

1. **Agent requests access**: The agent presents its delegation credential to the service
2. **Service validates**: The service checks the credential signature, scopes, and revocation status
3. **Session created**: If valid, the service creates a session with the granted scopes
4. **Scoped operations**: The agent can only perform operations allowed by its scopes

```typescript
// Agent creates presentation
const agentManager = userWallet.getAgentManager();
const presentation = await agentManager.createPresentation(agent.did, {
  serviceDID: 'did:key:service',
  challenge: 'service-challenge-123'
});

// Service verifies presentation
const result = await serviceProvider.verifyPresentation(presentation);

if (result.valid) {
  // Check specific permissions
  const canAddToCart = serviceProvider.hasScope(agent.did, 'write:cart:add');
  const canPurchase = serviceProvider.hasScope(agent.did, 'execute:payments:limit:100');
}
```

## Scope System

### Scope Format

Scopes follow a hierarchical structure:
```
action:resource[:constraint[:value]]
```

### Predefined Scopes

#### Profile Scopes
- `read:profile:basic` - Read basic profile (name, public info)
- `read:profile:full` - Read complete profile including sensitive data
- `write:profile:basic` - Update basic profile information

#### Data Scopes
- `read:data:own` - Read data created by this agent
- `read:data:all` - Read all user data
- `write:data:create` - Create new data entries
- `write:data:update:own` - Update own data
- `delete:data:own` - Delete own data

#### Action Scopes
- `execute:transactions:read` - View transaction history
- `execute:transactions:create` - Create transactions
- `execute:payments:limit:N` - Execute payments up to N amount

#### Admin Scopes
- `admin:agents:read` - View other agents
- `admin:agents:manage` - Create/update/delete other agents

### Custom Scopes

Services can define custom scopes:

```typescript
import { ScopeRegistry } from 'anon-identity';

const registry = ScopeRegistry.getInstance();

registry.registerScope({
  id: 'custom:feature:access',
  name: 'Custom Feature Access',
  description: 'Access to proprietary feature X',
  category: 'actions',
  riskLevel: 'medium',
  dependencies: ['read:profile:basic']
});
```

## Revocation

### Revoking Agent Access

```typescript
// Revoke access to specific service
await userWallet.revokeAgentAccess(agent.did, 'did:key:service');

// Revoke all agent access
await userWallet.revokeAgentAccess(agent.did);

// Complete agent removal
await userWallet.revokeAgent(agent.did);
```

### Revocation Service Integration

```typescript
import { AgentRevocationService } from 'anon-identity';

const revocationService = new AgentRevocationService(keyPair, issuerDID);

// Service provider checks revocation
const serviceProvider = new AgentEnabledServiceProvider(
  'My Service',
  'did:key:service',
  trustedIssuers,
  { agentRevocationService: revocationService }
);
```

## Security Considerations

### Time-Based Security
- All delegations have expiration times
- No permanent agent access by default
- Regular re-authorization required

### Principle of Least Privilege
- Grant minimal necessary permissions
- Use specific scopes rather than broad access
- Review and audit agent permissions regularly

### Revocation Mechanisms
- Immediate revocation capability
- Service-specific or complete revocation
- Revocation lists checked on every validation

### Audit Trail
- All agent actions should be logged
- Parent identity can review agent activity
- Services maintain agent action history

## Best Practices

### For Users
1. **Regular Review**: Periodically review agent permissions
2. **Short Expiration**: Use short expiration times for sensitive operations
3. **Minimal Scopes**: Only grant necessary scopes
4. **Monitor Activity**: Check agent activity logs

### For Services
1. **Clear Scope Definitions**: Provide clear descriptions of required scopes
2. **Validate Always**: Check credentials and revocation on every request
3. **Audit Logging**: Log all agent operations with agent DID
4. **Risk Assessment**: Evaluate risk levels for different scopes

### For Developers
1. **Error Handling**: Handle revocation and expiration gracefully
2. **Scope Dependencies**: Declare and check scope dependencies
3. **Testing**: Test with expired and revoked credentials
4. **Documentation**: Document all custom scopes clearly

## Example Use Cases

### Personal Assistant Agent
```typescript
const assistant = await wallet.createAgent({
  name: 'Personal Assistant',
  description: 'Manages calendar and tasks'
});

await wallet.grantAgentAccess(assistant.did, {
  serviceDID: 'did:key:calendar-service',
  scopes: ['read:events:all', 'write:events:create'],
  expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
});
```

### Research Agent
```typescript
const researcher = await wallet.createAgent({
  name: 'Research Bot',
  description: 'Gathers and analyzes data'
});

await wallet.grantAgentAccess(researcher.did, {
  serviceDID: 'did:key:data-service',
  scopes: ['read:documents:public', 'read:analytics:aggregate'],
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
});
```

### Shopping Agent
```typescript
const shopper = await wallet.createAgent({
  name: 'Shopping Assistant',
  description: 'Helps with online purchases'
});

await wallet.grantAgentAccess(shopper.did, {
  serviceDID: 'did:key:store-service',
  scopes: ['read:products:all', 'write:cart:add', 'execute:purchase:limit:50'],
  constraints: {
    maxPurchaseAmount: 50,
    requireApprovalAbove: 25
  },
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
});
```

## API Reference

### UserWallet Extensions

```typescript
interface UserWallet {
  // Create a new agent
  createAgent(config: AgentConfig): Promise<AgentIdentity>;
  
  // Grant agent access to a service
  grantAgentAccess(agentDID: string, grant: AccessGrant): Promise<DelegationCredential>;
  
  // List all agents
  listAgents(): AgentIdentity[];
  
  // Get agent access details
  getAgentAccess(agentDID: string): AccessGrant[];
  
  // Revoke agent access
  revokeAgentAccess(agentDID: string, serviceDID?: string): Promise<void>;
  
  // Complete agent revocation
  revokeAgent(agentDID: string): Promise<void>;
}
```

### AgentEnabledServiceProvider

```typescript
class AgentEnabledServiceProvider extends ServiceProvider {
  // Get service manifest
  getServiceManifest(): ServiceManifest;
  
  // Validate agent presentation
  validateAgent(presentation: VerifiablePresentation, requiredScopes: string[]): Promise<AgentValidation>;
  
  // Check agent scope
  hasScope(agentDID: string, scope: string): boolean;
  
  // Get all agent scopes
  getAgentScopes(agentDID: string): string[];
}
```

## Migration Guide

### For Existing Services

1. **Update Dependencies**: Install latest version with agent support
2. **Define Scopes**: Create service manifest with required scopes
3. **Update Provider**: Switch to AgentEnabledServiceProvider
4. **Test Integration**: Test with agent presentations
5. **Deploy**: Roll out with backwards compatibility

### Example Migration

```typescript
// Before
const provider = new ServiceProvider('My Service', trustedIssuers);

// After
const manifest = ServiceManifestBuilder.createBasicReadService(
  'did:key:my-service',
  'My Service'
);

const provider = new AgentEnabledServiceProvider(
  'My Service',
  'did:key:my-service',
  trustedIssuers,
  { serviceManifest: manifest }
);
```

## Troubleshooting

### Common Issues

1. **"Agent not found"**: Ensure agent was created and not deleted
2. **"Insufficient permissions"**: Check granted scopes match requirements
3. **"Credential expired"**: Delegation credentials have time limits
4. **"Agent revoked"**: Check revocation status with revocation service

### Debugging Tips

```typescript
// Check agent status
const agents = wallet.listAgents();
console.log('Active agents:', agents);

// Check granted access
const access = wallet.getAgentAccess(agentDID);
console.log('Agent access:', access);

// Check service requirements
const manifest = serviceProvider.getServiceManifest();
console.log('Required scopes:', manifest.requiredScopes);

// Validate scopes
const validation = serviceProvider.validateScopeRequirements(grantedScopes);
console.log('Missing scopes:', validation.missingRequired);
```