# Agent Sub-Identity Feature Plan

## Implementation Status: ✅ COMPLETED

All phases have been successfully implemented. The agent sub-identity feature is now fully functional with:
- Core agent identity management
- Comprehensive scope system  
- Service provider integration
- Revocation mechanisms
- Complete documentation and examples

## Overview

This document outlines the plan for implementing sub-identities for LLM agents within the Anonymous Identity Framework. The feature allows users to create delegated identities for AI agents with specific scoped permissions, enabling agents to act on behalf of users within defined boundaries.

## Core Requirements

- **Sub-Identity Creation**: Users can create agent identities derived from their main identity
- **Scoped Access Control**: Fine-grained permissions defining what agents can do
- **Service Authorization**: Agents must be explicitly granted access to each service
- **Revocation**: Instant revocation of agent access by the identity owner
- **Scope Transparency**: Services clearly present required scopes with descriptions
- **Third-Party Compatibility**: Standardized scope format for easy adoption

## Architecture Overview

The system extends the existing identity framework with:

1. **Agent Identities**: Derived sub-identities with limited scope
2. **Scope Management**: Granular permission system
3. **Delegation Credentials**: Special VCs that grant agent authority
4. **Revocation Support**: Instant revocation of agent access

## Scope Permission Format

### Structure

```typescript
interface ScopeDefinition {
  id: string;              // Unique identifier (e.g., "read:profile")
  name: string;            // Human-readable name
  description: string;     // Detailed explanation
  category: string;        // Grouping (e.g., "profile", "data", "actions")
  riskLevel: "low" | "medium" | "high";
  dependencies?: string[]; // Other required scopes
}
```

### Naming Convention

Scopes follow the pattern: `action:resource:constraint`

Examples:
- `read:profile:basic` - Read basic profile information
- `write:posts:own` - Write posts owned by the user
- `execute:payments:limit:100` - Execute payments up to $100
- `delete:data:temporary` - Delete temporary data only

### Categories

- **profile**: User profile and identity information
- **data**: User-generated content and data
- **actions**: Executable operations (payments, posts, etc.)
- **admin**: Administrative functions
- **analytics**: Usage and analytics data

## Core Components

### Agent Identity Manager (`src/agent/`)

- **agent-identity.ts**
  - Agent DID creation and management
  - Agent metadata storage
  - Parent-child relationship tracking

- **delegation-manager.ts**
  - Create delegation credentials
  - Revoke delegations
  - Manage delegation lifecycle

- **scope-registry.ts**
  - Register available scopes
  - Validate scope combinations
  - Manage scope dependencies

### Delegation Credential Structure

```typescript
interface DelegationCredential {
  "@context": string[];
  type: ["VerifiableCredential", "DelegationCredential"];
  issuer: string;           // Parent identity DID
  credentialSubject: {
    id: string;             // Agent DID
    parentDID: string;      // Parent identity DID
    name: string;           // Agent name
    scopes: string[];       // Granted scopes
    services: {             // Service-specific permissions
      [serviceDID: string]: {
        scopes: string[];
        constraints?: any;
      }
    };
    validFrom: string;      // ISO 8601 timestamp
    validUntil: string;     // ISO 8601 timestamp
  };
  proof: any;               // Parent identity signature
}
```

### Service Integration Components

- **scope-validator.ts**
  - Validate agent permissions against required scopes
  - Check delegation credential validity
  - Verify parent identity signatures

- **service-manifest.ts**
  - Define service required scopes
  - Describe scope purposes
  - Specify minimum permission sets

## Implementation Flow

### 1. Agent Creation

```typescript
// User creates an agent sub-identity
const agent = await userWallet.createAgent({
  name: "My AI Assistant",
  description: "Personal task automation agent",
  maxValidityPeriod: 30 * 24 * 60 * 60 * 1000 // 30 days
});
```

### 2. Service Authorization

```typescript
// Service presents required scopes
const serviceManifest = {
  serviceDID: "did:key:service123",
  name: "Task Management Service",
  requiredScopes: [
    {
      id: "read:tasks:all",
      name: "Read All Tasks",
      description: "View all tasks in your account",
      riskLevel: "low"
    },
    {
      id: "write:tasks:create",
      name: "Create Tasks",
      description: "Create new tasks on your behalf",
      riskLevel: "medium"
    }
  ],
  optionalScopes: [
    {
      id: "delete:tasks:own",
      name: "Delete Tasks",
      description: "Delete tasks created by this agent",
      riskLevel: "medium"
    }
  ]
};

// User reviews and grants specific scopes
await userWallet.grantAgentAccess(agent.did, {
  serviceDID: serviceManifest.serviceDID,
  scopes: ["read:tasks:all", "write:tasks:create"],
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
});
```

### 3. Agent Authentication

```typescript
// Agent presents delegation credential to service
const agentPresentation = await agent.createPresentation({
  serviceDID: "did:key:service123",
  challenge: serviceChallenge
});

// Service validates agent permissions
const validation = await serviceProvider.validateAgent(
  agentPresentation,
  ["read:tasks:all", "write:tasks:create"]
);

if (validation.isValid) {
  // Grant access with scope restrictions
  const session = await service.createAgentSession({
    agentDID: validation.agentDID,
    parentDID: validation.parentDID,
    scopes: validation.grantedScopes
  });
}
```

### 4. Revocation

```typescript
// Revoke specific service access
await userWallet.revokeAgentAccess(agent.did, {
  serviceDID: "did:key:service123"
});

// Revoke entire agent
await userWallet.revokeAgent(agent.did);
```

## API Design

### UserWallet Extensions

```typescript
interface UserWallet {
  // Create a new agent identity
  createAgent(config: AgentConfig): Promise<AgentIdentity>;
  
  // Grant agent access to a service
  grantAgentAccess(agentDID: string, grant: AccessGrant): Promise<DelegationCredential>;
  
  // List all agents
  listAgents(): Promise<AgentIdentity[]>;
  
  // Get agent access details
  getAgentAccess(agentDID: string): Promise<AccessGrant[]>;
  
  // Revoke agent access
  revokeAgentAccess(agentDID: string, serviceDID?: string): Promise<void>;
  
  // Complete agent revocation
  revokeAgent(agentDID: string): Promise<void>;
}
```

### ServiceProvider Extensions

```typescript
interface ServiceProvider {
  // Present service manifest
  getServiceManifest(): ServiceManifest;
  
  // Validate agent presentation
  validateAgent(
    presentation: VerifiablePresentation,
    requiredScopes: string[]
  ): Promise<AgentValidation>;
  
  // Check specific scope
  hasScope(agentDID: string, scope: string): boolean;
  
  // Get agent's granted scopes
  getAgentScopes(agentDID: string): string[];
}
```

### Agent API

```typescript
interface AgentIdentity {
  did: string;
  name: string;
  description: string;
  parentDID: string;
  createdAt: Date;
  
  // Create presentation for service
  createPresentation(options: PresentationOptions): Promise<VerifiablePresentation>;
  
  // Get current access grants
  getAccessGrants(): Promise<AccessGrant[]>;
  
  // Check if agent has access to service
  hasServiceAccess(serviceDID: string): boolean;
}
```

## Security Considerations

### Principle of Least Privilege
- Agents receive minimal necessary permissions
- Scopes are granular and specific
- Default deny for unspecified actions

### Time-Based Security
- All delegations have expiration times
- No permanent agent access
- Regular re-authorization required

### Revocation Mechanisms
- Immediate revocation capability
- Revocation list checked on every validation
- Parent identity maintains full control

### Audit Trail
- All agent actions logged with agent DID
- Parent identity can review agent activity
- Services maintain agent action history

### Cryptographic Security
- Delegation credentials signed by parent identity
- Agent has separate key pair
- Cannot escalate beyond granted permissions

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2) ✅ COMPLETED
- ✅ Implement agent identity creation
- ✅ Basic delegation credential structure
- ✅ Parent-child DID relationship
- ✅ AgentIdentityManager implementation
- ✅ DelegationManager implementation
- ✅ UserWallet agent methods
- ✅ Comprehensive unit tests

### Phase 2: Scope System (Week 2-3) ✅ COMPLETED
- ✅ Implement scope registry with default scopes
- ✅ Define standard scope format (action:resource:constraint)
- ✅ Create scope validation logic
- ✅ Implement scope validator with hierarchy support
- ✅ Create service manifest builder and validator
- ✅ Add comprehensive scope tests
- ✅ Export components in main entry points

### Phase 3: Service Integration (Week 3-4) ✅ COMPLETED
- ✅ Extend ServiceProvider for agent support (AgentEnabledServiceProvider)
- ✅ Implement service manifest system integration
- ✅ Add agent validation methods
- ✅ Implement scope checking for agents
- ✅ Add agent session management
- ✅ Create comprehensive tests
- ✅ Build example demonstrating agent functionality

### Phase 4: Revocation System (Week 4-5) ✅ COMPLETED
- ✅ Implement revocation mechanisms (AgentRevocationService)
- ✅ Integrate with existing revocation service
- ✅ Add revocation list checking in service provider
- ✅ Support agent-level and service-level revocation
- ✅ Add restore functionality
- ✅ Include revocation statistics and export/import
- ✅ Comprehensive revocation tests

### Phase 5: Testing & Documentation (Week 5-6) ✅ COMPLETED
- ✅ Comprehensive test suite (unit and integration tests)
- ✅ API documentation (agent-identity.md)
- ✅ Integration examples (agent-example.ts)
- ✅ Migration guide for services (included in documentation)
- ✅ Updated main documentation to include agent features

## Example Use Cases

### Personal Assistant Agent
```typescript
const assistant = await wallet.createAgent({
  name: "Personal Assistant",
  description: "Helps manage daily tasks"
});

// Grant calendar access
await wallet.grantAgentAccess(assistant.did, {
  serviceDID: "did:key:calendar-service",
  scopes: ["read:events:all", "write:events:create"],
  expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
});
```

### Research Agent
```typescript
const researcher = await wallet.createAgent({
  name: "Research Bot",
  description: "Gathers and analyzes data"
});

// Grant read-only access to documents
await wallet.grantAgentAccess(researcher.did, {
  serviceDID: "did:key:document-service",
  scopes: ["read:documents:public", "read:analytics:aggregate"],
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
});
```

### Shopping Agent
```typescript
const shopper = await wallet.createAgent({
  name: "Shopping Assistant",
  description: "Helps find and purchase items"
});

// Grant limited purchase ability
await wallet.grantAgentAccess(shopper.did, {
  serviceDID: "did:key:shopping-service",
  scopes: ["read:products:all", "write:cart:add", "execute:purchase:limit:50"],
  constraints: {
    maxPurchaseAmount: 50,
    requireApprovalAbove: 25
  },
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
});
```

## Migration Path for Existing Services

1. **Add Scope Definitions**: Define required scopes for service operations
2. **Implement Manifest**: Create service manifest with scope descriptions
3. **Update Validation**: Extend credential validation to check delegations
4. **Add Scope Checking**: Implement scope-based access control
5. **Test Integration**: Verify agent access works correctly

## Success Metrics

- Agent creation and delegation in < 2 seconds
- Scope validation in < 100ms
- Zero security breaches from agent misuse
- 90% of services adopt within 6 months
- User satisfaction > 4.5/5 for agent control

## Future Enhancements

- Multi-signature requirements for high-risk scopes
- Agent-to-agent delegation (with depth limits)
- Behavioral analysis for anomaly detection
- Scope templates for common use cases
- Integration with AI model providers