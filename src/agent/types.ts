export interface AgentConfig {
  name: string;
  description: string;
  maxValidityPeriod?: number; // milliseconds
  maxDelegationDepth?: number;
  canDelegate?: boolean;
}

export interface AgentIdentity {
  did: string;
  name: string;
  description: string;
  parentDID: string;
  createdAt: Date;
  keyPair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
  maxDelegationDepth?: number;
  delegationDepth: number;
  canDelegate: boolean;
  delegatedBy?: string; // DID of the delegating agent (if applicable)
}

export interface AccessGrant {
  serviceDID: string;
  scopes: string[];
  constraints?: Record<string, any>;
  expiresAt: Date;
}

export interface DelegationCredential {
  '@context': string[];
  type: string[];
  id: string;
  issuer: string;
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: {
    id: string;
    parentDID: string;
    name: string;
    scopes: string[];
    services: {
      [serviceDID: string]: {
        scopes: string[];
        constraints?: any;
      };
    };
    validFrom: string;
    validUntil: string;
    delegationDepth?: number;
    maxDelegationDepth?: number;
    canDelegate?: boolean;
  };
  proof?: any;
}

export interface ScopeDefinition {
  id: string;
  name: string;
  description: string;
  category: string;
  riskLevel: 'low' | 'medium' | 'high';
  dependencies?: string[];
}

export interface ServiceManifest {
  serviceDID: string;
  name: string;
  description?: string;
  requiredScopes: ScopeDefinition[];
  optionalScopes?: ScopeDefinition[];
}

export interface AgentValidation {
  isValid: boolean;
  agentDID?: string;
  parentDID?: string;
  grantedScopes?: string[];
  errors?: string[];
}

export interface PresentationOptions {
  serviceDID: string;
  challenge: string;
  scopes?: string[];
}

// Agent-to-Agent Delegation Types

export interface AgentDelegationOptions {
  maxDepth?: number;
  scopeReduction?: ScopeReductionPolicy;
  expirationPolicy?: ExpirationPolicy;
  auditLevel?: 'basic' | 'detailed' | 'comprehensive';
}

export interface DelegationChain {
  agents: AgentIdentity[];
  credentials: DelegationCredential[];
  maxDepth: number;
  currentDepth: number;
}

export interface ScopeReductionPolicy {
  strategy: 'intersection' | 'subset' | 'custom';
  customReducer?: (parentScopes: string[], requestedScopes: string[]) => string[];
}

export interface ExpirationPolicy {
  strategy: 'inherit' | 'fixed' | 'reduced';
  fixedDuration?: number; // milliseconds
  reductionFactor?: number; // 0-1, reduces parent's remaining time
}

export interface SubAgentConfig extends AgentConfig {
  parentAgentDID: string;
  delegationOptions?: AgentDelegationOptions;
  requestedScopes?: string[];
}

export interface DelegationContext {
  parentAgent: AgentIdentity;
  childAgent?: Partial<AgentIdentity>;
  requestedScopes: string[];
  serviceDID?: string;
  metadata?: Record<string, any>;
}