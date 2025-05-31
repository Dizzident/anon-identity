export interface AgentConfig {
  name: string;
  description: string;
  maxValidityPeriod?: number; // milliseconds
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