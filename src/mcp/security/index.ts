/**
 * MCP Security Module Exports
 * 
 * Consolidates all security components for the MCP system
 */

export { CredentialManager } from './credential-manager';
export type {
  Credential,
  CredentialValidationResult,
  CredentialRotationResult
} from './credential-manager';

export { AuthManager } from './auth-manager';
export type {
  AuthToken,
  AuthenticationResult,
  AuthorizationResult
} from './auth-manager';

export { AuditLogger, AuditEventType } from './audit-logger';
export type {
  AuditLogEntry,
  AuditQueryOptions,
  AuditStatistics,
  ComplianceReport
} from './audit-logger';

export { RateLimiterManager, RateLimitWindow } from './rate-limiter';
export type {
  RateLimitRule,
  Quota,
  RateLimitResult,
  QuotaStatus
} from './rate-limiter';

/**
 * Security configuration builder
 */
export class SecurityConfigBuilder {
  private credentialConfig: any = {
    storage: 'memory',
    encryption: true,
    rotation: {
      enabled: false,
      interval: 30 * 24 * 60 * 60 * 1000, // 30 days
      retentionCount: 3
    },
    validation: {
      validateOnLoad: true,
      validateOnUse: false,
      cacheValidation: true
    }
  };

  private authConfig: any = {
    method: 'api_key',
    tokenExpiration: 3600000, // 1 hour
    refreshTokenExpiration: 86400000, // 24 hours
    multiFactorEnabled: false,
    sessionTimeout: 1800000 // 30 minutes
  };

  private authzConfig: any = {
    enableRBAC: true,
    enableABAC: false,
    defaultDeny: true,
    agentPermissions: new Map(),
    resourceAccess: {
      rules: [],
      defaultAction: 'deny'
    }
  };

  private auditConfig: any = {
    enabled: true,
    logAllRequests: true,
    logResponses: false,
    logSensitiveData: false,
    retentionPeriod: 90 * 24 * 60 * 60 * 1000, // 90 days
    exportFormat: ['json']
  };

  /**
   * Enable credential encryption
   */
  withEncryption(enabled = true): this {
    this.credentialConfig.encryption = enabled;
    return this;
  }

  /**
   * Enable credential rotation
   */
  withRotation(interval: number, retentionCount = 3): this {
    this.credentialConfig.rotation = {
      enabled: true,
      interval,
      retentionCount
    };
    return this;
  }

  /**
   * Set authentication method
   */
  withAuthentication(method: string, tokenExpiration?: number): this {
    this.authConfig.method = method;
    if (tokenExpiration) {
      this.authConfig.tokenExpiration = tokenExpiration;
    }
    return this;
  }

  /**
   * Enable MFA
   */
  withMFA(enabled = true): this {
    this.authConfig.multiFactorEnabled = enabled;
    return this;
  }

  /**
   * Enable RBAC
   */
  withRBAC(enabled = true): this {
    this.authzConfig.enableRBAC = enabled;
    return this;
  }

  /**
   * Enable ABAC
   */
  withABAC(enabled = true): this {
    this.authzConfig.enableABAC = enabled;
    return this;
  }

  /**
   * Set default deny policy
   */
  withDefaultDeny(enabled = true): this {
    this.authzConfig.defaultDeny = enabled;
    return this;
  }

  /**
   * Enable audit logging
   */
  withAuditLogging(config: {
    logAllRequests?: boolean;
    logResponses?: boolean;
    logSensitiveData?: boolean;
    retentionPeriod?: number;
  }): this {
    Object.assign(this.auditConfig, config);
    return this;
  }

  /**
   * Build security configuration
   */
  build(): {
    credentialConfig: any;
    authConfig: any;
    authzConfig: any;
    auditConfig: any;
  } {
    return {
      credentialConfig: this.credentialConfig,
      authConfig: this.authConfig,
      authzConfig: this.authzConfig,
      auditConfig: this.auditConfig
    };
  }
}

/**
 * Create a pre-configured security setup for development
 */
export function createDevelopmentSecurity() {
  return new SecurityConfigBuilder()
    .withEncryption(false)
    .withAuthentication('api_key')
    .withRBAC(true)
    .withDefaultDeny(false)
    .withAuditLogging({
      logAllRequests: true,
      logResponses: true,
      logSensitiveData: true,
      retentionPeriod: 7 * 24 * 60 * 60 * 1000 // 7 days
    })
    .build();
}

/**
 * Create a pre-configured security setup for production
 */
export function createProductionSecurity() {
  return new SecurityConfigBuilder()
    .withEncryption(true)
    .withRotation(30 * 24 * 60 * 60 * 1000) // 30 days
    .withAuthentication('oauth2', 3600000) // 1 hour
    .withMFA(true)
    .withRBAC(true)
    .withABAC(true)
    .withDefaultDeny(true)
    .withAuditLogging({
      logAllRequests: true,
      logResponses: false,
      logSensitiveData: false,
      retentionPeriod: 90 * 24 * 60 * 60 * 1000 // 90 days
    })
    .build();
}