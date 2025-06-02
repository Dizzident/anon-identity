/**
 * Authentication and Authorization Manager for MCP
 * 
 * Handles authentication, authorization, and access control for LLM interactions
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import {
  AuthenticationConfig,
  AuthorizationConfig,
  AuthenticationMethod,
  Permission,
  AccessControlList,
  AccessRule,
  AccessAction,
  PolicyCondition,
  MCPError,
  MCPErrorCode,
  LLMRequest,
  RequestMetadata
} from '../types';
import { AgentIdentity } from '../../agent/types';
import { AgentIdentityManager } from '../../agent/agent-identity';
import { DelegationCredential } from '../../agent/types';

/**
 * Authentication token
 */
export interface AuthToken {
  id: string;
  agentDID: string;
  sessionId: string;
  method: AuthenticationMethod;
  issuedAt: Date;
  expiresAt: Date;
  refreshToken?: string;
  refreshExpiresAt?: Date;
  metadata?: {
    ip?: string;
    userAgent?: string;
    deviceId?: string;
  };
}

/**
 * Authentication result
 */
export interface AuthenticationResult {
  authenticated: boolean;
  token?: AuthToken;
  error?: string;
  requiresMFA?: boolean;
}

/**
 * Authorization result
 */
export interface AuthorizationResult {
  authorized: boolean;
  permissions?: Permission[];
  deniedReasons?: string[];
  conditions?: PolicyCondition[];
}

/**
 * Session data
 */
interface Session {
  id: string;
  agentDID: string;
  token: AuthToken;
  permissions: Permission[];
  lastActivity: Date;
  requestCount: number;
}

/**
 * Authentication and Authorization Manager
 */
export class AuthManager extends EventEmitter {
  private sessions: Map<string, Session> = new Map();
  private tokens: Map<string, AuthToken> = new Map();
  private jwtSecret: string;
  private sessionTimeouts: Map<string, NodeJS.Timeout> = new Map();
  private failedAttempts: Map<string, number> = new Map();
  private blacklist: Set<string> = new Set();

  constructor(
    private authConfig: AuthenticationConfig,
    private authzConfig: AuthorizationConfig,
    private agentManager?: AgentIdentityManager
  ) {
    super();
    
    // Initialize JWT secret
    this.jwtSecret = process.env.MCP_JWT_SECRET || crypto.randomBytes(32).toString('hex');
    
    // Start session cleanup
    this.startSessionCleanup();
  }

  /**
   * Authenticate agent
   */
  async authenticate(
    agentDID: string,
    credentials: any,
    method: AuthenticationMethod = AuthenticationMethod.API_KEY
  ): Promise<AuthenticationResult> {
    // Check if agent is blacklisted
    if (this.blacklist.has(agentDID)) {
      return {
        authenticated: false,
        error: 'Agent is blacklisted'
      };
    }

    // Check failed attempts
    const attempts = this.failedAttempts.get(agentDID) || 0;
    if (attempts >= 5) {
      this.blacklist.add(agentDID);
      this.emit('security_alert', {
        type: 'excessive_failed_attempts',
        agentDID,
        attempts
      });
      return {
        authenticated: false,
        error: 'Too many failed attempts'
      };
    }

    try {
      let authenticated = false;
      let requiresMFA = false;

      switch (method) {
        case AuthenticationMethod.API_KEY:
          authenticated = await this.authenticateAPIKey(agentDID, credentials.apiKey);
          break;
        case AuthenticationMethod.JWT:
          authenticated = await this.authenticateJWT(agentDID, credentials.token);
          break;
        case AuthenticationMethod.OAUTH2:
          authenticated = await this.authenticateOAuth2(agentDID, credentials.accessToken);
          break;
        case AuthenticationMethod.CERTIFICATE:
          authenticated = await this.authenticateCertificate(agentDID, credentials.certificate);
          break;
        case AuthenticationMethod.DELEGATION:
          authenticated = await this.authenticateDelegation(agentDID, credentials.delegationCredential);
          break;
        default:
          throw new Error(`Unsupported authentication method: ${method}`);
      }

      if (!authenticated) {
        this.failedAttempts.set(agentDID, attempts + 1);
        return {
          authenticated: false,
          error: 'Invalid credentials'
        };
      }

      // Check if MFA is required
      if (this.authConfig.multiFactorEnabled) {
        requiresMFA = await this.checkMFARequired(agentDID, method);
        if (requiresMFA && !credentials.mfaCode) {
          return {
            authenticated: false,
            requiresMFA: true,
            error: 'MFA code required'
          };
        }

        if (requiresMFA) {
          const mfaValid = await this.validateMFA(agentDID, credentials.mfaCode);
          if (!mfaValid) {
            return {
              authenticated: false,
              error: 'Invalid MFA code'
            };
          }
        }
      }

      // Create authentication token
      const token = await this.createAuthToken(agentDID, method);
      
      // Clear failed attempts
      this.failedAttempts.delete(agentDID);

      this.emit('authentication_success', {
        agentDID,
        method,
        tokenId: token.id
      });

      return {
        authenticated: true,
        token
      };

    } catch (error) {
      this.emit('authentication_error', {
        agentDID,
        method,
        error: (error as Error).message
      });

      return {
        authenticated: false,
        error: (error as Error).message
      };
    }
  }

  /**
   * Authorize request
   */
  async authorize(
    agentDID: string,
    resource: string,
    action: string,
    context?: any
  ): Promise<AuthorizationResult> {
    // Check if authorization is enabled
    if (!this.authzConfig.enableRBAC && !this.authzConfig.enableABAC) {
      return { authorized: true };
    }

    const deniedReasons: string[] = [];
    
    // Get agent permissions
    const permissions = await this.getAgentPermissions(agentDID);
    
    // Check RBAC (Role-Based Access Control)
    if (this.authzConfig.enableRBAC) {
      const rbacResult = this.checkRBACPermission(permissions, resource, action);
      if (!rbacResult.authorized) {
        deniedReasons.push(`RBAC: ${rbacResult.reason}`);
      }
    }

    // Check ABAC (Attribute-Based Access Control)
    if (this.authzConfig.enableABAC) {
      const abacResult = await this.checkABACPermission(agentDID, resource, action, context);
      if (!abacResult.authorized) {
        deniedReasons.push(`ABAC: ${abacResult.reason}`);
      }
    }

    // Check ACL rules
    const aclResult = this.checkACLRules(agentDID, resource, action, context);
    if (!aclResult.authorized) {
      deniedReasons.push(`ACL: ${aclResult.reason}`);
    }

    // Final decision
    const authorized = deniedReasons.length === 0 || !this.authzConfig.defaultDeny;

    if (authorized) {
      this.emit('authorization_granted', {
        agentDID,
        resource,
        action
      });
    } else {
      this.emit('authorization_denied', {
        agentDID,
        resource,
        action,
        reasons: deniedReasons
      });
    }

    return {
      authorized,
      permissions: authorized ? permissions : undefined,
      deniedReasons: authorized ? undefined : deniedReasons
    };
  }

  /**
   * Validate token
   */
  async validateToken(tokenId: string): Promise<AuthToken | null> {
    const token = this.tokens.get(tokenId);
    
    if (!token) {
      return null;
    }

    // Check expiration
    if (token.expiresAt < new Date()) {
      this.tokens.delete(tokenId);
      return null;
    }

    return token;
  }

  /**
   * Refresh token
   */
  async refreshToken(refreshToken: string): Promise<AuthenticationResult> {
    try {
      // Decode and verify refresh token
      const decoded = jwt.verify(refreshToken, this.jwtSecret) as any;
      
      const oldToken = this.tokens.get(decoded.tokenId);
      if (!oldToken || oldToken.refreshToken !== refreshToken) {
        return {
          authenticated: false,
          error: 'Invalid refresh token'
        };
      }

      // Check refresh token expiration
      if (oldToken.refreshExpiresAt && oldToken.refreshExpiresAt < new Date()) {
        return {
          authenticated: false,
          error: 'Refresh token expired'
        };
      }

      // Create new token
      const newToken = await this.createAuthToken(oldToken.agentDID, oldToken.method);
      
      // Invalidate old token
      this.tokens.delete(oldToken.id);

      return {
        authenticated: true,
        token: newToken
      };

    } catch (error) {
      return {
        authenticated: false,
        error: 'Invalid refresh token'
      };
    }
  }

  /**
   * Create session for authenticated agent
   */
  async createSession(token: AuthToken): Promise<Session> {
    const permissions = await this.getAgentPermissions(token.agentDID);
    
    const session: Session = {
      id: token.sessionId,
      agentDID: token.agentDID,
      token,
      permissions,
      lastActivity: new Date(),
      requestCount: 0
    };

    this.sessions.set(session.id, session);
    
    // Setup session timeout
    this.setupSessionTimeout(session.id);

    return session;
  }

  /**
   * Get session
   */
  getSession(sessionId: string): Session | null {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      return null;
    }

    // Update activity
    session.lastActivity = new Date();
    session.requestCount++;
    
    // Reset timeout
    this.setupSessionTimeout(sessionId);

    return session;
  }

  /**
   * Authenticate API key
   */
  private async authenticateAPIKey(agentDID: string, apiKey: string): Promise<boolean> {
    // In production, this would validate against stored API keys
    // For now, we'll do a simple validation
    if (!apiKey || apiKey.length < 32) {
      return false;
    }

    // Validate agent exists
    if (this.agentManager) {
      const agent = await this.agentManager.getAgent(agentDID);
      if (!agent) {
        return false;
      }
    }

    return true;
  }

  /**
   * Authenticate JWT
   */
  private async authenticateJWT(agentDID: string, token: string): Promise<boolean> {
    try {
      const decoded = jwt.verify(token, this.jwtSecret) as any;
      return decoded.agentDID === agentDID;
    } catch {
      return false;
    }
  }

  /**
   * Authenticate OAuth2
   */
  private async authenticateOAuth2(agentDID: string, accessToken: string): Promise<boolean> {
    // In production, this would validate against OAuth2 provider
    // For now, we'll do a simple validation
    return !!(accessToken && accessToken.length > 0);
  }

  /**
   * Authenticate certificate
   */
  private async authenticateCertificate(agentDID: string, certificate: string): Promise<boolean> {
    // In production, this would validate the certificate chain
    // For now, we'll do a simple validation
    return !!(certificate && certificate.includes('BEGIN CERTIFICATE'));
  }

  /**
   * Authenticate delegation credential
   */
  private async authenticateDelegation(agentDID: string, delegationCredential: DelegationCredential): Promise<boolean> {
    if (!delegationCredential) {
      return false;
    }

    // Verify the delegation credential is for this agent
    if ((delegationCredential.credentialSubject as any).agentDID !== agentDID) {
      return false;
    }

    // Verify signature (simplified - in production would use proper verification)
    return delegationCredential.proof && delegationCredential.proof.jws.length > 0;
  }

  /**
   * Check if MFA is required
   */
  private async checkMFARequired(agentDID: string, method: AuthenticationMethod): Promise<boolean> {
    // In production, this would check user settings and policies
    // For now, require MFA for OAuth2 and certificate auth
    return method === AuthenticationMethod.OAUTH2 || method === AuthenticationMethod.CERTIFICATE;
  }

  /**
   * Validate MFA code
   */
  private async validateMFA(agentDID: string, mfaCode: string): Promise<boolean> {
    // In production, this would validate against TOTP/SMS/etc
    // For now, accept any 6-digit code
    return /^\d{6}$/.test(mfaCode);
  }

  /**
   * Create authentication token
   */
  private async createAuthToken(agentDID: string, method: AuthenticationMethod): Promise<AuthToken> {
    const tokenId = `token-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const sessionId = `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const token: AuthToken = {
      id: tokenId,
      agentDID,
      sessionId,
      method,
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + this.authConfig.tokenExpiration),
    };

    // Create refresh token if configured
    if (this.authConfig.refreshTokenExpiration > 0) {
      token.refreshToken = jwt.sign(
        { tokenId, agentDID },
        this.jwtSecret,
        { expiresIn: this.authConfig.refreshTokenExpiration / 1000 }
      );
      token.refreshExpiresAt = new Date(Date.now() + this.authConfig.refreshTokenExpiration);
    }

    this.tokens.set(tokenId, token);
    return token;
  }

  /**
   * Get agent permissions
   */
  private async getAgentPermissions(agentDID: string): Promise<Permission[]> {
    const permissions = this.authzConfig.agentPermissions.get(agentDID) || [];
    
    // Add default permissions if needed
    if (permissions.length === 0 && !this.authzConfig.defaultDeny) {
      permissions.push({
        resource: '*',
        actions: ['read'],
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
      });
    }

    return permissions;
  }

  /**
   * Check RBAC permission
   */
  private checkRBACPermission(
    permissions: Permission[],
    resource: string,
    action: string
  ): { authorized: boolean; reason?: string } {
    for (const permission of permissions) {
      // Check resource match (supports wildcards)
      const resourceMatch = this.matchResource(permission.resource, resource);
      if (!resourceMatch) continue;

      // Check action match
      const actionMatch = permission.actions.includes(action) || permission.actions.includes('*');
      if (!actionMatch) continue;

      // Check expiration
      if (permission.expiresAt && permission.expiresAt < new Date()) continue;

      // Check conditions
      if (permission.conditions) {
        const conditionsMatch = this.evaluateConditions(permission.conditions, {});
        if (!conditionsMatch) continue;
      }

      return { authorized: true };
    }

    return {
      authorized: false,
      reason: `No permission for ${action} on ${resource}`
    };
  }

  /**
   * Check ABAC permission
   */
  private async checkABACPermission(
    agentDID: string,
    resource: string,
    action: string,
    context: any
  ): Promise<{ authorized: boolean; reason?: string }> {
    // In production, this would evaluate attribute-based policies
    // For now, we'll implement some basic checks
    
    // Example: Time-based access
    const hour = new Date().getHours();
    if (context?.requiresBusinessHours && (hour < 9 || hour > 17)) {
      return {
        authorized: false,
        reason: 'Access denied outside business hours'
      };
    }

    // Example: Resource owner check
    if (context?.resourceOwner && context.resourceOwner !== agentDID) {
      return {
        authorized: false,
        reason: 'Not resource owner'
      };
    }

    return { authorized: true };
  }

  /**
   * Check ACL rules
   */
  private checkACLRules(
    agentDID: string,
    resource: string,
    action: string,
    context: any
  ): { authorized: boolean; reason?: string } {
    const acl = this.authzConfig.resourceAccess;
    let finalDecision = acl.defaultAction;

    for (const rule of acl.rules) {
      // Check subject match
      if (rule.subject !== agentDID && rule.subject !== '*') continue;

      // Check resource match
      if (!this.matchResource(rule.resource, resource)) continue;

      // Check action match
      if (rule.action !== action && rule.action !== '*') continue;

      // Check conditions
      if (rule.conditions) {
        const conditionsMatch = this.evaluateConditions(rule.conditions, context);
        if (!conditionsMatch) continue;
      }

      // Apply rule effect
      finalDecision = rule.effect;
      break; // First matching rule wins
    }

    return finalDecision === AccessAction.ALLOW
      ? { authorized: true }
      : { authorized: false, reason: 'ACL denied' };
  }

  /**
   * Match resource pattern
   */
  private matchResource(pattern: string, resource: string): boolean {
    if (pattern === '*') return true;
    if (pattern === resource) return true;

    // Support wildcard patterns
    const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
    return regex.test(resource);
  }

  /**
   * Evaluate policy conditions
   */
  private evaluateConditions(conditions: PolicyCondition[], context: any): boolean {
    for (const condition of conditions) {
      const contextValue = context[condition.type];
      
      switch (condition.operator) {
        case 'equals':
          if (contextValue !== condition.value) return false;
          break;
        case 'not_equals':
          if (contextValue === condition.value) return false;
          break;
        case 'contains':
          if (!contextValue?.includes(condition.value)) return false;
          break;
        case 'greater_than':
          if (contextValue <= condition.value) return false;
          break;
        case 'less_than':
          if (contextValue >= condition.value) return false;
          break;
        default:
          return false;
      }
    }

    return true;
  }

  /**
   * Setup session timeout
   */
  private setupSessionTimeout(sessionId: string): void {
    // Clear existing timeout
    const existingTimeout = this.sessionTimeouts.get(sessionId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    // Set new timeout
    const timeout = setTimeout(() => {
      this.invalidateSession(sessionId);
    }, this.authConfig.sessionTimeout);

    this.sessionTimeouts.set(sessionId, timeout);
  }

  /**
   * Invalidate session
   */
  private invalidateSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    // Remove session
    this.sessions.delete(sessionId);
    
    // Remove associated token
    this.tokens.delete(session.token.id);
    
    // Clear timeout
    const timeout = this.sessionTimeouts.get(sessionId);
    if (timeout) {
      clearTimeout(timeout);
      this.sessionTimeouts.delete(sessionId);
    }

    this.emit('session_expired', {
      sessionId,
      agentDID: session.agentDID
    });
  }

  /**
   * Start session cleanup timer
   */
  private startSessionCleanup(): void {
    setInterval(() => {
      const now = new Date();
      
      // Clean expired tokens
      for (const [tokenId, token] of this.tokens.entries()) {
        if (token.expiresAt < now) {
          this.tokens.delete(tokenId);
        }
      }

      // Clean inactive sessions
      for (const [sessionId, session] of this.sessions.entries()) {
        const inactivityTime = now.getTime() - session.lastActivity.getTime();
        if (inactivityTime > this.authConfig.sessionTimeout) {
          this.invalidateSession(sessionId);
        }
      }
    }, 60000); // Run every minute
  }

  /**
   * Add permission for agent
   */
  addAgentPermission(agentDID: string, permission: Permission): void {
    const permissions = this.authzConfig.agentPermissions.get(agentDID) || [];
    permissions.push(permission);
    this.authzConfig.agentPermissions.set(agentDID, permissions);
  }

  /**
   * Remove permission for agent
   */
  removeAgentPermission(agentDID: string, resource: string, action: string): void {
    const permissions = this.authzConfig.agentPermissions.get(agentDID) || [];
    const filtered = permissions.filter(p => 
      !(p.resource === resource && p.actions.includes(action))
    );
    this.authzConfig.agentPermissions.set(agentDID, filtered);
  }

  /**
   * Add ACL rule
   */
  addACLRule(rule: AccessRule): void {
    this.authzConfig.resourceAccess.rules.push(rule);
  }

  /**
   * Remove ACL rule
   */
  removeACLRule(subject: string, resource: string, action: string): void {
    this.authzConfig.resourceAccess.rules = this.authzConfig.resourceAccess.rules.filter(
      rule => !(rule.subject === subject && rule.resource === resource && rule.action === action)
    );
  }

  /**
   * Get authentication statistics
   */
  getStatistics(): {
    activeSessions: number;
    activeTokens: number;
    failedAttempts: number;
    blacklistedAgents: number;
  } {
    return {
      activeSessions: this.sessions.size,
      activeTokens: this.tokens.size,
      failedAttempts: Array.from(this.failedAttempts.values()).reduce((a, b) => a + b, 0),
      blacklistedAgents: this.blacklist.size
    };
  }

  /**
   * Shutdown auth manager
   */
  shutdown(): void {
    // Clear all session timeouts
    for (const timeout of this.sessionTimeouts.values()) {
      clearTimeout(timeout);
    }

    // Clear all data
    this.sessions.clear();
    this.tokens.clear();
    this.sessionTimeouts.clear();
    this.failedAttempts.clear();
    this.blacklist.clear();

    this.removeAllListeners();
  }
}

export default AuthManager;