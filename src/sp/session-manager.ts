import { randomBytes } from 'crypto';
import { VerificationResult } from './service-provider';

export interface Session {
  id: string;
  holderDID: string;
  credentialIds: string[];
  attributes: Record<string, any>;
  createdAt: Date;
  expiresAt: Date;
  lastAccessedAt: Date;
  metadata?: Record<string, any>;
}

export interface SessionValidation {
  valid: boolean;
  session?: Session;
  reason?: string;
}

export interface SessionManagerOptions {
  defaultSessionDuration?: number; // milliseconds
  maxSessionDuration?: number; // milliseconds
  cleanupInterval?: number; // milliseconds
}

export class SessionManager {
  private sessions: Map<string, Session> = new Map();
  private credentialToSessions: Map<string, Set<string>> = new Map();
  private cleanupTimer?: NodeJS.Timeout;
  private options: Required<SessionManagerOptions>;

  constructor(options: SessionManagerOptions = {}) {
    this.options = {
      defaultSessionDuration: options.defaultSessionDuration || 3600000, // 1 hour
      maxSessionDuration: options.maxSessionDuration || 86400000, // 24 hours
      cleanupInterval: options.cleanupInterval || 300000 // 5 minutes
    };

    // Start cleanup timer
    this.startCleanupTimer();
  }

  /**
   * Create a new session from a verification result
   */
  async createSession(verificationResult: VerificationResult, metadata?: Record<string, any>): Promise<Session> {
    if (!verificationResult.valid || !verificationResult.holder || !verificationResult.credentials) {
      throw new Error('Cannot create session from invalid verification result');
    }

    const sessionId = this.generateSessionId();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.options.defaultSessionDuration);

    // Aggregate all attributes from verified credentials
    const allAttributes: Record<string, any> = {};
    const credentialIds: string[] = [];

    for (const credential of verificationResult.credentials) {
      credentialIds.push(credential.id);
      Object.assign(allAttributes, credential.attributes);
    }

    const session: Session = {
      id: sessionId,
      holderDID: verificationResult.holder,
      credentialIds,
      attributes: allAttributes,
      createdAt: now,
      expiresAt,
      lastAccessedAt: now,
      metadata
    };

    // Store session
    this.sessions.set(sessionId, session);

    // Map credentials to sessions for revocation handling
    for (const credentialId of credentialIds) {
      if (!this.credentialToSessions.has(credentialId)) {
        this.credentialToSessions.set(credentialId, new Set());
      }
      this.credentialToSessions.get(credentialId)!.add(sessionId);
    }

    return session;
  }

  /**
   * Validate an existing session
   */
  async validateSession(sessionId: string): Promise<SessionValidation> {
    const session = this.sessions.get(sessionId);

    if (!session) {
      return {
        valid: false,
        reason: 'Session not found'
      };
    }

    const now = new Date();

    // Check if session has expired
    if (now > session.expiresAt) {
      this.removeSession(sessionId);
      return {
        valid: false,
        reason: 'Session expired'
      };
    }

    // Update last accessed time
    session.lastAccessedAt = now;

    return {
      valid: true,
      session
    };
  }

  /**
   * Revoke all sessions associated with a credential
   */
  async revokeSessions(credentialId: string): Promise<void> {
    const sessionIds = this.credentialToSessions.get(credentialId);
    
    if (!sessionIds) {
      return;
    }

    // Remove all associated sessions
    for (const sessionId of sessionIds) {
      this.removeSession(sessionId);
    }

    // Clean up the credential mapping
    this.credentialToSessions.delete(credentialId);
  }

  /**
   * Set or update session expiry
   */
  async setSessionExpiry(sessionId: string, duration: number): Promise<void> {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      throw new Error('Session not found');
    }

    // Enforce maximum session duration
    const maxDuration = Math.min(duration, this.options.maxSessionDuration);
    const now = new Date();
    session.expiresAt = new Date(now.getTime() + maxDuration);
  }

  /**
   * Get session by ID
   */
  getSession(sessionId: string): Session | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Get all active sessions
   */
  getAllSessions(): Session[] {
    return Array.from(this.sessions.values());
  }

  /**
   * Get sessions by holder DID
   */
  getSessionsByHolder(holderDID: string): Session[] {
    return Array.from(this.sessions.values()).filter(
      session => session.holderDID === holderDID
    );
  }

  /**
   * Manually remove a session
   */
  removeSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      return;
    }

    // Remove from main storage
    this.sessions.delete(sessionId);

    // Remove from credential mappings
    for (const credentialId of session.credentialIds) {
      const sessions = this.credentialToSessions.get(credentialId);
      if (sessions) {
        sessions.delete(sessionId);
        if (sessions.size === 0) {
          this.credentialToSessions.delete(credentialId);
        }
      }
    }
  }

  /**
   * Clear all sessions
   */
  clearAllSessions(): void {
    this.sessions.clear();
    this.credentialToSessions.clear();
  }

  /**
   * Stop the cleanup timer
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
  }

  /**
   * Generate a secure session ID
   */
  private generateSessionId(): string {
    return randomBytes(32).toString('base64url');
  }

  /**
   * Start the cleanup timer to remove expired sessions
   */
  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredSessions();
    }, this.options.cleanupInterval);
  }

  /**
   * Clean up expired sessions
   */
  private cleanupExpiredSessions(): void {
    const now = new Date();
    const expiredSessionIds: string[] = [];

    for (const [sessionId, session] of this.sessions) {
      if (now > session.expiresAt) {
        expiredSessionIds.push(sessionId);
      }
    }

    for (const sessionId of expiredSessionIds) {
      this.removeSession(sessionId);
    }
  }
}