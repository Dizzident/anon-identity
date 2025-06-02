import { DelegationCredential, DelegationChain, AgentIdentity } from './types';
import { DelegationManager } from './delegation-manager';
import { AgentIdentityManager } from './agent-identity';
import { DIDService } from '../core/did';
import * as ed from '@noble/ed25519';

export interface ChainValidationResult {
  valid: boolean;
  chain?: DelegationChain;
  errors: string[];
  warnings: string[];
}

export interface ChainCacheEntry {
  chain: DelegationChain;
  validatedAt: Date;
  expiresAt: Date;
}

export class DelegationChainValidator {
  private chainCache: Map<string, ChainCacheEntry> = new Map();
  private readonly cacheTimeout = 5 * 60 * 1000; // 5 minutes
  
  constructor(
    private delegationManager: DelegationManager,
    private agentManager: AgentIdentityManager
  ) {}

  /**
   * Validates a complete delegation chain from root to target agent
   */
  async validateDelegationChain(
    targetAgentDID: string,
    rootDID: string,
    serviceDID?: string
  ): Promise<ChainValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];
    
    // Check cache first
    const cacheKey = `${rootDID}:${targetAgentDID}:${serviceDID || 'all'}`;
    const cached = this.getCachedChain(cacheKey);
    if (cached) {
      return { valid: true, chain: cached, errors: [], warnings: [] };
    }

    try {
      // Build the chain from target to root
      const chain = await this.buildDelegationChain(targetAgentDID, rootDID);
      
      if (!chain) {
        errors.push('Failed to build delegation chain');
        return { valid: false, errors, warnings };
      }

      // Validate each link in the chain
      for (let i = 0; i < chain.credentials.length; i++) {
        const credential = chain.credentials[i];
        const validationResult = await this.validateChainLink(
          credential,
          i > 0 ? chain.credentials[i - 1] : undefined,
          serviceDID
        );
        
        if (!validationResult.valid) {
          errors.push(`Link ${i + 1}: ${validationResult.error}`);
        }
        
        if (validationResult.warning) {
          warnings.push(`Link ${i + 1}: ${validationResult.warning}`);
        }
      }

      // Validate overall chain properties
      const chainValidation = this.validateChainProperties(chain);
      errors.push(...chainValidation.errors);
      warnings.push(...chainValidation.warnings);

      const valid = errors.length === 0;
      
      if (valid) {
        this.cacheChain(cacheKey, chain);
      }

      return { valid, chain, errors, warnings };
    } catch (error) {
      errors.push(`Chain validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Builds a delegation chain from target agent to root
   */
  private async buildDelegationChain(
    targetAgentDID: string,
    rootDID: string
  ): Promise<DelegationChain | null> {
    const agents: AgentIdentity[] = [];
    const credentials: DelegationCredential[] = [];
    
    let currentDID = targetAgentDID;
    let maxDepth = 0;
    
    while (currentDID !== rootDID) {
      const agent = this.agentManager.getAgent(currentDID);
      if (!agent) {
        // If we can't find the agent, we might have reached a user DID
        if (agents.length > 0 && agents[agents.length - 1].parentDID === rootDID) {
          break;
        }
        return null;
      }
      
      agents.push(agent);
      maxDepth = Math.max(maxDepth, agent.maxDelegationDepth || 3);
      
      // Get delegation credential for this agent
      const agentCredentials = this.agentManager.getDelegationCredentials(currentDID);
      if (agentCredentials.length === 0) {
        return null;
      }
      
      // Find the most recent valid credential
      const validCredential = this.findValidCredential(agentCredentials);
      if (!validCredential) {
        return null;
      }
      
      credentials.push(validCredential);
      currentDID = agent.parentDID;
      
      // Prevent infinite loops
      if (agents.length > 10) {
        throw new Error('Delegation chain too deep or circular reference detected');
      }
    }

    return {
      agents: agents.reverse(),
      credentials: credentials.reverse(),
      maxDepth,
      currentDepth: agents.length
    };
  }

  /**
   * Validates a single link in the delegation chain
   */
  private async validateChainLink(
    credential: DelegationCredential,
    parentCredential: DelegationCredential | undefined,
    serviceDID?: string
  ): Promise<{ valid: boolean; error?: string; warning?: string }> {
    // Basic credential validation
    if (!this.delegationManager.validateDelegation(credential)) {
      return { valid: false, error: 'Invalid or expired credential' };
    }

    // Verify signature
    const signatureValid = await this.verifyCredentialSignature(credential);
    if (!signatureValid) {
      return { valid: false, error: 'Invalid credential signature' };
    }

    // If this is not the root credential, validate against parent
    if (parentCredential) {
      // Check that parent can delegate
      if (!this.delegationManager.canAgentDelegate(parentCredential)) {
        return { valid: false, error: 'Parent cannot delegate' };
      }

      // Validate scope inheritance
      if (serviceDID) {
        const parentScopes = this.delegationManager.extractScopes(parentCredential, serviceDID);
        const currentScopes = this.delegationManager.extractScopes(credential, serviceDID);
        
        const validation = this.delegationManager.validateAgentDelegation(
          parentCredential,
          currentScopes,
          serviceDID
        );
        
        if (!validation.valid) {
          return { valid: false, error: validation.reason };
        }
      }

      // Check delegation depth consistency
      const parentDepth = parentCredential.credentialSubject.delegationDepth || 0;
      const currentDepth = credential.credentialSubject.delegationDepth || 0;
      
      if (currentDepth !== parentDepth + 1) {
        return { 
          valid: true, 
          warning: `Inconsistent delegation depth: expected ${parentDepth + 1}, got ${currentDepth}` 
        };
      }
    }

    return { valid: true };
  }

  /**
   * Verifies the cryptographic signature of a credential
   */
  private async verifyCredentialSignature(credential: DelegationCredential): Promise<boolean> {
    try {
      if (!credential.proof?.jws) {
        return false;
      }

      // Extract the issuer's public key
      const issuerDID = credential.issuer;
      const issuerAgent = this.agentManager.getAgent(issuerDID);
      
      let publicKey: Uint8Array;
      if (issuerAgent) {
        publicKey = issuerAgent.keyPair.publicKey;
      } else {
        // Try to extract public key from DID
        try {
          publicKey = DIDService.getPublicKeyFromDID(issuerDID);
        } catch {
          return false;
        }
      }

      // Remove proof for verification
      const { proof, ...credentialWithoutProof } = credential;
      const message = JSON.stringify(credentialWithoutProof, Object.keys(credentialWithoutProof).sort());
      
      // Verify signature
      const signature = credential.proof.jws;
      const signatureBytes = typeof signature === 'string' 
        ? Uint8Array.from(Buffer.from(signature, 'base64'))
        : signature;
      
      return await ed.verify(
        signatureBytes,
        new TextEncoder().encode(message),
        publicKey
      );
    } catch (error) {
      return false;
    }
  }

  /**
   * Validates overall chain properties
   */
  private validateChainProperties(chain: DelegationChain): {
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check maximum depth
    if (chain.currentDepth > chain.maxDepth) {
      errors.push(`Chain depth (${chain.currentDepth}) exceeds maximum allowed (${chain.maxDepth})`);
    }

    // Check for expired credentials
    const now = new Date();
    chain.credentials.forEach((cred, index) => {
      const expirationDate = new Date(cred.expirationDate);
      const timeUntilExpiration = expirationDate.getTime() - now.getTime();
      
      if (timeUntilExpiration < 24 * 60 * 60 * 1000) { // Less than 24 hours
        warnings.push(`Credential for agent ${index + 1} expires soon`);
      }
    });

    // Check for scope degradation
    if (chain.credentials.length > 1) {
      for (let i = 1; i < chain.credentials.length; i++) {
        const parentScopes = chain.credentials[i - 1].credentialSubject.scopes;
        const currentScopes = chain.credentials[i].credentialSubject.scopes;
        
        if (currentScopes.length > parentScopes.length) {
          warnings.push(`Agent ${i + 1} has more scopes than parent - possible configuration issue`);
        }
      }
    }

    return { errors, warnings };
  }

  /**
   * Finds the most recent valid credential from a list
   */
  private findValidCredential(credentials: DelegationCredential[]): DelegationCredential | null {
    const now = new Date();
    
    const validCredentials = credentials
      .filter(cred => {
        const expirationDate = new Date(cred.expirationDate);
        const validFrom = new Date(cred.credentialSubject.validFrom);
        return expirationDate > now && validFrom <= now;
      })
      .sort((a, b) => {
        // Sort by issuance date, most recent first
        return new Date(b.issuanceDate).getTime() - new Date(a.issuanceDate).getTime();
      });

    return validCredentials[0] || null;
  }

  /**
   * Caches a validated chain
   */
  private cacheChain(key: string, chain: DelegationChain): void {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.cacheTimeout);
    
    // Find the earliest credential expiration
    const earliestExpiration = chain.credentials.reduce((earliest, cred) => {
      const expDate = new Date(cred.expirationDate);
      return expDate < earliest ? expDate : earliest;
    }, expiresAt);

    this.chainCache.set(key, {
      chain,
      validatedAt: now,
      expiresAt: earliestExpiration < expiresAt ? earliestExpiration : expiresAt
    });
  }

  /**
   * Retrieves a cached chain if still valid
   */
  private getCachedChain(key: string): DelegationChain | null {
    const entry = this.chainCache.get(key);
    if (!entry) return null;

    const now = new Date();
    if (now > entry.expiresAt) {
      this.chainCache.delete(key);
      return null;
    }

    return entry.chain;
  }

  /**
   * Clears expired entries from the cache
   */
  clearExpiredCache(): void {
    const now = new Date();
    for (const [key, entry] of this.chainCache.entries()) {
      if (now > entry.expiresAt) {
        this.chainCache.delete(key);
      }
    }
  }

  /**
   * Exports a delegation chain for visualization or debugging
   */
  exportChain(chain: DelegationChain): object {
    return {
      depth: chain.currentDepth,
      maxDepth: chain.maxDepth,
      agents: chain.agents.map(agent => ({
        did: agent.did,
        name: agent.name,
        delegationDepth: agent.delegationDepth,
        canDelegate: agent.canDelegate
      })),
      credentials: chain.credentials.map(cred => ({
        id: cred.id,
        issuer: cred.issuer,
        subject: cred.credentialSubject.id,
        scopes: cred.credentialSubject.scopes,
        issuanceDate: cred.issuanceDate,
        expirationDate: cred.expirationDate
      }))
    };
  }
}