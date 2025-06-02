import { DelegationManager, DelegationContext } from './delegation-manager';
import { DelegationCredential, AccessGrant, AgentIdentity } from './types';
import { generateKeyPair } from '../core/crypto';

describe('DelegationManager', () => {
  let manager: DelegationManager;
  let issuerKeyPair: any;
  const issuerDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const agentDID = 'did:key:z6MkhvZgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doL';
  const serviceDID = 'did:key:z6Mkservice';

  beforeEach(async () => {
    manager = new DelegationManager();
    issuerKeyPair = await generateKeyPair();
  });

  describe('createDelegationCredential', () => {
    it('should create credential with delegation context', async () => {
      const grant: AccessGrant = {
        serviceDID,
        scopes: ['read:profile', 'write:data'],
        expiresAt: new Date(Date.now() + 3600000)
      };

      const context: DelegationContext = {
        delegationDepth: 1,
        maxDelegationDepth: 3,
        canDelegate: true
      };

      const credential = await manager.createDelegationCredential(
        issuerDID,
        issuerKeyPair,
        agentDID,
        'Test Agent',
        grant,
        context
      );

      expect(credential.credentialSubject.delegationDepth).toBe(1);
      expect(credential.credentialSubject.maxDelegationDepth).toBe(3);
      expect(credential.credentialSubject.canDelegate).toBe(true);
    });
  });

  describe('canAgentDelegate', () => {
    it('should return true for valid delegation capability', () => {
      const credential: DelegationCredential = createTestCredential({
        canDelegate: true,
        delegationDepth: 1,
        maxDelegationDepth: 3
      });

      expect(manager.canAgentDelegate(credential)).toBe(true);
    });

    it('should return false when delegation is disabled', () => {
      const credential: DelegationCredential = createTestCredential({
        canDelegate: false,
        delegationDepth: 0,
        maxDelegationDepth: 3
      });

      expect(manager.canAgentDelegate(credential)).toBe(false);
    });

    it('should return false when max depth is reached', () => {
      const credential: DelegationCredential = createTestCredential({
        canDelegate: true,
        delegationDepth: 3,
        maxDelegationDepth: 3
      });

      expect(manager.canAgentDelegate(credential)).toBe(false);
    });
  });

  describe('validateAgentDelegation', () => {
    it('should validate valid agent delegation', () => {
      const parentCredential: DelegationCredential = createTestCredential({
        canDelegate: true,
        delegationDepth: 1,
        maxDelegationDepth: 3,
        scopes: ['read:profile', 'write:data', 'read:analytics']
      });

      const childScopes = ['read:profile', 'write:data'];
      const result = manager.validateAgentDelegation(
        parentCredential,
        childScopes,
        serviceDID
      );

      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('should reject when parent cannot delegate', () => {
      const parentCredential: DelegationCredential = createTestCredential({
        canDelegate: false,
        delegationDepth: 0,
        maxDelegationDepth: 3,
        scopes: ['read:profile']
      });

      const result = manager.validateAgentDelegation(
        parentCredential,
        ['read:profile'],
        serviceDID
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('cannot delegate further');
    });

    it('should reject when child scopes exceed parent', () => {
      const parentCredential: DelegationCredential = createTestCredential({
        canDelegate: true,
        delegationDepth: 1,
        maxDelegationDepth: 3,
        scopes: ['read:profile']
      });

      const childScopes = ['read:profile', 'write:data'];
      const result = manager.validateAgentDelegation(
        parentCredential,
        childScopes,
        serviceDID
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('exceed parent agent\'s permissions');
    });

    it('should reject expired parent credential', () => {
      const parentCredential: DelegationCredential = createTestCredential({
        canDelegate: true,
        delegationDepth: 1,
        maxDelegationDepth: 3,
        scopes: ['read:profile'],
        expirationDate: new Date(Date.now() - 1000).toISOString() // expired
      });

      const result = manager.validateAgentDelegation(
        parentCredential,
        ['read:profile'],
        serviceDID
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('invalid or expired');
    });
  });

  // Helper function to create test credentials
  function createTestCredential(options: {
    canDelegate?: boolean;
    delegationDepth?: number;
    maxDelegationDepth?: number;
    scopes?: string[];
    expirationDate?: string;
  }): DelegationCredential {
    const now = new Date();
    const expires = options.expirationDate || new Date(now.getTime() + 3600000).toISOString();

    return {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'DelegationCredential'],
      id: 'test-credential',
      issuer: issuerDID,
      issuanceDate: now.toISOString(),
      expirationDate: expires,
      credentialSubject: {
        id: agentDID,
        parentDID: issuerDID,
        name: 'Test Agent',
        scopes: options.scopes || ['read:profile'],
        services: {
          [serviceDID]: {
            scopes: options.scopes || ['read:profile']
          }
        },
        validFrom: now.toISOString(),
        validUntil: expires,
        canDelegate: options.canDelegate,
        delegationDepth: options.delegationDepth,
        maxDelegationDepth: options.maxDelegationDepth
      }
    };
  }
});