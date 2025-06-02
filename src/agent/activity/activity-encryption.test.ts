import { ActivityEncryption, EncryptedData } from './activity-encryption';
import { AgentActivity, ActivityBatch, ActivityType, ActivityStatus } from './types';

describe('ActivityEncryption', () => {
  let encryption: ActivityEncryption;
  let testKey: Uint8Array;

  beforeEach(() => {
    encryption = new ActivityEncryption();
    testKey = ActivityEncryption.generateKey();
  });

  describe('Key Generation', () => {
    test('should generate a 32-byte key', () => {
      const key = ActivityEncryption.generateKey();
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
    });

    test('should generate different keys each time', () => {
      const key1 = ActivityEncryption.generateKey();
      const key2 = ActivityEncryption.generateKey();
      expect(key1).not.toEqual(key2);
    });
  });

  describe('Key Derivation', () => {
    test('should derive consistent key from DID and passphrase', async () => {
      const userDID = 'did:key:z6MkTest123';
      const passphrase = 'test-passphrase';
      
      const key1 = await ActivityEncryption.deriveKey(userDID, passphrase);
      const key2 = await ActivityEncryption.deriveKey(userDID, passphrase);
      
      expect(key1).toEqual(key2);
      expect(key1.length).toBe(32);
    });

    test('should derive different keys for different DIDs', async () => {
      const passphrase = 'test-passphrase';
      
      const key1 = await ActivityEncryption.deriveKey('did:key:z6MkUser1', passphrase);
      const key2 = await ActivityEncryption.deriveKey('did:key:z6MkUser2', passphrase);
      
      expect(key1).not.toEqual(key2);
    });
  });

  describe('Activity Encryption/Decryption', () => {
    const testActivity: AgentActivity = {
      id: 'test-activity-1',
      agentDID: 'did:key:z6MkAgent123',
      parentDID: 'did:key:z6MkParent456',
      timestamp: new Date(),
      type: ActivityType.DATA_ACCESS,
      serviceDID: 'did:key:z6MkService789',
      status: ActivityStatus.SUCCESS,
      scopes: ['read:data'],
      details: {
        message: 'Test activity',
        metadata: { foo: 'bar' }
      }
    };

    test('should encrypt and decrypt activity successfully', async () => {
      const encrypted = await encryption.encryptActivity(testActivity, testKey);
      
      expect(encrypted).toHaveProperty('data');
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('tag');
      expect(encrypted.algorithm).toBe('aes-256-gcm');
      
      const decrypted = await encryption.decryptActivity(encrypted, testKey);
      
      expect(decrypted.id).toBe(testActivity.id);
      expect(decrypted.agentDID).toBe(testActivity.agentDID);
      expect(decrypted.type).toBe(testActivity.type);
      expect(decrypted.details).toEqual(testActivity.details);
    });

    test('should fail to decrypt with wrong key', async () => {
      const encrypted = await encryption.encryptActivity(testActivity, testKey);
      const wrongKey = ActivityEncryption.generateKey();
      
      await expect(
        encryption.decryptActivity(encrypted, wrongKey)
      ).rejects.toThrow();
    });

    test('should produce different ciphertexts for same activity', async () => {
      const encrypted1 = await encryption.encryptActivity(testActivity, testKey);
      const encrypted2 = await encryption.encryptActivity(testActivity, testKey);
      
      expect(encrypted1.data).not.toBe(encrypted2.data);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
    });
  });

  describe('Batch Encryption/Decryption', () => {
    const testBatch: ActivityBatch = {
      id: 'test-batch-1',
      activities: [
        {
          id: 'activity-1',
          agentDID: 'did:key:z6MkAgent123',
          parentDID: 'did:key:z6MkParent456',
          timestamp: new Date(),
          type: ActivityType.AUTHENTICATION,
          serviceDID: 'did:key:z6MkService789',
          status: ActivityStatus.SUCCESS,
          scopes: [],
          details: {}
        },
        {
          id: 'activity-2',
          agentDID: 'did:key:z6MkAgent123',
          parentDID: 'did:key:z6MkParent456',
          timestamp: new Date(),
          type: ActivityType.DATA_ACCESS,
          serviceDID: 'did:key:z6MkService789',
          status: ActivityStatus.SUCCESS,
          scopes: ['read:data'],
          details: { resourceId: 'resource-1' }
        }
      ],
      startTime: new Date(),
      endTime: new Date(),
      count: 2,
      agentDID: 'did:key:z6MkAgent123',
      parentDID: 'did:key:z6MkParent456'
    };

    test('should encrypt and decrypt batch successfully', async () => {
      const encrypted = await encryption.encryptBatch(testBatch, testKey);
      const decrypted = await encryption.decryptBatch(encrypted, testKey);
      
      expect(decrypted.id).toBe(testBatch.id);
      expect(decrypted.activities.length).toBe(testBatch.activities.length);
      expect(decrypted.activities[0].id).toBe(testBatch.activities[0].id);
      expect(decrypted.activities[1].details).toEqual(testBatch.activities[1].details);
    });
  });

  describe('Activity Hashing', () => {
    test('should create consistent hash for same activity', () => {
      const activity: AgentActivity = {
        id: 'test-1',
        agentDID: 'did:key:z6MkAgent123',
        parentDID: 'did:key:z6MkParent456',
        timestamp: new Date('2024-01-01T00:00:00Z'),
        type: ActivityType.DATA_ACCESS,
        serviceDID: 'did:key:z6MkService789',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data'],
        details: { metadata: { foo: 'bar' } }
      };
      
      const hash1 = ActivityEncryption.createActivityHash(activity);
      const hash2 = ActivityEncryption.createActivityHash(activity);
      
      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/); // SHA256 hex
    });

    test('should create different hashes for different activities', () => {
      const activity1: AgentActivity = {
        id: 'test-1',
        agentDID: 'did:key:z6MkAgent123',
        parentDID: 'did:key:z6MkParent456',
        timestamp: new Date(),
        type: ActivityType.DATA_ACCESS,
        serviceDID: 'did:key:z6MkService789',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data'],
        details: {}
      };
      
      const activity2 = { ...activity1, id: 'test-2' };
      
      const hash1 = ActivityEncryption.createActivityHash(activity1);
      const hash2 = ActivityEncryption.createActivityHash(activity2);
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('Merkle Root Creation', () => {
    test('should create merkle root for activities', () => {
      const activities: AgentActivity[] = [
        {
          id: 'test-1',
          agentDID: 'did:key:z6MkAgent123',
          parentDID: 'did:key:z6MkParent456',
          timestamp: new Date(),
          type: ActivityType.DATA_ACCESS,
          serviceDID: 'did:key:z6MkService789',
          status: ActivityStatus.SUCCESS,
          scopes: [],
          details: {}
        },
        {
          id: 'test-2',
          agentDID: 'did:key:z6MkAgent123',
          parentDID: 'did:key:z6MkParent456',
          timestamp: new Date(),
          type: ActivityType.DATA_MODIFICATION,
          serviceDID: 'did:key:z6MkService789',
          status: ActivityStatus.SUCCESS,
          scopes: [],
          details: {}
        }
      ];
      
      const merkleRoot = ActivityEncryption.createBatchMerkleRoot(activities);
      expect(merkleRoot).toMatch(/^[a-f0-9]{64}$/);
    });

    test('should handle empty activity array', () => {
      const merkleRoot = ActivityEncryption.createBatchMerkleRoot([]);
      expect(merkleRoot).toBe('');
    });

    test('should handle single activity', () => {
      const activity: AgentActivity = {
        id: 'test-1',
        agentDID: 'did:key:z6MkAgent123',
        parentDID: 'did:key:z6MkParent456',
        timestamp: new Date(),
        type: ActivityType.DATA_ACCESS,
        serviceDID: 'did:key:z6MkService789',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {}
      };
      
      const merkleRoot = ActivityEncryption.createBatchMerkleRoot([activity]);
      const singleHash = ActivityEncryption.createActivityHash(activity);
      
      // For a single item, merkle root should be the hash of that item
      expect(merkleRoot).toBe(singleHash);
    });

    test('should create consistent merkle root for same activities', () => {
      const activities: AgentActivity[] = Array(5).fill(null).map((_, i) => ({
        id: `test-${i}`,
        agentDID: 'did:key:z6MkAgent123',
        parentDID: 'did:key:z6MkParent456',
        timestamp: new Date('2024-01-01T00:00:00Z'),
        type: ActivityType.DATA_ACCESS,
        serviceDID: 'did:key:z6MkService789',
        status: ActivityStatus.SUCCESS,
        scopes: [],
        details: {}
      }));
      
      const root1 = ActivityEncryption.createBatchMerkleRoot(activities);
      const root2 = ActivityEncryption.createBatchMerkleRoot(activities);
      
      expect(root1).toBe(root2);
    });
  });
});