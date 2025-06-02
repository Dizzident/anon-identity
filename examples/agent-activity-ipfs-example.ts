/**
 * Agent Activity IPFS Storage Example
 * 
 * Demonstrates storing agent activities in IPFS with encryption and redundancy
 */

import { 
  ActivityLogger, 
  ActivityType, 
  ActivityStatus,
  createActivity,
  ActivityEncryption,
  IPFSActivityStorage,
  IPFSRedundancyManager
} from '../src/agent/activity';

// Example 1: Basic IPFS Storage
async function basicIPFSExample() {
  console.log('\n=== Basic IPFS Storage Example ===\n');

  // Generate encryption key
  const encryptionKey = ActivityEncryption.generateKey();
  console.log('Generated encryption key for activities');

  // Create activity logger with IPFS enabled
  const logger = new ActivityLogger({
    batchSize: 5,
    batchInterval: 2000,
    enableIPFS: true,
    enableBatching: true,
    encryptionKey,
    ipfsUrl: 'http://localhost:5001' // Local IPFS node
  });

  console.log('Created activity logger with IPFS storage enabled');

  // Log some activities
  const activities = [];
  for (let i = 0; i < 10; i++) {
    const activity = await logger.logActivity(createActivity(
      ActivityType.DATA_ACCESS,
      {
        agentDID: 'did:key:z6MkAgent123',
        parentDID: 'did:key:z6MkParent456',
        serviceDID: 'did:key:z6MkService789',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data', 'list:resources'],
        details: {
          resourceType: 'user-profile',
          resourceId: `user-${i}`,
          operation: 'read',
          dataSize: Math.floor(Math.random() * 1000) + 100
        }
      }
    ));
    activities.push(activity);
    console.log(`Logged activity ${i + 1}: ${activity.id}`);
  }

  // Wait for batch processing
  console.log('\nWaiting for batch processing...');
  await new Promise(resolve => setTimeout(resolve, 3000));

  // Force flush remaining activities
  await logger.flush();
  console.log('Flushed remaining activities to IPFS');

  // Check IPFS connection
  const isConnected = await logger.checkIPFSConnection();
  console.log(`\nIPFS connection status: ${isConnected ? 'Connected' : 'Disconnected'}`);

  await logger.cleanup();
}

// Example 2: Direct IPFS Storage with Encryption
async function directIPFSStorageExample() {
  console.log('\n=== Direct IPFS Storage Example ===\n');

  // Create encryption key from user passphrase
  const userDID = 'did:key:z6MkUser123';
  const passphrase = 'my-secure-passphrase';
  const encryptionKey = await ActivityEncryption.deriveKey(userDID, passphrase);
  console.log(`Derived encryption key for user: ${userDID}`);

  // Create IPFS storage instance
  const ipfsStorage = new IPFSActivityStorage({
    url: 'http://localhost:5001',
    encryptionKey
  });

  // Create and store a single activity
  const activity = {
    id: 'activity-001',
    agentDID: 'did:key:z6MkAgent123',
    parentDID: userDID,
    timestamp: new Date(),
    type: ActivityType.AUTHENTICATION,
    serviceDID: 'did:key:z6MkService789',
    status: ActivityStatus.SUCCESS,
    scopes: [],
    details: {
      message: 'Agent authenticated successfully',
      metadata: { ipAddress: '192.168.1.100' }
    }
  };

  console.log('\nStoring activity to IPFS...');
  const stored = await ipfsStorage.storeActivity(activity);
  console.log(`Activity stored:
  - IPFS Hash: ${stored.ipfsHash}
  - Encrypted: ${stored.encrypted}
  - Checksum: ${stored.checksum}`);

  // Retrieve the activity
  console.log('\nRetrieving activity from IPFS...');
  const retrieved = await ipfsStorage.retrieveActivity(stored.ipfsHash);
  console.log(`Retrieved activity:
  - ID: ${retrieved.id}
  - Type: ${retrieved.type}
  - Agent: ${retrieved.agentDID}
  - Status: ${retrieved.status}`);

  // Verify integrity
  const expectedChecksum = ActivityEncryption.createActivityHash(retrieved);
  console.log(`\nIntegrity check: ${expectedChecksum === stored.checksum ? 'PASSED' : 'FAILED'}`);
}

// Example 3: Redundant IPFS Storage
async function redundantIPFSExample() {
  console.log('\n=== Redundant IPFS Storage Example ===\n');

  const encryptionKey = ActivityEncryption.generateKey();

  // Configure multiple IPFS nodes for redundancy
  const redundancyManager = new IPFSRedundancyManager({
    minReplicas: 2,
    encryptionKey,
    nodes: [
      {
        url: 'http://localhost:5001',
        name: 'local-node',
        priority: 10,
        active: true
      },
      {
        url: 'https://ipfs.infura.io:5001',
        name: 'infura-node',
        priority: 8,
        active: true
      },
      {
        url: 'https://api.pinata.cloud',
        name: 'pinata-node',
        priority: 6,
        active: false // Requires API key
      }
    ]
  });

  // Check node health
  console.log('Checking IPFS nodes health...');
  const health = await redundancyManager.checkNodesHealth();
  health.forEach((healthy, node) => {
    console.log(`- ${node}: ${healthy ? 'Healthy' : 'Unhealthy'}`);
  });

  // Create activity batch
  const activities = [];
  for (let i = 0; i < 5; i++) {
    activities.push({
      id: `batch-activity-${i}`,
      agentDID: 'did:key:z6MkAgent123',
      parentDID: 'did:key:z6MkParent456',
      timestamp: new Date(),
      type: ActivityType.SCOPE_USAGE,
      serviceDID: 'did:key:z6MkService789',
      status: ActivityStatus.SUCCESS,
      scopes: ['write:data'],
      details: {
        resourceType: 'document',
        operation: 'update',
        resourceId: `doc-${i}`
      }
    });
  }

  const batch = {
    id: 'batch-001',
    activities,
    startTime: activities[0].timestamp,
    endTime: activities[activities.length - 1].timestamp,
    count: activities.length,
    agentDID: activities[0].agentDID,
    parentDID: activities[0].parentDID
  };

  // Store with redundancy
  console.log('\nStoring batch with redundancy...');
  const result = await redundancyManager.storeBatchWithRedundancy(batch);
  console.log(`Storage result:
  - Success: ${result.success}
  - Nodes:`);
  result.nodes.forEach(node => {
    if (node.ipfsHash) {
      console.log(`  - ${node.name}: ${node.ipfsHash}`);
    } else {
      console.log(`  - ${node.name}: Failed - ${node.error}`);
    }
  });

  // Get aggregate statistics
  const stats = await redundancyManager.getAggregateStats();
  console.log(`\nAggregate Statistics:
  - Total Nodes: ${stats.totalNodes}
  - Active Nodes: ${stats.activeNodes}
  - Total Pinned: ${stats.totalPinned}`);
}

// Example 4: Activity Logger with Redundancy
async function loggerWithRedundancyExample() {
  console.log('\n=== Activity Logger with Redundancy Example ===\n');

  const encryptionKey = ActivityEncryption.generateKey();

  // Create logger with redundancy configuration
  const logger = new ActivityLogger({
    batchSize: 3,
    batchInterval: 1000,
    enableIPFS: true,
    enableRedundancy: true,
    encryptionKey,
    ipfsNodes: [
      {
        url: 'http://localhost:5001',
        name: 'primary',
        priority: 10,
        active: true
      },
      {
        url: 'http://localhost:5002',
        name: 'secondary',
        priority: 5,
        active: true
      }
    ],
    minReplicas: 2
  });

  // Subscribe to real-time updates
  const subscription = logger.subscribe(
    { agentDID: 'did:key:z6MkAgent789' },
    (activity) => {
      console.log(`[Real-time] Activity logged: ${activity.type} - ${activity.status}`);
    }
  );

  // Log activities
  for (let i = 0; i < 6; i++) {
    await logger.logActivity(createActivity(
      i % 2 === 0 ? ActivityType.DATA_ACCESS : ActivityType.DATA_MODIFICATION,
      {
        agentDID: 'did:key:z6MkAgent789',
        parentDID: 'did:key:z6MkParent123',
        serviceDID: 'did:key:z6MkService456',
        status: ActivityStatus.SUCCESS,
        scopes: i % 2 === 0 ? ['read:data'] : ['write:data'],
        details: {
          operation: i % 2 === 0 ? 'read' : 'write',
          resourceId: `resource-${i}`
        }
      }
    ));
    await new Promise(resolve => setTimeout(resolve, 200));
  }

  // Wait for batch processing
  await new Promise(resolve => setTimeout(resolve, 2000));

  // Cleanup
  subscription.unsubscribe();
  await logger.cleanup();
  console.log('\nLogger cleaned up successfully');
}

// Run examples
async function runExamples() {
  console.log('=== Agent Activity IPFS Storage Examples ===');
  console.log('\nNote: These examples require a running IPFS node.');
  console.log('Start IPFS with: ipfs daemon or docker run -p 5001:5001 ipfs/kubo');

  try {
    // Check if we can connect to IPFS
    const testStorage = new IPFSActivityStorage({ url: 'http://localhost:5001' });
    const connected = await testStorage.isConnected();
    
    if (!connected) {
      console.log('\n⚠️  Warning: Cannot connect to IPFS at localhost:5001');
      console.log('Examples will demonstrate the API but storage operations may fail.\n');
    }

    // Run examples
    await basicIPFSExample();
    await directIPFSStorageExample();
    await redundantIPFSExample();
    await loggerWithRedundancyExample();

  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Execute
runExamples().catch(console.error);