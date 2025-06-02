/**
 * Agent Activity Real-time Streaming Example
 * 
 * Demonstrates real-time activity streaming, WebSocket server, and monitoring
 */

import { 
  ActivityMonitoringService,
  ActivityLogger,
  ActivityStreamManager,
  ActivityWebSocketServer,
  createActivity,
  ActivityType,
  ActivityStatus,
  StreamEventType,
  AlertSeverity
} from '../src/agent/activity';
import { createServer } from 'http';
import WebSocket from 'ws';

// Example 1: Basic Real-time Streaming
async function basicStreamingExample() {
  console.log('\n=== Basic Real-time Streaming ===\n');

  // Create monitoring service with streaming enabled
  const monitoring = new ActivityMonitoringService({
    enableStreaming: true,
    enableIndexing: true,
    enableBatching: false, // Disable for immediate streaming
    batchSize: 1
  });

  const streamManager = monitoring.getStreamManager();
  if (!streamManager) {
    throw new Error('Stream manager not initialized');
  }

  // Subscribe to all activities
  const allActivitiesSubscription = streamManager.subscribe(
    {}, // No filters - get all activities
    (event) => {
      console.log(`[Stream] ${event.type}: ${event.id} at ${event.timestamp.toISOString()}`);
      if (event.type === StreamEventType.ACTIVITY_LOGGED) {
        const activity = event.data as any;
        console.log(`  - Agent: ${activity.agentDID}`);
        console.log(`  - Type: ${activity.type}`);
        console.log(`  - Status: ${activity.status}`);
      }
    },
    { source: 'basic-example' }
  );

  // Subscribe to critical events only
  const criticalSubscription = streamManager.subscribeToCriticalEvents(
    (event) => {
      console.log(`[CRITICAL] ${event.type}: ${JSON.stringify(event.data)}`);
    },
    { source: 'critical-monitor' }
  );

  // Log some activities
  const agentDID = 'did:key:z6MkStreamAgent123';
  const parentDID = 'did:key:z6MkStreamParent456';
  const serviceDID = 'did:key:z6MkStreamService789';

  console.log('Logging activities for real-time streaming...\n');

  const activities = [
    createActivity(ActivityType.AUTHENTICATION, {
      agentDID, parentDID, serviceDID,
      status: ActivityStatus.SUCCESS,
      scopes: [],
      details: { message: 'Agent authenticated' }
    }),
    
    createActivity(ActivityType.DATA_ACCESS, {
      agentDID, parentDID, serviceDID,
      status: ActivityStatus.SUCCESS,
      scopes: ['read:data'],
      details: { resourceId: 'user-profile-123' }
    }),
    
    createActivity(ActivityType.DATA_MODIFICATION, {
      agentDID, parentDID, serviceDID,
      status: ActivityStatus.FAILED, // This should trigger critical event
      scopes: ['write:data'],
      details: { 
        resourceId: 'document-456',
        errorMessage: 'Permission denied'
      }
    })
  ];

  for (let i = 0; i < activities.length; i++) {
    await monitoring.logActivity(activities[i]);
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  console.log('\nStream statistics:');
  const streamStats = streamManager.getMetrics();
  console.log(`- Total events: ${streamStats.totalEvents}`);
  console.log(`- Subscriptions: ${streamManager.getSubscriptionStats().total}`);

  // Cleanup
  allActivitiesSubscription.unsubscribe();
  criticalSubscription.unsubscribe();
  await monitoring.stop();
}

// Example 2: Agent-specific Streaming
async function agentSpecificStreamingExample() {
  console.log('\n=== Agent-specific Streaming ===\n');

  const streamManager = new ActivityStreamManager({
    enableAlerts: true,
    alertThresholds: {
      errorRateThreshold: 0.3, // 30% error rate
      suspiciousVolumeThreshold: 10 // 10 activities per minute
    }
  });

  const agent1DID = 'did:key:z6MkAgent1';
  const agent2DID = 'did:key:z6MkAgent2';
  const parentDID = 'did:key:z6MkParent123';
  const serviceDID = 'did:key:z6MkService456';

  // Subscribe to Agent 1 activities only
  const agent1Subscription = streamManager.subscribeToAgent(
    agent1DID,
    (event) => {
      console.log(`[Agent1] ${event.type}: ${(event.data as any).type || 'N/A'}`);
    }
  );

  // Subscribe to error events only
  const errorSubscription = streamManager.subscribe(
    { errorOnly: true },
    (event) => {
      console.log(`[ERROR] Agent: ${(event.data as any).agentDID}, Status: ${(event.data as any).status}`);
    }
  );

  // Subscribe to alerts
  const alertSubscription = streamManager.subscribeToAlerts(
    (event) => {
      const alert = event.data as any;
      console.log(`[ALERT] ${alert.severity.toUpperCase()}: ${alert.message}`);
    }
  );

  console.log('Publishing activities for different agents...\n');

  // Simulate activities for different agents
  const activities = [
    // Agent 1 activities (successful)
    { agentDID: agent1DID, type: ActivityType.AUTHENTICATION, status: ActivityStatus.SUCCESS },
    { agentDID: agent1DID, type: ActivityType.DATA_ACCESS, status: ActivityStatus.SUCCESS },
    
    // Agent 2 activities (some failures)
    { agentDID: agent2DID, type: ActivityType.AUTHENTICATION, status: ActivityStatus.SUCCESS },
    { agentDID: agent2DID, type: ActivityType.DATA_MODIFICATION, status: ActivityStatus.FAILED },
    { agentDID: agent2DID, type: ActivityType.SCOPE_USAGE, status: ActivityStatus.DENIED },
    
    // More Agent 1 activities
    { agentDID: agent1DID, type: ActivityType.SCOPE_USAGE, status: ActivityStatus.SUCCESS }
  ];

  for (const activityData of activities) {
    const activity = {
      id: `activity-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      agentDID: activityData.agentDID,
      parentDID,
      serviceDID,
      timestamp: new Date(),
      type: activityData.type,
      status: activityData.status,
      scopes: ['read:data'],
      details: { 
        example: true,
        timestamp: new Date().toISOString()
      }
    };

    await streamManager.publishActivity(activity as any);
    await new Promise(resolve => setTimeout(resolve, 200));
  }

  // Generate high volume for Agent 2 to trigger volume alert
  console.log('\nGenerating high volume activities for Agent 2...\n');
  for (let i = 0; i < 15; i++) {
    const activity = {
      id: `volume-${i}`,
      agentDID: agent2DID,
      parentDID,
      serviceDID,
      timestamp: new Date(),
      type: ActivityType.DATA_ACCESS,
      status: ActivityStatus.SUCCESS,
      scopes: ['read:data'],
      details: { volumeTest: true, index: i }
    };

    await streamManager.publishActivity(activity as any);
    await new Promise(resolve => setTimeout(resolve, 50)); // Very fast to trigger volume alert
  }

  console.log('\nFinal stream statistics:');
  const finalStats = streamManager.getMetrics();
  console.log(`- Total events: ${finalStats.totalEvents}`);
  console.log(`- Alerts generated: ${finalStats.alertsGenerated}`);

  // Cleanup
  agent1Subscription.unsubscribe();
  errorSubscription.unsubscribe();
  alertSubscription.unsubscribe();
}

// Example 3: WebSocket Server Integration
async function webSocketServerExample() {
  console.log('\n=== WebSocket Server Integration ===\n');

  // Create HTTP server
  const httpServer = createServer();
  const PORT = 8081;

  // Create monitoring service with WebSocket enabled
  const monitoring = new ActivityMonitoringService({
    enableStreaming: true,
    enableIndexing: true,
    websocket: {
      enabled: true,
      port: PORT,
      path: '/activity-stream',
      maxConnections: 100
    }
  });

  // Start the monitoring service
  await monitoring.start(httpServer);

  // Start HTTP server
  httpServer.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`WebSocket available at ws://localhost:${PORT}/activity-stream`);
  });

  // Wait a bit for server to start
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Create WebSocket client to test
  const ws = new WebSocket(`ws://localhost:${PORT}/activity-stream`);

  ws.on('open', () => {
    console.log('WebSocket client connected');
    
    // Subscribe to all activities
    ws.send(JSON.stringify({
      type: 'subscribe',
      id: 'sub-1',
      data: {
        filters: {} // All activities
      }
    }));

    // Subscribe to specific agent
    ws.send(JSON.stringify({
      type: 'subscribe',
      id: 'sub-2',
      data: {
        filters: {
          agentDID: 'did:key:z6MkWebSocketAgent'
        }
      }
    }));
  });

  ws.on('message', (data: Buffer) => {
    const message = JSON.parse(data.toString());
    console.log(`[WebSocket] ${message.type}:`, 
      message.type === 'event' ? 
        `${message.data.type} - ${(message.data.data as any)?.type || 'N/A'}` : 
        JSON.stringify(message.data || message.error)
    );
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });

  // Wait for connection to be established
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Generate some activities
  console.log('\nGenerating activities for WebSocket clients...\n');
  
  const agentDID = 'did:key:z6MkWebSocketAgent';
  const parentDID = 'did:key:z6MkWebSocketParent';
  const serviceDID = 'did:key:z6MkWebSocketService';

  for (let i = 0; i < 5; i++) {
    await monitoring.logActivity(createActivity(
      i % 2 === 0 ? ActivityType.DATA_ACCESS : ActivityType.SCOPE_USAGE,
      {
        agentDID,
        parentDID,
        serviceDID,
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data'],
        details: { 
          websocketExample: true,
          iteration: i + 1
        }
      }
    ));

    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  // Get server statistics
  console.log('\nWebSocket Server Statistics:');
  const wsStats = monitoring.getWebSocketServer()?.getStats();
  if (wsStats) {
    console.log(`- Connected clients: ${wsStats.connectedClients}`);
    console.log(`- Total subscriptions: ${wsStats.totalSubscriptions}`);
    console.log(`- Uptime: ${wsStats.uptime.toFixed(2)}s`);
  }

  // Cleanup
  console.log('\nCleaning up...');
  ws.close();
  httpServer.close();
  await monitoring.stop();
}

// Example 4: Complete Monitoring Dashboard Backend
async function monitoringDashboardExample() {
  console.log('\n=== Monitoring Dashboard Backend ===\n');

  const monitoring = new ActivityMonitoringService({
    enableStreaming: true,
    enableIndexing: true,
    enableIPFS: false, // Disable IPFS for this example
    alerts: {
      enabled: true,
      errorRateThreshold: 0.2,
      volumeThreshold: 20
    }
  });

  // Create multiple agents for demonstration
  const agents = [
    'did:key:z6MkDashboardAgent1',
    'did:key:z6MkDashboardAgent2',
    'did:key:z6MkDashboardAgent3'
  ];
  const parentDID = 'did:key:z6MkDashboardParent';
  const serviceDID = 'did:key:z6MkDashboardService';

  console.log('Generating diverse activity patterns...\n');

  // Generate different activity patterns for each agent
  for (let hour = 0; hour < 3; hour++) {
    for (let agent = 0; agent < agents.length; agent++) {
      const agentDID = agents[agent];
      const activitiesThisHour = Math.floor(Math.random() * 20) + 5; // 5-25 activities per hour

      for (let i = 0; i < activitiesThisHour; i++) {
        const types = Object.values(ActivityType);
        const type = types[Math.floor(Math.random() * types.length)] as ActivityType;
        
        // Agent 2 has higher error rate
        const errorRate = agent === 1 ? 0.3 : 0.1;
        const status = Math.random() < errorRate ? ActivityStatus.FAILED : ActivityStatus.SUCCESS;

        const activity = createActivity(type, {
          agentDID,
          parentDID,
          serviceDID,
          status,
          scopes: ['read:data', 'write:data'],
          details: {
            hour: hour + 1,
            agent: agent + 1,
            iteration: i + 1,
            dashboardExample: true
          }
        });

        await monitoring.logActivity(activity);
        
        // Small delay to simulate real-world timing
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    }
    
    console.log(`Completed hour ${hour + 1}/3`);
  }

  // Get comprehensive monitoring statistics
  console.log('\nMonitoring Dashboard Statistics:');
  const stats = await monitoring.getMonitoringStats();
  
  console.log('\nActivity Statistics:');
  console.log(`- Total activities: ${stats.activities.total}`);
  console.log(`- Last hour activities: ${stats.activities.lastHour}`);
  console.log(`- Error rate: ${(stats.activities.errorRate * 100).toFixed(2)}%`);
  
  console.log('\nAgent Statistics:');
  console.log(`- Active agents: ${stats.agents.active}`);
  
  console.log('\nStorage Statistics:');
  console.log(`- Index enabled: ${stats.storage.indexEnabled}`);
  console.log(`- IPFS enabled: ${stats.storage.ipfsEnabled}`);
  console.log(`- Total indexed: ${stats.storage.totalIndexed}`);

  // Get summaries for each agent
  console.log('\nAgent Summaries:');
  for (const agentDID of agents) {
    try {
      const summary = await monitoring.getActivitySummary(agentDID, 'hour');
      console.log(`\n${agentDID}:`);
      console.log(`  - Total activities: ${summary.totalActivities}`);
      console.log(`  - Error rate: ${(summary.errorRate * 100).toFixed(2)}%`);
      console.log(`  - Most used scope: ${summary.mostUsedScope || 'N/A'}`);
      
      const typeBreakdown = Object.entries(summary.byType)
        .map(([type, count]) => `${type}: ${count}`)
        .join(', ');
      console.log(`  - By type: ${typeBreakdown}`);
    } catch (error) {
      console.log(`  - No data available for ${agentDID}`);
    }
  }

  // Get activity trends
  console.log('\nActivity Trends (Agent 1):');
  try {
    const trends = await monitoring.getActivityTrends(agents[0], 1);
    trends.forEach(trend => {
      console.log(`  ${trend.date}: ${trend.count} activities, ${(trend.errorRate * 100).toFixed(1)}% errors`);
    });
  } catch (error) {
    console.log('  - Trends not available (insufficient data)');
  }

  // Compare agents
  console.log('\nAgent Comparison:');
  try {
    const comparison = await monitoring.compareAgents(agents, 'hour');
    Object.entries(comparison).forEach(([agentDID, summary]) => {
      console.log(`  ${agentDID}: ${summary.totalActivities} activities, ${(summary.errorRate * 100).toFixed(1)}% errors`);
    });
  } catch (error) {
    console.log('  - Comparison not available (insufficient data)');
  }

  await monitoring.stop();
}

// Run examples
async function runExamples() {
  console.log('=== Agent Activity Real-time Streaming Examples ===');

  try {
    await basicStreamingExample();
    await agentSpecificStreamingExample();
    await webSocketServerExample();
    await monitoringDashboardExample();
    
    console.log('\n=== All Real-time Examples Completed Successfully ===');
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Execute
runExamples().catch(console.error);