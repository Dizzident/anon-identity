/**
 * Agent Activity Search and Indexing Example
 * 
 * Demonstrates searching and aggregating agent activities with advanced querying
 */

import { 
  ActivityLogger, 
  ActivityType, 
  ActivityStatus,
  createActivity,
  ActivityIndex,
  ActivitySearchService
} from '../src/agent/activity';

// Example 1: Basic Activity Indexing and Search
async function basicSearchExample() {
  console.log('\n=== Basic Activity Indexing and Search ===\n');

  // Create activity logger with indexing enabled
  const logger = new ActivityLogger({
    batchSize: 10,
    batchInterval: 1000,
    enableIndexing: true,
    enableBatching: false // Disable for immediate indexing
  });

  const agentDID = 'did:key:z6MkSearchAgent123';
  const parentDID = 'did:key:z6MkSearchParent456';
  const serviceDID = 'did:key:z6MkSearchService789';

  // Log various activities
  console.log('Logging sample activities...');
  
  const activities = [
    // Authentication
    createActivity(ActivityType.AUTHENTICATION, {
      agentDID, parentDID, serviceDID,
      status: ActivityStatus.SUCCESS,
      scopes: [],
      details: { message: 'Agent authenticated successfully' }
    }),
    
    // Data access activities
    createActivity(ActivityType.DATA_ACCESS, {
      agentDID, parentDID, serviceDID,
      status: ActivityStatus.SUCCESS,
      scopes: ['read:data', 'list:resources'],
      details: { 
        resourceType: 'user-profile',
        resourceId: 'user-123',
        operation: 'read'
      }
    }),
    
    createActivity(ActivityType.DATA_ACCESS, {
      agentDID, parentDID, serviceDID,
      status: ActivityStatus.SUCCESS,
      scopes: ['read:data'],
      details: { 
        resourceType: 'document',
        resourceId: 'doc-456',
        operation: 'read'
      }
    }),
    
    // Data modification
    createActivity(ActivityType.DATA_MODIFICATION, {
      agentDID, parentDID, serviceDID,
      status: ActivityStatus.FAILED,
      scopes: ['write:data'],
      details: { 
        resourceType: 'document',
        resourceId: 'doc-789',
        operation: 'update',
        errorMessage: 'Insufficient permissions'
      }
    }),
    
    // Scope usage
    createActivity(ActivityType.SCOPE_USAGE, {
      agentDID, parentDID, serviceDID,
      status: ActivityStatus.SUCCESS,
      scopes: ['write:data'],
      details: { 
        scope: 'write:data',
        operation: 'create',
        resourceType: 'note'
      }
    })
  ];

  for (let i = 0; i < activities.length; i++) {
    await logger.logActivity(activities[i]);
    // Add small delay to ensure different timestamps
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  console.log(`Logged ${activities.length} activities`);

  // Get the activity index
  const index = logger.getActivityIndex();
  if (!index) {
    throw new Error('Activity indexing not enabled');
  }

  // Display index statistics
  const stats = index.getStats();
  console.log(`\nIndex Statistics:
  - Total Activities: ${stats.totalActivities}
  - Agents: ${stats.agentCount}
  - Services: ${stats.serviceCount}
  - Date Range: ${stats.dateRange.earliest.toISOString()} to ${stats.dateRange.latest.toISOString()}`);

  console.log(`\nBy Type:`);
  Object.entries(stats.byType).forEach(([type, count]) => {
    console.log(`  - ${type}: ${count}`);
  });

  console.log(`\nBy Status:`);
  Object.entries(stats.byStatus).forEach(([status, count]) => {
    console.log(`  - ${status}: ${count}`);
  });

  await logger.cleanup();
}

// Example 2: Advanced Search Queries
async function advancedSearchExample() {
  console.log('\n=== Advanced Search Queries ===\n');

  const index = new ActivityIndex();
  const searchService = new ActivitySearchService(index);

  // Create sample data for different agents and services
  const agents = ['did:key:z6MkAgent1', 'did:key:z6MkAgent2', 'did:key:z6MkAgent3'];
  const services = ['did:key:z6MkService1', 'did:key:z6MkService2'];
  
  console.log('Creating sample dataset...');
  
  const activities = [];
  for (let i = 0; i < 50; i++) {
    const agentDID = agents[i % agents.length];
    const serviceDID = services[i % services.length];
    const parentDID = `did:key:z6MkParent${(i % 3) + 1}`;
    
    const activity = {
      id: `activity-${i + 1}`,
      agentDID,
      parentDID,
      serviceDID,
      timestamp: new Date(Date.now() - (50 - i) * 60000), // Activities spread over 50 minutes
      type: Object.values(ActivityType)[i % Object.values(ActivityType).length] as ActivityType,
      status: i % 7 === 0 ? ActivityStatus.FAILED : ActivityStatus.SUCCESS, // ~14% failure rate
      scopes: i % 3 === 0 ? ['read:data'] : ['read:data', 'write:data'],
      details: {
        resourceId: `resource-${i + 1}`,
        operation: i % 2 === 0 ? 'read' : 'write',
        metadata: { batch: Math.floor(i / 10) }
      },
      sessionId: `session-${Math.floor(i / 5) + 1}`
    };
    
    activities.push(activity);
  }

  await index.indexActivities(activities);
  console.log(`Indexed ${activities.length} activities`);

  // 1. Search by specific agent
  console.log('\n1. Search by specific agent:');
  const agentResults = await searchService.searchActivities({
    agentDID: 'did:key:z6MkAgent1',
    limit: 5
  });
  console.log(`   Found ${agentResults.total} activities for Agent1 (showing ${agentResults.activities.length})`);

  // 2. Search by activity type
  console.log('\n2. Search by activity type:');
  const typeResults = await searchService.searchActivities({
    types: [ActivityType.DATA_ACCESS, ActivityType.DATA_MODIFICATION],
    limit: 10
  });
  console.log(`   Found ${typeResults.total} data-related activities`);

  // 3. Search failed activities
  console.log('\n3. Search failed activities:');
  const failedResults = await searchService.searchActivities({
    status: [ActivityStatus.FAILED]
  });
  console.log(`   Found ${failedResults.total} failed activities`);
  failedResults.activities.forEach(activity => {
    console.log(`   - ${activity.id}: ${activity.type} (${activity.agentDID})`);
  });

  // 4. Search by scope
  console.log('\n4. Search by scope:');
  const scopeResults = await searchService.searchActivities({
    scopes: ['write:data'],
    limit: 5
  });
  console.log(`   Found ${scopeResults.total} activities with write:data scope`);

  // 5. Search by date range
  console.log('\n5. Search by date range (last 30 minutes):');
  const thirtyMinutesAgo = new Date(Date.now() - 30 * 60000);
  const now = new Date();
  const dateResults = await searchService.searchActivities({
    dateRange: { start: thirtyMinutesAgo, end: now },
    sortBy: 'timestamp',
    sortOrder: 'desc'
  });
  console.log(`   Found ${dateResults.total} activities in the last 30 minutes`);

  // 6. Combined search
  console.log('\n6. Combined search (Agent1, successful, with write scope):');
  const combinedResults = await searchService.searchActivities({
    agentDID: 'did:key:z6MkAgent1',
    status: [ActivityStatus.SUCCESS],
    scopes: ['write:data'],
    sortBy: 'timestamp',
    sortOrder: 'desc'
  });
  console.log(`   Found ${combinedResults.total} matching activities`);
}

// Example 3: Activity Summaries and Analytics
async function analyticsExample() {
  console.log('\n=== Activity Summaries and Analytics ===\n');

  const index = new ActivityIndex();
  const searchService = new ActivitySearchService(index);

  // Create realistic activity data
  const agentDID = 'did:key:z6MkAnalyticsAgent';
  const parentDID = 'did:key:z6MkAnalyticsParent';
  const services = ['did:key:z6MkService1', 'did:key:z6MkService2', 'did:key:z6MkService3'];

  console.log('Generating analytics dataset...');
  
  const activities = [];
  const now = new Date();
  
  // Generate activities over the past week
  for (let day = 0; day < 7; day++) {
    for (let hour = 8; hour < 18; hour++) { // Business hours
      const activitiesPerHour = Math.floor(Math.random() * 10) + 5; // 5-15 activities per hour
      
      for (let i = 0; i < activitiesPerHour; i++) {
        const timestamp = new Date(now);
        timestamp.setDate(timestamp.getDate() - (6 - day));
        timestamp.setHours(hour, Math.floor(Math.random() * 60), 0, 0);
        
        const serviceDID = services[Math.floor(Math.random() * services.length)];
        const types = Object.values(ActivityType);
        const type = types[Math.floor(Math.random() * types.length)] as ActivityType;
        
        // Higher failure rate during peak hours (12-14)
        const isFailure = (hour >= 12 && hour <= 14) ? 
          Math.random() < 0.2 : Math.random() < 0.05;
        
        const activity = {
          id: `analytics-${day}-${hour}-${i}`,
          agentDID,
          parentDID,
          serviceDID,
          timestamp,
          type,
          status: isFailure ? ActivityStatus.FAILED : ActivityStatus.SUCCESS,
          scopes: Math.random() < 0.7 ? ['read:data'] : ['read:data', 'write:data'],
          details: {
            hour,
            day,
            operation: Math.random() < 0.6 ? 'read' : 'write'
          },
          duration: Math.floor(Math.random() * 1000) + 100 // 100-1100ms
        };
        
        activities.push(activity);
      }
    }
  }

  await index.indexActivities(activities);
  console.log(`Generated ${activities.length} activities over 7 days`);

  // Generate daily summary
  console.log('\n1. Daily Activity Summary:');
  const dailySummary = await searchService.getActivitySummary(agentDID, 'day');
  console.log(`   Agent: ${dailySummary.agentDID}`);
  console.log(`   Period: ${dailySummary.period.start.toDateString()}`);
  console.log(`   Total Activities: ${dailySummary.totalActivities}`);
  console.log(`   Average Duration: ${dailySummary.averageDuration.toFixed(2)}ms`);
  console.log(`   Error Rate: ${(dailySummary.errorRate * 100).toFixed(2)}%`);
  console.log(`   Peak Hour: ${dailySummary.peakHour || 'N/A'}`);
  console.log(`   Most Used Service: ${dailySummary.mostUsedService || 'N/A'}`);

  // Generate weekly trends
  console.log('\n2. Weekly Activity Trends:');
  const trends = await searchService.getActivityTrends(agentDID, 7);
  console.log('   Date       | Count | Error Rate | Top Activity Type');
  console.log('   -----------|-------|------------|------------------');
  trends.forEach(trend => {
    const topType = Object.entries(trend.byType)
      .sort(([,a], [,b]) => b - a)[0]?.[0] || 'None';
    console.log(`   ${trend.date} |  ${trend.count.toString().padStart(3)} |    ${(trend.errorRate * 100).toFixed(1)}%    | ${topType}`);
  });

  // Service usage comparison
  console.log('\n3. Service Usage Breakdown:');
  const serviceStats: Record<string, number> = {};
  activities.forEach(activity => {
    serviceStats[activity.serviceDID] = (serviceStats[activity.serviceDID] || 0) + 1;
  });
  
  Object.entries(serviceStats)
    .sort(([,a], [,b]) => b - a)
    .forEach(([service, count]) => {
      const percentage = (count / activities.length * 100).toFixed(1);
      console.log(`   ${service}: ${count} activities (${percentage}%)`);
    });

  // Peak hours analysis
  console.log('\n4. Peak Hours Analysis:');
  const hourlyStats: Record<number, number> = {};
  activities.forEach(activity => {
    const hour = activity.timestamp.getHours();
    hourlyStats[hour] = (hourlyStats[hour] || 0) + 1;
  });
  
  const sortedHours = Object.entries(hourlyStats)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 5);
  
  sortedHours.forEach(([hour, count], index) => {
    console.log(`   ${index + 1}. ${hour}:00 - ${count} activities`);
  });
}

// Example 4: Real-time Search with Activity Logger
async function realTimeSearchExample() {
  console.log('\n=== Real-time Search with Activity Logger ===\n');

  const logger = new ActivityLogger({
    batchSize: 5,
    batchInterval: 2000,
    enableIndexing: true,
    enableRealtime: true
  });

  const index = logger.getActivityIndex();
  if (!index) {
    throw new Error('Activity indexing not enabled');
  }

  const searchService = new ActivitySearchService(index);

  // Subscribe to real-time updates
  const subscription = logger.subscribe(
    { types: [ActivityType.DATA_ACCESS] },
    (activity) => {
      console.log(`[Real-time] New data access: ${activity.id} - ${activity.status}`);
    }
  );

  console.log('Starting real-time activity logging and searching...');

  const agentDID = 'did:key:z6MkRealtimeAgent';
  const parentDID = 'did:key:z6MkRealtimeParent';
  const serviceDID = 'did:key:z6MkRealtimeService';

  // Log activities over time
  for (let i = 0; i < 15; i++) {
    const types = [ActivityType.DATA_ACCESS, ActivityType.DATA_MODIFICATION, ActivityType.SCOPE_USAGE];
    const type = types[i % types.length];
    
    await logger.logActivity(createActivity(type, {
      agentDID, parentDID, serviceDID,
      status: i % 4 === 0 ? ActivityStatus.FAILED : ActivityStatus.SUCCESS,
      scopes: ['read:data', 'write:data'],
      details: { 
        operation: `operation-${i + 1}`,
        step: i + 1
      }
    }));

    // Search current state every few activities
    if ((i + 1) % 5 === 0) {
      const currentStats = index.getStats();
      console.log(`\n[Search Update] After ${i + 1} activities:`);
      console.log(`  - Total indexed: ${currentStats.totalActivities}`);
      
      const recentActivities = await searchService.getRecentActivities(agentDID, 3);
      console.log(`  - Recent activities: ${recentActivities.map(a => a.type).join(', ')}`);
      
      const failedCount = await searchService.searchActivities({
        agentDID,
        status: [ActivityStatus.FAILED]
      });
      console.log(`  - Failed activities: ${failedCount.total}`);
    }

    await new Promise(resolve => setTimeout(resolve, 300));
  }

  console.log('\nFinal search results:');
  const finalResults = await searchService.searchActivities({
    agentDID,
    sortBy: 'timestamp',
    sortOrder: 'desc'
  });
  
  console.log(`Total activities logged: ${finalResults.total}`);
  console.log('Latest 3 activities:');
  finalResults.activities.slice(0, 3).forEach((activity, index) => {
    console.log(`  ${index + 1}. ${activity.type} - ${activity.status} (${activity.timestamp.toISOString()})`);
  });

  subscription.unsubscribe();
  await logger.cleanup();
}

// Run examples
async function runExamples() {
  console.log('=== Agent Activity Search and Indexing Examples ===');

  try {
    await basicSearchExample();
    await advancedSearchExample();
    await analyticsExample();
    await realTimeSearchExample();
    
    console.log('\n=== All Examples Completed Successfully ===');
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Execute
runExamples().catch(console.error);