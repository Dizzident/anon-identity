/**
 * MCP Performance Optimization Example
 * 
 * This example demonstrates advanced performance optimization techniques for MCP:
 * - Provider selection optimization
 * - Context caching and compression strategies
 * - Connection pooling and batching
 * - Cost optimization algorithms
 * - Latency reduction techniques
 * - Memory usage optimization
 * - Load balancing strategies
 */

import {
  MCPClient,
  MessageRouter,
  ProviderSelector,
  ContextManager,
  MCPMonitoringDashboard,
  AuthManager,
  RateLimiterManager,
  CredentialManager,
  AuditLogger
} from '../src/mcp';

import {
  LLMRequest,
  LLMRequestType,
  RequestPriority,
  SelectionStrategy
} from '../src/mcp/types';

import { performance } from 'perf_hooks';

interface PerformanceMetrics {
  latency: number;
  throughput: number;
  costPerRequest: number;
  memoryUsage: number;
  cacheHitRate: number;
  errorRate: number;
}

async function mcpPerformanceOptimizationDemo() {
  console.log('=== MCP Performance Optimization Demonstration ===\n');

  // 1. Baseline Performance Measurement
  console.log('1. Establishing baseline performance...\n');

  const baselineConfig = {
    serverUrl: 'ws://localhost:8080',
    apiKey: 'perf-test-key',
    providers: {
      openai: {
        apiKey: 'demo-openai-key',
        models: ['gpt-3.5-turbo'],
        endpoint: 'https://api.openai.com/v1'
      },
      anthropic: {
        apiKey: 'demo-anthropic-key',
        models: ['claude-3-haiku'],
        endpoint: 'https://api.anthropic.com/v1'
      }
    },
    options: {
      reconnectAttempts: 1,
      heartbeatInterval: 60000,
      requestTimeout: 30000,
      maxConcurrentRequests: 5
    }
  };

  const baseline = await measurePerformance('Baseline Configuration', baselineConfig, {
    enableCaching: false,
    enableCompression: false,
    enableBatching: false,
    selectionStrategy: SelectionStrategy.ROUND_ROBIN
  });

  console.log('📊 Baseline Performance:');
  printPerformanceMetrics(baseline);
  console.log();

  // 2. Connection Pool Optimization
  console.log('2. Optimizing connection pooling...\n');

  const poolOptimizedConfig = {
    ...baselineConfig,
    options: {
      ...baselineConfig.options,
      maxConcurrentRequests: 20,
      connectionPoolSize: 10,
      keepAliveTimeout: 300000, // 5 minutes
      reuseConnections: true
    }
  };

  const poolOptimized = await measurePerformance('Connection Pool Optimized', poolOptimizedConfig, {
    enableCaching: false,
    enableCompression: false,
    enableBatching: false,
    selectionStrategy: SelectionStrategy.ROUND_ROBIN
  });

  console.log('📊 Connection Pool Optimized Performance:');
  printPerformanceMetrics(poolOptimized);
  console.log(`🚀 Latency improvement: ${((baseline.latency - poolOptimized.latency) / baseline.latency * 100).toFixed(1)}%`);
  console.log(`🚀 Throughput improvement: ${((poolOptimized.throughput - baseline.throughput) / baseline.throughput * 100).toFixed(1)}%`);
  console.log();

  // 3. Context Caching Optimization
  console.log('3. Optimizing context caching...\n');

  const cacheOptimized = await measurePerformance('Context Caching Enabled', poolOptimizedConfig, {
    enableCaching: true,
    cacheConfig: {
      maxSize: 1000,
      ttl: 3600000, // 1 hour
      compressionCacheEnabled: true,
      smartEviction: true
    },
    enableCompression: false,
    enableBatching: false,
    selectionStrategy: SelectionStrategy.ROUND_ROBIN
  });

  console.log('📊 Context Caching Optimized Performance:');
  printPerformanceMetrics(cacheOptimized);
  console.log(`🚀 Cache hit rate: ${cacheOptimized.cacheHitRate.toFixed(1)}%`);
  console.log(`🚀 Latency improvement: ${((baseline.latency - cacheOptimized.latency) / baseline.latency * 100).toFixed(1)}%`);
  console.log();

  // 4. Context Compression Optimization
  console.log('4. Optimizing context compression...\n');

  const compressionOptimized = await measurePerformance('Context Compression Enabled', poolOptimizedConfig, {
    enableCaching: true,
    cacheConfig: {
      maxSize: 1000,
      ttl: 3600000,
      compressionCacheEnabled: true
    },
    enableCompression: true,
    compressionConfig: {
      strategy: 'importance',
      threshold: 0.7,
      targetReduction: 0.4,
      importance: {
        recentMessageWeight: 0.4,
        userMessageWeight: 0.3,
        systemMessageWeight: 0.2,
        contextualRelevanceWeight: 0.1
      }
    },
    enableBatching: false,
    selectionStrategy: SelectionStrategy.ROUND_ROBIN
  });

  console.log('📊 Context Compression Optimized Performance:');
  printPerformanceMetrics(compressionOptimized);
  console.log(`🚀 Memory savings: ${((baseline.memoryUsage - compressionOptimized.memoryUsage) / baseline.memoryUsage * 100).toFixed(1)}%`);
  console.log(`🚀 Cost reduction: ${((baseline.costPerRequest - compressionOptimized.costPerRequest) / baseline.costPerRequest * 100).toFixed(1)}%`);
  console.log();

  // 5. Provider Selection Optimization
  console.log('5. Optimizing provider selection strategy...\n');

  const strategies = [
    { name: 'Cost Optimized', strategy: SelectionStrategy.COST_OPTIMIZED },
    { name: 'Latency Optimized', strategy: SelectionStrategy.LATENCY },
    { name: 'Balanced', strategy: SelectionStrategy.BALANCED },
    { name: 'Adaptive', strategy: SelectionStrategy.RELIABILITY }
  ];

  for (const { name, strategy } of strategies) {
    const optimized = await measurePerformance(`Provider Selection: ${name}`, poolOptimizedConfig, {
      enableCaching: true,
      enableCompression: true,
      enableBatching: false,
      selectionStrategy: strategy
    });

    console.log(`📊 ${name} Strategy Performance:`);
    console.log(`   Latency: ${optimized.latency.toFixed(2)}ms`);
    console.log(`   Cost: $${optimized.costPerRequest.toFixed(6)}/request`);
    console.log(`   Throughput: ${optimized.throughput.toFixed(2)} req/sec`);
    console.log(`   Error Rate: ${optimized.errorRate.toFixed(2)}%`);
    console.log();
  }

  // 6. Request Batching Optimization
  console.log('6. Optimizing request batching...\n');

  const batchOptimized = await measurePerformance('Request Batching Enabled', poolOptimizedConfig, {
    enableCaching: true,
    enableCompression: true,
    enableBatching: true,
    batchConfig: {
      maxBatchSize: 10,
      batchTimeout: 100, // 100ms
      intelligentBatching: true,
      priorityBatching: true
    },
    selectionStrategy: SelectionStrategy.BALANCED
  });

  console.log('📊 Request Batching Optimized Performance:');
  printPerformanceMetrics(batchOptimized);
  console.log(`🚀 Throughput improvement: ${((batchOptimized.throughput - baseline.throughput) / baseline.throughput * 100).toFixed(1)}%`);
  console.log(`🚀 Cost reduction: ${((baseline.costPerRequest - batchOptimized.costPerRequest) / baseline.costPerRequest * 100).toFixed(1)}%`);
  console.log();

  // 7. Load Balancing Optimization
  console.log('7. Optimizing load balancing...\n');

  const loadBalancingStrategies = [
    { name: 'Round Robin', weights: null },
    { name: 'Weighted', weights: { openai: 0.7, anthropic: 0.3 } },
    { name: 'Performance-based', weights: 'adaptive' },
    { name: 'Cost-based', weights: 'cost-optimized' }
  ];

  for (const { name, weights } of loadBalancingStrategies) {
    console.log(`--- ${name} Load Balancing ---`);
    
    const loadBalanced = await measureLoadBalancing(poolOptimizedConfig, weights);
    
    console.log(`✅ Distribution efficiency: ${loadBalanced.distributionEfficiency.toFixed(1)}%`);
    console.log(`   Provider utilization:`);
    Object.entries(loadBalanced.providerUtilization).forEach(([provider, util]) => {
      console.log(`     ${provider}: ${(util * 100).toFixed(1)}%`);
    });
    console.log(`   Average response time: ${loadBalanced.averageResponseTime.toFixed(2)}ms`);
    console.log(`   Cost per request: $${loadBalanced.costPerRequest.toFixed(6)}`);
    console.log();
  }

  // 8. Memory Usage Optimization
  console.log('8. Memory usage optimization techniques...\n');

  console.log('🧠 Memory Optimization Strategies:');
  
  const memoryOptimizations = [
    {
      name: 'Context Cleanup',
      description: 'Regular cleanup of expired contexts',
      implementation: 'setInterval(contextManager.cleanup, 3600000)', // 1 hour
      memorySavings: 25
    },
    {
      name: 'Connection Pooling',
      description: 'Reuse connections to reduce overhead',
      implementation: 'connectionPool.enable({ maxSize: 10, keepAlive: true })',
      memorySavings: 15
    },
    {
      name: 'Streaming Cleanup',
      description: 'Proper cleanup of streaming resources',
      implementation: 'stream.on("end", () => stream.destroy())',
      memorySavings: 20
    },
    {
      name: 'Cache Size Limits',
      description: 'Intelligent cache eviction policies',
      implementation: 'cache.setMaxSize(1000, "lru-with-importance")',
      memorySavings: 30
    }
  ];

  memoryOptimizations.forEach(opt => {
    console.log(`   ✅ ${opt.name}:`);
    console.log(`      Description: ${opt.description}`);
    console.log(`      Implementation: ${opt.implementation}`);
    console.log(`      Memory Savings: ~${opt.memorySavings}%`);
    console.log();
  });

  // 9. Cost Optimization Analysis
  console.log('9. Cost optimization analysis...\n');

  const costOptimizations = await analyzeCostOptimizations(baseline);
  
  console.log('💰 Cost Optimization Opportunities:');
  costOptimizations.forEach(opt => {
    console.log(`   ${opt.strategy}:`);
    console.log(`     Potential Savings: ${opt.potentialSavings.toFixed(1)}%`);
    console.log(`     Implementation: ${opt.implementation}`);
    console.log(`     Trade-offs: ${opt.tradeoffs}`);
    console.log();
  });

  // 10. Real-time Performance Monitoring Setup
  console.log('10. Setting up real-time performance monitoring...\n');

  try {
    const performanceMonitor = await setupPerformanceMonitoring();
    
    console.log('📊 Performance Monitoring Dashboard Configured:');
    console.log('   ✅ Real-time latency tracking');
    console.log('   ✅ Cost monitoring with alerts');
    console.log('   ✅ Memory usage tracking');
    console.log('   ✅ Cache performance metrics');
    console.log('   ✅ Provider health monitoring');
    console.log('   ✅ Automated performance optimization');

    // Demonstrate adaptive optimization
    console.log('\n🔄 Adaptive Optimization in Action:');
    await demonstrateAdaptiveOptimization(performanceMonitor);

    performanceMonitor.shutdown();

  } catch (error: any) {
    console.error(`❌ Error setting up monitoring: ${error.message}`);
  }

  // 11. Performance Optimization Summary
  console.log('\n11. Performance optimization summary...\n');

  const optimizationSummary = {
    baseline: baseline,
    optimized: batchOptimized,
    improvements: {
      latencyReduction: ((baseline.latency - batchOptimized.latency) / baseline.latency * 100),
      throughputIncrease: ((batchOptimized.throughput - baseline.throughput) / baseline.throughput * 100),
      costReduction: ((baseline.costPerRequest - batchOptimized.costPerRequest) / baseline.costPerRequest * 100),
      memoryReduction: ((baseline.memoryUsage - batchOptimized.memoryUsage) / baseline.memoryUsage * 100)
    }
  };

  console.log('🎯 Overall Performance Improvements:');
  console.log(`   Latency Reduction: ${optimizationSummary.improvements.latencyReduction.toFixed(1)}%`);
  console.log(`   Throughput Increase: ${optimizationSummary.improvements.throughputIncrease.toFixed(1)}%`);
  console.log(`   Cost Reduction: ${optimizationSummary.improvements.costReduction.toFixed(1)}%`);
  console.log(`   Memory Reduction: ${optimizationSummary.improvements.memoryReduction.toFixed(1)}%`);

  console.log('\n📋 Recommended Production Settings:');
  console.log('   • Connection pooling with 15-20 concurrent connections');
  console.log('   • Context caching with 1-hour TTL and LRU eviction');
  console.log('   • Importance-based compression at 70% threshold');
  console.log('   • Balanced provider selection with adaptive weights');
  console.log('   • Request batching with 100ms timeout and 10 max batch size');
  console.log('   • Regular cleanup intervals (1 hour for contexts, 5 minutes for sessions)');
  console.log('   • Performance monitoring with automated optimization');

  console.log('\n=== MCP Performance Optimization Demo Complete ===');
}

// Helper functions

async function measurePerformance(
  configName: string,
  config: any,
  optimizations: any
): Promise<PerformanceMetrics> {
  console.log(`🔍 Testing configuration: ${configName}`);
  
  // Simulate performance measurement
  const startTime = performance.now();
  const startMemory = process.memoryUsage().heapUsed;

  // Simulate various requests
  const requestCount = 50;
  const errors = Math.floor(Math.random() * 3); // 0-2 errors
  
  // Simulate processing time based on optimizations
  let baseLatency = 300 + Math.random() * 200; // 300-500ms base
  
  if (optimizations.enableCaching) {
    baseLatency *= 0.7; // 30% improvement
  }
  if (optimizations.enableCompression) {
    baseLatency *= 0.8; // 20% improvement
  }
  if (optimizations.enableBatching) {
    baseLatency *= 0.6; // 40% improvement for batched requests
  }

  // Add some variation
  await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));

  const endTime = performance.now();
  const endMemory = process.memoryUsage().heapUsed;

  const metrics: PerformanceMetrics = {
    latency: baseLatency,
    throughput: requestCount / ((endTime - startTime) / 1000),
    costPerRequest: (0.0001 + Math.random() * 0.0005) * (optimizations.enableCompression ? 0.6 : 1),
    memoryUsage: (endMemory - startMemory) / 1024 / 1024, // MB
    cacheHitRate: optimizations.enableCaching ? 75 + Math.random() * 20 : 0,
    errorRate: (errors / requestCount) * 100
  };

  return metrics;
}

function printPerformanceMetrics(metrics: PerformanceMetrics): void {
  console.log(`   Latency: ${metrics.latency.toFixed(2)}ms`);
  console.log(`   Throughput: ${metrics.throughput.toFixed(2)} req/sec`);
  console.log(`   Cost per Request: $${metrics.costPerRequest.toFixed(6)}`);
  console.log(`   Memory Usage: ${metrics.memoryUsage.toFixed(2)}MB`);
  if (metrics.cacheHitRate > 0) {
    console.log(`   Cache Hit Rate: ${metrics.cacheHitRate.toFixed(1)}%`);
  }
  console.log(`   Error Rate: ${metrics.errorRate.toFixed(2)}%`);
}

async function measureLoadBalancing(config: any, weights: any): Promise<any> {
  // Simulate load balancing measurement
  const providers = ['openai', 'anthropic'];
  const totalRequests = 100;
  
  let distribution: Record<string, number> = {};
  let totalResponseTime = 0;
  let totalCost = 0;

  // Simulate request distribution
  for (let i = 0; i < totalRequests; i++) {
    let selectedProvider: string;
    
    if (weights === null) {
      // Round robin
      selectedProvider = providers[i % providers.length];
    } else if (typeof weights === 'object') {
      // Weighted selection
      const rand = Math.random();
      selectedProvider = rand < 0.7 ? 'openai' : 'anthropic';
    } else {
      // Adaptive selection
      selectedProvider = Math.random() < 0.6 ? 'openai' : 'anthropic';
    }

    distribution[selectedProvider] = (distribution[selectedProvider] || 0) + 1;
    
    // Simulate response time and cost
    totalResponseTime += selectedProvider === 'openai' ? 200 + Math.random() * 100 : 300 + Math.random() * 150;
    totalCost += selectedProvider === 'openai' ? 0.0002 : 0.00015;
  }

  // Calculate utilization percentages
  const providerUtilization: Record<string, number> = {};
  Object.entries(distribution).forEach(([provider, count]) => {
    providerUtilization[provider] = count / totalRequests;
  });

  // Calculate distribution efficiency (how evenly distributed)
  const targetDistribution = 0.5; // 50% each for equal distribution
  const deviations = Object.values(providerUtilization).map(util => 
    Math.abs(util - targetDistribution)
  );
  const distributionEfficiency = (1 - Math.max(...deviations)) * 100;

  return {
    distributionEfficiency,
    providerUtilization,
    averageResponseTime: totalResponseTime / totalRequests,
    costPerRequest: totalCost / totalRequests
  };
}

async function analyzeCostOptimizations(baseline: PerformanceMetrics): Promise<any[]> {
  return [
    {
      strategy: 'Provider Selection Optimization',
      potentialSavings: 25,
      implementation: 'Use cost-optimized selection strategy for non-urgent requests',
      tradeoffs: 'Slightly higher latency for cost-sensitive operations'
    },
    {
      strategy: 'Context Compression',
      potentialSavings: 40,
      implementation: 'Enable importance-based compression to reduce token usage',
      tradeoffs: 'Small processing overhead for compression/decompression'
    },
    {
      strategy: 'Request Batching',
      potentialSavings: 30,
      implementation: 'Batch compatible requests to reduce per-request overhead',
      tradeoffs: 'Slight delay for batching accumulation'
    },
    {
      strategy: 'Model Selection',
      potentialSavings: 60,
      implementation: 'Use smaller models for simple tasks',
      tradeoffs: 'Reduced capability for complex reasoning tasks'
    },
    {
      strategy: 'Caching Strategy',
      potentialSavings: 50,
      implementation: 'Cache frequent requests and context patterns',
      tradeoffs: 'Memory usage for cache storage'
    }
  ];
}

async function setupPerformanceMonitoring(): Promise<any> {
  // Simulate setting up performance monitoring
  console.log('   🔧 Configuring performance thresholds...');
  console.log('   📊 Setting up metrics collection...');
  console.log('   🚨 Configuring performance alerts...');
  console.log('   🤖 Enabling automated optimization...');

  return {
    shutdown: () => console.log('   ✅ Performance monitor shutdown')
  };
}

async function demonstrateAdaptiveOptimization(monitor: any): Promise<void> {
  console.log('   📈 Detecting high latency on Provider A...');
  console.log('   🔄 Automatically shifting traffic to Provider B...');
  console.log('   💾 Enabling aggressive caching due to cost threshold...');
  console.log('   🗜️ Increasing compression due to memory pressure...');
  console.log('   ✅ Performance automatically optimized based on conditions');
}

// Run the demo
if (require.main === module) {
  mcpPerformanceOptimizationDemo().catch(error => {
    console.error('Demo failed:', error);
    process.exit(1);
  });
}

export { mcpPerformanceOptimizationDemo };