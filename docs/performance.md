# Performance Optimization Guide

Comprehensive guide for optimizing anon-identity library performance in production environments.

## Performance Characteristics

### Baseline Performance Metrics

#### Single Operations (typical hardware)
- **Credential verification**: 20-50ms
- **Session creation**: 5-15ms
- **Session validation**: 1-5ms
- **Selective disclosure**: 30-80ms
- **Key generation**: 10-30ms

#### Batch Operations
- **100 credentials**: 2-5 seconds
- **1000 credentials**: 15-30 seconds
- **Concurrent limit**: 10 operations (configurable)

## Memory Optimization

### Efficient Credential Management
```typescript
class OptimizedCredentialManager {
  private credentialCache = new LRUCache<string, VerifiableCredential>({
    max: 1000,
    ttl: 300000, // 5 minutes
    updateAgeOnGet: true
  });
  
  async getCredential(id: string): Promise<VerifiableCredential | null> {
    // Check cache first
    const cached = this.credentialCache.get(id);
    if (cached) {
      return cached;
    }
    
    // Fetch from storage
    const credential = await this.storage.getCredential(id);
    if (credential) {
      this.credentialCache.set(id, credential);
    }
    
    return credential;
  }
  
  // Preload frequently accessed credentials
  async preloadCredentials(credentialIds: string[]): Promise<void> {
    const uncached = credentialIds.filter(id => !this.credentialCache.has(id));
    
    if (uncached.length > 0) {
      const credentials = await this.storage.batchGetCredentials(uncached);
      credentials.forEach(cred => {
        if (cred) this.credentialCache.set(cred.id, cred);
      });
    }
  }
}
```

### Memory-Efficient Batch Processing
```typescript
class StreamingBatchProcessor {
  async processLargeBatch<T, R>(
    items: T[],
    processor: (item: T) => Promise<R>,
    options: {
      batchSize?: number;
      concurrency?: number;
      memoryThreshold?: number; // MB
    } = {}
  ): Promise<R[]> {
    const {
      batchSize = 100,
      concurrency = 10,
      memoryThreshold = 500 // 500MB
    } = options;
    
    const results: R[] = [];
    
    for (let i = 0; i < items.length; i += batchSize) {
      // Check memory usage
      const memoryUsage = process.memoryUsage();
      if (memoryUsage.heapUsed / 1024 / 1024 > memoryThreshold) {
        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
        
        // Wait for memory to stabilize
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      const batch = items.slice(i, i + batchSize);
      const batchResults = await this.processBatchConcurrently(batch, processor, concurrency);
      results.push(...batchResults);
      
      // Progress reporting
      console.log(`Processed ${Math.min(i + batchSize, items.length)}/${items.length} items`);
    }
    
    return results;
  }
  
  private async processBatchConcurrently<T, R>(
    batch: T[],
    processor: (item: T) => Promise<R>,
    concurrency: number
  ): Promise<R[]> {
    const results: R[] = [];
    
    for (let i = 0; i < batch.length; i += concurrency) {
      const chunk = batch.slice(i, i + concurrency);
      const chunkResults = await Promise.all(chunk.map(processor));
      results.push(...chunkResults);
    }
    
    return results;
  }
}
```

## CPU Optimization

### Cryptographic Operation Optimization
```typescript
class OptimizedCryptoService {
  private static workerPool?: Worker[];
  private static keyCache = new Map<string, CryptoKey>();
  
  // Use Web Workers for CPU-intensive operations
  static async initializeWorkerPool(poolSize: number = 4): Promise<void> {
    this.workerPool = [];
    
    for (let i = 0; i < poolSize; i++) {
      const worker = new Worker('./crypto-worker.js');
      this.workerPool.push(worker);
    }
  }
  
  // Cache frequently used keys
  static async getCachedKey(publicKeyBytes: Uint8Array): Promise<CryptoKey> {
    const keyId = Buffer.from(publicKeyBytes).toString('base64');
    
    if (this.keyCache.has(keyId)) {
      return this.keyCache.get(keyId)!;
    }
    
    const key = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    
    this.keyCache.set(keyId, key);
    return key;
  }
  
  // Batch signature verification
  static async batchVerifySignatures(
    operations: Array<{
      data: Uint8Array;
      signature: Uint8Array;
      publicKey: Uint8Array;
    }>
  ): Promise<boolean[]> {
    if (!this.workerPool || this.workerPool.length === 0) {
      // Fallback to sequential processing
      return Promise.all(operations.map(op => this.verifySignature(op.data, op.signature, op.publicKey)));
    }
    
    // Distribute work across workers
    const results: boolean[] = new Array(operations.length);
    const chunks = this.chunkArray(operations, this.workerPool.length);
    
    const workerPromises = chunks.map((chunk, index) => {
      return this.processChunkInWorker(this.workerPool![index], chunk, index * chunk.length);
    });
    
    const chunkResults = await Promise.all(workerPromises);
    
    // Flatten results
    chunkResults.forEach((chunkResult, chunkIndex) => {
      chunkResult.forEach((result, resultIndex) => {
        results[chunkIndex * chunks[chunkIndex].length + resultIndex] = result;
      });
    });
    
    return results;
  }
  
  private static chunkArray<T>(array: T[], chunkCount: number): T[][] {
    const chunks: T[][] = [];
    const chunkSize = Math.ceil(array.length / chunkCount);
    
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    
    return chunks;
  }
}
```

### Parallel Processing
```typescript
class ParallelVerificationService {
  private serviceProvider: ServiceProvider;
  private maxConcurrency: number;
  
  constructor(serviceProvider: ServiceProvider, maxConcurrency: number = 10) {
    this.serviceProvider = serviceProvider;
    this.maxConcurrency = maxConcurrency;
  }
  
  async verifyPresentationsParallel(
    presentations: VerifiablePresentation[]
  ): Promise<BatchVerificationResult[]> {
    const semaphore = new Semaphore(this.maxConcurrency);
    
    const verificationPromises = presentations.map(async (presentation, index) => {
      return semaphore.execute(async () => {
        const startTime = Date.now();
        
        try {
          const result = await this.serviceProvider.verifyPresentation(presentation);
          
          return {
            presentationIndex: index,
            result,
            processingTime: Date.now() - startTime
          };
        } catch (error) {
          return {
            presentationIndex: index,
            result: {
              valid: false,
              errors: [new VerificationError(
                VerificationErrorCode.NETWORK_ERROR,
                `Verification failed: ${error.message}`
              )],
              timestamp: new Date()
            },
            processingTime: Date.now() - startTime
          };
        }
      });
    });
    
    return Promise.all(verificationPromises);
  }
}

class Semaphore {
  private permits: number;
  private waiting: (() => void)[] = [];
  
  constructor(permits: number) {
    this.permits = permits;
  }
  
  async execute<T>(task: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await task();
    } finally {
      this.release();
    }
  }
  
  private async acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return;
    }
    
    return new Promise<void>(resolve => {
      this.waiting.push(resolve);
    });
  }
  
  private release(): void {
    this.permits++;
    
    if (this.waiting.length > 0) {
      this.permits--;
      const resolve = this.waiting.shift()!;
      resolve();
    }
  }
}
```

## Storage Optimization

### Connection Pooling
```typescript
class OptimizedStorageProvider {
  private connectionPool: Pool;
  private queryCache = new LRUCache<string, any>({
    max: 500,
    ttl: 60000 // 1 minute cache
  });
  
  constructor(config: PoolConfig) {
    this.connectionPool = new Pool({
      ...config,
      min: 2,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
      acquireTimeoutMillis: 60000
    });
    
    // Monitor pool health
    this.setupPoolMonitoring();
  }
  
  async getCredential(credentialId: string): Promise<VerifiableCredential | null> {
    const cacheKey = `credential:${credentialId}`;
    
    // Check cache first
    if (this.queryCache.has(cacheKey)) {
      return this.queryCache.get(cacheKey);
    }
    
    const client = await this.connectionPool.connect();
    
    try {
      const query = 'SELECT data FROM credentials WHERE id = $1';
      const result = await client.query(query, [credentialId]);
      
      const credential = result.rows[0]?.data || null;
      
      // Cache result
      if (credential) {
        this.queryCache.set(cacheKey, credential);
      }
      
      return credential;
    } finally {
      client.release();
    }
  }
  
  async batchGetCredentials(credentialIds: string[]): Promise<(VerifiableCredential | null)[]> {
    if (credentialIds.length === 0) return [];
    
    // Check cache for each credential
    const results: (VerifiableCredential | null)[] = new Array(credentialIds.length);
    const uncachedIndices: number[] = [];
    const uncachedIds: string[] = [];
    
    credentialIds.forEach((id, index) => {
      const cacheKey = `credential:${id}`;
      if (this.queryCache.has(cacheKey)) {
        results[index] = this.queryCache.get(cacheKey);
      } else {
        uncachedIndices.push(index);
        uncachedIds.push(id);
      }
    });
    
    // Fetch uncached credentials
    if (uncachedIds.length > 0) {
      const client = await this.connectionPool.connect();
      
      try {
        const placeholders = uncachedIds.map((_, i) => `$${i + 1}`).join(',');
        const query = `SELECT id, data FROM credentials WHERE id IN (${placeholders})`;
        const result = await client.query(query, uncachedIds);
        
        // Map results back to original positions
        const fetchedMap = new Map(result.rows.map(row => [row.id, row.data]));
        
        uncachedIndices.forEach((originalIndex, fetchIndex) => {
          const id = uncachedIds[fetchIndex];
          const credential = fetchedMap.get(id) || null;
          results[originalIndex] = credential;
          
          // Cache the result
          if (credential) {
            this.queryCache.set(`credential:${id}`, credential);
          }
        });
      } finally {
        client.release();
      }
    }
    
    return results;
  }
  
  private setupPoolMonitoring(): void {
    setInterval(() => {
      const totalCount = this.connectionPool.totalCount;
      const idleCount = this.connectionPool.idleCount;
      const waitingCount = this.connectionPool.waitingCount;
      
      console.log(`Pool stats: Total=${totalCount}, Idle=${idleCount}, Waiting=${waitingCount}`);
      
      // Alert if pool is under stress
      if (waitingCount > 5) {
        console.warn('Database connection pool under stress');
      }
    }, 30000);
  }
}
```

### Efficient Caching Strategy
```typescript
class MultiLevelCache {
  private l1Cache: LRUCache<string, any>; // Memory cache
  private l2Cache: Redis.Redis; // Redis cache
  
  constructor(redisClient: Redis.Redis) {
    this.l1Cache = new LRUCache({
      max: 1000,
      ttl: 60000 // 1 minute
    });
    this.l2Cache = redisClient;
  }
  
  async get(key: string): Promise<any> {
    // Try L1 cache first
    if (this.l1Cache.has(key)) {
      return this.l1Cache.get(key);
    }
    
    // Try L2 cache
    try {
      const cached = await this.l2Cache.get(key);
      if (cached) {
        const value = JSON.parse(cached);
        this.l1Cache.set(key, value);
        return value;
      }
    } catch (error) {
      console.warn('L2 cache error:', error);
    }
    
    return null;
  }
  
  async set(key: string, value: any, ttl: number = 300): Promise<void> {
    // Set in both caches
    this.l1Cache.set(key, value);
    
    try {
      await this.l2Cache.setex(key, ttl, JSON.stringify(value));
    } catch (error) {
      console.warn('L2 cache set error:', error);
    }
  }
  
  async invalidate(key: string): Promise<void> {
    this.l1Cache.delete(key);
    
    try {
      await this.l2Cache.del(key);
    } catch (error) {
      console.warn('L2 cache delete error:', error);
    }
  }
}
```

## Network Optimization

### Request Batching
```typescript
class BatchedVerificationClient {
  private pendingRequests: Map<string, Promise<VerificationResult>> = new Map();
  private batchQueue: Array<{
    presentation: VerifiablePresentation;
    resolve: (result: VerificationResult) => void;
    reject: (error: Error) => void;
  }> = [];
  private batchTimer?: NodeJS.Timeout;
  
  async verifyPresentation(presentation: VerifiablePresentation): Promise<VerificationResult> {
    const presentationHash = this.hashPresentation(presentation);
    
    // Check if already being processed
    if (this.pendingRequests.has(presentationHash)) {
      return this.pendingRequests.get(presentationHash)!;
    }
    
    // Create promise for this request
    const promise = new Promise<VerificationResult>((resolve, reject) => {
      this.batchQueue.push({ presentation, resolve, reject });
      this.scheduleBatch();
    });
    
    this.pendingRequests.set(presentationHash, promise);
    
    try {
      const result = await promise;
      return result;
    } finally {
      this.pendingRequests.delete(presentationHash);
    }
  }
  
  private scheduleBatch(): void {
    if (this.batchTimer) return;
    
    this.batchTimer = setTimeout(async () => {
      await this.processBatch();
      this.batchTimer = undefined;
    }, 50); // 50ms batch window
  }
  
  private async processBatch(): Promise<void> {
    if (this.batchQueue.length === 0) return;
    
    const batch = this.batchQueue.splice(0, 10); // Process up to 10 at once
    
    try {
      const presentations = batch.map(item => item.presentation);
      const results = await this.serviceProvider.batchVerifyPresentations(presentations);
      
      batch.forEach((item, index) => {
        item.resolve(results[index].result);
      });
    } catch (error) {
      batch.forEach(item => {
        item.reject(error);
      });
    }
  }
  
  private hashPresentation(presentation: VerifiablePresentation): string {
    return crypto
      .createHash('sha256')
      .update(JSON.stringify(presentation))
      .digest('hex');
  }
}
```

### Connection Keep-Alive
```typescript
// HTTP client optimization
const httpClient = axios.create({
  timeout: 30000,
  maxRedirects: 3,
  httpAgent: new http.Agent({
    keepAlive: true,
    maxSockets: 50,
    maxFreeSockets: 10,
    timeout: 60000,
    freeSocketTimeout: 30000
  }),
  httpsAgent: new https.Agent({
    keepAlive: true,
    maxSockets: 50,
    maxFreeSockets: 10,
    timeout: 60000,
    freeSocketTimeout: 30000
  })
});

// Request compression
httpClient.defaults.headers['Accept-Encoding'] = 'gzip, deflate, br';
```

## Performance Monitoring

### Metrics Collection
```typescript
class PerformanceMonitor {
  private metrics = new Map<string, number[]>();
  private gauges = new Map<string, number>();
  
  recordTiming(operation: string, duration: number): void {
    if (!this.metrics.has(operation)) {
      this.metrics.set(operation, []);
    }
    
    const timings = this.metrics.get(operation)!;
    timings.push(duration);
    
    // Keep only last 1000 measurements
    if (timings.length > 1000) {
      timings.shift();
    }
  }
  
  setGauge(metric: string, value: number): void {
    this.gauges.set(metric, value);
  }
  
  getStatistics(operation: string): {
    count: number;
    avg: number;
    p50: number;
    p95: number;
    p99: number;
    min: number;
    max: number;
  } | null {
    const timings = this.metrics.get(operation);
    if (!timings || timings.length === 0) {
      return null;
    }
    
    const sorted = [...timings].sort((a, b) => a - b);
    const count = sorted.length;
    
    return {
      count,
      avg: sorted.reduce((a, b) => a + b, 0) / count,
      p50: sorted[Math.floor(count * 0.5)],
      p95: sorted[Math.floor(count * 0.95)],
      p99: sorted[Math.floor(count * 0.99)],
      min: sorted[0],
      max: sorted[count - 1]
    };
  }
  
  exportMetrics(): Record<string, any> {
    const exported: Record<string, any> = {};
    
    // Export timing statistics
    for (const [operation, _] of this.metrics) {
      exported[operation] = this.getStatistics(operation);
    }
    
    // Export gauges
    for (const [metric, value] of this.gauges) {
      exported[metric] = value;
    }
    
    // Add system metrics
    const memUsage = process.memoryUsage();
    exported.system = {
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      external: memUsage.external,
      rss: memUsage.rss
    };
    
    return exported;
  }
}

// Instrumentation wrapper
function instrument<T extends any[], R>(
  operation: string,
  fn: (...args: T) => Promise<R>
): (...args: T) => Promise<R> {
  return async (...args: T): Promise<R> => {
    const startTime = Date.now();
    
    try {
      const result = await fn(...args);
      monitor.recordTiming(operation, Date.now() - startTime);
      return result;
    } catch (error) {
      monitor.recordTiming(`${operation}_error`, Date.now() - startTime);
      throw error;
    }
  };
}

// Usage
const instrumentedVerify = instrument('credential_verification', 
  serviceProvider.verifyPresentation.bind(serviceProvider)
);
```

### Performance Profiling
```typescript
class ProfiledServiceProvider extends ServiceProvider {
  private profiler = new PerformanceMonitor();
  
  async verifyPresentation(presentation: VerifiablePresentation): Promise<VerificationResult> {
    const startTime = process.hrtime.bigint();
    
    try {
      const result = await super.verifyPresentation(presentation);
      
      const duration = Number(process.hrtime.bigint() - startTime) / 1_000_000; // Convert to ms
      this.profiler.recordTiming('verification_total', duration);
      
      if (result.valid) {
        this.profiler.recordTiming('verification_success', duration);
      } else {
        this.profiler.recordTiming('verification_failure', duration);
      }
      
      return result;
    } catch (error) {
      const duration = Number(process.hrtime.bigint() - startTime) / 1_000_000;
      this.profiler.recordTiming('verification_error', duration);
      throw error;
    }
  }
  
  getPerformanceReport(): any {
    return this.profiler.exportMetrics();
  }
}
```

## Load Testing

### Stress Testing Framework
```typescript
class LoadTester {
  async runVerificationLoadTest(
    serviceProvider: ServiceProvider,
    options: {
      concurrency: number;
      duration: number; // seconds
      requestsPerSecond: number;
    }
  ): Promise<LoadTestResults> {
    const { concurrency, duration, requestsPerSecond } = options;
    const endTime = Date.now() + duration * 1000;
    
    const results: LoadTestResults = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      p95ResponseTime: 0,
      requestsPerSecond: 0,
      errors: new Map()
    };
    
    const responseTimes: number[] = [];
    const workers: Promise<void>[] = [];
    
    // Create worker threads
    for (let i = 0; i < concurrency; i++) {
      workers.push(this.createWorker(serviceProvider, endTime, requestsPerSecond / concurrency, results, responseTimes));
    }
    
    await Promise.all(workers);
    
    // Calculate final statistics
    responseTimes.sort((a, b) => a - b);
    results.averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    results.p95ResponseTime = responseTimes[Math.floor(responseTimes.length * 0.95)];
    results.requestsPerSecond = results.totalRequests / duration;
    
    return results;
  }
  
  private async createWorker(
    serviceProvider: ServiceProvider,
    endTime: number,
    rps: number,
    results: LoadTestResults,
    responseTimes: number[]
  ): Promise<void> {
    const intervalMs = 1000 / rps;
    
    while (Date.now() < endTime) {
      const startTime = Date.now();
      
      try {
        const presentation = await this.generateTestPresentation();
        const result = await serviceProvider.verifyPresentation(presentation);
        
        results.totalRequests++;
        
        if (result.valid) {
          results.successfulRequests++;
        } else {
          results.failedRequests++;
        }
        
        responseTimes.push(Date.now() - startTime);
      } catch (error) {
        results.totalRequests++;
        results.failedRequests++;
        
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        results.errors.set(errorMessage, (results.errors.get(errorMessage) || 0) + 1);
      }
      
      // Rate limiting
      const elapsed = Date.now() - startTime;
      const waitTime = Math.max(0, intervalMs - elapsed);
      if (waitTime > 0) {
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
  }
}

interface LoadTestResults {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  p95ResponseTime: number;
  requestsPerSecond: number;
  errors: Map<string, number>;
}
```

## Configuration Tuning

### Production Configuration
```typescript
const productionConfig = {
  serviceProvider: {
    sessionManager: {
      defaultSessionDuration: 1800000, // 30 minutes
      maxSessionDuration: 7200000,     // 2 hours
      cleanupInterval: 60000           // 1 minute
    },
    batchOperations: {
      maxConcurrency: 20,              // Higher for production
      timeout: 10000,                  // 10 seconds
      continueOnError: true
    }
  },
  storage: {
    connectionPool: {
      min: 5,
      max: 50,
      idleTimeoutMillis: 30000,
      acquireTimeoutMillis: 60000
    }
  },
  cache: {
    redis: {
      maxMemoryPolicy: 'allkeys-lru',
      maxMemory: '1gb'
    },
    l1Cache: {
      max: 5000,
      ttl: 300000 // 5 minutes
    }
  }
};
```

### Memory Tuning
```bash
# Node.js memory optimization
export NODE_OPTIONS="--max-old-space-size=4096 --max-semi-space-size=256"

# Garbage collection tuning
export NODE_OPTIONS="$NODE_OPTIONS --expose-gc --optimize-for-size"

# V8 optimization flags
export NODE_OPTIONS="$NODE_OPTIONS --use-largepages=on"
```

This performance guide provides comprehensive strategies for optimizing the anon-identity library for high-scale production deployments.