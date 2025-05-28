# IPFS to Helia Migration Plan

## ✅ Migration Status: COMPLETED (2025-05-28)

Successfully migrated from `ipfs-http-client` to `kubo-rpc-client`.

## Overview

The `ipfs-http-client` package has been deprecated in favor of Helia. This document outlines the migration plan from ipfs-http-client to either:
1. **kubo-rpc-client** - Direct replacement for HTTP client (recommended for our use case)
2. **Helia** - Modern IPFS implementation for JavaScript

## Current IPFS Usage Analysis

### Current Implementation
- **Location**: `src/storage/providers/ipfs-storage-provider.ts`
- **Purpose**: Store DIDs, credentials, revocation lists, and schemas on IPFS
- **Key Operations**:
  - `add()` - Store JSON data to IPFS
  - `cat()` - Retrieve data from IPFS
  - `pin.add()` / `pin.rm()` - Pin/unpin content
  - `id()` - Get node information

### Current Issues
1. Security vulnerabilities in `ipfs-http-client` dependencies
2. Package is deprecated and no longer maintained
3. Import issues with ESM modules

## Migration Options

### Option 1: kubo-rpc-client (Recommended)
Since we're using IPFS as an HTTP client connecting to a running IPFS node, `kubo-rpc-client` is the most appropriate replacement.

**Pros:**
- Drop-in replacement for ipfs-http-client
- Minimal code changes required
- Maintains same HTTP API approach
- Active maintenance and security updates

**Cons:**
- Still requires running IPFS node (Kubo)

### Option 2: Helia
Complete rewrite using Helia, which runs IPFS directly in JavaScript.

**Pros:**
- Modern, composable architecture
- No need for external IPFS node
- Better TypeScript support

**Cons:**
- Significant code rewrite required
- Different API and concepts
- May have different performance characteristics

## Recommended Approach: kubo-rpc-client

### Phase 1: Immediate Fix (Short-term)
1. Keep IPFS provider disabled (as currently done)
2. Update workflows to handle disabled IPFS gracefully
3. Focus on blockchain and hybrid storage providers

### Phase 2: Migration to kubo-rpc-client (Medium-term)
1. Replace `ipfs-http-client` with `kubo-rpc-client`
2. Update import statements and initialization
3. Test all IPFS operations
4. Re-enable IPFS provider

### Phase 3: Evaluate Helia (Long-term)
1. Create proof-of-concept with Helia
2. Compare performance and features
3. Plan full migration if beneficial

## Implementation Plan

### Step 1: Update Dependencies
```bash
npm uninstall ipfs-http-client
npm install kubo-rpc-client
```

### Step 2: Update IPFSStorageProvider

```typescript
// Old import
import { create, IPFSHTTPClient } from 'ipfs-http-client';

// New import
import { create } from 'kubo-rpc-client';
import type { KuboRPCClient } from 'kubo-rpc-client';
```

### Step 3: Update Type Definitions
```typescript
// Old
private ipfsClient: IPFSHTTPClient | null = null;

// New
private ipfsClient: KuboRPCClient | null = null;
```

### Step 4: Update Initialization
```typescript
private async initializeIPFSClient(ipfsConfig: { host: string; port: number; protocol: string }) {
  try {
    const { create } = await import('kubo-rpc-client');
    this.ipfsClient = create({
      host: ipfsConfig.host,
      port: ipfsConfig.port,
      protocol: ipfsConfig.protocol,
    });
  } catch (error) {
    console.error('Failed to initialize IPFS client:', error);
    throw new Error('IPFS client initialization failed');
  }
}
```

### Step 5: Test All Operations
- Store and retrieve DIDs
- Store and retrieve credentials
- Publish and check revocations
- Register and get schemas
- Pin/unpin operations
- Get storage stats

## Alternative: Helia Implementation Example

If we decide to go with Helia in the future:

```typescript
import { createHelia } from 'helia';
import { unixfs } from '@helia/unixfs';
import { json } from '@helia/json';

export class HeliaStorageProvider implements IStorageProvider {
  private helia: Helia;
  private fs: UnixFS;
  private j: JSON;

  constructor() {
    this.helia = await createHelia();
    this.fs = unixfs(this.helia);
    this.j = json(this.helia);
  }

  private async storeToIPFS<T>(data: IPFSStoredData<T>): Promise<string> {
    const cid = await this.j.add(data);
    return cid.toString();
  }

  private async retrieveFromIPFS<T>(cid: string): Promise<IPFSStoredData<T> | null> {
    try {
      const data = await this.j.get(CID.parse(cid));
      return data as IPFSStoredData<T>;
    } catch (error) {
      console.error('Error retrieving from IPFS:', error);
      return null;
    }
  }
}
```

## Testing Strategy

1. Create test suite specifically for IPFS operations
2. Test with local IPFS node (Kubo)
3. Verify data persistence and retrieval
4. Performance benchmarking
5. Integration testing with hybrid storage

## Rollback Plan

If migration causes issues:
1. Keep current implementation with IPFS disabled
2. Revert to previous commit
3. Focus on blockchain-only storage

## Timeline

- **Week 1**: Implement kubo-rpc-client migration
- **Week 2**: Testing and validation
- **Week 3**: Deploy and monitor
- **Month 2**: Evaluate Helia for future migration

## Success Criteria

1. All npm audit vulnerabilities resolved
2. IPFS storage provider functional
3. No performance degradation
4. All tests passing
5. Successful integration with hybrid storage provider