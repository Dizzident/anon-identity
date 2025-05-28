import { ethers } from 'ethers';
import { VerifiableCredential } from '../../types';
import { DIDDocument } from '../../types/did';
import { RevocationList, CredentialSchema } from '../types';

export interface BatchOperation {
  type: 'registerDID' | 'updateDID' | 'publishRevocation' | 'registerSchema' | 'revokeCredentials';
  data: any;
}

export class BatchOperationsManager {
  private pendingOperations: BatchOperation[] = [];
  private batchSize: number;
  private flushTimeout?: NodeJS.Timeout;
  private flushIntervalMs: number;

  constructor(batchSize: number = 10, flushIntervalMs: number = 5000) {
    this.batchSize = batchSize;
    this.flushIntervalMs = flushIntervalMs;
  }

  addOperation(operation: BatchOperation): void {
    this.pendingOperations.push(operation);

    // Auto-flush if batch size reached
    if (this.pendingOperations.length >= this.batchSize) {
      this.flush();
    } else {
      // Set timeout for auto-flush
      this.resetFlushTimeout();
    }
  }

  private resetFlushTimeout(): void {
    if (this.flushTimeout) {
      clearTimeout(this.flushTimeout);
    }
    this.flushTimeout = setTimeout(() => this.flush(), this.flushIntervalMs);
  }

  async flush(): Promise<void> {
    if (this.flushTimeout) {
      clearTimeout(this.flushTimeout);
      this.flushTimeout = undefined;
    }

    if (this.pendingOperations.length === 0) {
      return;
    }

    const operations = [...this.pendingOperations];
    this.pendingOperations = [];

    // Group operations by type for efficient batching
    const grouped = this.groupOperationsByType(operations);

    // Execute each group in parallel
    const promises: Promise<any>[] = [];
    
    for (const [type, ops] of Object.entries(grouped)) {
      switch (type) {
        case 'registerDID':
          promises.push(this.batchRegisterDIDs(ops));
          break;
        case 'updateDID':
          promises.push(this.batchUpdateDIDs(ops));
          break;
        case 'publishRevocation':
          promises.push(this.batchPublishRevocations(ops));
          break;
        case 'registerSchema':
          promises.push(this.batchRegisterSchemas(ops));
          break;
        case 'revokeCredentials':
          promises.push(this.batchRevokeCredentials(ops));
          break;
      }
    }

    await Promise.all(promises);
  }

  private groupOperationsByType(operations: BatchOperation[]): Record<string, BatchOperation[]> {
    return operations.reduce((acc, op) => {
      if (!acc[op.type]) {
        acc[op.type] = [];
      }
      acc[op.type].push(op);
      return acc;
    }, {} as Record<string, BatchOperation[]>);
  }

  // Batch operation implementations
  private async batchRegisterDIDs(operations: BatchOperation[]): Promise<void> {
    // In a real implementation, this would call a batch register contract method
    // For now, we'll simulate the batch processing
    console.log(`Batch registering ${operations.length} DIDs`);
  }

  private async batchUpdateDIDs(operations: BatchOperation[]): Promise<void> {
    console.log(`Batch updating ${operations.length} DIDs`);
  }

  private async batchPublishRevocations(operations: BatchOperation[]): Promise<void> {
    // Combine all revocations by issuer for efficiency
    const byIssuer = new Map<string, string[]>();
    
    for (const op of operations) {
      const { issuerDID, credentialHashes } = op.data;
      if (!byIssuer.has(issuerDID)) {
        byIssuer.set(issuerDID, []);
      }
      byIssuer.get(issuerDID)!.push(...credentialHashes);
    }

    console.log(`Batch publishing revocations for ${byIssuer.size} issuers`);
  }

  private async batchRegisterSchemas(operations: BatchOperation[]): Promise<void> {
    console.log(`Batch registering ${operations.length} schemas`);
  }

  private async batchRevokeCredentials(operations: BatchOperation[]): Promise<void> {
    // Group by issuer for efficient batch revocation
    const byIssuer = new Map<string, Set<string>>();
    
    for (const op of operations) {
      const { issuerDID, credentialHash } = op.data;
      if (!byIssuer.has(issuerDID)) {
        byIssuer.set(issuerDID, new Set());
      }
      byIssuer.get(issuerDID)!.add(credentialHash);
    }

    console.log(`Batch revoking credentials for ${byIssuer.size} issuers`);
  }

  // Gas estimation helpers
  static estimateBatchGas(operations: BatchOperation[]): bigint {
    // Base gas for batch transaction
    let gasEstimate = 21000n;
    
    // Add estimated gas per operation type
    for (const op of operations) {
      switch (op.type) {
        case 'registerDID':
          gasEstimate += 80000n; // Estimated gas for DID registration
          break;
        case 'updateDID':
          gasEstimate += 50000n; // Estimated gas for DID update
          break;
        case 'publishRevocation':
          gasEstimate += 60000n; // Estimated gas for revocation
          break;
        case 'registerSchema':
          gasEstimate += 100000n; // Estimated gas for schema registration
          break;
        case 'revokeCredentials':
          gasEstimate += 40000n; // Estimated gas per credential revocation
          break;
      }
    }

    // Add 20% buffer
    return (gasEstimate * 120n) / 100n;
  }

  static calculateBatchSavings(operations: BatchOperation[]): {
    individualGas: bigint;
    batchGas: bigint;
    savings: bigint;
    savingsPercent: number;
  } {
    const individualGas = BigInt(operations.length) * 21000n + this.estimateBatchGas(operations);
    const batchGas = this.estimateBatchGas(operations);
    const savings = individualGas - batchGas;
    const savingsPercent = Number((savings * 100n) / individualGas);

    return {
      individualGas,
      batchGas,
      savings,
      savingsPercent,
    };
  }
}

// Merkle tree implementation for efficient revocation proofs
export class RevocationMerkleTree {
  private leaves: string[];
  private layers: string[][];

  constructor(revokedCredentialHashes: string[]) {
    this.leaves = revokedCredentialHashes.sort();
    this.layers = this.buildTree();
  }

  private buildTree(): string[][] {
    const layers: string[][] = [this.leaves];
    
    while (layers[layers.length - 1].length > 1) {
      const currentLayer = layers[layers.length - 1];
      const nextLayer: string[] = [];
      
      for (let i = 0; i < currentLayer.length; i += 2) {
        if (i + 1 < currentLayer.length) {
          const combined = ethers.concat([currentLayer[i], currentLayer[i + 1]]);
          nextLayer.push(ethers.keccak256(combined));
        } else {
          nextLayer.push(currentLayer[i]);
        }
      }
      
      layers.push(nextLayer);
    }
    
    return layers;
  }

  getRoot(): string {
    return this.layers.length > 0 ? this.layers[this.layers.length - 1][0] : ethers.ZeroHash;
  }

  getProof(credentialHash: string): string[] {
    const index = this.leaves.indexOf(credentialHash);
    if (index === -1) {
      return [];
    }

    const proof: string[] = [];
    let currentIndex = index;

    for (let i = 0; i < this.layers.length - 1; i++) {
      const currentLayer = this.layers[i];
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

      if (siblingIndex < currentLayer.length) {
        proof.push(currentLayer[siblingIndex]);
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    return proof;
  }

  verify(credentialHash: string, proof: string[], root: string): boolean {
    let computedHash = credentialHash;
    let index = this.leaves.indexOf(credentialHash);

    for (const proofElement of proof) {
      const isRightNode = index % 2 === 1;
      
      if (isRightNode) {
        computedHash = ethers.keccak256(ethers.concat([proofElement, computedHash]));
      } else {
        computedHash = ethers.keccak256(ethers.concat([computedHash, proofElement]));
      }

      index = Math.floor(index / 2);
    }

    return computedHash === root;
  }

  // Static method to create a merkle tree from a revocation list
  static fromRevocationList(revocationList: RevocationList): RevocationMerkleTree {
    const hashes = revocationList.revokedCredentialIds.map(id => 
      ethers.keccak256(ethers.toUtf8Bytes(id))
    );
    return new RevocationMerkleTree(hashes);
  }
}