import { RevocationService } from '../revocation/revocation-service';
import { KeyPair } from '../types/index';
import { IStorageProvider } from '../storage';
import { DelegationCredential } from './types';
import { DelegationManager } from './delegation-manager';

export interface AgentRevocationRecord {
  agentDID: string;
  parentDID: string;
  serviceDID?: string;
  revokedAt: Date;
  reason?: string;
}

export class AgentRevocationService extends RevocationService {
  private delegationManager: DelegationManager;
  private agentRevocations: Map<string, AgentRevocationRecord[]> = new Map();

  constructor(keyPair: KeyPair, issuerDID: string, storageProvider?: IStorageProvider) {
    super(keyPair, issuerDID, storageProvider);
    this.delegationManager = new DelegationManager();
  }

  /**
   * Revoke an agent's access entirely
   */
  async revokeAgent(agentDID: string, parentDID: string, reason?: string): Promise<void> {
    // Add to agent revocation list
    const record: AgentRevocationRecord = {
      agentDID,
      parentDID,
      revokedAt: new Date(),
      reason
    };

    const records = this.agentRevocations.get(parentDID) || [];
    records.push(record);
    this.agentRevocations.set(parentDID, records);

    // Revoke all delegation credentials for this agent
    await this.revokeDelegationCredentialsForAgent(agentDID);
  }

  /**
   * Revoke an agent's access to a specific service
   */
  async revokeAgentServiceAccess(
    agentDID: string, 
    parentDID: string, 
    serviceDID: string,
    reason?: string
  ): Promise<void> {
    // Add to agent revocation list
    const record: AgentRevocationRecord = {
      agentDID,
      parentDID,
      serviceDID,
      revokedAt: new Date(),
      reason
    };

    const records = this.agentRevocations.get(parentDID) || [];
    records.push(record);
    this.agentRevocations.set(parentDID, records);

    // Revoke delegation credentials for this service
    await this.revokeDelegationCredentialsForService(agentDID, serviceDID);
  }

  /**
   * Check if an agent is revoked
   */
  async isAgentRevoked(agentDID: string, parentDID: string): Promise<boolean> {
    const records = this.agentRevocations.get(parentDID) || [];
    return records.some(r => r.agentDID === agentDID && !r.serviceDID);
  }

  /**
   * Check if an agent's service access is revoked
   */
  async isAgentServiceRevoked(
    agentDID: string, 
    parentDID: string, 
    serviceDID: string
  ): Promise<boolean> {
    const records = this.agentRevocations.get(parentDID) || [];
    
    // Check if entire agent is revoked
    const agentRevoked = records.some(r => r.agentDID === agentDID && !r.serviceDID);
    if (agentRevoked) return true;

    // Check if specific service access is revoked
    return records.some(r => 
      r.agentDID === agentDID && 
      r.serviceDID === serviceDID
    );
  }

  /**
   * Get all revocation records for a parent
   */
  getRevocationRecords(parentDID: string): AgentRevocationRecord[] {
    return this.agentRevocations.get(parentDID) || [];
  }

  /**
   * Validate a delegation credential including revocation check
   */
  async validateDelegationCredential(
    credential: DelegationCredential
  ): Promise<{ valid: boolean; reason?: string }> {
    // Check basic validation
    if (!this.delegationManager.validateDelegation(credential)) {
      return { valid: false, reason: 'Invalid delegation credential' };
    }

    const agentDID = credential.credentialSubject.id;
    const parentDID = credential.credentialSubject.parentDID;

    // Check if agent is entirely revoked
    if (await this.isAgentRevoked(agentDID, parentDID)) {
      return { valid: false, reason: 'Agent has been revoked' };
    }

    // Check if credential itself is revoked
    if (await this.isRevoked(credential.id)) {
      return { valid: false, reason: 'Delegation credential has been revoked' };
    }

    // Check service-specific revocations
    for (const serviceDID of Object.keys(credential.credentialSubject.services)) {
      if (await this.isAgentServiceRevoked(agentDID, parentDID, serviceDID)) {
        return { 
          valid: false, 
          reason: `Agent access to service ${serviceDID} has been revoked` 
        };
      }
    }

    return { valid: true };
  }

  /**
   * Revoke all delegation credentials for an agent
   */
  private async revokeDelegationCredentialsForAgent(agentDID: string): Promise<void> {
    // In a real implementation, this would query the storage for all
    // delegation credentials issued to this agent and revoke them
    // For now, we'll store a marker that can be checked
    const credentialId = `delegation:${agentDID}:*`;
    await this.revokeCredential(credentialId);
  }

  /**
   * Revoke delegation credentials for a specific service
   */
  private async revokeDelegationCredentialsForService(
    agentDID: string, 
    serviceDID: string
  ): Promise<void> {
    // In a real implementation, this would query and revoke specific credentials
    const credentialId = `delegation:${agentDID}:${serviceDID}`;
    await this.revokeCredential(credentialId);
  }

  /**
   * Restore an agent's access
   */
  async restoreAgent(agentDID: string, parentDID: string): Promise<void> {
    const records = this.agentRevocations.get(parentDID) || [];
    const filteredRecords = records.filter(r => 
      !(r.agentDID === agentDID && !r.serviceDID)
    );
    this.agentRevocations.set(parentDID, filteredRecords);

    // Unrevoke the marker credential
    const credentialId = `delegation:${agentDID}:*`;
    await this.unrevokeCredential(credentialId);
  }

  /**
   * Restore an agent's service access
   */
  async restoreAgentServiceAccess(
    agentDID: string, 
    parentDID: string, 
    serviceDID: string
  ): Promise<void> {
    const records = this.agentRevocations.get(parentDID) || [];
    const filteredRecords = records.filter(r => 
      !(r.agentDID === agentDID && r.serviceDID === serviceDID)
    );
    this.agentRevocations.set(parentDID, filteredRecords);

    // Unrevoke the service-specific credential
    const credentialId = `delegation:${agentDID}:${serviceDID}`;
    await this.unrevokeCredential(credentialId);
  }

  /**
   * Get revocation statistics
   */
  getRevocationStats(): {
    totalAgentsRevoked: number;
    totalServiceRevocations: number;
    revocationsByParent: Record<string, number>;
  } {
    let totalAgentsRevoked = 0;
    let totalServiceRevocations = 0;
    const revocationsByParent: Record<string, number> = {};

    this.agentRevocations.forEach((records, parentDID) => {
      revocationsByParent[parentDID] = records.length;
      
      records.forEach(record => {
        if (record.serviceDID) {
          totalServiceRevocations++;
        } else {
          totalAgentsRevoked++;
        }
      });
    });

    return {
      totalAgentsRevoked,
      totalServiceRevocations,
      revocationsByParent
    };
  }

  /**
   * Export revocation data for backup/migration
   */
  exportRevocationData(): {
    agentRevocations: Array<{ parentDID: string; records: AgentRevocationRecord[] }>;
  } {
    const data: Array<{ parentDID: string; records: AgentRevocationRecord[] }> = [];
    
    this.agentRevocations.forEach((records, parentDID) => {
      data.push({ parentDID, records });
    });

    return { agentRevocations: data };
  }

  /**
   * Import revocation data from backup/migration
   */
  importRevocationData(data: {
    agentRevocations: Array<{ parentDID: string; records: AgentRevocationRecord[] }>;
  }): void {
    this.agentRevocations.clear();
    
    data.agentRevocations.forEach(({ parentDID, records }) => {
      this.agentRevocations.set(parentDID, records);
    });
  }
}