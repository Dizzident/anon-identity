import { AgentIdentity, DelegationCredential } from '../types';
import { AgentIdentityManager } from '../agent-identity';
import { DelegationChainValidator } from '../delegation-chain-validator';
import { CommunicationManager } from '../communication/communication-manager';
import { MessageFactory } from '../communication/message-factory';
import { ActivityLogger, createActivity } from '../activity/activity-logger';
import { ActivityType, ActivityStatus } from '../activity/types';

export interface RevocationRequest {
  targetAgentDID: string;
  reason: string;
  revokedBy: string;
  timestamp: Date;
  cascading: boolean;
  serviceDID?: string;
  effectiveDate?: Date;
}

export interface RevocationResult {
  success: boolean;
  revokedAgents: string[];
  failedRevocations: Array<{
    agentDID: string;
    error: string;
  }>;
  notificationsSent: number;
  auditEntries: number;
}

export interface RevocationAuditEntry {
  id: string;
  targetAgentDID: string;
  revokedBy: string;
  reason: string;
  timestamp: Date;
  cascading: boolean;
  serviceDID?: string;
  effectiveDate: Date;
  childRevocations: string[];
  notificationsSent: string[];
  status: 'pending' | 'completed' | 'failed' | 'partial';
}

export class CascadingRevocationManager {
  private revocationAudit: Map<string, RevocationAuditEntry> = new Map();
  private activeRevocations: Set<string> = new Set();

  constructor(
    private agentManager: AgentIdentityManager,
    private chainValidator: DelegationChainValidator,
    private communicationManager: CommunicationManager,
    private activityLogger: ActivityLogger
  ) {}

  /**
   * Revokes an agent and optionally cascades to all sub-agents
   */
  async revokeAgent(request: RevocationRequest): Promise<RevocationResult> {
    const auditId = this.generateAuditId();
    const result: RevocationResult = {
      success: false,
      revokedAgents: [],
      failedRevocations: [],
      notificationsSent: 0,
      auditEntries: 0
    };

    // Prevent concurrent revocations of the same agent
    if (this.activeRevocations.has(request.targetAgentDID)) {
      throw new Error(`Revocation already in progress for agent ${request.targetAgentDID}`);
    }

    this.activeRevocations.add(request.targetAgentDID);

    try {
      // Create audit entry
      const auditEntry: RevocationAuditEntry = {
        id: auditId,
        targetAgentDID: request.targetAgentDID,
        revokedBy: request.revokedBy,
        reason: request.reason,
        timestamp: request.timestamp,
        cascading: request.cascading,
        serviceDID: request.serviceDID,
        effectiveDate: request.effectiveDate || request.timestamp,
        childRevocations: [],
        notificationsSent: [],
        status: 'pending'
      };

      this.revocationAudit.set(auditId, auditEntry);
      result.auditEntries++;

      // Log revocation initiation
      await this.activityLogger.logActivity(createActivity(
        ActivityType.REVOCATION,
        {
          agentDID: request.targetAgentDID,
          parentDID: '',
          serviceDID: request.serviceDID || 'all',
          status: ActivityStatus.SUCCESS,
          scopes: [],
          details: {
            action: 'revocation_initiated',
            reason: request.reason,
            revokedBy: request.revokedBy,
            cascading: request.cascading,
            auditId
          }
        }
      ));

      // Get the target agent
      const targetAgent = this.agentManager.getAgent(request.targetAgentDID);
      if (!targetAgent) {
        auditEntry.status = 'failed';
        result.failedRevocations.push({
          agentDID: request.targetAgentDID,
          error: 'Agent not found'
        });
        return result;
      }

      // Revoke the target agent
      const revokeResult = await this.performSingleRevocation(
        targetAgent,
        request,
        auditEntry
      );

      if (revokeResult.success) {
        result.revokedAgents.push(request.targetAgentDID);
      } else {
        result.failedRevocations.push({
          agentDID: request.targetAgentDID,
          error: revokeResult.error || 'Unknown error'
        });
      }

      // If cascading is enabled, find and revoke all sub-agents
      if (request.cascading) {
        const subAgents = await this.findSubAgents(request.targetAgentDID);
        
        for (const subAgent of subAgents) {
          try {
            const subRevocationRequest: RevocationRequest = {
              ...request,
              targetAgentDID: subAgent.did,
              reason: `Cascaded from parent revocation: ${request.reason}`
            };

            const subResult = await this.performSingleRevocation(
              subAgent,
              subRevocationRequest,
              auditEntry
            );

            if (subResult.success) {
              result.revokedAgents.push(subAgent.did);
              auditEntry.childRevocations.push(subAgent.did);
            } else {
              result.failedRevocations.push({
                agentDID: subAgent.did,
                error: subResult.error || 'Unknown error'
              });
            }
          } catch (error) {
            result.failedRevocations.push({
              agentDID: subAgent.did,
              error: error instanceof Error ? error.message : 'Unknown error'
            });
          }
        }
      }

      // Send notifications
      result.notificationsSent = await this.sendRevocationNotifications(
        request,
        result.revokedAgents,
        auditEntry
      );

      // Update audit status
      if (result.failedRevocations.length === 0) {
        auditEntry.status = 'completed';
        result.success = true;
      } else if (result.revokedAgents.length > 0) {
        auditEntry.status = 'partial';
        result.success = true; // Partial success
      } else {
        auditEntry.status = 'failed';
      }

      // Log completion
      await this.activityLogger.logActivity(createActivity(
        ActivityType.REVOCATION,
        {
          agentDID: request.targetAgentDID,
          parentDID: '',
          serviceDID: request.serviceDID || 'all',
          status: result.success ? ActivityStatus.SUCCESS : ActivityStatus.FAILED,
          scopes: [],
          details: {
            action: 'revocation_completed',
            auditId,
            revokedCount: result.revokedAgents.length,
            failedCount: result.failedRevocations.length,
            notificationsSent: result.notificationsSent
          }
        }
      ));

      return result;

    } finally {
      this.activeRevocations.delete(request.targetAgentDID);
    }
  }

  /**
   * Performs revocation of a single agent
   */
  private async performSingleRevocation(
    agent: AgentIdentity,
    request: RevocationRequest,
    auditEntry: RevocationAuditEntry
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Mark agent as revoked (in practice, this might involve updating database records)
      // For now, we'll remove the agent's delegation capabilities
      
      // Revoke all delegation credentials for this agent
      const credentials = this.agentManager.getDelegationCredentials(agent.did);
      
      if (request.serviceDID) {
        // Service-specific revocation
        const filteredCredentials = credentials.filter(cred => 
          !cred.credentialSubject.services[request.serviceDID!]
        );
        
        // In a real implementation, you would update the credential storage
        // For now, we'll use the existing revocation method
        const revoked = this.agentManager.revokeServiceAccess(agent.did, request.serviceDID);
        
        if (!revoked) {
          return { success: false, error: 'Failed to revoke service access' };
        }
      } else {
        // Complete agent revocation
        const revoked = this.agentManager.deleteAgent(agent.did);
        
        if (!revoked) {
          return { success: false, error: 'Failed to delete agent' };
        }
      }

      return { success: true };

    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Finds all sub-agents of a given agent
   */
  private async findSubAgents(parentAgentDID: string): Promise<AgentIdentity[]> {
    const allAgents = this.agentManager.listAgents(parentAgentDID);
    const subAgents: AgentIdentity[] = [];

    // Direct children
    subAgents.push(...allAgents);

    // Recursive search for deeper sub-agents
    for (const agent of allAgents) {
      const deeperSubAgents = await this.findSubAgents(agent.did);
      subAgents.push(...deeperSubAgents);
    }

    return subAgents;
  }

  /**
   * Sends revocation notifications to relevant parties
   */
  private async sendRevocationNotifications(
    request: RevocationRequest,
    revokedAgents: string[],
    auditEntry: RevocationAuditEntry
  ): Promise<number> {
    let notificationsSent = 0;

    for (const agentDID of revokedAgents) {
      try {
        // Find agents that might need to be notified about this revocation
        const notificationTargets = await this.findNotificationTargets(agentDID);

        for (const targetDID of notificationTargets) {
          try {
            const message = MessageFactory.createRevocationNotification(
              request.revokedBy,
              targetDID,
              agentDID,
              request.reason,
              {
                effectiveDate: request.effectiveDate,
                cascading: request.cascading,
                metadata: {
                  auditId: auditEntry.id,
                  serviceDID: request.serviceDID
                }
              }
            );

            await this.communicationManager.sendMessage(message);
            auditEntry.notificationsSent.push(targetDID);
            notificationsSent++;
          } catch (error) {
            // Log notification failure but don't fail the entire operation
            await this.activityLogger.logActivity(createActivity(
              ActivityType.COMMUNICATION,
              {
                agentDID: request.revokedBy,
                parentDID: '',
                serviceDID: 'notification',
                status: ActivityStatus.FAILED,
                scopes: [],
                details: {
                  action: 'revocation_notification_failed',
                  targetDID,
                  error: error instanceof Error ? error.message : 'Unknown error'
                }
              }
            ));
          }
        }
      } catch (error) {
        // Log error finding notification targets
        console.error(`Failed to find notification targets for ${agentDID}:`, error);
      }
    }

    return notificationsSent;
  }

  /**
   * Finds agents that should be notified about a revocation
   */
  private async findNotificationTargets(revokedAgentDID: string): Promise<string[]> {
    const targets = new Set<string>();

    try {
      // Find parent agents in the delegation chain
      const agent = this.agentManager.getAgent(revokedAgentDID);
      if (agent) {
        // Add parent to notification list
        targets.add(agent.parentDID);

        // Find root of the chain for notification
        let currentDID = agent.parentDID;
        const visited = new Set<string>();
        
        while (currentDID && !visited.has(currentDID)) {
          visited.add(currentDID);
          const parentAgent = this.agentManager.getAgent(currentDID);
          
          if (parentAgent) {
            targets.add(parentAgent.did);
            currentDID = parentAgent.parentDID;
          } else {
            // Reached a user DID
            targets.add(currentDID);
            break;
          }
        }
      }

      // Find peer agents that might be affected
      // (This is application-specific logic that could be extended)

    } catch (error) {
      console.error('Error finding notification targets:', error);
    }

    return Array.from(targets);
  }

  /**
   * Gets revocation audit trail for an agent
   */
  getRevocationAudit(agentDID?: string): RevocationAuditEntry[] {
    const entries = Array.from(this.revocationAudit.values());
    
    if (agentDID) {
      return entries.filter(entry => 
        entry.targetAgentDID === agentDID || 
        entry.childRevocations.includes(agentDID)
      );
    }
    
    return entries;
  }

  /**
   * Checks if an agent has been revoked
   */
  isAgentRevoked(agentDID: string, serviceDID?: string): boolean {
    const auditEntries = this.getRevocationAudit(agentDID);
    
    return auditEntries.some(entry => {
      if (entry.status !== 'completed' && entry.status !== 'partial') {
        return false;
      }
      
      // Check if revocation is for this specific service or global
      if (serviceDID && entry.serviceDID && entry.serviceDID !== serviceDID) {
        return false;
      }
      
      return entry.targetAgentDID === agentDID || 
             entry.childRevocations.includes(agentDID);
    });
  }

  /**
   * Gets revocation statistics
   */
  getRevocationStats(): {
    totalRevocations: number;
    cascadingRevocations: number;
    serviceSpecificRevocations: number;
    averageChildRevocations: number;
    notificationsSent: number;
  } {
    const entries = Array.from(this.revocationAudit.values());
    
    const cascadingCount = entries.filter(e => e.cascading).length;
    const serviceSpecificCount = entries.filter(e => e.serviceDID).length;
    const totalChildRevocations = entries.reduce((sum, e) => sum + e.childRevocations.length, 0);
    const totalNotifications = entries.reduce((sum, e) => sum + e.notificationsSent.length, 0);
    
    return {
      totalRevocations: entries.length,
      cascadingRevocations: cascadingCount,
      serviceSpecificRevocations: serviceSpecificCount,
      averageChildRevocations: entries.length > 0 ? totalChildRevocations / entries.length : 0,
      notificationsSent: totalNotifications
    };
  }

  /**
   * Purges old audit entries
   */
  purgeOldAuditEntries(olderThan: Date): number {
    const initialSize = this.revocationAudit.size;
    
    for (const [id, entry] of this.revocationAudit.entries()) {
      if (entry.timestamp < olderThan) {
        this.revocationAudit.delete(id);
      }
    }
    
    return initialSize - this.revocationAudit.size;
  }

  /**
   * Exports audit trail for compliance
   */
  exportAuditTrail(format: 'json' | 'csv' = 'json'): string {
    const entries = Array.from(this.revocationAudit.values());
    
    if (format === 'csv') {
      const headers = [
        'id', 'targetAgentDID', 'revokedBy', 'reason', 'timestamp', 
        'cascading', 'serviceDID', 'effectiveDate', 'childRevocations', 
        'notificationsSent', 'status'
      ];
      
      const rows = entries.map(entry => [
        entry.id,
        entry.targetAgentDID,
        entry.revokedBy,
        entry.reason,
        entry.timestamp.toISOString(),
        entry.cascading.toString(),
        entry.serviceDID || '',
        entry.effectiveDate.toISOString(),
        entry.childRevocations.length.toString(),
        entry.notificationsSent.length.toString(),
        entry.status
      ]);
      
      return [headers, ...rows].map(row => row.join(',')).join('\n');
    }
    
    return JSON.stringify(entries, null, 2);
  }

  private generateAuditId(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2);
    return `rev_${timestamp}_${random}`;
  }
}