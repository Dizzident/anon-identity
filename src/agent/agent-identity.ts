import { generateKeyPair } from '../core/crypto';
import { DIDService } from '../core/did';
import { AgentConfig, AgentIdentity, AccessGrant, PresentationOptions, DelegationCredential } from './types';
import { VerifiablePresentation, VerifiableCredential } from '../types/index';

export class AgentIdentityManager {
  private agents: Map<string, AgentIdentity> = new Map();
  private accessGrants: Map<string, AccessGrant[]> = new Map();
  private delegationCredentials: Map<string, DelegationCredential[]> = new Map();

  async createAgent(parentDID: string, config: AgentConfig): Promise<AgentIdentity> {
    // Generate new key pair for agent
    const keyPair = await generateKeyPair();
    
    // Create agent DID
    const didObject = DIDService.createDIDKey(keyPair.publicKey);
    const agentDID = didObject.id;
    
    // Create agent identity
    const agent: AgentIdentity = {
      did: agentDID,
      name: config.name,
      description: config.description,
      parentDID,
      createdAt: new Date(),
      keyPair
    };
    
    // Store agent
    this.agents.set(agentDID, agent);
    this.accessGrants.set(agentDID, []);
    this.delegationCredentials.set(agentDID, []);
    
    return agent;
  }

  getAgent(agentDID: string): AgentIdentity | undefined {
    return this.agents.get(agentDID);
  }

  listAgents(parentDID: string): AgentIdentity[] {
    return Array.from(this.agents.values()).filter(
      agent => agent.parentDID === parentDID
    );
  }

  deleteAgent(agentDID: string): boolean {
    const agent = this.agents.get(agentDID);
    if (!agent) return false;
    
    this.agents.delete(agentDID);
    this.accessGrants.delete(agentDID);
    this.delegationCredentials.delete(agentDID);
    
    return true;
  }

  addAccessGrant(agentDID: string, grant: AccessGrant): void {
    const grants = this.accessGrants.get(agentDID) || [];
    grants.push(grant);
    this.accessGrants.set(agentDID, grants);
  }

  getAccessGrants(agentDID: string): AccessGrant[] {
    return this.accessGrants.get(agentDID) || [];
  }

  hasServiceAccess(agentDID: string, serviceDID: string): boolean {
    const grants = this.getAccessGrants(agentDID);
    return grants.some(grant => 
      grant.serviceDID === serviceDID && 
      grant.expiresAt > new Date()
    );
  }

  revokeServiceAccess(agentDID: string, serviceDID: string): boolean {
    const grants = this.accessGrants.get(agentDID);
    if (!grants) return false;
    
    const filteredGrants = grants.filter(grant => grant.serviceDID !== serviceDID);
    this.accessGrants.set(agentDID, filteredGrants);
    
    // Also remove delegation credentials for this service
    const credentials = this.delegationCredentials.get(agentDID) || [];
    const filteredCredentials = credentials.filter(cred => 
      !cred.credentialSubject.services[serviceDID]
    );
    this.delegationCredentials.set(agentDID, filteredCredentials);
    
    return grants.length !== filteredGrants.length;
  }

  addDelegationCredential(agentDID: string, credential: DelegationCredential): void {
    const credentials = this.delegationCredentials.get(agentDID) || [];
    credentials.push(credential);
    this.delegationCredentials.set(agentDID, credentials);
  }

  getDelegationCredentials(agentDID: string): DelegationCredential[] {
    return this.delegationCredentials.get(agentDID) || [];
  }

  async createPresentation(
    agentDID: string, 
    options: PresentationOptions
  ): Promise<VerifiablePresentation | null> {
    const agent = this.agents.get(agentDID);
    if (!agent) return null;

    // Find relevant delegation credential
    const credentials = this.getDelegationCredentials(agentDID);
    const relevantCredential = credentials.find(cred => 
      cred.credentialSubject.services[options.serviceDID] &&
      new Date(cred.expirationDate) > new Date()
    );

    if (!relevantCredential) return null;

    // Create presentation
    const presentation: VerifiablePresentation = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation', 'AgentPresentation'],
      verifiableCredential: [relevantCredential as unknown as VerifiableCredential],
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: `${agentDID}#key-1`,
        proofPurpose: 'authentication',
        jws: 'mock-signature' // In real implementation, this would be signed
      }
    };
    
    // Add holder as a custom property
    (presentation as any).holder = agentDID;

    return presentation;
  }
}