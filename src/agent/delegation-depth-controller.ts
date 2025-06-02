import { AgentIdentity, DelegationChain } from './types';
import { AgentIdentityManager } from './agent-identity';
import { DelegationChainValidator } from './delegation-chain-validator';

export interface DepthConfiguration {
  globalMaxDepth: number;
  perAgentOverrides: Map<string, number>;
  depthCalculationStrategy: 'absolute' | 'relative' | 'dynamic';
  warningThreshold: number; // Percentage of max depth
}

export interface DepthValidationResult {
  valid: boolean;
  currentDepth: number;
  maxAllowedDepth: number;
  remainingDepth: number;
  warnings: string[];
  metadata?: Record<string, any>;
}

export interface DepthAnalysis {
  averageDepth: number;
  maxDepthReached: number;
  depthDistribution: Map<number, number>;
  deepestChains: Array<{
    leafAgentDID: string;
    depth: number;
    path: string[];
  }>;
}

export class DelegationDepthController {
  private configuration: DepthConfiguration;
  private depthCache: Map<string, number> = new Map();

  constructor(
    private agentManager: AgentIdentityManager,
    private chainValidator: DelegationChainValidator,
    config?: Partial<DepthConfiguration>
  ) {
    this.configuration = {
      globalMaxDepth: 5,
      perAgentOverrides: new Map(),
      depthCalculationStrategy: 'absolute',
      warningThreshold: 0.8,
      ...config
    };
  }

  /**
   * Updates the global maximum depth
   */
  setGlobalMaxDepth(depth: number): void {
    if (depth < 1 || depth > 10) {
      throw new Error('Global max depth must be between 1 and 10');
    }
    this.configuration.globalMaxDepth = depth;
    this.clearCache();
  }

  /**
   * Sets a depth override for a specific agent
   */
  setAgentDepthOverride(agentDID: string, maxDepth: number): void {
    if (maxDepth < 0) {
      throw new Error('Agent max depth cannot be negative');
    }
    this.configuration.perAgentOverrides.set(agentDID, maxDepth);
    this.clearCache();
  }

  /**
   * Validates if a new delegation would exceed depth limits
   */
  async validateDelegationDepth(
    parentAgentDID: string,
    childAgentConfig?: { name: string; description: string }
  ): Promise<DepthValidationResult> {
    const warnings: string[] = [];
    const parentAgent = this.agentManager.getAgent(parentAgentDID);
    
    if (!parentAgent) {
      return {
        valid: false,
        currentDepth: 0,
        maxAllowedDepth: 0,
        remainingDepth: 0,
        warnings: ['Parent agent not found']
      };
    }

    // Calculate effective max depth for this agent
    const effectiveMaxDepth = this.getEffectiveMaxDepth(parentAgent);
    const currentDepth = parentAgent.delegationDepth;
    const wouldBeDepth = currentDepth + 1;

    // Check if delegation would exceed limits
    const valid = wouldBeDepth <= effectiveMaxDepth;
    const remainingDepth = Math.max(0, effectiveMaxDepth - wouldBeDepth);

    // Add warnings if approaching limit
    const depthPercentage = wouldBeDepth / effectiveMaxDepth;
    if (depthPercentage >= this.configuration.warningThreshold) {
      warnings.push(
        `Delegation depth reaching ${Math.round(depthPercentage * 100)}% of maximum`
      );
    }

    if (remainingDepth === 0 && valid) {
      warnings.push('This will be the last possible delegation level');
    }

    // Dynamic depth calculation if enabled
    let metadata: Record<string, any> | undefined;
    if (this.configuration.depthCalculationStrategy === 'dynamic') {
      const dynamicAnalysis = await this.performDynamicDepthAnalysis(parentAgent);
      metadata = { dynamicAnalysis };
      
      if (dynamicAnalysis.suggestedMaxDepth < effectiveMaxDepth) {
        warnings.push(
          `Dynamic analysis suggests lower max depth: ${dynamicAnalysis.suggestedMaxDepth}`
        );
      }
    }

    return {
      valid,
      currentDepth: wouldBeDepth,
      maxAllowedDepth: effectiveMaxDepth,
      remainingDepth,
      warnings,
      metadata
    };
  }

  /**
   * Gets the effective maximum depth for an agent considering all rules
   */
  getEffectiveMaxDepth(agent: AgentIdentity): number {
    // Check for agent-specific override
    const override = this.configuration.perAgentOverrides.get(agent.did);
    if (override !== undefined) {
      return Math.min(override, this.configuration.globalMaxDepth);
    }

    // Check agent's own max depth setting
    if (agent.maxDelegationDepth !== undefined) {
      return Math.min(agent.maxDelegationDepth, this.configuration.globalMaxDepth);
    }

    // Use global default
    return this.configuration.globalMaxDepth;
  }

  /**
   * Calculates the remaining delegation depth for an agent
   */
  getRemainingDepth(agentDID: string): number {
    const agent = this.agentManager.getAgent(agentDID);
    if (!agent) return 0;

    const effectiveMaxDepth = this.getEffectiveMaxDepth(agent);
    return Math.max(0, effectiveMaxDepth - agent.delegationDepth);
  }

  /**
   * Analyzes delegation depth across all agents
   */
  async analyzeDepthDistribution(): Promise<DepthAnalysis> {
    const allAgents = this.getAllAgents();
    const depthDistribution = new Map<number, number>();
    const deepestChains: Array<{
      leafAgentDID: string;
      depth: number;
      path: string[];
    }> = [];

    let totalDepth = 0;
    let maxDepthReached = 0;

    for (const agent of allAgents) {
      const depth = agent.delegationDepth;
      totalDepth += depth;
      maxDepthReached = Math.max(maxDepthReached, depth);

      // Update distribution
      depthDistribution.set(depth, (depthDistribution.get(depth) || 0) + 1);

      // Track deepest chains
      if (depth >= 3) {
        const path = await this.buildAgentPath(agent.did);
        deepestChains.push({
          leafAgentDID: agent.did,
          depth,
          path
        });
      }
    }

    // Sort deepest chains by depth
    deepestChains.sort((a, b) => b.depth - a.depth);

    return {
      averageDepth: allAgents.length > 0 ? totalDepth / allAgents.length : 0,
      maxDepthReached,
      depthDistribution,
      deepestChains: deepestChains.slice(0, 10) // Top 10 deepest
    };
  }

  /**
   * Performs dynamic depth analysis to suggest optimal max depth
   */
  private async performDynamicDepthAnalysis(
    agent: AgentIdentity
  ): Promise<{
    suggestedMaxDepth: number;
    factors: Record<string, any>;
  }> {
    const factors: Record<string, any> = {};
    let suggestedMaxDepth = this.configuration.globalMaxDepth;

    // Factor 1: Agent's scope count
    const credentials = this.agentManager.getDelegationCredentials(agent.did);
    const totalScopes = new Set<string>();
    credentials.forEach(cred => {
      cred.credentialSubject.scopes.forEach(scope => totalScopes.add(scope));
    });
    factors.scopeCount = totalScopes.size;

    // More scopes = potentially lower max depth
    if (totalScopes.size > 10) {
      suggestedMaxDepth = Math.min(suggestedMaxDepth, 3);
      factors.scopeImpact = 'high scope count suggests lower depth';
    }

    // Factor 2: Time since creation
    const ageInDays = (Date.now() - agent.createdAt.getTime()) / (1000 * 60 * 60 * 24);
    factors.ageInDays = ageInDays;

    // Newer agents might get more restrictive depths
    if (ageInDays < 1) {
      suggestedMaxDepth = Math.min(suggestedMaxDepth, 2);
      factors.ageImpact = 'new agent suggests lower depth';
    }

    // Factor 3: Current chain complexity
    try {
      const rootDID = await this.findRootDID(agent.did);
      if (rootDID) {
        const chainResult = await this.chainValidator.validateDelegationChain(
          agent.did,
          rootDID
        );
        
        if (chainResult.chain) {
          factors.currentChainDepth = chainResult.chain.currentDepth;
          
          // If already in a deep chain, limit further delegation
          if (chainResult.chain.currentDepth >= 2) {
            suggestedMaxDepth = Math.min(
              suggestedMaxDepth, 
              chainResult.chain.currentDepth + 1
            );
            factors.chainImpact = 'already in deep chain';
          }
        }
      }
    } catch (error) {
      factors.chainAnalysisError = error;
    }

    return { suggestedMaxDepth, factors };
  }

  /**
   * Builds the path from an agent to the root
   */
  private async buildAgentPath(agentDID: string): Promise<string[]> {
    const path: string[] = [agentDID];
    let currentDID = agentDID;
    const maxIterations = 10; // Prevent infinite loops

    for (let i = 0; i < maxIterations; i++) {
      const agent = this.agentManager.getAgent(currentDID);
      if (!agent) break;

      path.push(agent.parentDID);
      
      // Check if parent is also an agent
      const parentAgent = this.agentManager.getAgent(agent.parentDID);
      if (!parentAgent) {
        // Reached a user DID
        break;
      }
      
      currentDID = agent.parentDID;
    }

    return path.reverse();
  }

  /**
   * Finds the root DID for an agent
   */
  private async findRootDID(agentDID: string): Promise<string | null> {
    let currentDID = agentDID;
    const visited = new Set<string>();

    while (true) {
      if (visited.has(currentDID)) {
        // Circular reference detected
        return null;
      }
      visited.add(currentDID);

      const agent = this.agentManager.getAgent(currentDID);
      if (!agent) {
        // Current DID is not an agent, so it might be the root user
        return currentDID;
      }

      currentDID = agent.parentDID;
    }
  }

  /**
   * Gets all agents managed by the system
   */
  private getAllAgents(): AgentIdentity[] {
    // This is a simplified implementation
    // In practice, you'd need a method to get all agents
    const agents: AgentIdentity[] = [];
    
    // For now, return empty array
    // In a real implementation, this would query all agents
    return agents;
  }

  /**
   * Clears the depth cache
   */
  private clearCache(): void {
    this.depthCache.clear();
  }

  /**
   * Enforces depth limits by preventing over-deep delegations
   */
  async enforceDepthLimits(): Promise<{
    processed: number;
    violations: Array<{
      agentDID: string;
      currentDepth: number;
      maxAllowed: number;
      action: string;
    }>;
  }> {
    const violations: Array<{
      agentDID: string;
      currentDepth: number;
      maxAllowed: number;
      action: string;
    }> = [];
    let processed = 0;

    const allAgents = this.getAllAgents();
    
    for (const agent of allAgents) {
      processed++;
      const effectiveMaxDepth = this.getEffectiveMaxDepth(agent);
      
      if (agent.delegationDepth > effectiveMaxDepth) {
        violations.push({
          agentDID: agent.did,
          currentDepth: agent.delegationDepth,
          maxAllowed: effectiveMaxDepth,
          action: 'Would revoke delegation capability'
        });
        
        // In a real implementation, you might:
        // - Revoke the agent's delegation capability
        // - Notify administrators
        // - Log the violation
      }
    }

    return { processed, violations };
  }

  /**
   * Exports depth configuration
   */
  exportConfiguration(): {
    globalMaxDepth: number;
    overrides: Array<{ agentDID: string; maxDepth: number }>;
    strategy: string;
    warningThreshold: number;
  } {
    return {
      globalMaxDepth: this.configuration.globalMaxDepth,
      overrides: Array.from(this.configuration.perAgentOverrides.entries()).map(
        ([agentDID, maxDepth]) => ({ agentDID, maxDepth })
      ),
      strategy: this.configuration.depthCalculationStrategy,
      warningThreshold: this.configuration.warningThreshold
    };
  }

  /**
   * Imports depth configuration
   */
  importConfiguration(config: {
    globalMaxDepth?: number;
    overrides?: Array<{ agentDID: string; maxDepth: number }>;
    strategy?: 'absolute' | 'relative' | 'dynamic';
    warningThreshold?: number;
  }): void {
    if (config.globalMaxDepth !== undefined) {
      this.setGlobalMaxDepth(config.globalMaxDepth);
    }

    if (config.overrides) {
      this.configuration.perAgentOverrides.clear();
      config.overrides.forEach(({ agentDID, maxDepth }) => {
        this.setAgentDepthOverride(agentDID, maxDepth);
      });
    }

    if (config.strategy) {
      this.configuration.depthCalculationStrategy = config.strategy;
    }

    if (config.warningThreshold !== undefined) {
      this.configuration.warningThreshold = config.warningThreshold;
    }

    this.clearCache();
  }
}