/**
 * Agent Matcher for MCP
 * 
 * Embedding-based agent matching and capability discovery
 */

import { EventEmitter } from 'events';
import {
  LLMRequest,
  LLMRequestType,
  RequestPriority,
  MCPError,
  MCPErrorCode
} from '../types';
import { MessageRouter } from '../routing/message-router';
import { AuthManager } from '../security/auth-manager';
import { AuditLogger } from '../security/audit-logger';

/**
 * Agent capabilities profile
 */
export interface AgentCapabilityProfile {
  agentDID: string;
  name: string;
  description: string;
  capabilities: string[];
  expertise: string[];
  availableActions: string[];
  performance: {
    averageResponseTime: number;
    successRate: number;
    reliability: number;
    costEfficiency: number;
  };
  constraints: {
    maxConcurrentTasks: number;
    workingHours?: {
      start: string;
      end: string;
      timezone: string;
    };
    dataRestrictions: string[];
    geographicLimitations: string[];
  };
  embedding?: number[]; // Vector representation of capabilities
  lastUpdated: Date;
  trustLevel: number;
}

/**
 * Task description for matching
 */
export interface TaskDescription {
  id: string;
  title: string;
  description: string;
  requiredCapabilities: string[];
  preferredCapabilities?: string[];
  priority: 'low' | 'medium' | 'high' | 'critical';
  constraints: {
    maxCost?: number;
    maxDuration?: number;
    minTrustLevel?: number;
    dataClassification?: 'public' | 'internal' | 'confidential' | 'restricted';
    requiredCertifications?: string[];
  };
  context: {
    domain: string;
    urgency: boolean;
    complexity: 'simple' | 'moderate' | 'complex' | 'expert';
    estimatedDuration: number;
  };
  embedding?: number[]; // Vector representation of task requirements
}

/**
 * Match result
 */
export interface AgentMatch {
  agent: AgentCapabilityProfile;
  score: number;
  confidence: number;
  reasoning: string;
  capabilityAlignment: {
    required: { capability: string; match: boolean; strength: number }[];
    preferred: { capability: string; match: boolean; strength: number }[];
    additional: { capability: string; strength: number }[];
  };
  riskAssessment: {
    level: 'low' | 'medium' | 'high';
    factors: string[];
    mitigations: string[];
  };
  estimatedMetrics: {
    cost: number;
    duration: number;
    successProbability: number;
  };
}

/**
 * Matching configuration
 */
export interface MatchingConfig {
  embeddingModel: string;
  similarityThreshold: number;
  maxResults: number;
  weightings: {
    capabilityMatch: number;
    performance: number;
    availability: number;
    cost: number;
    trust: number;
    experience: number;
  };
  enableSemanticMatching: boolean;
  enableLearning: boolean;
  cacheEmbeddings: boolean;
}

/**
 * Agent Matcher
 */
export class AgentMatcher extends EventEmitter {
  private agentProfiles: Map<string, AgentCapabilityProfile> = new Map();
  private taskEmbeddings: Map<string, number[]> = new Map();
  private agentEmbeddings: Map<string, number[]> = new Map();
  private matchHistory: Array<{
    taskId: string;
    matches: AgentMatch[];
    selectedAgent: string;
    outcome: 'success' | 'failure' | 'partial';
    actualMetrics: {
      cost: number;
      duration: number;
      quality: number;
    };
    timestamp: Date;
  }> = [];
  private semanticCache: Map<string, number[]> = new Map();

  constructor(
    private messageRouter: MessageRouter,
    private authManager: AuthManager,
    private auditLogger: AuditLogger,
    private config: MatchingConfig = {
      embeddingModel: 'text-embedding-ada-002',
      similarityThreshold: 0.7,
      maxResults: 10,
      weightings: {
        capabilityMatch: 0.3,
        performance: 0.25,
        availability: 0.15,
        cost: 0.1,
        trust: 0.1,
        experience: 0.1
      },
      enableSemanticMatching: true,
      enableLearning: true,
      cacheEmbeddings: true
    }
  ) {
    super();
    this.loadAgentProfiles();
  }

  /**
   * Register agent profile
   */
  async registerAgent(profile: Omit<AgentCapabilityProfile, 'embedding' | 'lastUpdated'>): Promise<void> {
    // Create temporary profile for embedding generation
    const tempProfile: AgentCapabilityProfile = {
      ...profile,
      embedding: [], // Will be replaced
      lastUpdated: new Date()
    };
    
    // Generate embedding for agent capabilities
    const embedding = await this.generateAgentEmbedding(tempProfile);
    
    const fullProfile: AgentCapabilityProfile = {
      ...profile,
      embedding,
      lastUpdated: new Date()
    };

    this.agentProfiles.set(profile.agentDID, fullProfile);
    this.agentEmbeddings.set(profile.agentDID, embedding);

    await this.saveAgentProfiles();
    
    this.emit('agent_registered', fullProfile);
  }

  /**
   * Update agent profile
   */
  async updateAgent(
    agentDID: string, 
    updates: Partial<AgentCapabilityProfile>
  ): Promise<void> {
    const existing = this.agentProfiles.get(agentDID);
    if (!existing) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: `Agent profile not found: ${agentDID}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    const updated = { ...existing, ...updates, lastUpdated: new Date() };
    
    // Regenerate embedding if capabilities changed
    if (updates.capabilities || updates.expertise || updates.availableActions) {
      updated.embedding = await this.generateAgentEmbedding(updated);
      this.agentEmbeddings.set(agentDID, updated.embedding);
    }

    this.agentProfiles.set(agentDID, updated);
    await this.saveAgentProfiles();
    
    this.emit('agent_updated', updated);
  }

  /**
   * Find matching agents for task
   */
  async findMatches(task: TaskDescription): Promise<AgentMatch[]> {
    // Generate task embedding
    const taskEmbedding = await this.generateTaskEmbedding(task);
    task.embedding = taskEmbedding;
    this.taskEmbeddings.set(task.id, taskEmbedding);

    // Get all available agents
    const availableAgents = await this.getAvailableAgents(task);
    
    if (availableAgents.length === 0) {
      return [];
    }

    // Score and rank agents
    const matches: AgentMatch[] = [];
    
    for (const agent of availableAgents) {
      const match = await this.scoreAgentMatch(agent, task);
      if (match.score >= this.config.similarityThreshold) {
        matches.push(match);
      }
    }

    // Sort by score (highest first)
    matches.sort((a, b) => b.score - a.score);

    // Apply learning adjustments if enabled
    if (this.config.enableLearning) {
      this.applyLearningAdjustments(matches, task);
    }

    // Return top results
    const results = matches.slice(0, this.config.maxResults);
    
    // Log matching request
    await this.auditLogger.logRequest(
      {
        id: `matching-${task.id}`,
        type: LLMRequestType.COMPLETION,
        prompt: `Find agents for task: ${task.title}`,
        agentDID: 'system-agent-matcher',
        sessionId: `matching-${Date.now()}`,
        metadata: {
          agentDID: 'system-agent-matcher',
          sessionId: `matching-${Date.now()}`,
          requestId: `matching-${task.id}`,
          timestamp: new Date(),
          source: 'agent-matcher',
          priority: RequestPriority.MEDIUM,
          taskId: task.id
        }
      },
      'system-agent-matcher',
      `matching-${Date.now()}`
    );

    this.emit('matches_found', { task, matches: results });
    return results;
  }

  /**
   * Find semantically similar agents
   */
  async findSimilarAgents(
    agentDID: string,
    options: {
      includeInactive?: boolean;
      maxResults?: number;
      minSimilarity?: number;
    } = {}
  ): Promise<Array<{ agent: AgentCapabilityProfile; similarity: number }>> {
    const sourceAgent = this.agentProfiles.get(agentDID);
    if (!sourceAgent || !sourceAgent.embedding) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: `Agent not found or missing embedding: ${agentDID}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    const similarities: Array<{ agent: AgentCapabilityProfile; similarity: number }> = [];
    
    for (const [id, agent] of this.agentProfiles) {
      if (id === agentDID) continue; // Skip self
      if (!agent.embedding) continue;

      const similarity = this.calculateCosineSimilarity(
        sourceAgent.embedding,
        agent.embedding
      );

      if (similarity >= (options.minSimilarity || 0.5)) {
        similarities.push({ agent, similarity });
      }
    }

    // Sort by similarity
    similarities.sort((a, b) => b.similarity - a.similarity);
    
    // Return top results
    return similarities.slice(0, options.maxResults || 10);
  }

  /**
   * Recommend agents based on context
   */
  async recommendAgents(
    context: {
      domain: string;
      urgency: boolean;
      complexity: 'simple' | 'moderate' | 'complex' | 'expert';
      budget?: number;
      requiredCertifications?: string[];
    },
    options: {
      maxResults?: number;
      diversityFactor?: number; // 0-1, higher = more diverse results
    } = {}
  ): Promise<AgentMatch[]> {
    // Create synthetic task for recommendation
    const syntheticTask: TaskDescription = {
      id: `recommendation-${Date.now()}`,
      title: `${context.domain} task`,
      description: `A ${context.complexity} ${context.domain} task`,
      requiredCapabilities: [context.domain],
      priority: context.urgency ? 'high' : 'medium',
      constraints: {
        maxCost: context.budget,
        requiredCertifications: context.requiredCertifications
      },
      context: {
        domain: context.domain,
        urgency: context.urgency,
        complexity: context.complexity,
        estimatedDuration: this.estimateDurationByComplexity(context.complexity)
      }
    };

    const matches = await this.findMatches(syntheticTask);
    
    // Apply diversity if requested
    if (options.diversityFactor && options.diversityFactor > 0) {
      return this.diversifyResults(matches, options.diversityFactor);
    }

    return matches.slice(0, options.maxResults || 5);
  }

  /**
   * Generate agent embedding
   */
  private async generateAgentEmbedding(agent: AgentCapabilityProfile): Promise<number[]> {
    if (!this.config.enableSemanticMatching) {
      return this.generateSimpleEmbedding(agent);
    }

    // Create text representation of agent capabilities
    const agentText = [
      agent.description,
      ...agent.capabilities,
      ...agent.expertise,
      ...agent.availableActions
    ].join(' ');

    // Check cache first
    const cacheKey = `agent:${this.hashString(agentText)}`;
    if (this.config.cacheEmbeddings && this.semanticCache.has(cacheKey)) {
      return this.semanticCache.get(cacheKey)!;
    }

    // Generate embedding using LLM
    const embedding = await this.generateEmbedding(agentText);
    
    // Cache result
    if (this.config.cacheEmbeddings) {
      this.semanticCache.set(cacheKey, embedding);
    }

    return embedding;
  }

  /**
   * Generate task embedding
   */
  private async generateTaskEmbedding(task: TaskDescription): Promise<number[]> {
    if (!this.config.enableSemanticMatching) {
      return this.generateSimpleTaskEmbedding(task);
    }

    // Create text representation of task requirements
    const taskText = [
      task.title,
      task.description,
      ...task.requiredCapabilities,
      ...(task.preferredCapabilities || []),
      task.context.domain,
      task.context.complexity
    ].join(' ');

    // Check cache first
    const cacheKey = `task:${this.hashString(taskText)}`;
    if (this.config.cacheEmbeddings && this.semanticCache.has(cacheKey)) {
      return this.semanticCache.get(cacheKey)!;
    }

    // Generate embedding using LLM
    const embedding = await this.generateEmbedding(taskText);
    
    // Cache result
    if (this.config.cacheEmbeddings) {
      this.semanticCache.set(cacheKey, embedding);
    }

    return embedding;
  }

  /**
   * Generate embedding using LLM
   */
  private async generateEmbedding(text: string): Promise<number[]> {
    try {
      const request: LLMRequest = {
        id: `embedding-${Date.now()}`,
        type: LLMRequestType.EMBEDDING,
        prompt: text,
        agentDID: 'system-agent-matcher',
        sessionId: `embedding-${Date.now()}`,
        parameters: {
          model: this.config.embeddingModel
        },
        metadata: {
          agentDID: 'system-agent-matcher',
          sessionId: `embedding-${Date.now()}`,
          requestId: `embedding-${Date.now()}`,
          timestamp: new Date(),
          source: 'agent-matcher',
          priority: RequestPriority.LOW
        }
      };

      const response = await this.messageRouter.routeMessage(request);
      
      if (response.embedding) {
        return response.embedding;
      }

      throw new Error('No embedding returned from LLM');
      
    } catch (error) {
      console.warn('Failed to generate semantic embedding, falling back to simple embedding:', error);
      return this.generateSimpleEmbedding({ capabilities: [text] } as any);
    }
  }

  /**
   * Generate simple embedding (fallback)
   */
  private generateSimpleEmbedding(agent: AgentCapabilityProfile): number[] {
    // Create a simple hash-based embedding
    const features = [
      ...agent.capabilities,
      ...agent.expertise,
      ...agent.availableActions
    ];

    const embedding = new Array(128).fill(0);
    
    for (const feature of features) {
      const hash = this.hashString(feature);
      for (let i = 0; i < embedding.length; i++) {
        embedding[i] += ((hash >> i) & 1) ? 1 : -1;
      }
    }

    // Normalize
    const magnitude = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
    return embedding.map(val => val / magnitude);
  }

  /**
   * Generate simple task embedding
   */
  private generateSimpleTaskEmbedding(task: TaskDescription): number[] {
    const features = [
      ...task.requiredCapabilities,
      ...(task.preferredCapabilities || []),
      task.context.domain,
      task.context.complexity
    ];

    const embedding = new Array(128).fill(0);
    
    for (const feature of features) {
      const hash = this.hashString(feature);
      for (let i = 0; i < embedding.length; i++) {
        embedding[i] += ((hash >> i) & 1) ? 1 : -1;
      }
    }

    // Normalize
    const magnitude = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
    return embedding.map(val => val / magnitude);
  }

  /**
   * Score agent match against task
   */
  private async scoreAgentMatch(
    agent: AgentCapabilityProfile,
    task: TaskDescription
  ): Promise<AgentMatch> {
    // Calculate base similarity using embeddings
    let similarity = 0;
    if (agent.embedding && task.embedding) {
      similarity = this.calculateCosineSimilarity(agent.embedding, task.embedding);
    }

    // Calculate capability alignment
    const capabilityAlignment = this.calculateCapabilityAlignment(agent, task);
    
    // Calculate performance score
    const performanceScore = this.calculatePerformanceScore(agent, task);
    
    // Calculate availability score
    const availabilityScore = this.calculateAvailabilityScore(agent, task);
    
    // Calculate cost score
    const costScore = this.calculateCostScore(agent, task);
    
    // Calculate trust score
    const trustScore = agent.trustLevel;
    
    // Calculate experience score
    const experienceScore = this.calculateExperienceScore(agent, task);

    // Weighted total score
    const score = 
      similarity * this.config.weightings.capabilityMatch +
      performanceScore * this.config.weightings.performance +
      availabilityScore * this.config.weightings.availability +
      costScore * this.config.weightings.cost +
      trustScore * this.config.weightings.trust +
      experienceScore * this.config.weightings.experience;

    // Calculate confidence based on data quality
    const confidence = this.calculateConfidence(agent, task, similarity);

    // Generate reasoning
    const reasoning = this.generateMatchReasoning(
      agent, task, score, capabilityAlignment, performanceScore
    );

    // Risk assessment
    const riskAssessment = this.assessRisk(agent, task);

    // Estimated metrics
    const estimatedMetrics = this.estimateTaskMetrics(agent, task);

    return {
      agent,
      score: Math.min(1, Math.max(0, score)),
      confidence,
      reasoning,
      capabilityAlignment,
      riskAssessment,
      estimatedMetrics
    };
  }

  /**
   * Calculate capability alignment
   */
  private calculateCapabilityAlignment(
    agent: AgentCapabilityProfile,
    task: TaskDescription
  ): AgentMatch['capabilityAlignment'] {
    const required = task.requiredCapabilities.map(capability => {
      const match = agent.capabilities.some(ac => 
        ac.toLowerCase().includes(capability.toLowerCase()) ||
        capability.toLowerCase().includes(ac.toLowerCase())
      );
      const strength = match ? this.calculateCapabilityStrength(agent, capability) : 0;
      
      return { capability, match, strength };
    });

    const preferred = (task.preferredCapabilities || []).map(capability => {
      const match = agent.capabilities.some(ac => 
        ac.toLowerCase().includes(capability.toLowerCase()) ||
        capability.toLowerCase().includes(ac.toLowerCase())
      );
      const strength = match ? this.calculateCapabilityStrength(agent, capability) : 0;
      
      return { capability, match, strength };
    });

    const additional = agent.capabilities
      .filter(capability => 
        !task.requiredCapabilities.some(rc => 
          rc.toLowerCase().includes(capability.toLowerCase())
        ) &&
        !(task.preferredCapabilities || []).some(pc => 
          pc.toLowerCase().includes(capability.toLowerCase())
        )
      )
      .map(capability => ({
        capability,
        strength: this.calculateCapabilityStrength(agent, capability)
      }));

    return { required, preferred, additional };
  }

  /**
   * Calculate capability strength
   */
  private calculateCapabilityStrength(agent: AgentCapabilityProfile, capability: string): number {
    // Check if it's in expertise (higher weight)
    if (agent.expertise.some(exp => exp.toLowerCase().includes(capability.toLowerCase()))) {
      return 0.9;
    }
    
    // Check if it's in available actions
    if (agent.availableActions.some(action => action.toLowerCase().includes(capability.toLowerCase()))) {
      return 0.7;
    }
    
    // Check if it's in general capabilities
    if (agent.capabilities.some(cap => cap.toLowerCase().includes(capability.toLowerCase()))) {
      return 0.6;
    }
    
    return 0;
  }

  /**
   * Calculate performance score
   */
  private calculatePerformanceScore(agent: AgentCapabilityProfile, task: TaskDescription): number {
    const performance = agent.performance;
    
    // Weighted performance score
    const responseTimeScore = Math.max(0, 1 - (performance.averageResponseTime / 10000)); // Normalize to 10s max
    const successScore = performance.successRate;
    const reliabilityScore = performance.reliability;
    const costScore = performance.costEfficiency;
    
    return (responseTimeScore + successScore + reliabilityScore + costScore) / 4;
  }

  /**
   * Calculate availability score
   */
  private calculateAvailabilityScore(agent: AgentCapabilityProfile, task: TaskDescription): number {
    // Check working hours
    if (agent.constraints.workingHours) {
      const now = new Date();
      const currentHour = now.getHours();
      const startHour = parseInt(agent.constraints.workingHours.start.split(':')[0]);
      const endHour = parseInt(agent.constraints.workingHours.end.split(':')[0]);
      
      if (currentHour < startHour || currentHour > endHour) {
        return 0.3; // Reduced availability outside working hours
      }
    }
    
    // Check concurrent task capacity
    // This would need to be tracked externally
    const estimatedUtilization = 0.5; // Mock value
    return Math.max(0, 1 - estimatedUtilization);
  }

  /**
   * Calculate cost score
   */
  private calculateCostScore(agent: AgentCapabilityProfile, task: TaskDescription): number {
    const estimatedCost = this.estimateTaskCost(agent, task);
    const maxCost = task.constraints.maxCost || 100;
    
    return Math.max(0, 1 - (estimatedCost / maxCost));
  }

  /**
   * Calculate experience score
   */
  private calculateExperienceScore(agent: AgentCapabilityProfile, task: TaskDescription): number {
    // This would be based on historical performance in similar tasks
    // For now, use expertise alignment
    const domainExpertise = agent.expertise.some(exp => 
      exp.toLowerCase().includes(task.context.domain.toLowerCase())
    );
    
    const complexityMatch = this.getComplexityScore(agent, task.context.complexity);
    
    return domainExpertise ? 0.8 + complexityMatch * 0.2 : complexityMatch;
  }

  /**
   * Get complexity score
   */
  private getComplexityScore(agent: AgentCapabilityProfile, complexity: string): number {
    // This would ideally be based on historical data
    const complexityScores = {
      simple: 0.9,
      moderate: 0.7,
      complex: 0.5,
      expert: agent.expertise.length > 3 ? 0.8 : 0.3
    };
    
    return complexityScores[complexity as keyof typeof complexityScores] || 0.5;
  }

  /**
   * Calculate confidence
   */
  private calculateConfidence(
    agent: AgentCapabilityProfile,
    task: TaskDescription,
    similarity: number
  ): number {
    // Base confidence on data quality and match strength
    let confidence = 0.5;
    
    // Boost confidence for strong similarity
    if (similarity > 0.8) confidence += 0.3;
    else if (similarity > 0.6) confidence += 0.2;
    else if (similarity > 0.4) confidence += 0.1;
    
    // Boost confidence for complete agent profile
    if (agent.performance.averageResponseTime > 0) confidence += 0.1;
    if (agent.trustLevel > 0.8) confidence += 0.1;
    if (agent.expertise.length > 0) confidence += 0.1;
    
    return Math.min(1, confidence);
  }

  /**
   * Generate match reasoning
   */
  private generateMatchReasoning(
    agent: AgentCapabilityProfile,
    task: TaskDescription,
    score: number,
    capabilityAlignment: AgentMatch['capabilityAlignment'],
    performanceScore: number
  ): string {
    const reasons = [];
    
    const requiredMatches = capabilityAlignment.required.filter(r => r.match).length;
    const requiredTotal = capabilityAlignment.required.length;
    
    reasons.push(`Matches ${requiredMatches}/${requiredTotal} required capabilities`);
    
    if (performanceScore > 0.8) {
      reasons.push('Excellent performance history');
    } else if (performanceScore > 0.6) {
      reasons.push('Good performance history');
    }
    
    if (agent.trustLevel > 0.8) {
      reasons.push('High trust level');
    }
    
    const preferredMatches = capabilityAlignment.preferred.filter(p => p.match).length;
    if (preferredMatches > 0) {
      reasons.push(`Matches ${preferredMatches} preferred capabilities`);
    }
    
    return `Score: ${(score * 100).toFixed(1)}%. ${reasons.join(', ')}.`;
  }

  /**
   * Assess risk
   */
  private assessRisk(
    agent: AgentCapabilityProfile,
    task: TaskDescription
  ): AgentMatch['riskAssessment'] {
    const factors: string[] = [];
    const mitigations: string[] = [];
    
    // Trust level risk
    if (agent.trustLevel < 0.5) {
      factors.push('Low trust level');
      mitigations.push('Require additional oversight');
    }
    
    // Performance risk
    if (agent.performance.successRate < 0.8) {
      factors.push('Below average success rate');
      mitigations.push('Monitor progress closely');
    }
    
    // Capability mismatch risk
    const requiredMatches = task.requiredCapabilities.filter(req =>
      agent.capabilities.some(cap => cap.toLowerCase().includes(req.toLowerCase()))
    ).length;
    
    if (requiredMatches < task.requiredCapabilities.length) {
      factors.push('Missing some required capabilities');
      mitigations.push('Provide additional training or support');
    }
    
    // Data classification risk
    if (task.constraints.dataClassification === 'restricted' && agent.trustLevel < 0.9) {
      factors.push('Restricted data access with moderate trust');
      mitigations.push('Enhanced security monitoring');
    }
    
    const level = factors.length === 0 ? 'low' : 
                  factors.length <= 2 ? 'medium' : 'high';
    
    return { level, factors, mitigations };
  }

  /**
   * Estimate task metrics
   */
  private estimateTaskMetrics(
    agent: AgentCapabilityProfile,
    task: TaskDescription
  ): AgentMatch['estimatedMetrics'] {
    const cost = this.estimateTaskCost(agent, task);
    const duration = this.estimateTaskDuration(agent, task);
    const successProbability = Math.min(1, agent.performance.successRate + 
      (agent.trustLevel - 0.5) * 0.2); // Adjust based on trust
    
    return { cost, duration, successProbability };
  }

  /**
   * Estimate task cost
   */
  private estimateTaskCost(agent: AgentCapabilityProfile, task: TaskDescription): number {
    // Base cost calculation (simplified)
    const complexityMultiplier = {
      simple: 1,
      moderate: 2,
      complex: 4,
      expert: 8
    };
    
    const baseCost = 10; // Base cost units
    const complexity = complexityMultiplier[task.context.complexity] || 1;
    const efficiency = agent.performance.costEfficiency || 0.5;
    
    return baseCost * complexity / efficiency;
  }

  /**
   * Estimate task duration
   */
  private estimateTaskDuration(agent: AgentCapabilityProfile, task: TaskDescription): number {
    const baseTime = this.estimateDurationByComplexity(task.context.complexity);
    const efficiency = agent.performance.averageResponseTime / 1000; // Convert to seconds
    
    return Math.max(300, baseTime * (1 + efficiency / 10)); // Minimum 5 minutes
  }

  /**
   * Estimate duration by complexity
   */
  private estimateDurationByComplexity(complexity: string): number {
    const durations = {
      simple: 1800,    // 30 minutes
      moderate: 3600,  // 1 hour
      complex: 7200,   // 2 hours
      expert: 14400    // 4 hours
    };
    
    return durations[complexity as keyof typeof durations] || 3600;
  }

  /**
   * Get available agents
   */
  private async getAvailableAgents(task: TaskDescription): Promise<AgentCapabilityProfile[]> {
    const available: AgentCapabilityProfile[] = [];
    
    for (const [, agent] of this.agentProfiles) {
      // Check trust level requirement
      if (task.constraints.minTrustLevel && agent.trustLevel < task.constraints.minTrustLevel) {
        continue;
      }
      
      // Check data restrictions
      if (this.hasDataRestrictions(agent, task)) {
        continue;
      }
      
      // Check certifications
      if (task.constraints.requiredCertifications) {
        // This would check against agent certifications
        // For now, assume all agents are certified
      }
      
      available.push(agent);
    }
    
    return available;
  }

  /**
   * Check data restrictions
   */
  private hasDataRestrictions(agent: AgentCapabilityProfile, task: TaskDescription): boolean {
    if (!task.constraints.dataClassification) return false;
    
    const restrictionLevel = {
      public: 0,
      internal: 1,
      confidential: 2,
      restricted: 3
    };
    
    const taskLevel = restrictionLevel[task.constraints.dataClassification] || 0;
    
    // Check if agent has sufficient clearance (simplified)
    const agentClearance = agent.trustLevel >= 0.9 ? 3 : 
                          agent.trustLevel >= 0.7 ? 2 :
                          agent.trustLevel >= 0.5 ? 1 : 0;
    
    return agentClearance < taskLevel;
  }

  /**
   * Apply learning adjustments
   */
  private applyLearningAdjustments(matches: AgentMatch[], task: TaskDescription): void {
    if (!this.config.enableLearning) return;
    
    // Adjust scores based on historical performance
    for (const match of matches) {
      const history = this.matchHistory.filter(h => 
        h.selectedAgent === match.agent.agentDID &&
        h.outcome === 'success'
      );
      
      if (history.length > 0) {
        const successRate = history.length / 
          this.matchHistory.filter(h => h.selectedAgent === match.agent.agentDID).length;
        
        // Boost score for agents with good track record
        match.score *= (0.8 + successRate * 0.2);
        match.score = Math.min(1, match.score);
      }
    }
    
    // Re-sort after adjustments
    matches.sort((a, b) => b.score - a.score);
  }

  /**
   * Diversify results
   */
  private diversifyResults(matches: AgentMatch[], diversityFactor: number): AgentMatch[] {
    if (matches.length <= 1) return matches;
    
    const diversified = [matches[0]]; // Always include top match
    const remaining = matches.slice(1);
    
    while (diversified.length < matches.length && remaining.length > 0) {
      let maxDiversity = -1;
      let bestIndex = 0;
      
      for (let i = 0; i < remaining.length; i++) {
        const candidate = remaining[i];
        let minSimilarity = 1;
        
        // Find minimum similarity to already selected agents
        for (const selected of diversified) {
          if (candidate.agent.embedding && selected.agent.embedding) {
            const similarity = this.calculateCosineSimilarity(
              candidate.agent.embedding,
              selected.agent.embedding
            );
            minSimilarity = Math.min(minSimilarity, similarity);
          }
        }
        
        const diversity = 1 - minSimilarity;
        const combinedScore = candidate.score * (1 - diversityFactor) + diversity * diversityFactor;
        
        if (combinedScore > maxDiversity) {
          maxDiversity = combinedScore;
          bestIndex = i;
        }
      }
      
      diversified.push(remaining[bestIndex]);
      remaining.splice(bestIndex, 1);
    }
    
    return diversified;
  }

  /**
   * Calculate cosine similarity
   */
  private calculateCosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) return 0;
    
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    
    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    
    const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
    return magnitude === 0 ? 0 : dotProduct / magnitude;
  }

  /**
   * Hash string to number
   */
  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  /**
   * Record match outcome for learning
   */
  async recordMatchOutcome(
    taskId: string,
    selectedAgentDID: string,
    outcome: 'success' | 'failure' | 'partial',
    actualMetrics: {
      cost: number;
      duration: number;
      quality: number;
    }
  ): Promise<void> {
    const matchRecord = this.matchHistory.find(h => h.taskId === taskId);
    if (matchRecord) {
      matchRecord.selectedAgent = selectedAgentDID;
      matchRecord.outcome = outcome;
      matchRecord.actualMetrics = actualMetrics;
    } else {
      this.matchHistory.push({
        taskId,
        matches: [], // Would be populated from original match
        selectedAgent: selectedAgentDID,
        outcome,
        actualMetrics,
        timestamp: new Date()
      });
    }
    
    // Update agent performance based on outcome
    const agent = this.agentProfiles.get(selectedAgentDID);
    if (agent) {
      this.updateAgentPerformance(agent, outcome, actualMetrics);
    }
    
    this.emit('match_outcome_recorded', {
      taskId,
      selectedAgentDID,
      outcome,
      actualMetrics
    });
  }

  /**
   * Update agent performance
   */
  private updateAgentPerformance(
    agent: AgentCapabilityProfile,
    outcome: 'success' | 'failure' | 'partial',
    actualMetrics: { cost: number; duration: number; quality: number }
  ): void {
    // Simple running average update
    const alpha = 0.1; // Learning rate
    
    if (outcome === 'success') {
      agent.performance.successRate = agent.performance.successRate * (1 - alpha) + alpha;
    } else {
      agent.performance.successRate = agent.performance.successRate * (1 - alpha);
    }
    
    // Update other metrics (simplified)
    agent.performance.averageResponseTime = 
      agent.performance.averageResponseTime * (1 - alpha) + actualMetrics.duration * alpha;
    
    agent.lastUpdated = new Date();
  }

  /**
   * Load agent profiles
   */
  private async loadAgentProfiles(): Promise<void> {
    // This would load from persistent storage
    // For now, create some mock profiles
    const mockProfiles: AgentCapabilityProfile[] = [
      {
        agentDID: 'did:key:customer-service-bot',
        name: 'Customer Service Assistant',
        description: 'Specialized in customer support and service inquiries',
        capabilities: ['customer_service', 'chat_support', 'ticket_management'],
        expertise: ['customer_relations', 'problem_solving'],
        availableActions: ['answer_questions', 'create_tickets', 'escalate_issues'],
        performance: {
          averageResponseTime: 2000,
          successRate: 0.92,
          reliability: 0.95,
          costEfficiency: 0.8
        },
        constraints: {
          maxConcurrentTasks: 10,
          dataRestrictions: [],
          geographicLimitations: []
        },
        lastUpdated: new Date(),
        trustLevel: 0.85
      }
    ];
    
    for (const profile of mockProfiles) {
      await this.registerAgent(profile);
    }
  }

  /**
   * Save agent profiles
   */
  private async saveAgentProfiles(): Promise<void> {
    // This would save to persistent storage
    // For now, just emit event
    this.emit('profiles_saved', Array.from(this.agentProfiles.values()));
  }

  /**
   * Get matching statistics
   */
  getStatistics(): {
    totalProfiles: number;
    totalMatches: number;
    averageMatchScore: number;
    successRate: number;
    embeddingCacheSize: number;
  } {
    const totalMatches = this.matchHistory.length;
    const successfulMatches = this.matchHistory.filter(h => h.outcome === 'success').length;
    
    return {
      totalProfiles: this.agentProfiles.size,
      totalMatches,
      averageMatchScore: 0.75, // Would calculate from history
      successRate: totalMatches > 0 ? successfulMatches / totalMatches : 0,
      embeddingCacheSize: this.semanticCache.size
    };
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    this.agentProfiles.clear();
    this.taskEmbeddings.clear();
    this.agentEmbeddings.clear();
    this.semanticCache.clear();
    this.removeAllListeners();
  }
}

export default AgentMatcher;