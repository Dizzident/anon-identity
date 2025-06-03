/**
 * Delegation Integration for MCP
 * 
 * Integrates LLM-assisted delegation with the existing agent delegation system
 */

import { EventEmitter } from 'events';
import {
  MCPError,
  MCPErrorCode
} from '../types';
import { LLMDelegationEngine, DelegationRequest, DelegationDecision, DecisionContext, AgentProfile } from './llm-delegation-engine';
import { MessageRouter } from '../routing/message-router';
import { ConversationManager } from '../conversation/conversation-manager';
import { AuthManager } from '../security/auth-manager';
import { AuditLogger } from '../security/audit-logger';

/**
 * Enhanced delegation request with MCP integration
 */
export interface EnhancedDelegationRequest extends DelegationRequest {
  conversationId?: string;
  sessionId?: string;
  llmProviderPreference?: string;
  requireExplanation: boolean;
  allowModifications: boolean;
  maxResponseTime: number;
}

/**
 * Delegation workflow state
 */
export interface DelegationWorkflow {
  id: string;
  request: EnhancedDelegationRequest;
  currentStep: 'initiated' | 'analyzing' | 'llm_processing' | 'human_review' | 'completed' | 'failed';
  decision?: DelegationDecision;
  humanReviewer?: string;
  startedAt: Date;
  completedAt?: Date;
  steps: Array<{
    step: string;
    timestamp: Date;
    duration: number;
    status: 'pending' | 'completed' | 'failed';
    output?: any;
    error?: string;
  }>;
  metadata: {
    llmProvider?: string;
    conversationTurns: number;
    confidenceScore: number;
    totalProcessingTime: number;
  };
}

/**
 * Integration configuration
 */
export interface DelegationIntegrationConfig {
  enableLLMAssistance: boolean;
  fallbackToRules: boolean;
  requireHumanReview: boolean;
  maxProcessingTime: number;
  confidenceThreshold: number;
  enableConversationalFlow: boolean;
  retryOnFailure: boolean;
  maxRetries: number;
}

/**
 * Delegation Integration
 */
export class DelegationIntegration extends EventEmitter {
  private activeWorkflows: Map<string, DelegationWorkflow> = new Map();
  private workflowHistory: Map<string, DelegationWorkflow> = new Map();

  constructor(
    private llmEngine: LLMDelegationEngine,
    private messageRouter: MessageRouter,
    private conversationManager: ConversationManager,
    private authManager: AuthManager,
    private auditLogger: AuditLogger,
    private config: DelegationIntegrationConfig = {
      enableLLMAssistance: true,
      fallbackToRules: true,
      requireHumanReview: false,
      maxProcessingTime: 60000, // 1 minute
      confidenceThreshold: 0.8,
      enableConversationalFlow: true,
      retryOnFailure: true,
      maxRetries: 2
    }
  ) {
    super();
    this.setupEventHandlers();
  }

  /**
   * Process delegation request with full MCP integration
   */
  async processDelegationRequest(
    request: EnhancedDelegationRequest,
    context: DecisionContext
  ): Promise<DelegationWorkflow> {
    const workflowId = `workflow-${request.requestId}`;
    
    const workflow: DelegationWorkflow = {
      id: workflowId,
      request,
      currentStep: 'initiated',
      startedAt: new Date(),
      steps: [],
      metadata: {
        conversationTurns: 0,
        confidenceScore: 0,
        totalProcessingTime: 0
      }
    };

    this.activeWorkflows.set(workflowId, workflow);

    try {
      // Step 1: Initial analysis
      await this.executeWorkflowStep(workflow, 'analyzing', async () => {
        return await this.performInitialAnalysis(request, context);
      });

      // Step 2: LLM processing
      if (this.config.enableLLMAssistance) {
        await this.executeWorkflowStep(workflow, 'llm_processing', async () => {
          return await this.processWithLLM(workflow, context);
        });
      }

      // Step 3: Human review (if required)
      if (this.config.requireHumanReview || workflow.decision?.reviewRequired) {
        await this.executeWorkflowStep(workflow, 'human_review', async () => {
          return await this.requestHumanReview(workflow);
        });
      }

      // Step 4: Finalize decision
      await this.executeWorkflowStep(workflow, 'completed', async () => {
        return await this.finalizeDecision(workflow);
      });

      // Move to history
      this.workflowHistory.set(workflowId, workflow);
      this.activeWorkflows.delete(workflowId);

      this.emit('workflow_completed', workflow);
      return workflow;

    } catch (error) {
      workflow.currentStep = 'failed';
      workflow.completedAt = new Date();
      workflow.metadata.totalProcessingTime = Date.now() - workflow.startedAt.getTime();

      this.emit('workflow_failed', { workflow, error });
      throw error;
    }
  }

  /**
   * Handle conversational delegation request
   */
  async processConversationalDelegation(
    naturalLanguageRequest: string,
    agentDID: string,
    sessionId?: string
  ): Promise<DelegationWorkflow> {
    if (!this.config.enableConversationalFlow) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Conversational delegation is disabled',
        timestamp: new Date(),
        retryable: false
      });
    }

    // Start or continue conversation
    const conversation = sessionId ? 
      await this.conversationManager.sendMessage(sessionId, naturalLanguageRequest) :
      await this.conversationManager.startConversation(agentDID, {
        purpose: 'delegation_request',
        systemPrompt: 'You are helping to process a delegation request. Be clear and thorough in your analysis.'
      });

    // Extract session and context properly based on conversation type
    const session = 'session' in conversation ? conversation.session : conversation;
    const conversationContext = 'context' in conversation ? conversation.context : null;

    // Build context from conversation and agent profile
    const context = await this.buildContextFromConversation(session, agentDID);

    // Extract delegation request from natural language
    const delegationRequest = await this.llmEngine.processNaturalLanguageRequest(
      naturalLanguageRequest,
      agentDID,
      context
    );

    // Enhance with conversation details
    const enhancedRequest: EnhancedDelegationRequest = {
      ...delegationRequest,
      conversationId: conversationContext?.conversationId || session.contextId,
      sessionId: session.id,
      requireExplanation: true,
      allowModifications: true,
      maxResponseTime: this.config.maxProcessingTime
    };

    // Process the extracted request
    return this.processDelegationRequest(enhancedRequest, context);
  }

  /**
   * Query delegation status
   */
  async queryDelegationStatus(
    query: string,
    agentDID: string,
    sessionId?: string
  ): Promise<{
    activeWorkflows: DelegationWorkflow[];
    recentDecisions: DelegationDecision[];
    summary: string;
  }> {
    // Get active workflows for agent
    const activeWorkflows = Array.from(this.activeWorkflows.values())
      .filter(workflow => workflow.request.parentAgentDID === agentDID);

    // Get recent decisions
    const recentDecisions = Array.from(this.workflowHistory.values())
      .filter(workflow => 
        workflow.request.parentAgentDID === agentDID &&
        workflow.decision &&
        workflow.completedAt &&
        Date.now() - workflow.completedAt.getTime() < 24 * 60 * 60 * 1000 // Last 24 hours
      )
      .map(workflow => workflow.decision!)
      .slice(-10); // Last 10 decisions

    // Generate summary using LLM
    const summary = await this.generateStatusSummary(query, activeWorkflows, recentDecisions, agentDID);

    return {
      activeWorkflows,
      recentDecisions,
      summary
    };
  }

  /**
   * Execute workflow step
   */
  private async executeWorkflowStep(
    workflow: DelegationWorkflow,
    stepName: string,
    operation: () => Promise<any>
  ): Promise<void> {
    const startTime = Date.now();
    workflow.currentStep = stepName as any;

    const step: {
      step: string;
      timestamp: Date;
      duration: number;
      status: 'pending' | 'completed' | 'failed';
      output?: any;
      error?: string;
    } = {
      step: stepName,
      timestamp: new Date(),
      duration: 0,
      status: 'pending'
    };
    workflow.steps.push(step);

    try {
      const result = await operation();
      step.duration = Date.now() - startTime;
      step.status = 'completed';
      step.output = result;

      this.emit('workflow_step_completed', { workflow, step });

    } catch (error) {
      step.duration = Date.now() - startTime;
      step.status = 'failed';
      step.error = (error as Error).message;

      this.emit('workflow_step_failed', { workflow, step, error });
      throw error;
    }
  }

  /**
   * Perform initial analysis
   */
  private async performInitialAnalysis(
    request: EnhancedDelegationRequest,
    context: DecisionContext
  ): Promise<any> {
    // Validate request
    if (!request.purpose || request.purpose.trim().length === 0) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'Delegation purpose is required',
        timestamp: new Date(),
        retryable: false
      });
    }

    if (!request.requestedScopes || request.requestedScopes.length === 0) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'At least one scope must be requested',
        timestamp: new Date(),
        retryable: false
      });
    }

    // Check authorization
    const authResult = await this.authManager.authorize(
      request.parentAgentDID,
      'delegation:request',
      'create'
    );

    if (!authResult.authorized) {
      throw new MCPError({
        code: MCPErrorCode.FORBIDDEN,
        message: 'Not authorized to create delegation requests',
        timestamp: new Date(),
        retryable: false
      });
    }

    // Audit request
    await this.auditLogger.logRequest(
      {
        id: request.requestId,
        type: 'delegation_request' as any,
        prompt: `Delegation request: ${request.purpose}`,
        agentDID: request.parentAgentDID,
        sessionId: request.sessionId || 'direct',
        metadata: {
          agentDID: request.parentAgentDID,
          sessionId: request.sessionId || 'direct',
          requestId: request.requestId,
          timestamp: new Date(),
          source: 'delegation-integration',
          priority: 'medium' as any,
          delegationPurpose: request.purpose
        }
      },
      request.parentAgentDID,
      request.sessionId
    );

    return {
      validated: true,
      authorized: true,
      audited: true
    };
  }

  /**
   * Process with LLM
   */
  private async processWithLLM(
    workflow: DelegationWorkflow,
    context: DecisionContext
  ): Promise<DelegationDecision> {
    const startTime = Date.now();
    
    try {
      // Make decision using LLM
      const decision = await this.llmEngine.makeDelegationDecision(
        workflow.request,
        context
      );

      // Update workflow metadata
      workflow.decision = decision;
      workflow.metadata.confidenceScore = decision.confidence;
      workflow.metadata.llmProvider = this.config.enableLLMAssistance ? 'integrated' : 'fallback';

      // Check if decision meets confidence threshold
      if (decision.confidence < this.config.confidenceThreshold) {
        decision.reviewRequired = true;
        decision.warnings.push(`Low confidence score: ${decision.confidence}`);
      }

      return decision;

    } catch (error) {
      // Fallback to rule-based system if enabled
      if (this.config.fallbackToRules) {
        return this.fallbackDecision(workflow.request, context);
      }
      throw error;

    } finally {
      workflow.metadata.conversationTurns++;
    }
  }

  /**
   * Request human review
   */
  private async requestHumanReview(workflow: DelegationWorkflow): Promise<any> {
    // In a real implementation, this would integrate with a human review system
    // For now, we'll simulate the request
    
    workflow.humanReviewer = 'system-admin'; // Would be assigned based on policies
    
    this.emit('human_review_requested', {
      workflow,
      reason: workflow.decision?.warnings.join(', ') || 'Policy-required review',
      estimatedTime: 3600000 // 1 hour
    });

    // Simulate review process
    // In reality, this would wait for human input
    const reviewDecision = {
      approved: workflow.decision?.decision === 'approve',
      comments: 'Automated simulation of human review',
      reviewer: workflow.humanReviewer,
      reviewedAt: new Date()
    };

    return reviewDecision;
  }

  /**
   * Finalize decision
   */
  private async finalizeDecision(workflow: DelegationWorkflow): Promise<any> {
    if (!workflow.decision) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_REQUEST,
        message: 'No decision available to finalize',
        timestamp: new Date(),
        retryable: false
      });
    }

    workflow.completedAt = new Date();
    workflow.metadata.totalProcessingTime = Date.now() - workflow.startedAt.getTime();

    // Log final decision
    await this.auditLogger.logAuthorization(
      workflow.request.parentAgentDID,
      `delegation:${workflow.request.targetAgentDID}`,
      'finalize',
      workflow.decision.decision === 'approve',
      workflow.decision.warnings
    );

    return {
      finalized: true,
      decision: workflow.decision,
      processingTime: workflow.metadata.totalProcessingTime
    };
  }

  /**
   * Fallback decision using rule-based system
   */
  private fallbackDecision(
    request: DelegationRequest,
    context: DecisionContext
  ): DelegationDecision {
    // Simple rule-based fallback
    const decision: DelegationDecision = {
      requestId: request.requestId,
      decision: 'deny',
      confidence: 0.5,
      reasoning: 'Fallback rule-based decision due to LLM processing failure',
      warnings: ['LLM processing failed', 'Using conservative fallback rules'],
      riskAssessment: {
        level: 'medium',
        factors: ['LLM processing failure', 'Conservative approach'],
        mitigations: ['Manual review recommended']
      },
      decidedAt: new Date(),
      reviewRequired: true
    };

    // Basic approval logic
    if (context.parentAgent.trustLevel > 0.8 && 
        request.requestedScopes.length <= 3 &&
        !request.requestedScopes.some(scope => scope.includes('admin'))) {
      decision.decision = 'approve';
      decision.reasoning = 'Approved based on high trust level and limited scopes';
      decision.confidence = 0.6;
    }

    return decision;
  }

  /**
   * Build context from conversation
   */
  private async buildContextFromConversation(
    session: any,
    agentDID: string
  ): Promise<DecisionContext> {
    // Build a basic context - in a real implementation this would be more comprehensive
    const context: DecisionContext = {
      parentAgent: {
        did: agentDID,
        name: agentDID.split(':').pop() || 'Unknown',
        type: 'user',
        trustLevel: 0.7, // Would be calculated based on history
        capabilities: [],
        permissions: [],
        history: {
          totalDelegations: 0,
          successfulDelegations: 0,
          revokedDelegations: 0,
          averageDelegationDuration: 0,
          lastActivity: new Date()
        },
        riskFactors: []
      },
      organizationalPolicies: [],
      systemPolicies: [],
      currentDelegations: [],
      systemLoad: {
        cpu: 50,
        memory: 60,
        activeAgents: 10
      },
      securityLevel: 'normal',
      timeOfDay: new Date().toLocaleTimeString(),
      workingHours: true
    };

    return context;
  }

  /**
   * Generate status summary using LLM
   */
  private async generateStatusSummary(
    query: string,
    activeWorkflows: DelegationWorkflow[],
    recentDecisions: DelegationDecision[],
    agentDID: string
  ): Promise<string> {
    // Create a summary of the delegation status
    const summary = `
Agent ${agentDID} has ${activeWorkflows.length} active delegation workflows and ${recentDecisions.length} recent decisions.

Active Workflows:
${activeWorkflows.map(w => `- ${w.request.purpose} (${w.currentStep})`).join('\n')}

Recent Decisions:
${recentDecisions.map(d => `- ${d.decision} (confidence: ${d.confidence})`).join('\n')}

Query: ${query}
    `;

    return summary;
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    this.llmEngine.on('delegation_decision', (event) => {
      this.emit('llm_decision', event);
    });

    this.llmEngine.on('delegation_error', (event) => {
      this.emit('llm_error', event);
    });
  }

  /**
   * Get workflow statistics
   */
  getStatistics(): {
    activeWorkflows: number;
    completedWorkflows: number;
    averageProcessingTime: number;
    successRate: number;
    llmUsageRate: number;
    humanReviewRate: number;
  } {
    const completed = Array.from(this.workflowHistory.values());
    const totalCompleted = completed.length;
    const successful = completed.filter(w => w.decision?.decision === 'approve').length;
    const avgTime = completed.reduce((sum, w) => sum + w.metadata.totalProcessingTime, 0) / totalCompleted || 0;
    const llmUsed = completed.filter(w => w.metadata.llmProvider === 'integrated').length;
    const humanReviewed = completed.filter(w => w.humanReviewer).length;

    return {
      activeWorkflows: this.activeWorkflows.size,
      completedWorkflows: totalCompleted,
      averageProcessingTime: avgTime,
      successRate: totalCompleted > 0 ? successful / totalCompleted : 0,
      llmUsageRate: totalCompleted > 0 ? llmUsed / totalCompleted : 0,
      humanReviewRate: totalCompleted > 0 ? humanReviewed / totalCompleted : 0
    };
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    // Cancel active workflows
    for (const workflow of this.activeWorkflows.values()) {
      workflow.currentStep = 'failed';
      workflow.completedAt = new Date();
    }

    this.activeWorkflows.clear();
    this.workflowHistory.clear();
    this.removeAllListeners();
  }
}

export default DelegationIntegration;