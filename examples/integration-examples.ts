/**
 * Integration Examples for Agent-to-Agent Delegation
 * 
 * This file demonstrates how to integrate the agent-to-agent delegation system
 * with popular frameworks and platforms:
 * 1. LangChain integration for AI agent workflows
 * 2. Express.js API integration
 * 3. WebSocket real-time communication
 * 4. React frontend integration
 * 5. OpenAI function calling integration
 */

import { AgentIdentityManager } from '../src/agent/agent-identity';
import { DelegationManager } from '../src/agent/delegation-manager';
import { DelegationChainValidator } from '../src/agent/delegation-chain-validator';
import { CommunicationManager } from '../src/agent/communication/communication-manager';
import { ServiceProviderAgent } from '../src/sp/service-provider-agent';
import { generateKeyPair } from '../src/core/crypto';
import { DIDService } from '../src/core/did';

// ============================================================================
// 1. LangChain Integration Example
// ============================================================================

/**
 * LangChain Tool wrapper for delegation operations
 */
class DelegationTool {
  constructor(
    private agentManager: AgentIdentityManager,
    private delegationManager: DelegationManager,
    private agentDID: string,
    private agentKeyPair: any
  ) {}

  async call(input: { action: string; params: any }): Promise<string> {
    try {
      switch (input.action) {
        case 'create_sub_agent':
          return await this.createSubAgent(input.params);
        case 'delegate_access':
          return await this.delegateAccess(input.params);
        case 'revoke_access':
          return await this.revokeAccess(input.params);
        case 'list_agents':
          return await this.listAgents();
        default:
          throw new Error(`Unknown action: ${input.action}`);
      }
    } catch (error) {
      return `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }

  private async createSubAgent(params: {
    name: string;
    description: string;
    scopes: string[];
  }): Promise<string> {
    const subAgent = await this.agentManager.createSubAgent(this.agentDID, {
      name: params.name,
      description: params.description,
      parentAgentDID: this.agentDID,
      requestedScopes: params.scopes
    });

    return `Created sub-agent "${params.name}" with DID: ${subAgent.did}`;
  }

  private async delegateAccess(params: {
    targetAgentDID: string;
    serviceDID: string;
    scopes: string[];
    duration: number;
  }): Promise<string> {
    const credential = await this.delegationManager.createDelegationCredential(
      this.agentDID,
      this.agentKeyPair,
      params.targetAgentDID,
      'Delegated Agent',
      {
        serviceDID: params.serviceDID,
        scopes: params.scopes,
        expiresAt: new Date(Date.now() + params.duration)
      }
    );

    this.agentManager.addDelegationCredential(params.targetAgentDID, credential);
    return `Access delegated to ${params.targetAgentDID} for service ${params.serviceDID}`;
  }

  private async listAgents(): Promise<string> {
    const agents = this.agentManager.listAgents(this.agentDID);
    return `Found ${agents.length} sub-agents: ${agents.map(a => a.name).join(', ')}`;
  }

  name = 'delegation_manager';
  description = 'Manage agent delegation and access control';
}

/**
 * LangChain Agent with Delegation Capabilities
 */
class DelegationEnabledAgent {
  private tools: DelegationTool[];
  
  constructor(
    private agentManager: AgentIdentityManager,
    private delegationManager: DelegationManager,
    private agentIdentity: any
  ) {
    this.tools = [
      new DelegationTool(
        agentManager,
        delegationManager,
        agentIdentity.did,
        agentIdentity.keyPair
      )
    ];
  }

  async processRequest(request: string): Promise<string> {
    // Simple rule-based processing for demonstration
    if (request.includes('create agent')) {
      return await this.handleCreateAgent(request);
    } else if (request.includes('delegate access')) {
      return await this.handleDelegateAccess(request);
    } else if (request.includes('list agents')) {
      return await this.handleListAgents();
    } else {
      return 'I can help you with creating agents, delegating access, or listing agents.';
    }
  }

  private async handleCreateAgent(request: string): Promise<string> {
    // Extract parameters from natural language request
    const name = this.extractAgentName(request);
    const scopes = this.extractScopes(request);
    
    return await this.tools[0].call({
      action: 'create_sub_agent',
      params: {
        name,
        description: `Agent created via natural language: ${request}`,
        scopes
      }
    });
  }

  private extractAgentName(request: string): string {
    const match = request.match(/create.*agent.*named? ["']([^"']+)["']/i);
    return match?.[1] || 'Unnamed Agent';
  }

  private extractScopes(request: string): string[] {
    const defaultScopes = ['read:basic'];
    
    if (request.includes('admin')) return ['admin:all'];
    if (request.includes('write')) return ['read:basic', 'write:basic'];
    if (request.includes('read')) return ['read:basic'];
    
    return defaultScopes;
  }

  private async handleDelegateAccess(request: string): Promise<string> {
    // Simplified delegation logic
    return 'Delegation functionality would be implemented based on the specific request';
  }

  private async handleListAgents(): Promise<string> {
    return await this.tools[0].call({ action: 'list_agents', params: {} });
  }
}

// ============================================================================
// 2. Express.js API Integration Example
// ============================================================================

/**
 * Express.js middleware for delegation authentication
 */
function createDelegationMiddleware(
  chainValidator: DelegationChainValidator,
  serviceProvider: ServiceProviderAgent
) {
  return async (req: any, res: any, next: any) => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid authorization header' });
      }

      // Extract verifiable presentation from token
      const token = authHeader.substring(7);
      const presentation = JSON.parse(Buffer.from(token, 'base64').toString());

      // Verify presentation
      const verification = await serviceProvider.verifyPresentation(presentation);
      
      if (!verification.verified) {
        return res.status(403).json({ error: verification.error });
      }

      // Add agent information to request
      req.agent = {
        did: presentation.holder,
        scopes: verification.grantedScopes,
        verified: true
      };

      next();
    } catch (error) {
      res.status(500).json({ error: 'Authentication error' });
    }
  };
}

/**
 * Express.js route handlers with delegation support
 */
class DelegationAPIController {
  constructor(
    private agentManager: AgentIdentityManager,
    private delegationManager: DelegationManager,
    private chainValidator: DelegationChainValidator
  ) {}

  setupRoutes(app: any) {
    const delegationMiddleware = createDelegationMiddleware(
      this.chainValidator,
      new ServiceProviderAgent(['api-service'], this.chainValidator)
    );

    // Create sub-agent endpoint
    app.post('/api/agents', delegationMiddleware, async (req: any, res: any) => {
      try {
        if (!req.agent.scopes.includes('create:agents')) {
          return res.status(403).json({ error: 'Insufficient privileges' });
        }

        const subAgent = await this.agentManager.createSubAgent(req.agent.did, {
          name: req.body.name,
          description: req.body.description,
          parentAgentDID: req.agent.did,
          requestedScopes: req.body.scopes
        });

        res.json({
          success: true,
          agent: {
            did: subAgent.did,
            name: subAgent.name,
            delegationDepth: subAgent.delegationDepth
          }
        });
      } catch (error) {
        res.status(400).json({ 
          error: error instanceof Error ? error.message : 'Unknown error' 
        });
      }
    });

    // List agents endpoint
    app.get('/api/agents', delegationMiddleware, async (req: any, res: any) => {
      try {
        if (!req.agent.scopes.includes('read:agents')) {
          return res.status(403).json({ error: 'Insufficient privileges' });
        }

        const agents = this.agentManager.listAgents(req.agent.did);
        
        res.json({
          success: true,
          agents: agents.map(agent => ({
            did: agent.did,
            name: agent.name,
            delegationDepth: agent.delegationDepth,
            canDelegate: agent.canDelegate
          }))
        });
      } catch (error) {
        res.status(500).json({ error: 'Server error' });
      }
    });

    // Delegate access endpoint
    app.post('/api/delegate', delegationMiddleware, async (req: any, res: any) => {
      try {
        if (!req.agent.scopes.includes('delegate:access')) {
          return res.status(403).json({ error: 'Insufficient privileges' });
        }

        const { targetAgentDID, serviceDID, scopes, duration } = req.body;

        const credential = await this.delegationManager.createDelegationCredential(
          req.agent.did,
          req.agent.keyPair, // Would need to be retrieved securely
          targetAgentDID,
          'API Delegated Agent',
          {
            serviceDID,
            scopes,
            expiresAt: new Date(Date.now() + duration)
          }
        );

        this.agentManager.addDelegationCredential(targetAgentDID, credential);

        res.json({
          success: true,
          credential: {
            id: credential.id,
            serviceDID,
            scopes,
            expiresAt: credential.expirationDate
          }
        });
      } catch (error) {
        res.status(400).json({ 
          error: error instanceof Error ? error.message : 'Unknown error' 
        });
      }
    });
  }
}

// ============================================================================
// 3. WebSocket Real-Time Communication Example
// ============================================================================

/**
 * WebSocket server with delegation support
 */
class DelegationWebSocketServer {
  private clients: Map<string, any> = new Map();

  constructor(
    private communicationManager: CommunicationManager,
    private chainValidator: DelegationChainValidator
  ) {}

  setupWebSocketServer(server: any) {
    const WebSocket = require('ws');
    const wss = new WebSocket.Server({ server });

    wss.on('connection', async (ws: any, req: any) => {
      try {
        // Authenticate WebSocket connection
        const token = this.extractTokenFromRequest(req);
        const agentDID = await this.authenticateToken(token);
        
        if (!agentDID) {
          ws.close(1008, 'Authentication failed');
          return;
        }

        // Register client
        this.clients.set(agentDID, ws);

        // Handle messages
        ws.on('message', async (data: string) => {
          try {
            const message = JSON.parse(data);
            await this.handleWebSocketMessage(agentDID, message, ws);
          } catch (error) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Invalid message format'
            }));
          }
        });

        // Handle disconnection
        ws.on('close', () => {
          this.clients.delete(agentDID);
        });

        // Send welcome message
        ws.send(JSON.stringify({
          type: 'connected',
          agentDID,
          timestamp: new Date()
        }));

      } catch (error) {
        ws.close(1011, 'Server error');
      }
    });
  }

  private async handleWebSocketMessage(
    senderDID: string,
    message: any,
    ws: any
  ) {
    switch (message.type) {
      case 'delegation_request':
        await this.handleDelegationRequest(senderDID, message, ws);
        break;
      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', timestamp: new Date() }));
        break;
      case 'send_to_agent':
        await this.handleAgentMessage(senderDID, message);
        break;
      default:
        ws.send(JSON.stringify({
          type: 'error',
          message: `Unknown message type: ${message.type}`
        }));
    }
  }

  private async handleDelegationRequest(
    senderDID: string,
    message: any,
    ws: any
  ) {
    try {
      // Forward delegation request through communication manager
      await this.communicationManager.requestDelegation(
        message.targetAgentDID,
        message.requestedScopes,
        {
          purpose: message.purpose,
          duration: message.duration
        }
      );

      ws.send(JSON.stringify({
        type: 'delegation_request_sent',
        targetAgentDID: message.targetAgentDID,
        timestamp: new Date()
      }));
    } catch (error) {
      ws.send(JSON.stringify({
        type: 'delegation_request_failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      }));
    }
  }

  private async handleAgentMessage(senderDID: string, message: any) {
    const targetWS = this.clients.get(message.targetAgentDID);
    
    if (targetWS) {
      targetWS.send(JSON.stringify({
        type: 'agent_message',
        from: senderDID,
        content: message.content,
        timestamp: new Date()
      }));
    }
  }

  private extractTokenFromRequest(req: any): string | null {
    const url = new URL(req.url, 'ws://localhost');
    return url.searchParams.get('token');
  }

  private async authenticateToken(token: string | null): Promise<string | null> {
    if (!token) return null;
    
    try {
      // Decode and verify token (simplified)
      const payload = JSON.parse(Buffer.from(token, 'base64').toString());
      
      // Verify delegation chain
      const validation = await this.chainValidator.validateChain(
        payload.agentDID,
        'websocket-service'
      );
      
      return validation.valid ? payload.agentDID : null;
    } catch (error) {
      return null;
    }
  }
}

// ============================================================================
// 4. React Frontend Integration Example
// ============================================================================

/**
 * React hook for delegation management
 */
const useDelegationManager = () => {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(false);

  const createAgent = async (agentData: {
    name: string;
    description: string;
    scopes: string[];
  }) => {
    setLoading(true);
    try {
      const response = await fetch('/api/agents', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify(agentData)
      });

      if (!response.ok) {
        throw new Error('Failed to create agent');
      }

      const result = await response.json();
      setAgents(prev => [...prev, result.agent]);
      return result.agent;
    } catch (error) {
      console.error('Error creating agent:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const delegateAccess = async (delegationData: {
    targetAgentDID: string;
    serviceDID: string;
    scopes: string[];
    duration: number;
  }) => {
    setLoading(true);
    try {
      const response = await fetch('/api/delegate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify(delegationData)
      });

      if (!response.ok) {
        throw new Error('Failed to delegate access');
      }

      return await response.json();
    } catch (error) {
      console.error('Error delegating access:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const loadAgents = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/agents', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to load agents');
      }

      const result = await response.json();
      setAgents(result.agents);
    } catch (error) {
      console.error('Error loading agents:', error);
    } finally {
      setLoading(false);
    }
  };

  return {
    agents,
    loading,
    createAgent,
    delegateAccess,
    loadAgents
  };
};

/**
 * React component for agent management
 */
const AgentManagementDashboard = () => {
  const { agents, loading, createAgent, delegateAccess, loadAgents } = useDelegationManager();
  const [showCreateForm, setShowCreateForm] = useState(false);

  useEffect(() => {
    loadAgents();
  }, []);

  const handleCreateAgent = async (formData: any) => {
    try {
      await createAgent(formData);
      setShowCreateForm(false);
    } catch (error) {
      alert('Failed to create agent');
    }
  };

  return (
    <div className="agent-dashboard">
      <h1>Agent Management Dashboard</h1>
      
      <div className="dashboard-actions">
        <button onClick={() => setShowCreateForm(true)}>
          Create New Agent
        </button>
        <button onClick={loadAgents}>
          Refresh
        </button>
      </div>

      {loading && <div className="loading">Loading...</div>}

      <div className="agents-grid">
        {agents.map((agent: any) => (
          <div key={agent.did} className="agent-card">
            <h3>{agent.name}</h3>
            <p>DID: {agent.did.substring(0, 20)}...</p>
            <p>Depth: {agent.delegationDepth}</p>
            <p>Can Delegate: {agent.canDelegate ? 'Yes' : 'No'}</p>
            
            <div className="agent-actions">
              <button onClick={() => handleDelegateAccess(agent)}>
                Delegate Access
              </button>
              <button onClick={() => viewAgent(agent)}>
                View Details
              </button>
            </div>
          </div>
        ))}
      </div>

      {showCreateForm && (
        <CreateAgentModal
          onSubmit={handleCreateAgent}
          onCancel={() => setShowCreateForm(false)}
        />
      )}
    </div>
  );
};

// ============================================================================
// 5. OpenAI Function Calling Integration Example
// ============================================================================

/**
 * OpenAI function definitions for delegation operations
 */
const DELEGATION_FUNCTIONS = [
  {
    name: 'create_sub_agent',
    description: 'Create a new sub-agent with specific capabilities',
    parameters: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Name for the new sub-agent'
        },
        description: {
          type: 'string',
          description: 'Description of the sub-agent\'s purpose'
        },
        scopes: {
          type: 'array',
          items: { type: 'string' },
          description: 'List of permission scopes for the sub-agent'
        },
        maxDelegationDepth: {
          type: 'number',
          description: 'Maximum delegation depth for the sub-agent'
        }
      },
      required: ['name', 'description', 'scopes']
    }
  },
  {
    name: 'delegate_access',
    description: 'Delegate access permissions to another agent',
    parameters: {
      type: 'object',
      properties: {
        targetAgentDID: {
          type: 'string',
          description: 'DID of the agent to receive delegated access'
        },
        serviceDID: {
          type: 'string',
          description: 'Service identifier for the access delegation'
        },
        scopes: {
          type: 'array',
          items: { type: 'string' },
          description: 'Permission scopes to delegate'
        },
        duration: {
          type: 'number',
          description: 'Duration of the delegation in milliseconds'
        }
      },
      required: ['targetAgentDID', 'serviceDID', 'scopes']
    }
  },
  {
    name: 'revoke_agent_access',
    description: 'Revoke access for a specific agent',
    parameters: {
      type: 'object',
      properties: {
        targetAgentDID: {
          type: 'string',
          description: 'DID of the agent to revoke'
        },
        reason: {
          type: 'string',
          description: 'Reason for revocation'
        },
        cascading: {
          type: 'boolean',
          description: 'Whether to cascade revocation to sub-agents'
        }
      },
      required: ['targetAgentDID', 'reason']
    }
  }
];

/**
 * OpenAI function handler for delegation operations
 */
class OpenAIDelegationHandler {
  constructor(
    private agentManager: AgentIdentityManager,
    private delegationManager: DelegationManager,
    private revocationManager: any,
    private agentDID: string,
    private agentKeyPair: any
  ) {}

  async handleFunctionCall(functionName: string, parameters: any): Promise<string> {
    try {
      switch (functionName) {
        case 'create_sub_agent':
          return await this.handleCreateSubAgent(parameters);
        case 'delegate_access':
          return await this.handleDelegateAccess(parameters);
        case 'revoke_agent_access':
          return await this.handleRevokeAccess(parameters);
        default:
          return `Unknown function: ${functionName}`;
      }
    } catch (error) {
      return `Error executing ${functionName}: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }

  private async handleCreateSubAgent(params: {
    name: string;
    description: string;
    scopes: string[];
    maxDelegationDepth?: number;
  }): Promise<string> {
    const subAgent = await this.agentManager.createSubAgent(this.agentDID, {
      name: params.name,
      description: params.description,
      parentAgentDID: this.agentDID,
      requestedScopes: params.scopes,
      maxDelegationDepth: params.maxDelegationDepth
    });

    // Create delegation credential
    const credential = await this.delegationManager.createDelegationCredential(
      this.agentDID,
      this.agentKeyPair,
      subAgent.did,
      subAgent.name,
      {
        serviceDID: 'default-service',
        scopes: params.scopes,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
      }
    );

    this.agentManager.addDelegationCredential(subAgent.did, credential);

    return `Successfully created sub-agent "${params.name}" with DID ${subAgent.did}. The agent has been granted the following scopes: ${params.scopes.join(', ')}.`;
  }

  private async handleDelegateAccess(params: {
    targetAgentDID: string;
    serviceDID: string;
    scopes: string[];
    duration?: number;
  }): Promise<string> {
    const duration = params.duration || 24 * 60 * 60 * 1000; // Default 24 hours
    
    const credential = await this.delegationManager.createDelegationCredential(
      this.agentDID,
      this.agentKeyPair,
      params.targetAgentDID,
      'Delegated Agent',
      {
        serviceDID: params.serviceDID,
        scopes: params.scopes,
        expiresAt: new Date(Date.now() + duration)
      }
    );

    this.agentManager.addDelegationCredential(params.targetAgentDID, credential);

    return `Successfully delegated access to agent ${params.targetAgentDID} for service ${params.serviceDID}. Granted scopes: ${params.scopes.join(', ')}. Access expires in ${Math.round(duration / (60 * 60 * 1000))} hours.`;
  }

  private async handleRevokeAccess(params: {
    targetAgentDID: string;
    reason: string;
    cascading?: boolean;
  }): Promise<string> {
    const result = await this.revocationManager.revokeAgent({
      targetAgentDID: params.targetAgentDID,
      reason: params.reason,
      revokedBy: this.agentDID,
      timestamp: new Date(),
      cascading: params.cascading || false
    });

    if (result.success) {
      return `Successfully revoked access for agent ${params.targetAgentDID}. ${result.revokedAgents.length} agents were revoked. Reason: ${params.reason}`;
    } else {
      return `Failed to revoke access for agent ${params.targetAgentDID}. Errors: ${result.failedRevocations.map(f => f.error).join(', ')}`;
    }
  }
}

/**
 * Example integration with OpenAI Chat Completions API
 */
async function integrateWithOpenAI(
  agentManager: AgentIdentityManager,
  delegationManager: DelegationManager,
  agentIdentity: any
) {
  const handler = new OpenAIDelegationHandler(
    agentManager,
    delegationManager,
    null, // Would be actual revocation manager
    agentIdentity.did,
    agentIdentity.keyPair
  );

  // Example OpenAI API call with function calling
  const completion = {
    model: 'gpt-4',
    messages: [
      {
        role: 'system',
        content: 'You are an AI assistant that can manage agent delegation and access control. Use the provided functions to help users with agent management tasks.'
      },
      {
        role: 'user',
        content: 'Create a new sub-agent called "Email Manager" that can read and write emails, and then delegate calendar access to it.'
      }
    ],
    functions: DELEGATION_FUNCTIONS,
    function_call: 'auto'
  };

  // Simulated response processing
  console.log('OpenAI Integration Example:');
  console.log('User Request: Create Email Manager and delegate calendar access');
  
  // Simulate function calls
  const createResult = await handler.handleFunctionCall('create_sub_agent', {
    name: 'Email Manager',
    description: 'Agent for managing email operations',
    scopes: ['read:emails', 'write:emails']
  });
  
  console.log('Create Sub-Agent Result:', createResult);
  
  // Get the created agent DID (would be extracted from the result in practice)
  const emailManagerDID = 'did:key:example-email-manager';
  
  const delegateResult = await handler.handleFunctionCall('delegate_access', {
    targetAgentDID: emailManagerDID,
    serviceDID: 'calendar-service',
    scopes: ['read:calendar', 'write:calendar']
  });
  
  console.log('Delegate Access Result:', delegateResult);
}

// ============================================================================
// Integration Example Runner
// ============================================================================

async function runIntegrationExamples() {
  console.log('🔗 Integration Examples for Agent-to-Agent Delegation\n');

  // Initialize core components
  const agentManager = new AgentIdentityManager();
  const delegationManager = new DelegationManager();
  const chainValidator = new DelegationChainValidator(delegationManager, agentManager);

  try {
    // Create a test user and agent
    const userKeyPair = await generateKeyPair();
    const userDID = DIDService.createDIDKey(userKeyPair.publicKey).id;

    const mainAgent = await agentManager.createAgent(userDID, {
      name: 'Integration Test Agent',
      description: 'Main agent for integration testing',
      canDelegate: true,
      maxDelegationDepth: 3
    });

    console.log('1️⃣  LangChain Integration Example:');
    const langchainAgent = new DelegationEnabledAgent(
      agentManager,
      delegationManager,
      mainAgent
    );

    const response1 = await langchainAgent.processRequest(
      'Create an agent named "Data Processor" with read and write access'
    );
    console.log('LangChain Response:', response1);

    console.log('\n2️⃣  Express.js API Integration Example:');
    const apiController = new DelegationAPIController(
      agentManager,
      delegationManager,
      chainValidator
    );
    console.log('API Controller created - routes would be set up with Express app');

    console.log('\n3️⃣  WebSocket Integration Example:');
    const wsServer = new DelegationWebSocketServer(
      null as any, // Would be actual communication manager
      chainValidator
    );
    console.log('WebSocket server created - would be attached to HTTP server');

    console.log('\n4️⃣  React Integration Example:');
    console.log('React hooks and components defined for frontend integration');

    console.log('\n5️⃣  OpenAI Function Calling Integration Example:');
    await integrateWithOpenAI(agentManager, delegationManager, mainAgent);

    console.log('\n✅ All integration examples completed successfully!');

  } catch (error) {
    console.error('❌ Integration example failed:', error);
    throw error;
  }
}

// Helper functions and types (simplified for example)
const useState = (initial: any) => {
  let state = initial;
  return [state, (newState: any) => { state = newState; }];
};

const useEffect = (fn: any, deps: any[]) => {
  fn(); // Simplified for example
};

const CreateAgentModal = ({ onSubmit, onCancel }: any) => null;
const handleDelegateAccess = (agent: any) => console.log('Delegate access for', agent);
const viewAgent = (agent: any) => console.log('View agent', agent);

// Run the examples
if (require.main === module) {
  runIntegrationExamples()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('Integration examples failed:', error);
      process.exit(1);
    });
}

export {
  DelegationTool,
  DelegationEnabledAgent,
  DelegationAPIController,
  DelegationWebSocketServer,
  OpenAIDelegationHandler,
  useDelegationManager,
  DELEGATION_FUNCTIONS,
  runIntegrationExamples
};