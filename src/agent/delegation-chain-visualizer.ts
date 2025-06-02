import { DelegationChain, AgentIdentity, DelegationCredential } from './types';

export interface ChainNode {
  id: string;
  name: string;
  type: 'user' | 'agent';
  depth: number;
  canDelegate: boolean;
  scopes: string[];
  children: ChainNode[];
}

export interface ChainVisualization {
  root: ChainNode;
  totalDepth: number;
  totalAgents: number;
  scopeHierarchy: Map<string, string[]>;
}

export class DelegationChainVisualizer {
  /**
   * Creates a tree structure from a delegation chain
   */
  static createVisualization(
    chain: DelegationChain,
    rootDID: string,
    rootName: string = 'Root User'
  ): ChainVisualization {
    const root: ChainNode = {
      id: rootDID,
      name: rootName,
      type: 'user',
      depth: 0,
      canDelegate: true,
      scopes: this.extractRootScopes(chain),
      children: []
    };

    const scopeHierarchy = new Map<string, string[]>();
    let currentParent = root;

    // Build tree structure
    for (let i = 0; i < chain.agents.length; i++) {
      const agent = chain.agents[i];
      const credential = chain.credentials[i];
      
      const node: ChainNode = {
        id: agent.did,
        name: agent.name,
        type: 'agent',
        depth: agent.delegationDepth + 1,
        canDelegate: agent.canDelegate,
        scopes: credential.credentialSubject.scopes,
        children: []
      };

      // Track scope hierarchy
      scopeHierarchy.set(agent.did, credential.credentialSubject.scopes);

      // Find correct parent in tree
      if (i === 0) {
        root.children.push(node);
      } else {
        const parent = this.findNodeById(root, agent.parentDID);
        if (parent) {
          parent.children.push(node);
        }
      }
    }

    return {
      root,
      totalDepth: chain.currentDepth,
      totalAgents: chain.agents.length,
      scopeHierarchy
    };
  }

  /**
   * Generates a text-based tree visualization
   */
  static toAsciiTree(visualization: ChainVisualization): string {
    const lines: string[] = [];
    this.buildAsciiTree(visualization.root, lines, '', true);
    
    lines.push('');
    lines.push(`Total Depth: ${visualization.totalDepth}`);
    lines.push(`Total Agents: ${visualization.totalAgents}`);
    
    return lines.join('\n');
  }

  /**
   * Generates a Mermaid diagram for the delegation chain
   */
  static toMermaidDiagram(visualization: ChainVisualization): string {
    const lines: string[] = ['graph TD'];
    const nodeDefinitions: string[] = [];
    const connections: string[] = [];
    
    // Create node definitions and connections
    this.buildMermaidNodes(visualization.root, nodeDefinitions, connections);
    
    // Add node definitions
    lines.push(...nodeDefinitions);
    lines.push('');
    
    // Add connections
    lines.push(...connections);
    
    // Add styling
    lines.push('');
    lines.push('classDef userNode fill:#4CAF50,stroke:#2E7D32,stroke-width:2px,color:#fff;');
    lines.push('classDef agentNode fill:#2196F3,stroke:#1565C0,stroke-width:2px,color:#fff;');
    lines.push('classDef cannotDelegate fill:#FF9800,stroke:#E65100,stroke-width:2px,color:#fff;');
    
    // Apply styles
    lines.push('');
    const userNodes = this.findNodesByType(visualization.root, 'user');
    if (userNodes.length > 0) {
      lines.push(`class ${userNodes.map(n => this.sanitizeId(n.id)).join(',')} userNode;`);
    }
    
    const delegatingAgents = this.findNodesByCondition(visualization.root, n => n.type === 'agent' && n.canDelegate);
    if (delegatingAgents.length > 0) {
      lines.push(`class ${delegatingAgents.map(n => this.sanitizeId(n.id)).join(',')} agentNode;`);
    }
    
    const nonDelegatingAgents = this.findNodesByCondition(visualization.root, n => n.type === 'agent' && !n.canDelegate);
    if (nonDelegatingAgents.length > 0) {
      lines.push(`class ${nonDelegatingAgents.map(n => this.sanitizeId(n.id)).join(',')} cannotDelegate;`);
    }
    
    return lines.join('\n');
  }

  /**
   * Generates a JSON representation suitable for D3.js or other visualization libraries
   */
  static toD3Json(visualization: ChainVisualization): object {
    return {
      name: visualization.root.name,
      value: visualization.root.scopes.length,
      data: {
        id: visualization.root.id,
        type: visualization.root.type,
        canDelegate: visualization.root.canDelegate,
        scopes: visualization.root.scopes
      },
      children: visualization.root.children.map(child => this.nodeToD3Json(child))
    };
  }

  /**
   * Analyzes scope reduction through the chain
   */
  static analyzeScopeReduction(chain: DelegationChain): {
    reductions: Array<{
      from: string;
      to: string;
      removed: string[];
      retained: string[];
    }>;
    totalScopeLoss: number;
  } {
    const reductions: Array<{
      from: string;
      to: string;
      removed: string[];
      retained: string[];
    }> = [];

    let previousScopes = this.extractRootScopes(chain);
    let totalScopeLoss = 0;

    for (let i = 0; i < chain.credentials.length; i++) {
      const credential = chain.credentials[i];
      const currentScopes = credential.credentialSubject.scopes;
      
      const removed = previousScopes.filter(s => !currentScopes.includes(s));
      const retained = currentScopes.filter(s => previousScopes.includes(s));
      
      if (removed.length > 0) {
        reductions.push({
          from: i === 0 ? 'Root' : chain.agents[i - 1].name,
          to: chain.agents[i].name,
          removed,
          retained
        });
        totalScopeLoss += removed.length;
      }
      
      previousScopes = currentScopes;
    }

    return { reductions, totalScopeLoss };
  }

  // Helper methods

  private static extractRootScopes(chain: DelegationChain): string[] {
    if (chain.credentials.length === 0) return [];
    
    // Assume root has all scopes that the first credential was issued with
    // In practice, this might come from a different source
    return chain.credentials[0].credentialSubject.scopes;
  }

  private static findNodeById(node: ChainNode, id: string): ChainNode | null {
    if (node.id === id) return node;
    
    for (const child of node.children) {
      const found = this.findNodeById(child, id);
      if (found) return found;
    }
    
    return null;
  }

  private static buildAsciiTree(
    node: ChainNode,
    lines: string[],
    prefix: string,
    isLast: boolean
  ): void {
    const connector = isLast ? '└── ' : '├── ';
    const nodeType = node.type === 'user' ? '[USER]' : '[AGENT]';
    const delegateFlag = node.canDelegate ? '✓' : '✗';
    
    lines.push(
      prefix + connector + `${nodeType} ${node.name} (${delegateFlag}) - ${node.scopes.length} scopes`
    );
    
    const extension = isLast ? '    ' : '│   ';
    const newPrefix = prefix + extension;
    
    for (let i = 0; i < node.children.length; i++) {
      this.buildAsciiTree(
        node.children[i],
        lines,
        newPrefix,
        i === node.children.length - 1
      );
    }
  }

  private static buildMermaidNodes(
    node: ChainNode,
    nodeDefinitions: string[],
    connections: string[],
    parentId?: string
  ): void {
    const nodeId = this.sanitizeId(node.id);
    const label = `${node.name}<br/>${node.scopes.length} scopes`;
    
    nodeDefinitions.push(`${nodeId}["${label}"]`);
    
    if (parentId) {
      const edgeLabel = node.canDelegate ? 'can delegate' : 'cannot delegate';
      connections.push(`${parentId} -->|"${edgeLabel}"| ${nodeId}`);
    }
    
    for (const child of node.children) {
      this.buildMermaidNodes(child, nodeDefinitions, connections, nodeId);
    }
  }

  private static sanitizeId(id: string): string {
    return id.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 20);
  }

  private static findNodesByType(node: ChainNode, type: 'user' | 'agent'): ChainNode[] {
    const nodes: ChainNode[] = [];
    
    if (node.type === type) {
      nodes.push(node);
    }
    
    for (const child of node.children) {
      nodes.push(...this.findNodesByType(child, type));
    }
    
    return nodes;
  }

  private static findNodesByCondition(
    node: ChainNode,
    condition: (node: ChainNode) => boolean
  ): ChainNode[] {
    const nodes: ChainNode[] = [];
    
    if (condition(node)) {
      nodes.push(node);
    }
    
    for (const child of node.children) {
      nodes.push(...this.findNodesByCondition(child, condition));
    }
    
    return nodes;
  }

  private static nodeToD3Json(node: ChainNode): any {
    return {
      name: node.name,
      value: node.scopes.length,
      data: {
        id: node.id,
        type: node.type,
        canDelegate: node.canDelegate,
        scopes: node.scopes
      },
      children: node.children.map(child => this.nodeToD3Json(child))
    };
  }
}