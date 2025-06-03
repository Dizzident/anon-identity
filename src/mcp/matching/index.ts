/**
 * MCP Matching Module
 * 
 * Exports agent matching and capability discovery functionality
 */

export { AgentMatcher } from './agent-matcher';
export type {
  AgentCapabilityProfile,
  TaskDescription,
  AgentMatch,
  MatchingConfig
} from './agent-matcher';

// Default export
export { AgentMatcher as default } from './agent-matcher';