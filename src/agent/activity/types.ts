/**
 * Agent Activity Monitoring Types
 * 
 * Defines the structure for tracking and auditing agent activities
 */

export enum ActivityType {
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  DATA_ACCESS = 'data_access',
  DATA_MODIFICATION = 'data_modification',
  SCOPE_USAGE = 'scope_usage',
  ERROR = 'error',
  REVOCATION = 'revocation',
  SESSION_START = 'session_start',
  SESSION_END = 'session_end'
}

export enum ActivityStatus {
  SUCCESS = 'success',
  FAILED = 'failed',
  DENIED = 'denied',
  PARTIAL = 'partial'
}

export interface ActivityDetails {
  // Common fields
  message?: string;
  errorCode?: string;
  errorMessage?: string;
  
  // Authentication/Authorization details
  presentationId?: string;
  credentialIds?: string[];
  challenge?: string;
  
  // Scope usage details
  scopesRequested?: string[];
  scopesGranted?: string[];
  scopesDenied?: string[];
  
  // Data access details
  resourceType?: string;
  resourceId?: string;
  operation?: string;
  dataSize?: number;
  
  // Additional context
  metadata?: Record<string, any>;
}

export interface AgentActivity {
  id: string;
  agentDID: string;
  parentDID: string;
  timestamp: Date;
  type: ActivityType;
  serviceDID: string;
  serviceEndpoint?: string;
  scopes: string[];
  status: ActivityStatus;
  details: ActivityDetails;
  
  // Added after storage
  ipfsHash?: string;
  signature?: string;
  checksum?: string;
  
  // Performance metrics
  duration?: number; // milliseconds
  
  // Session tracking
  sessionId?: string;
}

export interface ActivityBatch {
  id: string;
  activities: AgentActivity[];
  startTime: Date;
  endTime: Date;
  count: number;
  agentDID: string;
  parentDID: string;
  batchHash?: string;
  merkleRoot?: string;
}

export interface ActivitySummary {
  agentDID: string;
  parentDID: string;
  period: {
    start: Date;
    end: Date;
    type: 'hour' | 'day' | 'week' | 'month' | 'year';
  };
  totalActivities: number;
  byType: Record<ActivityType, number>;
  byStatus: Record<ActivityStatus, number>;
  byService: Record<string, number>;
  scopeUsage: Record<string, number>;
  averageDuration: number;
  errorRate: number;
  peakHour?: string;
  mostUsedService?: string;
  mostUsedScope?: string;
}

export interface ActivityQuery {
  agentDID?: string;
  parentDID?: string;
  serviceDID?: string;
  types?: ActivityType[];
  status?: ActivityStatus[];
  scopes?: string[];
  dateRange?: {
    start: Date;
    end: Date;
  };
  sessionId?: string;
  limit?: number;
  offset?: number;
  sortBy?: 'timestamp' | 'type' | 'service';
  sortOrder?: 'asc' | 'desc';
}

export interface ActivitySearchResult {
  activities: AgentActivity[];
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
}

export interface ActivitySubscription {
  id: string;
  agentDID?: string;
  parentDID?: string;
  types?: ActivityType[];
  callback: (activity: AgentActivity) => void;
  unsubscribe: () => void;
}

export interface ActivityLoggerConfig {
  batchSize?: number; // Default: 100
  batchInterval?: number; // Default: 5000ms
  enableRealtime?: boolean; // Default: true
  enableBatching?: boolean; // Default: true
  retentionDays?: number; // Default: 90
  encryptionKey?: Uint8Array | undefined;
  enableIPFS?: boolean; // Default: false
  ipfsUrl?: string; // Default: http://localhost:5001
  enableRedundancy?: boolean; // Default: false
  ipfsNodes?: Array<{
    url: string;
    name: string;
    priority: number;
    active: boolean;
  }>;
  minReplicas?: number; // Default: 2
  enableIndexing?: boolean; // Default: true
  enableStreaming?: boolean; // Default: false
}

export interface ActivityHook {
  type: ActivityType;
  beforeActivity?: (activity: Partial<AgentActivity>) => Promise<boolean>;
  afterActivity?: (activity: AgentActivity) => Promise<void>;
}

// Schema validation
export const ACTIVITY_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  properties: {
    id: { type: 'string', format: 'uuid' },
    agentDID: { type: 'string', pattern: '^did:' },
    parentDID: { type: 'string', pattern: '^did:' },
    timestamp: { type: 'string', format: 'date-time' },
    type: { 
      type: 'string', 
      enum: Object.values(ActivityType) 
    },
    serviceDID: { type: 'string', pattern: '^did:' },
    serviceEndpoint: { type: 'string', format: 'uri' },
    scopes: { 
      type: 'array', 
      items: { type: 'string' } 
    },
    status: { 
      type: 'string', 
      enum: Object.values(ActivityStatus) 
    },
    details: { type: 'object' },
    ipfsHash: { type: 'string' },
    signature: { type: 'string' },
    duration: { type: 'number', minimum: 0 },
    sessionId: { type: 'string' }
  },
  required: [
    'id', 
    'agentDID', 
    'parentDID', 
    'timestamp', 
    'type', 
    'serviceDID', 
    'status', 
    'details'
  ]
};