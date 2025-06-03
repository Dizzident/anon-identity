/**
 * MCP (Model Context Protocol) Type Definitions
 * 
 * Core types and interfaces for MCP integration in the Anonymous Identity Framework
 */

// Core MCP Types
export interface MCPMessage {
  id: string;
  type: MCPMessageType;
  timestamp: Date;
  sender: string;
  recipient: string;
  payload: any;
  metadata?: Record<string, any>;
}

export enum MCPMessageType {
  REQUEST = 'request',
  RESPONSE = 'response',
  NOTIFICATION = 'notification',
  ERROR = 'error',
  HEARTBEAT = 'heartbeat'
}

// LLM Request/Response Types
export interface LLMRequest {
  id: string;
  type: LLMRequestType;
  prompt: string;
  context?: ConversationContext;
  functions?: FunctionDefinition[];
  parameters?: LLMParameters;
  metadata: RequestMetadata;
  agentDID: string;
  sessionId: string;
  streaming?: boolean;
}

export enum LLMRequestType {
  COMPLETION = 'completion',
  FUNCTION_CALL = 'function_call',
  EMBEDDING = 'embedding',
  MODERATION = 'moderation',
  STREAMING = 'streaming'
}

export interface LLMResponse {
  id: string;
  requestId?: string;
  type?: LLMRequestType;
  status?: ResponseStatus | 'success' | 'error';
  content?: string;
  role?: MessageRole;
  functionCall?: FunctionCall;
  embedding?: number[];
  moderationResult?: ModerationResult;
  usage?: UsageInfo;
  provider?: string;
  model?: string;
  timestamp: Date;
  error?: MCPError;
  metadata?: any;
  streaming?: boolean;
  tokens?: number;
  finishReason?: string;
}

export enum ResponseStatus {
  SUCCESS = 'success',
  ERROR = 'error',
  PARTIAL = 'partial',
  TIMEOUT = 'timeout',
  RATE_LIMITED = 'rate_limited'
}

export interface LLMResponseChunk {
  id: string;
  requestId?: string;
  type?: 'chunk' | 'complete';
  content?: string;
  delta?: string;
  finished?: boolean;
  usage?: Partial<UsageInfo>;
  tokens?: number;
  provider?: string;
  model?: string;
  timestamp?: Date;
  metadata?: any;
}

// Provider Types
export interface MCPProvider {
  id: string;
  name: string;
  version: string;
  description: string;
  capabilities: LLMCapabilities;
  models: ModelInfo[];
  rateLimits: RateLimitInfo;
  config: ProviderConfig;
  status: ProviderStatus;
}

export interface LLMCapabilities {
  completion: boolean;
  streaming: boolean;
  functionCalling: boolean;
  embeddings: boolean;
  moderation: boolean;
  multimodal: boolean;
  codeGeneration: boolean;
  jsonMode: boolean;
}

export interface ModelInfo {
  id: string;
  name: string;
  description: string;
  capabilities: string[];
  contextLength: number;
  inputCost: number; // per 1K tokens
  outputCost: number; // per 1K tokens
  deprecated: boolean;
}

export interface RateLimitInfo {
  requestsPerMinute: number;
  tokensPerMinute: number;
  requestsPerDay: number;
  tokensPerDay: number;
  concurrentRequests: number;
}

export enum ProviderStatus {
  AVAILABLE = 'available',
  UNAVAILABLE = 'unavailable',
  RATE_LIMITED = 'rate_limited',
  MAINTENANCE = 'maintenance',
  ERROR = 'error'
}

// Connection and Communication Types
export interface MCPConnection {
  id: string;
  providerId: string;
  status: ConnectionStatus;
  lastHeartbeat: Date;
  createdAt: Date;
  metadata: ConnectionMetadata;
  
  // Connection methods
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  sendRequest(request: LLMRequest): Promise<LLMResponse>;
  streamRequest(request: LLMRequest): AsyncIterable<LLMResponseChunk>;
  health(): Promise<{ status: 'healthy' | 'unhealthy'; latency?: number; details?: any }>;
  
  // Event emitter
  on(event: string, listener: (...args: any[]) => void): void;
  emit(event: string, ...args: any[]): boolean;
}

export enum ConnectionStatus {
  CONNECTED = 'connected',
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  RECONNECTING = 'reconnecting',
  ERROR = 'error'
}

export interface ConnectionMetadata {
  endpoint: string;
  version: string;
  features: string[];
  latency?: number;
  retryCount: number;
  lastError?: string;
}

// Context Management Types
export interface ConversationContext {
  agentDID: string;
  sessionId: string;
  conversationId: string;
  history: ConversationMessage[];
  summary?: string;
  metadata: ContextMetadata;
  lastUpdated: Date;
  compressedAt?: Date;
  tokens: number;
  maxTokens: number;
}

export interface ConversationMessage {
  id: string;
  role: MessageRole;
  content: string;
  timestamp: Date;
  metadata?: MessageMetadata;
  functionCall?: FunctionCall;
  functionResult?: FunctionResult;
}

export enum MessageRole {
  USER = 'user',
  ASSISTANT = 'assistant',
  SYSTEM = 'system',
  FUNCTION = 'function'
}

export interface ContextMetadata {
  agentName: string;
  purpose: string;
  domain: string;
  priority: ContextPriority;
  retention: ContextRetention;
  sharedWith: string[];
}

export enum ContextPriority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface ContextRetention {
  duration: number; // milliseconds
  autoCompress: boolean;
  autoDelete: boolean;
  archiveAfter?: number;
}

// Function Calling Types
export interface FunctionDefinition {
  name: string;
  description: string;
  parameters: FunctionParameters;
  handler?: string; // Handler function identifier
  security?: FunctionSecurity;
}

export interface FunctionParameters {
  type: 'object';
  properties: Record<string, ParameterDefinition>;
  required: string[];
  additionalProperties?: boolean;
}

export interface ParameterDefinition {
  type: string;
  description: string;
  enum?: any[];
  format?: string;
  minimum?: number;
  maximum?: number;
  pattern?: string;
  examples?: any[];
  items?: ParameterDefinition | { type: string };
  default?: any;
  minLength?: number;
  maxLength?: number;
  multipleOf?: number;
  minItems?: number;
  maxItems?: number;
  properties?: Record<string, ParameterDefinition>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface FunctionSecurity {
  requiredScopes: string[];
  riskLevel: FunctionRiskLevel;
  auditRequired: boolean;
  approvalRequired: boolean;
}

export enum FunctionRiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface FunctionCall {
  name: string;
  arguments: Record<string, any>;
  id?: string;
}

export interface FunctionResult {
  functionCallId: string;
  result: any;
  error?: string;
  executionTime: number;
  timestamp: Date;
}

// Configuration Types
export interface MCPConfig {
  server: MCPServerConfig;
  client: MCPClientConfig;
  providers: ProviderConfig[];
  security: MCPSecurityConfig;
  monitoring: MCPMonitoringConfig;
  performance: MCPPerformanceConfig;
}

export interface MCPServerConfig {
  host: string;
  port: number;
  tls: TLSConfig;
  cors?: CORSConfig;
  compression: boolean;
  timeout: number;
  maxConnections: number;
}

export interface MCPClientConfig {
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
  backoffMultiplier: number;
  maxRetryDelay: number;
  keepAlive: boolean;
  heartbeatInterval: number;
}

export interface ProviderConfig {
  id: string;
  enabled: boolean;
  endpoint: string;
  apiKey?: string;
  models: string[];
  defaultModel: string;
  rateLimits: RateLimitInfo;
  priority: number;
  timeout: number;
  retryConfig: RetryConfig;
  customHeaders?: Record<string, string>;
}

export interface TLSConfig {
  enabled: boolean;
  certFile?: string;
  keyFile?: string;
  caFile?: string;
  minVersion?: string;
  maxVersion?: string;
  ciphers?: string[];
}

export interface CORSConfig {
  enabled: boolean;
  origins: string[];
  methods: string[];
  headers: string[];
  credentials: boolean;
}

export interface RetryConfig {
  maxAttempts: number;
  initialDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
  jitter: boolean;
}

// Security Types
export interface MCPSecurityConfig {
  authentication: AuthenticationConfig;
  authorization: AuthorizationConfig;
  encryption: EncryptionConfig;
  audit: AuditConfig;
  credentials: CredentialConfig;
}

export interface AuthenticationConfig {
  method: AuthenticationMethod;
  tokenExpiration: number;
  refreshTokenExpiration: number;
  multiFactorEnabled: boolean;
  sessionTimeout: number;
}

export enum AuthenticationMethod {
  API_KEY = 'api_key',
  OAUTH2 = 'oauth2',
  JWT = 'jwt',
  CERTIFICATE = 'certificate',
  DELEGATION = 'delegation'
}

export interface AuthorizationConfig {
  enableRBAC: boolean;
  enableABAC: boolean;
  defaultDeny: boolean;
  agentPermissions: Map<string, Permission[]>;
  resourceAccess: AccessControlList;
}

export interface Permission {
  resource: string;
  actions: string[];
  conditions?: PolicyCondition[];
  expiresAt?: Date;
}

export interface AccessControlList {
  rules: AccessRule[];
  defaultAction: AccessAction;
}

export interface AccessRule {
  subject: string;
  resource: string;
  action: string;
  effect: AccessAction;
  conditions?: PolicyCondition[];
}

export enum AccessAction {
  ALLOW = 'allow',
  DENY = 'deny'
}

export interface PolicyCondition {
  type: string;
  operator: string;
  value: any;
}

export interface EncryptionConfig {
  inTransit: boolean;
  atRest: boolean;
  keyRotationInterval: number;
  algorithm: string;
  keyLength: number;
}

export interface AuditConfig {
  enabled: boolean;
  logAllRequests: boolean;
  logResponses: boolean;
  logSensitiveData: boolean;
  retentionPeriod: number;
  exportFormat: AuditExportFormat[];
}

export enum AuditExportFormat {
  JSON = 'json',
  CSV = 'csv',
  SYSLOG = 'syslog'
}

export interface CredentialConfig {
  storage: CredentialStorageType;
  encryption: boolean;
  rotation: CredentialRotationConfig;
  validation: CredentialValidationConfig;
}

export enum CredentialStorageType {
  MEMORY = 'memory',
  FILE = 'file',
  DATABASE = 'database',
  VAULT = 'vault',
  ENV = 'environment'
}

export interface CredentialRotationConfig {
  enabled: boolean;
  interval: number;
  retentionCount: number;
  notifyBefore: number;
}

export interface CredentialValidationConfig {
  validateOnLoad: boolean;
  validateOnUse: boolean;
  cacheValidation: boolean;
  validationTimeout: number;
}

// Monitoring and Performance Types
export interface MCPMonitoringConfig {
  metrics: MetricsConfig;
  logging: LoggingConfig;
  alerts: AlertConfig;
  health: HealthCheckConfig;
}

export interface MetricsConfig {
  enabled: boolean;
  interval: number;
  retention: number;
  exporters: MetricExporter[];
}

export interface MetricExporter {
  type: MetricExporterType;
  endpoint?: string;
  config?: Record<string, any>;
}

export enum MetricExporterType {
  PROMETHEUS = 'prometheus',
  INFLUXDB = 'influxdb',
  CONSOLE = 'console',
  FILE = 'file'
}

export interface LoggingConfig {
  level: LogLevel;
  format: LogFormat;
  output: LogOutput[];
  rotation: LogRotationConfig;
}

export enum LogLevel {
  TRACE = 'trace',
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
  FATAL = 'fatal'
}

export enum LogFormat {
  JSON = 'json',
  TEXT = 'text',
  STRUCTURED = 'structured'
}

export interface LogOutput {
  type: LogOutputType;
  destination: string;
  config?: Record<string, any>;
}

export enum LogOutputType {
  CONSOLE = 'console',
  FILE = 'file',
  SYSLOG = 'syslog',
  REMOTE = 'remote'
}

export interface LogRotationConfig {
  enabled: boolean;
  maxSize: number;
  maxAge: number;
  maxBackups: number;
  compress: boolean;
}

export interface AlertConfig {
  enabled: boolean;
  channels: AlertChannel[];
  rules: AlertRule[];
}

export interface AlertChannel {
  id: string;
  type: AlertChannelType;
  config: Record<string, any>;
  enabled: boolean;
}

export enum AlertChannelType {
  EMAIL = 'email',
  SLACK = 'slack',
  WEBHOOK = 'webhook',
  SMS = 'sms',
  PAGERDUTY = 'pagerduty'
}

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  condition: AlertCondition;
  severity: AlertSeverity;
  channels: string[];
  enabled: boolean;
}

export interface AlertCondition {
  metric: string;
  operator: AlertOperator;
  threshold: number;
  duration: number;
}

export enum AlertOperator {
  GREATER_THAN = 'gt',
  LESS_THAN = 'lt',
  EQUALS = 'eq',
  NOT_EQUALS = 'ne',
  GREATER_EQUAL = 'ge',
  LESS_EQUAL = 'le'
}

export enum AlertSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface HealthCheckConfig {
  enabled: boolean;
  interval: number;
  timeout: number;
  checks: HealthCheck[];
}

export interface HealthCheck {
  name: string;
  type: HealthCheckType;
  config: Record<string, any>;
  enabled: boolean;
}

export enum HealthCheckType {
  HTTP = 'http',
  TCP = 'tcp',
  DATABASE = 'database',
  CUSTOM = 'custom'
}

export interface MCPPerformanceConfig {
  caching: CachingConfig;
  pooling: PoolingConfig;
  optimization: OptimizationConfig;
}

export interface CachingConfig {
  enabled: boolean;
  provider: CacheProvider;
  ttl: number;
  maxSize: number;
  strategy: CacheStrategy;
}

export enum CacheProvider {
  MEMORY = 'memory',
  REDIS = 'redis',
  MEMCACHED = 'memcached'
}

export enum CacheStrategy {
  LRU = 'lru',
  LFU = 'lfu',
  TTL = 'ttl'
}

export interface PoolingConfig {
  connections: ConnectionPoolConfig;
  requests: RequestPoolConfig;
}

export interface ConnectionPoolConfig {
  maxConnections: number;
  minConnections: number;
  acquireTimeout: number;
  idleTimeout: number;
  validationInterval: number;
}

export interface RequestPoolConfig {
  maxConcurrent: number;
  queueSize: number;
  queueTimeout: number;
  batchSize: number;
  batchTimeout: number;
}

export interface OptimizationConfig {
  compression: boolean;
  keepAlive: boolean;
  pipelining: boolean;
  requestCoalescing: boolean;
  contextCompression: boolean;
}

// Utility Types
export interface LLMParameters {
  model?: string;
  temperature?: number;
  maxTokens?: number;
  topP?: number;
  topK?: number;
  frequencyPenalty?: number;
  presencePenalty?: number;
  stop?: string[];
  stream?: boolean;
  responseFormat?: ResponseFormat;
  seed?: number;
}

export interface ResponseFormat {
  type: ResponseFormatType;
  jsonSchema?: object;
}

export enum ResponseFormatType {
  TEXT = 'text',
  JSON = 'json',
  JSON_OBJECT = 'json_object'
}

export interface RequestMetadata {
  agentDID: string;
  sessionId: string;
  requestId: string;
  timestamp: Date;
  source: string;
  priority: RequestPriority;
  tags?: string[];
  tracking?: RequestTracking;
  conversationId?: string;
  preferredProvider?: string;
  providerId?: string;
  multiTurn?: boolean;
  delegationPurpose?: string;
  delegationRequestId?: string;
  functionName?: string;
  taskId?: string;
  purpose?: string;
}

export enum RequestPriority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  URGENT = 'urgent',
  CRITICAL = 'critical'
}

export interface RequestTracking {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  sampled: boolean;
}

export interface UsageInfo {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  cost?: number;
  model: string;
  provider: string;
}

export interface ModerationResult {
  flagged: boolean;
  categories: Record<string, boolean>;
  categoryScores: Record<string, number>;
  details?: Record<string, any>;
}

export interface MessageMetadata {
  edited?: boolean;
  editedAt?: Date;
  deleted?: boolean;
  deletedAt?: Date;
  reactions?: Reaction[];
  references?: MessageReference[];
  source?: string;
  topic?: string;
  type?: string;
  sessionId?: string;
  provider?: string;
  model?: string;
  usage?: UsageInfo;
  streaming?: boolean;
  totalTokens?: number;
  functionName?: string;
  multiTurn?: boolean;
  sharedFrom?: string;
  previousContextId?: string;
}

export interface Reaction {
  type: string;
  count: number;
  users: string[];
}

export interface MessageReference {
  type: ReferenceType;
  messageId: string;
  content?: string;
}

export enum ReferenceType {
  REPLY = 'reply',
  QUOTE = 'quote',
  THREAD = 'thread'
}

// Error Types
export interface MCPErrorData {
  code: MCPErrorCode;
  message: string;
  details?: Record<string, any>;
  timestamp: Date;
  requestId?: string;
  provider?: string;
  retryable: boolean;
}

export class MCPError extends Error {
  public readonly code: MCPErrorCode;
  public readonly timestamp: Date;
  public readonly requestId?: string;
  public readonly provider?: string;
  public readonly retryable: boolean;
  public readonly details?: Record<string, any>;

  constructor(options: MCPErrorData) {
    super(options.message);
    this.name = 'MCPError';
    this.code = options.code;
    this.timestamp = options.timestamp;
    this.requestId = options.requestId;
    this.provider = options.provider;
    this.retryable = options.retryable;
    this.details = options.details;
  }
}

export enum MCPErrorCode {
  // General errors
  UNKNOWN = 'UNKNOWN',
  INVALID_REQUEST = 'INVALID_REQUEST',
  INVALID_RESPONSE = 'INVALID_RESPONSE',
  TIMEOUT = 'TIMEOUT',
  NETWORK_ERROR = 'NETWORK_ERROR',
  
  // Authentication/Authorization errors
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  
  // Provider errors
  PROVIDER_UNAVAILABLE = 'PROVIDER_UNAVAILABLE',
  PROVIDER_ERROR = 'PROVIDER_ERROR',
  MODEL_NOT_FOUND = 'MODEL_NOT_FOUND',
  RATE_LIMITED = 'RATE_LIMITED',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED',
  
  // Context errors
  CONTEXT_TOO_LARGE = 'CONTEXT_TOO_LARGE',
  CONTEXT_NOT_FOUND = 'CONTEXT_NOT_FOUND',
  CONTEXT_EXPIRED = 'CONTEXT_EXPIRED',
  
  // Function calling errors
  FUNCTION_NOT_FOUND = 'FUNCTION_NOT_FOUND',
  FUNCTION_ERROR = 'FUNCTION_ERROR',
  INVALID_FUNCTION_CALL = 'INVALID_FUNCTION_CALL',
  FUNCTION_TIMEOUT = 'FUNCTION_TIMEOUT',
  
  // Configuration errors
  INVALID_CONFIG = 'INVALID_CONFIG',
  MISSING_CONFIG = 'MISSING_CONFIG',
  CONFIG_VALIDATION_ERROR = 'CONFIG_VALIDATION_ERROR',
  
  // Connection errors
  CONNECTION_ERROR = 'CONNECTION_ERROR',
  NO_AVAILABLE_PROVIDERS = 'NO_AVAILABLE_PROVIDERS',
  MAX_RETRIES_EXCEEDED = 'MAX_RETRIES_EXCEEDED'
}

// Additional types for Phase 3 features
export interface LLMProvider {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  endpoint: string;
  models: string[];
  capabilities: LLMCapabilities;
  rateLimits: RateLimitInfo;
  config: Record<string, any>;
  version?: string;
}

export interface ProviderHealth {
  providerId: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  lastCheck: Date;
  responseTime: number;
  uptime: number;
  errorRate: number;
  connectionCount: number;
  version: string;
}

export interface ProviderMetrics {
  providerId: string;
  requestCount: number;
  successCount: number;
  errorCount: number;
  totalLatency: number;
  averageLatency: number;
  successRate: number;
  requestsPerSecond: number;
  tokensPerSecond: number;
  costPer1kTokens: number;
  lastUpdated: Date;
}

export interface StreamingConfig {
  enabled: boolean;
  chunkSize: number;
  flushInterval: number;
  maxConcurrentStreams: number;
  backpressureThreshold: number;
  compressionEnabled: boolean;
}

// Additional Phase 4 types that were missing exports

/**
 * Provider selection strategy
 */
export enum SelectionStrategy {
  PERFORMANCE = 'performance',
  COST_OPTIMIZED = 'cost_optimized',
  RELIABILITY = 'reliability',
  CAPABILITY_MATCH = 'capability_match',
  LOAD_BALANCED = 'load_balanced',
  SMART_ADAPTIVE = 'smart_adaptive'
}

/**
 * Stream session
 */
export interface StreamSession {
  id: string;
  agentDID: string;
  requestId: string;
  providerId: string;
  status: 'active' | 'paused' | 'completed' | 'error' | 'cancelled';
  startedAt: Date;
  lastChunkAt?: Date;
  completedAt?: Date;
  totalChunks: number;
  totalTokens: number;
  metadata: {
    purpose: string;
    priority: 'low' | 'medium' | 'high' | 'critical';
    maxDuration?: number;
    bufferSize?: number;
  };
}

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
 * Security threat types
 */
export enum ThreatType {
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  DATA_EXFILTRATION = 'data_exfiltration',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  INJECTION_ATTACK = 'injection_attack',
  DENIAL_OF_SERVICE = 'denial_of_service',
  ANOMALOUS_BEHAVIOR = 'anomalous_behavior',
  POLICY_VIOLATION = 'policy_violation',
  SUSPICIOUS_PATTERN = 'suspicious_pattern'
}

/**
 * Threat severity levels
 */
export enum ThreatSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Agent message types - re-export from agent communication
 */
export enum AgentMessageType {
  // Delegation requests
  DELEGATION_REQUEST = 'delegation.request',
  DELEGATION_GRANT = 'delegation.grant',
  DELEGATION_DENY = 'delegation.deny',
  DELEGATION_REVOKE = 'delegation.revoke',
  
  // Queries
  QUERY_STATUS = 'query.status',
  QUERY_CAPABILITIES = 'query.capabilities',
  QUERY_CHAIN = 'query.chain',
  
  // Responses
  RESPONSE_STATUS = 'response.status',
  RESPONSE_CAPABILITIES = 'response.capabilities',
  RESPONSE_CHAIN = 'response.chain',
  
  // Notifications
  NOTIFY_REVOCATION = 'notify.revocation',
  NOTIFY_EXPIRATION = 'notify.expiration',
  NOTIFY_POLICY_CHANGE = 'notify.policy_change',
  
  // System
  PING = 'system.ping',
  PONG = 'system.pong',
  ERROR = 'system.error',
  ACK = 'system.ack',
  
  // MCP-specific extensions
  REQUEST = 'mcp.request',
  COMMAND = 'mcp.command',
  QUERY = 'mcp.query',
  NOTIFICATION = 'mcp.notification'
}

/**
 * Agent message interface - re-export from agent communication
 */
export interface AgentMessage {
  id: string;
  type: AgentMessageType;
  from: string; // Agent DID
  to: string; // Agent DID
  timestamp: Date;
  version: string;
  signature?: string;
  replyTo?: string; // Message ID this is replying to
  expiresAt?: Date;
  metadata?: Record<string, any>;
  payload: any;
}

/**
 * Message envelope - re-export from agent communication
 */
export interface MessageEnvelope {
  message: AgentMessage;
  routingInfo?: {
    path: string[];
    ttl: number;
  };
  encryption?: {
    algorithm: string;
    recipientKey: string;
    encryptedContent?: string;
  };
}

/**
 * Dashboard configuration
 */
export interface DashboardConfig {
  refreshInterval: number;
  retentionPeriod: number;
  enableRealTimeUpdates: boolean;
  enableHistoricalAnalysis: boolean;
  alerts: Array<{
    condition: string;
    threshold: number;
    action: string;
  }>;
  exportFormats: Array<'json' | 'csv' | 'prometheus'>;
}