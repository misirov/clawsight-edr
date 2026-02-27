export type ClawdstrikeMode = "off" | "audit" | "enforce" | "local";

export type ClawdstrikeCaptureConfig = {
  messages: boolean;
  messageBody: boolean;
  tools: boolean;
  toolParams: boolean;
  toolResult: boolean;
  diagnostics: boolean;
  logs: boolean;
};

export type ClawdstrikeNetworkConfig = {
  timeoutMs: number;
};

export type ClawdstrikeTelemetrySeverity = "trace" | "debug" | "info" | "warn" | "error";

export type ClawdstrikePluginConfig = {
  enabled: boolean;
  mode: ClawdstrikeMode;
  platformUrl: string;
  localRulesPath?: string;
  apiToken?: string;
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  identityPath?: string;
  ingestPath: string;
  decidePath: string;
  paymentsSendPath: string;
  flushIntervalMs: number;
  batchMaxEvents: number;
  capture: ClawdstrikeCaptureConfig;
  network: ClawdstrikeNetworkConfig;
};

export type TelemetryEnvelope = {
  eventId: string;
  ts: number;
  severity: ClawdstrikeTelemetrySeverity;
  category:
    | "agent"
    | "message"
    | "tool"
    | "session"
    | "gateway"
    | "diagnostic"
    | "log"
    | "policy"
    | "payment";
  action: string;
  openclaw?: {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
    messageProvider?: string;
    toolName?: string;
    toolCallId?: string;
    gatewayPort?: number;
  };
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  payload?: unknown;
  requestId?: string;
  correlationId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  result?: "ok" | "blocked" | "modified" | "error";
  outcome?: "allow" | "warn" | "block" | "modify" | "error" | "unknown";
  outcomeReason?: string;
  policyRuleId?: string;
  policyDecisionId?: string;
  durationMs?: number;
  latencyMs?: number;
  errorClass?: string;
  errorCode?: string;
  toolExitCode?: number;
  schemaVersion?: number;
  policyDecision?: {
    requestId?: string;
    decisionId?: string;
    action?: "allow" | "warn" | "block" | "modify";
    reason?: string;
    latencyMs?: number;
    ruleId?: string;
  };
};

export type ToolDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  toolName: string;
  params: Record<string, unknown>;
  requestId?: string;
  traceId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  parentSpanId?: string;
};

export type ToolDecision =
  | { action: "allow"; decisionId?: string; ruleId?: string }
  | { action: "warn"; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "block"; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "modify"; params: Record<string, unknown>; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "confirm"; reason?: string; decisionId?: string; ruleId?: string };

export type MessageDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  channelId: string;
  accountId?: string;
  sessionId?: string;
  sessionKey?: string;
  to: string;
  content: string;
  metadata?: Record<string, unknown>;
  requestId?: string;
};

export type MessageDecision =
  | { action: "allow"; decisionId?: string; ruleId?: string }
  | { action: "warn"; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "block"; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "modify"; content: string; reason?: string; decisionId?: string; ruleId?: string };

export type InboundMessageDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  channelId: string;
  accountId?: string;
  conversationId?: string;
  from: string;
  content: string;
  metadata?: Record<string, unknown>;
  requestId?: string;
  sessionKey?: string;
};

export type InboundMessageDecision = {
  action: "allow" | "block";
  enforcement?: "advisory" | "hard";
  decisionId?: string;
  ruleId?: string;
  reason?: string;
  signals?: string[];
};

export type IntentDecisionAction = "allow" | "warn" | "block" | "modify";

export type IntentBaselineDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  managedAgentKey?: string;
  requestId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  traceId?: string;
  sessionKey?: string;
  runId?: string;
  sourceType?: string;
  prompt?: string;
  systemPrompt?: string;
  historyMessages?: string[];
  provider?: string;
  model?: string;
};

export type IntentActionDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  managedAgentKey?: string;
  requestId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  traceId?: string;
  spanId?: string;
  sessionKey?: string;
  runId?: string;
  toolName: string;
  params: Record<string, unknown>;
};

export type IntentOutputDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  managedAgentKey?: string;
  requestId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  traceId?: string;
  spanId?: string;
  sessionKey?: string;
  runId?: string;
  toolName?: string;
  toolCallId?: string;
  content: string;
  isSynthetic?: boolean;
};

export type IntentDecision = {
  action: IntentDecisionAction;
  mode?: "off" | "audit" | "enforce";
  reason?: string;
  decisionId?: string;
  scoreDelta?: number;
  driftScore?: number;
  confidence?: number;
  signals?: string[];
  targetDomains?: string[];
  expectedDomains?: string[];
  expectedScopes?: string[];
  sanitizedContent?: string;
};

export type PaymentsSendRequest = {
  chain?: string;
  asset?: string;
  toAddress: string;
  amount: string;
  memo?: string;
  idempotencyKey?: string;
};

export type PaymentsSendResponse = {
  status: "submitted" | "blocked" | "error";
  txId?: string;
  decisionId?: string;
  reason?: string;
};

export type ClawdstrikeRuntime = {
  config: ClawdstrikePluginConfig;
  emit: (evt: Omit<TelemetryEnvelope, "eventId" | "ts"> & { eventId?: string; ts?: number }) => void;
  decideToolCall: (req: ToolDecisionRequest) => Promise<ToolDecision | null>;
  decideOutboundMessage: (req: MessageDecisionRequest) => Promise<MessageDecision | null>;
  decideInboundMessage: (req: InboundMessageDecisionRequest) => Promise<InboundMessageDecision | null>;
  decideIntentBaseline: (req: IntentBaselineDecisionRequest) => Promise<IntentDecision | null>;
  decideIntentAction: (req: IntentActionDecisionRequest) => Promise<IntentDecision | null>;
  decideIntentOutput: (req: IntentOutputDecisionRequest) => Promise<IntentDecision | null>;
  paymentsSend: (req: PaymentsSendRequest) => Promise<PaymentsSendResponse>;
  stop: () => Promise<void>;
};
