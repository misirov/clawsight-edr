import type {
  ClawdstrikePluginConfig,
  IntentActionDecisionRequest,
  IntentBaselineDecisionRequest,
  IntentDecision,
  IntentOutputDecisionRequest,
  InboundMessageDecision,
  InboundMessageDecisionRequest,
  MessageDecision,
  MessageDecisionRequest,
  PaymentsSendRequest,
  PaymentsSendResponse,
  TelemetryEnvelope,
  ToolDecision,
  ToolDecisionRequest,
} from "./service-types.js";

function joinUrl(base: string, path: string): string {
  const b = base.replace(/\/+$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export class PlatformClient {
  readonly cfg: ClawdstrikePluginConfig;

  constructor(cfg: ClawdstrikePluginConfig) {
    this.cfg = cfg;
  }

  private async postJson<T>(url: string, body: unknown): Promise<T> {
    return this.postJsonWithMetadata<T>(url, body);
  }

  private async postJsonWithMetadata<T>(url: string, body: unknown, requestId?: string): Promise<T> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (this.cfg.apiToken) {
      headers.authorization = `Bearer ${this.cfg.apiToken}`;
    }
    if (requestId) {
      headers["x-clawdstrike-request-id"] = requestId;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.cfg.network.timeoutMs);
    try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
      const text = await res.text();
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 500)}`);
      }
      if (!text.trim()) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-return
        return undefined as T;
      }
      return JSON.parse(text) as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  async ingest(events: TelemetryEnvelope[]): Promise<void> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.ingestPath);
    await this.postJson(url, { events });
  }

  async decideToolCall(req: ToolDecisionRequest): Promise<ToolDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "tool", ...req }, req.requestId);
    const record = asRecord(res);
    const action = String(record?.action ?? "allow");
    const decisionId = typeof record?.decisionId === "string" ? record.decisionId : undefined;
    const ruleId = typeof record?.ruleId === "string" ? record.ruleId : undefined;
    if (action === "warn") {
      return {
        action: "warn",
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    if (action === "block") {
      return {
        action: "block",
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    if (action === "modify") {
      const params = asRecord(record?.params) ?? {};
      return {
        action: "modify",
        params,
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    return { action: "allow", decisionId, ruleId };
  }

  async decideOutboundMessage(req: MessageDecisionRequest): Promise<MessageDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "message", ...req }, req.requestId);
    const record = asRecord(res);
    const action = String(record?.action ?? "allow");
    const decisionId = typeof record?.decisionId === "string" ? record.decisionId : undefined;
    const ruleId = typeof record?.ruleId === "string" ? record.ruleId : undefined;
    if (action === "warn") {
      return {
        action: "warn",
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    if (action === "block") {
      return {
        action: "block",
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    if (action === "modify") {
      return {
        action: "modify",
        content: typeof record?.content === "string" ? record.content : req.content,
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    return { action: "allow", decisionId, ruleId };
  }

  async decideInboundMessage(req: InboundMessageDecisionRequest): Promise<InboundMessageDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "inbound_message", ...req }, req.requestId);
    const record = asRecord(res);
    const actionRaw = String(record?.action ?? "allow");
    const action: InboundMessageDecision["action"] = actionRaw === "block" ? "block" : "allow";
    const enforcementRaw = String(record?.enforcement ?? "advisory");
    const enforcement: InboundMessageDecision["enforcement"] =
      enforcementRaw === "hard" ? "hard" : "advisory";
    const signalsRaw = Array.isArray(record?.signals) ? record?.signals : [];
    const signals = signalsRaw
      .map((item) => (typeof item === "string" ? item : String(item)))
      .slice(0, 20);
    return {
      action,
      enforcement,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      ruleId: typeof record?.ruleId === "string" ? record.ruleId : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
      signals,
    };
  }

  async decideIntentBaseline(req: IntentBaselineDecisionRequest): Promise<IntentDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "intent_baseline", ...req }, req.requestId);
    const record = asRecord(res);
    return {
      action: String(record?.action ?? "allow") as IntentDecision["action"],
      mode:
        String(record?.mode) === "off" || String(record?.mode) === "enforce" || String(record?.mode) === "audit"
          ? (String(record?.mode) as IntentDecision["mode"])
          : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      scoreDelta: typeof record?.scoreDelta === "number" ? record.scoreDelta : undefined,
      driftScore: typeof record?.driftScore === "number" ? record.driftScore : undefined,
      confidence: typeof record?.confidence === "number" ? record.confidence : undefined,
      signals: Array.isArray(record?.signals) ? record.signals.map((v) => String(v)).slice(0, 20) : undefined,
      targetDomains: Array.isArray(record?.targetDomains) ? record.targetDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedDomains: Array.isArray(record?.expectedDomains) ? record.expectedDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedScopes: Array.isArray(record?.expectedScopes) ? record.expectedScopes.map((v) => String(v)).slice(0, 20) : undefined,
      sanitizedContent: typeof record?.sanitizedContent === "string" ? record.sanitizedContent : undefined,
    };
  }

  async decideIntentAction(req: IntentActionDecisionRequest): Promise<IntentDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "intent_action", ...req }, req.requestId);
    const record = asRecord(res);
    return {
      action: String(record?.action ?? "allow") as IntentDecision["action"],
      mode:
        String(record?.mode) === "off" || String(record?.mode) === "enforce" || String(record?.mode) === "audit"
          ? (String(record?.mode) as IntentDecision["mode"])
          : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      scoreDelta: typeof record?.scoreDelta === "number" ? record.scoreDelta : undefined,
      driftScore: typeof record?.driftScore === "number" ? record.driftScore : undefined,
      confidence: typeof record?.confidence === "number" ? record.confidence : undefined,
      signals: Array.isArray(record?.signals) ? record.signals.map((v) => String(v)).slice(0, 20) : undefined,
      targetDomains: Array.isArray(record?.targetDomains) ? record.targetDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedDomains: Array.isArray(record?.expectedDomains) ? record.expectedDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedScopes: Array.isArray(record?.expectedScopes) ? record.expectedScopes.map((v) => String(v)).slice(0, 20) : undefined,
      sanitizedContent: typeof record?.sanitizedContent === "string" ? record.sanitizedContent : undefined,
    };
  }

  async decideIntentOutput(req: IntentOutputDecisionRequest): Promise<IntentDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "intent_output", ...req }, req.requestId);
    const record = asRecord(res);
    return {
      action: String(record?.action ?? "allow") as IntentDecision["action"],
      mode:
        String(record?.mode) === "off" || String(record?.mode) === "enforce" || String(record?.mode) === "audit"
          ? (String(record?.mode) as IntentDecision["mode"])
          : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      scoreDelta: typeof record?.scoreDelta === "number" ? record.scoreDelta : undefined,
      driftScore: typeof record?.driftScore === "number" ? record.driftScore : undefined,
      confidence: typeof record?.confidence === "number" ? record.confidence : undefined,
      signals: Array.isArray(record?.signals) ? record.signals.map((v) => String(v)).slice(0, 20) : undefined,
      targetDomains: Array.isArray(record?.targetDomains) ? record.targetDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedDomains: Array.isArray(record?.expectedDomains) ? record.expectedDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedScopes: Array.isArray(record?.expectedScopes) ? record.expectedScopes.map((v) => String(v)).slice(0, 20) : undefined,
      sanitizedContent: typeof record?.sanitizedContent === "string" ? record.sanitizedContent : undefined,
    };
  }

  async paymentsSend(req: PaymentsSendRequest): Promise<PaymentsSendResponse> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.paymentsSendPath);
    const res = await this.postJson(url, req);
    const record = asRecord(res);
    const statusRaw = typeof record?.status === "string" ? record.status : "error";
    const status: PaymentsSendResponse["status"] =
      statusRaw === "submitted" || statusRaw === "blocked" || statusRaw === "error"
        ? statusRaw
        : "error";
    return {
      status,
      txId: typeof record?.txId === "string" ? record.txId : undefined,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
    };
  }
}
