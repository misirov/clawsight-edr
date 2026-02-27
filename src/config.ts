import path from "node:path";
import os from "node:os";
import type { ClawdstrikePluginConfig, ClawdstrikeMode } from "./service-types.js";

function asBoolean(value: unknown, defaultValue: boolean): boolean {
  return typeof value === "boolean" ? value : defaultValue;
}

function asNumber(value: unknown, defaultValue: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : defaultValue;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asMode(value: unknown, defaultValue: ClawdstrikeMode): ClawdstrikeMode {
  const raw = asString(value)?.toLowerCase();
  if (raw === "off" || raw === "audit" || raw === "enforce" || raw === "local") {
    return raw;
  }
  return defaultValue;
}

function joinUrl(base: string, path: string): string {
  const b = base.replace(/\/+$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

export function resolvePluginConfig(raw: Record<string, unknown>): ClawdstrikePluginConfig {
  const enabled = asBoolean(raw.enabled, true);
  const mode = asMode(raw.mode, "audit");
  const platformUrl = asString(raw.platformUrl) ?? "";

  const apiToken = asString(raw.apiToken);
  const projectId = asString(raw.projectId);
  const agentInstanceId = asString(raw.agentInstanceId);
  const agentName = asString(raw.agentName);
  const identityPath = asString(raw.identityPath);
  const localRulesPath =
    asString(raw.localRulesPath) ??
    (mode === "local"
      ? path.join(os.homedir(), ".openclaw", "plugins", "clawdstrike", "rules.json")
      : undefined);

  const ingestPath = asString(raw.ingestPath) ?? "/v1/telemetry/ingest";
  const decidePath = asString(raw.decidePath) ?? "/v1/guardrails/decide";
  const paymentsSendPath = asString(raw.paymentsSendPath) ?? "/v1/payments/send";

  const flushIntervalMs = Math.max(250, asNumber(raw.flushIntervalMs, 1000));
  const batchMaxEvents = Math.max(1, Math.floor(asNumber(raw.batchMaxEvents, 200)));

  const captureRaw = raw.capture && typeof raw.capture === "object" ? (raw.capture as any) : {};
  const capture = {
    messages: asBoolean(captureRaw.messages, true),
    messageBody: asBoolean(captureRaw.messageBody, false),
    tools: asBoolean(captureRaw.tools, true),
    toolParams: asBoolean(captureRaw.toolParams, true),
    toolResult: asBoolean(captureRaw.toolResult, false),
    diagnostics: asBoolean(captureRaw.diagnostics, true),
    logs: asBoolean(captureRaw.logs, false),
  };

  const networkRaw = raw.network && typeof raw.network === "object" ? (raw.network as any) : {};
  const network = {
    timeoutMs: Math.max(1000, asNumber(networkRaw.timeoutMs, 30_000)),
  };

  return {
    enabled,
    mode,
    platformUrl,
    localRulesPath,
    apiToken,
    projectId,
    agentInstanceId,
    agentName,
    identityPath,
    ingestPath,
    decidePath,
    paymentsSendPath,
    flushIntervalMs,
    batchMaxEvents,
    capture,
    network,
  };
}

export const __internal = { joinUrl };
