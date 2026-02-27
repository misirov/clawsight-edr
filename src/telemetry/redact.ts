import crypto from "node:crypto";
import type { ClawdstrikeCaptureConfig } from "../service-types.js";

type RedactInput = {
  hook: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  event: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  context?: any;
  capture: ClawdstrikeCaptureConfig;
};

type Artifact = {
  kind: "file" | "url" | "media";
  label?: string;
  mimeType?: string;
  fileName?: string;
  filePath?: string;
  url?: string;
  source: string;
};

function sha256Base64(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("base64");
}

function truncateString(value: string, max: number): string {
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, max)}…`;
}

function truncateUnknown(value: unknown, maxStr = 4_000): unknown {
  if (typeof value === "string") {
    return truncateString(value, maxStr);
  }
  if (Array.isArray(value)) {
    return value.slice(0, 50).map((v) => truncateUnknown(v, maxStr));
  }
  if (value && typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    const entries = Object.entries(rec).slice(0, 50);
    for (const [k, v] of entries) {
      out[k] = truncateUnknown(v, maxStr);
    }
    return out;
  }
  return value;
}

function redactMessageBody(body: string) {
  const trimmed = body ?? "";
  return { body: trimmed, bodySha256: sha256Base64(trimmed), len: trimmed.length };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function maybeArtifact(
  rec: Record<string, unknown>,
  source: string,
): Artifact | null {
  const filePath =
    asString(rec.file_path) ??
    asString(rec.filePath) ??
    asString(rec.path) ??
    asString(rec.mediaPath);
  const url =
    asString(rec.url) ??
    asString(rec.mediaUrl) ??
    asString(rec.href);
  const fileName =
    asString(rec.file_name) ??
    asString(rec.fileName) ??
    asString(rec.filename) ??
    asString(rec.name);
  const mimeType =
    asString(rec.mime_type) ??
    asString(rec.mimeType) ??
    asString(rec.mimetype) ??
    asString(rec.contentType) ??
    asString(rec.type);
  const label =
    asString(rec.label) ??
    asString(rec.kind) ??
    asString(rec.mediaType) ??
    asString(rec.type);

  if (!filePath && !url && !fileName && !mimeType) {
    return null;
  }

  const kind: Artifact["kind"] = filePath ? "file" : (url ? "url" : "media");
  return {
    kind,
    label,
    mimeType,
    fileName,
    filePath,
    url,
    source,
  };
}

function pushArtifact(out: Artifact[], seen: Set<string>, artifact: Artifact | null) {
  if (!artifact) return;
  const key = [
    artifact.kind,
    artifact.filePath ?? "",
    artifact.url ?? "",
    artifact.fileName ?? "",
    artifact.mimeType ?? "",
    artifact.source,
  ].join("|");
  if (seen.has(key)) return;
  seen.add(key);
  out.push(artifact);
}

function collectArtifactsFromUnknown(
  value: unknown,
  source: string,
  out: Artifact[],
  seen: Set<string>,
  depth = 0,
) {
  if (depth > 4) return;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 32)) {
      collectArtifactsFromUnknown(item, source, out, seen, depth + 1);
    }
    return;
  }

  const rec = asRecord(value);
  if (!rec) return;

  pushArtifact(out, seen, maybeArtifact(rec, source));

  const candidateKeys = [
    "attachments",
    "media",
    "files",
    "file",
    "documents",
    "document",
    "photos",
    "photo",
    "items",
    "mediaItems",
    "payload",
    "params",
    "metadata",
    "context",
  ];
  for (const key of candidateKeys) {
    if (!(key in rec)) continue;
    collectArtifactsFromUnknown(rec[key], `${source}.${key}`, out, seen, depth + 1);
  }
}

function extractArtifacts(event: unknown, context?: unknown): Artifact[] {
  const out: Artifact[] = [];
  const seen = new Set<string>();
  collectArtifactsFromUnknown(event, "event", out, seen);
  collectArtifactsFromUnknown(context, "context", out, seen);
  return out.slice(0, 24);
}

export function redactHookEventForTelemetry(input: RedactInput): unknown {
  const { hook, event, context, capture } = input;

  if (hook === "message_received") {
    const content = typeof event?.content === "string" ? event.content : "";
    const artifacts = extractArtifacts(event, context);
    return {
      hook,
      from: event?.from,
      timestamp: event?.timestamp,
      ...redactMessageBody(content),
      metadata: truncateUnknown(event?.metadata),
      context: truncateUnknown(context),
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  if (hook === "message_sending") {
    const content = typeof event?.content === "string" ? event.content : "";
    const artifacts = extractArtifacts(event, context);
    return {
      hook,
      to: event?.to,
      ...redactMessageBody(content),
      metadata: truncateUnknown(event?.metadata),
      context: truncateUnknown(context),
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  if (hook === "message_sent") {
    const content = typeof event?.content === "string" ? event.content : "";
    const artifacts = extractArtifacts(event, context);
    return {
      hook,
      to: event?.to,
      success: Boolean(event?.success),
      error: event?.error,
      ...redactMessageBody(content),
      context: truncateUnknown(context),
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  if (hook === "before_tool_call") {
    const artifacts = extractArtifacts(event?.params ?? event, context);
    return {
      hook,
      toolName: event?.toolName,
      params: capture.toolParams ? truncateUnknown(event?.params) : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  if (hook === "after_tool_call") {
    const artifacts = extractArtifacts(event, context);
    return {
      hook,
      toolName: event?.toolName,
      params: capture.toolParams ? truncateUnknown(event?.params) : undefined,
      error: event?.error,
      durationMs: event?.durationMs,
      result: capture.toolResult ? truncateUnknown(event?.result) : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  return truncateUnknown({ hook, event, context });
}
