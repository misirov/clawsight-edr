import fs from "node:fs/promises";
import path from "node:path";
import type { TelemetryEnvelope } from "../service-types.js";

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function safeParseJsonLine(line: string): unknown {
  try {
    return JSON.parse(line) as unknown;
  } catch {
    return undefined;
  }
}

function isTelemetryEnvelope(value: unknown): value is TelemetryEnvelope {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const rec = value as Record<string, unknown>;
  return isNonEmptyString(rec.eventId) && typeof rec.ts === "number" && isNonEmptyString(rec.category);
}

export async function loadWal(filePath: string): Promise<TelemetryEnvelope[]> {
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch {
    return [];
  }
  const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean);
  const out: TelemetryEnvelope[] = [];
  for (const line of lines) {
    const parsed = safeParseJsonLine(line);
    if (isTelemetryEnvelope(parsed)) {
      out.push(parsed);
    }
  }
  return out;
}

export async function appendWal(filePath: string, evt: TelemetryEnvelope): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const line = `${JSON.stringify(evt)}\n`;
  await fs.appendFile(filePath, line, { encoding: "utf8" });
}

export async function rewriteWal(filePath: string, events: TelemetryEnvelope[]): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const tmpPath = `${filePath}.tmp`;
  const payload =
    events.length === 0 ? "" : `${events.map((evt) => JSON.stringify(evt)).join("\n")}\n`;
  await fs.writeFile(tmpPath, payload, { encoding: "utf8" });
  await fs.rename(tmpPath, filePath);
}

