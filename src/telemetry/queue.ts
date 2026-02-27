import crypto from "node:crypto";
import type { PlatformClient } from "../platform-client.js";
import type { ClawdstrikePluginConfig, TelemetryEnvelope } from "../service-types.js";

function nowMs(): number {
  return Date.now();
}

function normalizeEvent(cfg: ClawdstrikePluginConfig, evt: TelemetryEnvelope): TelemetryEnvelope {
  return {
    ...evt,
    eventId: evt.eventId || crypto.randomUUID(),
    ts: typeof evt.ts === "number" ? evt.ts : nowMs(),
    severity: evt.severity ?? "info",
    projectId: evt.projectId ?? cfg.projectId,
    agentInstanceId: evt.agentInstanceId ?? cfg.agentInstanceId,
    agentName: evt.agentName ?? cfg.agentName,
  };
}

export class TelemetryQueue {
  readonly cfg: ClawdstrikePluginConfig;
  readonly client: PlatformClient;

  private queue: TelemetryEnvelope[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private flushing = false;

  constructor(params: {
    cfg: ClawdstrikePluginConfig;
    client: PlatformClient;
  }) {
    this.cfg = params.cfg;
    this.client = params.client;
  }

  async start(): Promise<void> {
    this.flushTimer = setInterval(() => {
      void this.flush().catch(() => {});
    }, this.cfg.flushIntervalMs);
  }

  async stop(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }

  emit(partial: Omit<TelemetryEnvelope, "eventId" | "ts"> & { eventId?: string; ts?: number }) {
    if (!this.cfg.enabled || this.cfg.mode === "off") {
      return;
    }
    const normalized = normalizeEvent(this.cfg, partial as TelemetryEnvelope);
    this.queue.push(normalized);
  }

  private dequeueBatch(): TelemetryEnvelope[] {
    const max = this.cfg.batchMaxEvents;
    if (this.queue.length <= max) {
      return [...this.queue];
    }
    return this.queue.slice(0, max);
  }

  async flush(): Promise<void> {
    if (!this.cfg.enabled || this.cfg.mode === "off") {
      return;
    }
    if (this.flushing) {
      return;
    }
    if (this.queue.length === 0) {
      return;
    }
    this.flushing = true;
    try {
      const batch = this.dequeueBatch();
      await this.client.ingest(batch);
      // Drop acknowledged events.
      this.queue.splice(0, batch.length);
    } finally {
      this.flushing = false;
    }
  }
}
