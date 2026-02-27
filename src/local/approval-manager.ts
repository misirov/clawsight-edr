import crypto from "node:crypto";

export type PendingApproval = {
  id: string;
  toolName: string;
  paramsHash: string;
  paramsSummary: string;
  reason: string;
  ruleId: string;
  status: "pending" | "approved" | "denied";
  createdAt: number;
  expiresAt: number;
};

function hashParams(toolName: string, params: Record<string, unknown>): string {
  const payload = JSON.stringify({ toolName, params });
  return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}

function shortId(): string {
  return crypto.randomBytes(2).toString("hex");
}

function summarizeParams(params: Record<string, unknown>, max = 120): string {
  const command = params.command;
  if (typeof command === "string") {
    return command.length <= max ? command : `${command.slice(0, max - 3)}...`;
  }
  const raw = JSON.stringify(params);
  return raw.length <= max ? raw : `${raw.slice(0, max - 3)}...`;
}

export class ApprovalManager {
  private pending = new Map<string, PendingApproval>();
  private DEFAULT_TTL_MS = 5 * 60 * 1000;

  createPending(
    toolName: string,
    params: Record<string, unknown>,
    reason: string,
    ruleId: string,
  ): PendingApproval {
    this.cleanup();
    const id = shortId();
    const now = Date.now();
    const entry: PendingApproval = {
      id,
      toolName,
      paramsHash: hashParams(toolName, params),
      paramsSummary: summarizeParams(params),
      reason,
      ruleId,
      status: "pending",
      createdAt: now,
      expiresAt: now + this.DEFAULT_TTL_MS,
    };
    this.pending.set(id, entry);
    return entry;
  }

  checkApproval(toolName: string, params: Record<string, unknown>): "approved" | "denied" | null {
    this.cleanup();
    const hash = hashParams(toolName, params);
    for (const entry of this.pending.values()) {
      if (entry.paramsHash === hash && entry.toolName === toolName) {
        if (entry.status === "approved") return "approved";
        if (entry.status === "denied") return "denied";
      }
    }
    return null;
  }

  resolve(id: string, decision: "approved" | "denied"): PendingApproval | null {
    const entry = this.pending.get(id);
    if (!entry) return null;
    entry.status = decision;
    return entry;
  }

  get(id: string): PendingApproval | undefined {
    return this.pending.get(id);
  }

  listPending(): PendingApproval[] {
    this.cleanup();
    return [...this.pending.values()].filter((e) => e.status === "pending");
  }

  listAll(): PendingApproval[] {
    this.cleanup();
    return [...this.pending.values()];
  }

  cleanup(): void {
    const now = Date.now();
    for (const [id, entry] of this.pending) {
      if (now > entry.expiresAt) {
        this.pending.delete(id);
      }
    }
  }
}
