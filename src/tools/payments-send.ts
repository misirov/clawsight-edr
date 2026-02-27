import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { jsonResult } from "openclaw/plugin-sdk";
import crypto from "node:crypto";
import { getRuntime } from "../runtime.js";

const paymentSendParameters = {
  type: "object",
  additionalProperties: false,
  required: ["toAddress", "amount"],
  properties: {
    toAddress: {
      type: "string",
      description: "Destination address.",
    },
    amount: {
      type: "string",
      description: "Amount (string to avoid float issues).",
    },
    chain: {
      type: "string",
      description: "Chain/network identifier (optional).",
    },
    asset: {
      type: "string",
      description: "Asset/currency ticker (optional).",
    },
    memo: {
      type: "string",
      description: "Memo/description (optional).",
    },
    idempotencyKey: {
      type: "string",
      description: "Idempotency key for safe retries (optional).",
    },
  },
};

export function createPaymentsSendTool(_api: OpenClawPluginApi) {
  return {
    name: "payments.send",
    label: "Payments Send (ClawdStrike)",
    description:
      "Send a payment via the ClawdStrike platform (policy-enforced: allow/deny lists, caps, approvals). The agent never receives wallet private keys.",
    parameters: paymentSendParameters,
    async execute(_toolCallId: string, params: Record<string, unknown>) {
      const rt = getRuntime();
      if (!rt) {
        throw new Error("clawdstrike runtime not initialized");
      }
      const toAddress = typeof params.toAddress === "string" ? params.toAddress.trim() : "";
      if (!toAddress) {
        throw new Error("toAddress required");
      }
      const amount = typeof params.amount === "string" ? params.amount.trim() : "";
      if (!amount) {
        throw new Error("amount required");
      }

      const req = {
        chain: typeof params.chain === "string" ? params.chain.trim() : undefined,
        asset: typeof params.asset === "string" ? params.asset.trim() : undefined,
        toAddress,
        amount,
        memo: typeof params.memo === "string" ? params.memo.trim() : undefined,
        idempotencyKey:
          typeof params.idempotencyKey === "string" ? params.idempotencyKey.trim() : undefined,
      };
      const requestId = crypto.randomUUID();
      const startedAt = Date.now();

      rt.emit({
        category: "payment",
        action: "send",
        severity: "debug",
        requestId,
        payload: { ...req, amount: req.amount, toAddress: req.toAddress },
      });

      const res = await rt.paymentsSend(req);

      rt.emit({
        category: "payment",
        action: "send_result",
        severity: res.status === "blocked" ? "warn" : res.status === "submitted" ? "info" : "error",
        requestId,
        durationMs: Date.now() - startedAt,
        result: res.status === "submitted" ? "ok" : res.status === "blocked" ? "blocked" : "error",
        payload: {
          ...res,
          chain: req.chain,
          asset: req.asset,
          amount: req.amount,
          toAddress: req.toAddress,
        },
      });

      if (res.status === "blocked") {
        throw new Error(res.reason ? `payment blocked: ${res.reason}` : "payment blocked by policy");
      }
      if (res.status === "error") {
        throw new Error(res.reason ? `payment failed: ${res.reason}` : "payment failed");
      }

      return jsonResult(res);
    },
  };
}
