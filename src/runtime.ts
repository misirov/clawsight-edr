import type { ClawdstrikeRuntime } from "./service-types.js";

let runtime: ClawdstrikeRuntime | null = null;

export function setRuntime(next: ClawdstrikeRuntime | null) {
  runtime = next;
}

export function getRuntime(): ClawdstrikeRuntime | null {
  return runtime;
}

