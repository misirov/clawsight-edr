import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import type { ClawdstrikePluginConfig } from "./service-types.js";

type PersistedIdentity = {
  agentInstanceId?: string;
  agentName?: string;
  createdAt?: string;
  updatedAt?: string;
};

export type RuntimeAgentIdentity = {
  agentInstanceId: string;
  agentName?: string;
  identityPath: string;
  hostName: string;
  osPlatform: string;
  osRelease: string;
  osArch: string;
  nodeVersion: string;
  pluginVersion?: string;
  openclawVersion?: string;
};

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function defaultIdentityPath(): string {
  return path.join(os.homedir(), ".openclaw", "plugins", "clawdstrike", "identity.json");
}

function resolvePluginVersion(): string | undefined {
  return (
    asString(process.env.CLAWDSTRIKE_PLUGIN_VERSION) ||
    asString(process.env.npm_package_version) ||
    undefined
  );
}

function resolveOpenclawVersion(): string | undefined {
  return (
    asString(process.env.OPENCLAW_VERSION) ||
    asString(process.env.OPENCLAW_BUILD_VERSION) ||
    undefined
  );
}

async function readPersistedIdentity(filePath: string): Promise<PersistedIdentity> {
  try {
    const raw = await readFile(filePath, "utf8");
    const parsed = JSON.parse(raw) as PersistedIdentity;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

async function writePersistedIdentity(filePath: string, data: PersistedIdentity): Promise<void> {
  const nowIso = new Date().toISOString();
  const current = await readPersistedIdentity(filePath);
  const payload: PersistedIdentity = {
    agentInstanceId: data.agentInstanceId || current.agentInstanceId || crypto.randomUUID(),
    agentName: data.agentName || current.agentName || undefined,
    createdAt: current.createdAt || nowIso,
    updatedAt: nowIso,
  };
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

export async function resolveRuntimeAgentIdentity(
  cfg: ClawdstrikePluginConfig,
): Promise<RuntimeAgentIdentity> {
  const identityPath = asString(cfg.identityPath) || defaultIdentityPath();
  const persisted = await readPersistedIdentity(identityPath);

  const configuredInstance = asString(cfg.agentInstanceId);
  const persistedInstance = asString(persisted.agentInstanceId);
  const agentInstanceId = configuredInstance || persistedInstance || crypto.randomUUID();

  const configuredName = asString(cfg.agentName);
  const persistedName = asString(persisted.agentName);
  const agentName = configuredName || persistedName || undefined;

  await writePersistedIdentity(identityPath, {
    agentInstanceId,
    agentName,
  });

  return {
    agentInstanceId,
    agentName,
    identityPath,
    hostName: os.hostname(),
    osPlatform: process.platform,
    osRelease: os.release(),
    osArch: process.arch,
    nodeVersion: process.version,
    pluginVersion: resolvePluginVersion(),
    openclawVersion: resolveOpenclawVersion(),
  };
}
