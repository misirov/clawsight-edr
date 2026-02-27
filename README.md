# ClawdStrike OpenClaw Plugin

OpenClaw plugin (`id: clawdstrike`) that provides security guardrails and telemetry for AI agents. Works standalone with local rules or connected to a remote SIEM platform.

## Modes

| Mode | Rules | Telemetry | Platform Required |
|------|-------|-----------|-------------------|
| `local` | Local file (`rules.json`) | Optional | No |
| `audit` | Remote (platform) | Yes | Yes |
| `enforce` | Remote (platform) | Yes | Yes |
| `off` | None | None | No |

## Quick Start (Local Mode)

No server required. Rules are enforced from a local JSON file.

```bash
node ./clawdstrike-plugin/bin/clawdstrike.mjs install --mode local --link
openclaw gateway restart
```

This creates default rules at `~/.openclaw/plugins/clawdstrike/rules.json` and starts enforcing immediately. Ships with 46 default rules covering download-and-execute, reverse shells, credential theft, persistence mechanisms, exfiltration domains, and more.

### Local Mode + SIEM Telemetry

Enforce rules locally while streaming telemetry to your SIEM:

```bash
node ./clawdstrike-plugin/bin/clawdstrike.mjs install \
  --mode local \
  --platform-url http://127.0.0.1:3000 \
  --token devtoken \
  --link
```

## Quick Start (Platform Mode)

Requires a running ClawdStrike SIEM platform.

```bash
node ./clawdstrike-plugin/bin/clawdstrike.mjs install \
  --platform-url http://127.0.0.1:3000 \
  --token devtoken \
  --mode enforce \
  --agent-name my-agent \
  --link
```

## Chat Commands

Manage rules live from any connected messaging channel (Telegram, Discord, Slack):

```
/cs status                          Show mode, rule count, advisory vs enforced
/cs rules                           List all active rules
/cs directives                      List custom prompt directives
/cs directive preview               Show full injected system + context prompt
/cs directive add <text>            Add a security directive (advisory)
/cs directive remove <index...>     Remove directives by index

/cs block command <text>            Block shell commands containing text
/cs block domain <pattern>          Block a domain (incl. subdomains)
/cs block ip <addr>                 Block an IP address
/cs block tool <name> [pattern]     Block a specific tool
/cs block message <text>            Block outbound messages containing text
/cs allow command <text>            Allow (same types as block)
/cs remove <id...>                  Remove rules by ID

/cs confirm command <text>          Require approval for matching commands
/cs confirm domain <pattern>        Require approval for domain access
/cs confirm tool <name> [pattern]   Require approval for a tool
/cs pending                         List pending approvals
/cs approve <id>                    Approve a pending action (one-time)
/cs approve-always <id>             Approve and add permanent allow rule
/cs deny <id>                       Deny a pending action

/cs enforce append <text>           Auto-append text to every outbound message
/cs enforce require <text>          Block messages not containing text
/cs enforce reject <text>           Block messages containing text
```

### Rule Actions

| Action | Mechanism | Guarantee |
|--------|-----------|-----------|
| **block** | `before_tool_call` / `message_sending` hooks | 100% — deterministic, LLM cannot bypass |
| **confirm** | `before_tool_call` hook + approval manager | 100% — blocks until user approves via `/cs approve` |
| **allow** | `before_tool_call` hook | Explicitly permits matching actions |
| **warn** | Telemetry emission | Logged but not blocked |

### Advisory vs Enforced

| Type | Mechanism | Guarantee |
|------|-----------|-----------|
| **Advisory** (prompt directives) | Injected into system prompt | Best-effort — LLM should follow but can ignore |
| **Enforced** (block/confirm rules) | `before_tool_call` / `message_sending` hooks | 100% — deterministic, LLM cannot bypass |
| **Enforced** (output rules) | `message_sending` hook | 100% — deterministic, modifies/blocks before send |

### Examples

```
/cs block command rm -rf            Block recursive force-delete
/cs block domain evil.com           Block evil.com + all subdomains
/cs block tool web_search           Block the web_search tool entirely
/cs confirm command npm install     Require approval for npm install
/cs approve a3f8                    Approve pending action a3f8
/cs enforce append  LOLOLOL         Guarantee LOLOLOL on every message
/cs enforce require [verified]      Block messages missing [verified]
/cs enforce reject <script>         Block messages containing <script>
/cs directive add Never share API keys in responses
/cs remove 1 2 3                    Remove multiple rules at once
```

## How It Works

### Local Mode

1. **System prompt injection** (`before_agent_start`): Security directives are set as the session's system prompt at session creation, giving them highest model authority. Persists across turns and compaction.
2. **Per-turn reinforcement** (`before_prompt_build`): Directives are also prepended to the user message each turn as secondary reinforcement.
3. **Policy engine** (`before_tool_call`): Evaluates tool calls against rules in `rules.json` — blocks domains, IPs, commands deterministically. Confirm rules trigger the approval flow.
4. **Approval system** (`before_tool_call`): When a confirm rule matches, the tool call is blocked with a pending approval ID. The user approves or denies via `/cs approve`/`/cs deny`. On retry, approved actions pass through.
5. **Output enforcement** (`message_sending`): Deterministic output rules (append/require/reject) run on every outbound message before send. The LLM cannot bypass these.

### Platform Mode (Audit/Enforce)

1. **Telemetry** streams all agent activity to the SIEM via `POST /v1/telemetry/ingest`
2. **Guardrails** call `POST /v1/guardrails/decide` for tool/message/intent decisions
3. **Intent policy** tracks baseline drift across LLM interactions
4. **Fail-safe** behavior: audit mode logs only; enforce mode blocks with fail-open for low-risk tools

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"audit"` | `off`, `audit`, `enforce`, or `local` |
| `platformUrl` | string | — | SIEM platform URL (required for audit/enforce, optional for local) |
| `apiToken` | string | — | Platform API token |
| `localRulesPath` | string | `~/.openclaw/plugins/clawdstrike/rules.json` | Path to local rules file (local mode) |
| `agentName` | string | — | Human-readable agent label |
| `agentInstanceId` | string | auto-generated | Stable instance ID (persisted to `identity.json`) |
| `flushIntervalMs` | number | `1000` | Telemetry flush interval |
| `batchMaxEvents` | number | `200` | Max events per telemetry batch |

## Telemetry Events

When telemetry is active (platform modes, or local mode with `platformUrl`):

- **Agent lifecycle**: `agent.bootstrap`, `agent.inventory_snapshot`
- **Session lifecycle**: `session_start`, `session_end`, `before_reset`
- **LLM phases**: `llm_input`, `llm_output`
- **Tool lifecycle**: `before_tool_call`, `after_tool_call`, `tool_result_persist`
- **Message lifecycle**: `message_received`, `message_sending`, `message_sent`
- **Policy decisions**: `tool_decision`, `message_decision`, `intent_*_decision`
- **Diagnostics**: heartbeats, webhooks, cron events

All events include distributed tracing fields (`traceId`, `spanId`, `parentSpanId`, `rootExecutionId`).

## Documentation

- [Architecture](docs/architecture.md) - System architecture and data flow
- [Capabilities](docs/capabilities.md) - Full feature reference
- [API Reference](docs/api.md) - Plugin API and decision endpoints
- [Local Rules](docs/local_rules.md) - Local rule engine and slash commands
- [SIEM Rules](docs/siem_rules.md) - Platform-enforced policy rules

## Notes

- Set a unique `agentName` per instance in multi-agent setups
- Plugin auto-generates and persists `agentInstanceId` at `~/.openclaw/plugins/clawdstrike/identity.json`
- Payments endpoint exists in platform as disabled (`410 Gone`) and is blocked in local mode
