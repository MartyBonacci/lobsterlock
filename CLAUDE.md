# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LobsterLock is a semantic security orchestrator for OpenClaw deployments. It uses OpenClaw's own CLI tools (`security audit --json`, `skills list --json`) as primary data sources and applies Claude-powered semantic reasoning to detect novel threats that pattern matchers miss. Third-party tools (SecureClaw, AgentGuard, ClawSec, SkillVet) are optional v0.2+ enhancements, not MVP dependencies.

**Status:** MVP v0.1 implemented (95 tests passing). See SPEC.md for the full technical specification.

## Tech Stack

- **Runtime:** Node.js 22+ (targets Node.js 24)
- **Language:** TypeScript (strict, ESM)
- **Filesystem watch:** chokidar
- **Database:** SQLite via better-sqlite3
- **Reasoning:** Anthropic Messages API via `@anthropic-ai/sdk`
- **Alerts:** Discord via `discord.js`
- **CLI:** commander
- **Target platform:** DigitalOcean marketplace image, Ubuntu 24, OpenClaw 3.12, systemd
- **Memory budget:** 2GB shared — OpenClaw gets 1280MB heap, LobsterLock gets 256MB heap

## Architecture (Three Layers)

1. **Collector Layer** — Gathers raw signals: `security audit --json` and `skills list --json` via periodic poll (default 5min), `journalctl -u openclaw` log tailing, and chokidar filesystem watches on skills directories.

2. **Reasoning Engine** — Event-driven (Claude never polled on a timer). Invoked only when hard or threshold triggers fire. Triggers are coalesced via a 3-second debounce window. Receives structured context in XML-delimited sections (with prompt injection mitigations). Produces exactly one verdict: `CLEAR`, `WATCH`, `ALERT [LOW|MEDIUM|HIGH]`, or `KILL`.

3. **Alert Dispatcher** — Routes verdicts: CLEAR/WATCH go to logs, ALERT pushes to Discord, KILL runs `openclaw security audit --fix` + alerts + awaits human confirmation via `lobsterlock ack`.

## Key Design Decisions

- **Event-driven reasoning, periodic collection** — Collectors poll cheaply (~200ms local CLI), but Claude is only invoked on triggers. Minimizes token waste while closing blind spots.
- **Trigger coalescing** — 3-second debounce window prevents trigger storms from causing multiple Claude calls.
- **Non-invasive** — Runs alongside OpenClaw as a separate process. Must not interfere if LobsterLock crashes.
- **Escalation model** — 3 consecutive WATCH verdicts without a CLEAR floors the next invocation at ALERT LOW. De-escalation via CLEAR verdict or `lobsterlock ack`.
- **Signal buffer** — Ring buffer (500 entries max) with structured `SignalEntry` format. Prevents unbounded memory growth on 256MB heap.
- **Prompt injection defense** — All data in reasoning prompt uses XML delimiters, system prompt warns about adversarial content, verdict parsed with strict regex.
- **Full auditability** — Every reasoning cycle logged to SQLite with complete context. Traces must be human-readable.

## Build Commands

```bash
npm install          # install dependencies
npm run build        # compile TypeScript to dist/
npm test             # run all 95 tests (no external services needed)
npm run dev          # watch mode (tsc --watch)
npm start            # run with 256MB heap limit
npm link             # make `lobsterlock` CLI globally available
```

## File Structure

```
src/
├── index.ts              # CLI entry point
├── config.ts             # Config loader (~/.lobsterlock/config.json)
├── collector/
│   ├── audit.ts          # security audit --json runner + diff (periodic poll)
│   ├── skills.ts         # skills list --json snapshot + diff
│   ├── log-tail.ts       # journalctl log ingestion
│   └── fs-watcher.ts     # skills directory watcher
├── reasoning/
│   ├── engine.ts         # Claude reasoning cycle
│   └── prompt.ts         # Prompt construction (XML-delimited, injection-hardened)
├── dispatcher/
│   ├── alert.ts          # Alert routing (Discord)
│   └── kill.ts           # Kill switch activation + confirmation gate
├── trigger/
│   ├── manager.ts        # Trigger detection + debounce coalescing
│   └── buffer.ts         # Signal ring buffer (500 entries)
└── storage/
    └── audit-log.ts      # SQLite audit trail
```

## Trigger System

**Hard triggers (v0.1):** new/modified skill file, new eligible skill in inventory, new security finding, critical count increase, config file change, external kill switch file, OpenClaw restart.

**Hard triggers (v0.2):** unknown outbound IP, gateway WebSocket failure.

**Threshold triggers (v0.1):** 3 low-severity log anomalies in 60s, 3 consecutive WATCHes without CLEAR.

**Threshold triggers (v0.2):** repeated unknown IP connections (2 in 5 min).

## Development Environment

- OpenClaw is running on this same droplet as a systemd service
- Logs: `journalctl -u openclaw`
- Config: `/home/openclaw/.openclaw/openclaw.json`
- Gateway: localhost:18789
- Skills directory: `/home/openclaw/.openclaw/workspace/skills`
- This user has READ-ONLY access to OpenClaw's files (by design)

**Architecture constraint:** LobsterLock must never write to OpenClaw's directories. All LobsterLock state lives in `~/.lobsterlock/`. The kill switch is the only action that touches OpenClaw: it runs `openclaw security audit --fix` then `systemctl stop openclaw`.

**Testing against live OpenClaw:**
- Test against the live gateway on this machine
- Trigger test events by sending messages in the Control UI
- Watch logs in real-time with `journalctl -u openclaw -f` to verify detection

## Environment Variables

- `ANTHROPIC_API_KEY` — required for reasoning engine and `lobsterlock check`
- `DISCORD_BOT_TOKEN` — optional, alerts fall back to stderr without it
- `DEBUG` — enables debug logging
