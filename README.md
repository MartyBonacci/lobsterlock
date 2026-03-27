# LobsterLock

**Semantic security monitoring for OpenClaw deployments, powered by Claude.**

[lobsterlock.dev](https://lobsterlock.dev)

---

## The Problem

OpenClaw is the fastest-growing open-source AI agent runtime, and one of 2026's most significant security incidents. As of March 2026:

- **31 CVEs** with published exploits, including [one-click RCE](https://nvd.nist.gov/vuln/detail/CVE-2026-25253) (CVSS 8.8) affecting 12,812 confirmed exploitable instances
- **1,184+ malicious skills** on ClawHub from the [ClawHavoc campaign](https://socket.dev/blog/clawhavoc-1184-malicious-npm-packages-attack-openclaw-users), sharing a single C2 IP
- **135,000+ publicly exposed instances** with [40,000+ gateway ports open to the internet](https://www.bitsight.com/blog/openclaw-exposed-instances)
- **Government bans** from Meta, Google, Microsoft, Amazon, and Chinese government agencies

Attack research from [Cisco](https://github.com/cisco-ai-defense/skill-scanner), [CNCERT/CC](https://www.cncert.org.cn/), [Oasis Security (ClawJacked)](https://www.oasis.security/resources/blog/clawjacked-how-any-website-could-hijack-your-ai-agent), [Palo Alto Networks](https://unit42.paloaltonetworks.com/), [CrowdStrike](https://www.crowdstrike.com/), and [others](https://thehackernews.com/2026/03/openclaw-ai-agent-flaws-could-enable.html) has documented attack vectors from no-click data exfiltration via link previews to persistent memory poisoning that survives skill uninstallation.

OpenClaw v2026.3.22+ hardened gateway auth and sandboxing defaults, which is real progress. But memory file poisoning, exec approval bypasses (sub-agents still skip approvals), and instruction-layer skill attacks remain architecturally unaddressed. These are semantic threats that require reasoning over combined signals, not just pattern matching.

That gap is what LobsterLock fills.

## How It Works

LobsterLock runs alongside OpenClaw as a separate process with read-only access. It has two operating modes:

**BORING MODE** (default): Zero Claude API calls. Collectors watch passively. Signals accumulate in a ring buffer. Costs nothing.

**TRIGGERED MODE** (something happened): A pattern-matched anomaly crosses a threshold or a hard trigger fires. All accumulated signals are coalesced through a 3-second debounce window. Claude receives the full context in XML-delimited sections (with prompt injection defenses) and produces exactly one verdict:

| Verdict | Action |
|---------|--------|
| **CLEAR** | Log only. Reset buffer. |
| **WATCH** | Log with context. Preserve buffer. 3 consecutive WATCHes escalate to ALERT. |
| **ALERT** [LOW/MEDIUM/HIGH] | Push notification via Discord. Awaits `lobsterlock ack`. |
| **KILL** | Run `openclaw security audit --fix`, then `systemctl stop openclaw`. Monitoring paused until `lobsterlock ack`. |

Every reasoning cycle is logged to SQLite with the full prompt, response, and signal context. Traces are human-readable.

## What It Detects Today

LobsterLock v0.2 covers approximately 40-45% of OpenClaw's documented attack surface across five monitoring categories. Tested against OpenClaw v2026.3.24 (March 2026). The remaining gaps are documented and on the roadmap.

| Category | Coverage | What's Implemented | What's Next |
|----------|----------|-------------------|-------------|
| **Memory Integrity** | ~50% | File hashing + baseline diffing, content scanning (base64, zero-width unicode, instruction injection, credential paths, suspicious commands, SSRF targets, known C2 IPs), 7-day drift detection | Write source attribution, gradual drift ML |
| **Network Egress** | ~40% | Log-based curl/wget detection, /dev/null redirect detection, SSRF target patterns, known C2 IP blocklist, `dangerouslyAllowPrivateNetwork` config check | Active network monitoring via ss/netstat, domain allowlists |
| **Gateway Security** | ~55% | Port 18789 exposure monitoring (Docker-aware), gateway auth validation with config ground truth, cross-origin WebSocket detection, brute-force log patterns, `exec.approvals` + `config.apply` detection, exec host-mode bypass detection | WebSocket connection analysis, device pairing monitoring |
| **Heartbeat System** | ~65% | HEARTBEAT.md watching + content scanning, `heartbeat.target` config check, heartbeat interval validation, response routing alerts | Token consumption tracking |
| **Autonomous Actions** | 0% | Not yet started | OAuth grant detection, account creation monitoring, identity data tracking |

160 tests. All passing.

## Live Proof of Concept

On the first live test, LobsterLock detected a new skill being created on an OpenClaw instance and produced this verdict:

```
[2026-03-25T15:08:50.115Z] [ALERT HIGH] New shell script created during unexplained
10-minute OpenClaw silence; possible unauthorized skill installation

The two consecutive "no log output for 5 minutes" signals (14:59 and 15:04) indicate
OpenClaw was silent or down from roughly 14:54-15:08, and the very first observable
action after that silence is the creation of a shell script (collect_system_info.sh)
in the skills directory. This pattern -- process goes quiet, then a new executable
skill file appears -- is consistent with an out-of-band modification or a compromised
session installing a reconnaissance tool without generating normal log traffic. The
security posture also shows two critical auth gaps (no gateway auth, no browser-control
auth) that could allow a local process or SSRF to interact with the agent without
credentials, making lateral movement or injection more plausible.
```

A rule-based tool would say "new file created." LobsterLock correlated filesystem changes with log silence and auth gaps to identify a pattern consistent with unauthorized skill installation. That semantic correlation is the core value proposition.

On a properly configured v2026.3.24 deployment (gateway auth enabled, sandbox active, trusted proxies set), LobsterLock correctly returns **CLEAR** with 4 confirmed-safe findings:

```
Config analysis: 0 warning(s), 4 confirmed safe

CLEAR
The security audit reports two critical findings (missing gateway auth, browser control
no auth), but the config_analysis section confirms gateway auth is configured
(token-based), trusted proxies are set, and sandbox mode with Docker isolation is
active -- the audit is reading from a different user context and seeing defaults.
No actionable security concerns.
```

LobsterLock doesn't just find problems. It validates good configurations and explains why apparent issues are actually false positives from user-context mismatches.

## Quick Start

### Prerequisites

- Node.js 22+
- An OpenClaw deployment (same machine or accessible via network)
- [Anthropic API key](https://console.anthropic.com/)
- Discord bot token (optional, for push alerts)

### Install

```bash
git clone https://github.com/MartyBonacci/lobsterlock.git
cd lobsterlock
npm install
npm run build
npm link
```

### Configure

Create `~/.lobsterlock/.env`:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
DISCORD_BOT_TOKEN=your-bot-token        # optional
```

Optionally create `~/.lobsterlock/config.json` (all fields have sensible defaults):

```json
{
  "openclaw_cli": "/usr/bin/openclaw",
  "openclaw_service": "openclaw",
  "skills_watch": ["/home/openclaw/.openclaw/workspace/skills"],
  "model": "claude-sonnet-4-6",
  "discord_channel_id": "YOUR_CHANNEL_ID"
}
```

### Run

```bash
# One-shot security check (no daemon needed)
lobsterlock check

# Start the monitoring daemon
lobsterlock start

# Other commands
lobsterlock status   # Show current status and escalation state
lobsterlock last     # Show most recent reasoning cycle
lobsterlock ack      # Acknowledge alerts, reset escalation
```

## Recommended Setup

### State directory

LobsterLock stores its config, database, PID file, and environment variables in `~/.lobsterlock/`. This directory is created automatically on first run, or you can create it manually:

```bash
mkdir -p ~/.lobsterlock
```

Place your `.env` (API keys) and `config.json` (path overrides) here.

### Separate OS user

LobsterLock is designed to run as a dedicated user with read-only access to OpenClaw's files. This is a security boundary: if OpenClaw is compromised, it can't tamper with LobsterLock's database or config. If LobsterLock has a bug, it can't accidentally modify OpenClaw's state.

```bash
sudo adduser --disabled-password --gecos "LobsterLock" lobsterlock
sudo usermod -aG adm,systemd-journal,openclaw lobsterlock
sudo chmod g+rx /home/openclaw
sudo chmod -R g+r /home/openclaw/.openclaw
```

This gives the `lobsterlock` user:
- **adm**: access to system logs
- **systemd-journal**: access to `journalctl -u openclaw`
- **openclaw**: read access to OpenClaw's config, skills, and memory files

For development or quick testing, running as your own user works fine. The separate user matters for production.

### OpenClaw path guidance

The default config assumes the **DigitalOcean marketplace image** layout:
- CLI: `/usr/bin/openclaw`
- Skills: `/home/openclaw/.openclaw/workspace/skills`
- Config: `/home/openclaw/.openclaw/openclaw.json`

If your installation differs, override in `~/.lobsterlock/config.json`:

```json
{
  "openclaw_cli": "/usr/local/bin/openclaw",
  "skills_watch": ["/path/to/your/skills"]
}
```

If using the marketplace helper scripts (which run commands as the `openclaw` user via `su`), set `openclaw_cli` to `/opt/openclaw-cli.sh`. Note this requires password-based `su` access.

### What to expect on first run

Running `lobsterlock check` on a default OpenClaw installation will typically produce a **WATCH** or **ALERT LOW** verdict identifying authentication configuration gaps (no gateway auth, no browser control auth). This is not a false positive. These are real findings from `openclaw security audit --json` that affect every default installation. The recommended fix is to configure `gateway.auth.token` in your `openclaw.json`.

## Architecture

LobsterLock is a Node.js daemon (256MB heap) that runs as a separate OS user with read-only access to OpenClaw's files.

```
Collectors                    Trigger Manager              Reasoning Engine
┌──────────────────┐         ┌─────────────────┐         ┌──────────────────┐
│ Audit poll (5min) │────┐   │ Hard triggers    │         │ Claude API call  │
│ Skills poll       │────┤   │ Threshold rules  │────────▶│ XML prompt +     │
│ journalctl tail   │────┼──▶│ 3s debounce      │         │ injection defense│
│ fs-watcher        │────┤   │ Escalation floor │         │ Verdict parser   │
│ Memory watcher    │────┤   └─────────────────┘         └────────┬─────────┘
│ Port checker      │────┘                                        │
└──────────────────┘                                              ▼
                                                         ┌──────────────────┐
                                                         │ Alert Dispatcher │
                                                         │ Discord / log    │
                                                         │ Kill switch      │
                                                         │ SQLite audit log │
                                                         └──────────────────┘
```

**Six collectors** feed signals through a trigger manager with debounce coalescing. Claude is only invoked when triggers fire. All verdicts and reasoning traces are stored in a local SQLite database.

See [SPEC.md](SPEC.md) for the full technical specification.

## What Makes LobsterLock Different

LobsterLock is not the only OpenClaw security tool. Here's how it compares:

| Tool | Approach | LobsterLock's Angle |
|------|----------|-------------------|
| [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner) | Pre-install static + behavioral + semantic analysis | LobsterLock monitors runtime behavior, not just pre-install |
| Cisco DefenseClaw | Enterprise governance layer | Enterprise-focused; LobsterLock is lightweight, open-source |
| [NVIDIA NemoClaw](https://developer.nvidia.com/nemoclaw) | Sandboxed runtime + privacy router | Out-of-process enforcement; LobsterLock adds multi-turn drift detection ([NemoClaw's known gap](https://repello.ai)) |
| clawdefender | Runtime scanning skill inside OpenClaw | Runs inside the agent it protects and can be bypassed by it |
| openclaw-security-monitor | Host-level 41-point scan, CVE detection | Pattern-matching; LobsterLock adds Claude-powered semantic analysis |
| ClawSecure | Skill auditing service (2,890+ scanned) | External service; LobsterLock runs locally alongside the agent |

**LobsterLock's differentiator:** Semantic security analysis powered by Claude that correlates multiple signals across time. Not just "did a pattern match?" but "what does this combination of events mean?" The live test proved this: correlating filesystem changes with log silence and auth gaps to identify a pattern that no individual rule would flag.

## Contributing

The coverage table above shows exactly what's built and what's not. Every unchecked item in the [ACTION-PLAN.md](ACTION-PLAN.md) is a contribution opportunity. The biggest open areas:

- **Autonomous action boundaries** (Phase 5): OAuth grant detection, account creation monitoring, identity data tracking. Fundamentally different from signal monitoring and needs fresh design.
- **Active network monitoring** (Phase 2): `ss`/`netstat` snapshots for outbound connection tracking, domain allowlists.
- **Gateway WebSocket analysis** (Phase 3): Deep inspection of WebSocket connections beyond log patterns.
- **Write source attribution** (Phase 1): Distinguishing user-initiated memory file changes from skill-triggered or agent-self-triggered writes.

See [SPEC.md](SPEC.md) for the full technical specification and [OPENCLAW-SECURITY-ISSUES.md](OPENCLAW-SECURITY-ISSUES.md) for the threat landscape research that drives the roadmap.

## License

MIT
