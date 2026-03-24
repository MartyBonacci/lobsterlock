# LobsterLock

Semantic security orchestrator for OpenClaw deployments. Uses Claude to reason over combined security signals and detect threats that no single pattern matcher would catch.

While existing tools (SecureClaw, AgentGuard, ClawSec) are smoke detectors, LobsterLock is the fire marshal who reads all the detectors, walks the building, and decides whether to call it in.

## Prerequisites

- Node.js 22+ (targets Node.js 24)
- An OpenClaw deployment with `openclaw` CLI available
- Anthropic API key
- Discord bot token (optional, for alerts)

## Install

```bash
git clone https://github.com/[your-handle]/lobsterlock.git
cd lobsterlock
npm install
npm run build
npm link  # makes `lobsterlock` available globally
```

## Configure

Create `~/.lobsterlock/config.json`:

```json
{
  "openclaw_cli": "/opt/openclaw-cli.sh",
  "openclaw_service": "openclaw",
  "skills_watch": [
    "/home/openclaw/.openclaw/skills",
    "/home/openclaw/.openclaw/workspace/skills"
  ],
  "model": "claude-sonnet-4-6",
  "discord_channel_id": "YOUR_CHANNEL_ID"
}
```

All fields are optional. See SPEC.md for the full configuration reference.

## Environment Variables

```bash
export ANTHROPIC_API_KEY="sk-ant-..."     # Required for reasoning
export DISCORD_BOT_TOKEN="..."             # Optional, for Discord alerts
```

## Usage

```bash
lobsterlock start    # Start monitoring (foreground)
lobsterlock status   # Show current status
lobsterlock last     # Show most recent reasoning cycle
lobsterlock check    # One-shot security check (no daemon required)
lobsterlock ack      # Acknowledge alerts, reset escalation
```

## How It Works

LobsterLock runs four collectors that watch your OpenClaw deployment:

1. **Audit collector** -- periodically runs `openclaw security audit --json` and diffs results
2. **Skills collector** -- monitors `openclaw skills list --json` for inventory changes
3. **Log tail** -- tails `journalctl -u openclaw` for anomaly patterns
4. **Filesystem watcher** -- watches skills directories for file changes

When a trigger fires (new skill, audit finding, log anomaly), signals are coalesced through a 3-second debounce window, then Claude reasons over the combined context and produces a verdict:

- **CLEAR** -- nothing notable, reset buffer
- **WATCH** -- worth tracking, keep monitoring
- **ALERT** -- notify human via Discord
- **KILL** -- run `openclaw security audit --fix`, pause monitoring

Three consecutive WATCH verdicts without a CLEAR automatically escalate to ALERT.

## Architecture

See [SPEC.md](SPEC.md) for the full technical specification.

## License

MIT
