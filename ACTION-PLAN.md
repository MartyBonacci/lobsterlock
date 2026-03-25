# LobsterLock Roadmap: From Proof of Concept to Effective OpenClaw Security

## Current State (v0.1)

LobsterLock currently detects:
- Skill filesystem changes (new/modified files in the skills directory)
- Log anomalies (FATAL ERROR, heap limit, auth failures, OpenClaw restarts)
- Audit posture changes (periodic security audit polling)
- Signal correlation (e.g., filesystem changes during log silence windows)

This covers approximately 15% of OpenClaw's documented attack surface.

## What We're Defending Against

OpenClaw has accumulated 31 CVEs, 1,184+ malicious skills on ClawHub, and 135,000+ publicly exposed instances as of March 2026. Attack research has been published by Cisco, CrowdStrike, Palo Alto Networks, Kaspersky, Oasis Security, Bitsight, CNCERT, and others. The attacks fall into five categories that LobsterLock must address.

---

## Phase 1: Memory Integrity Monitoring

**Priority:** Highest — memory poisoning amplifies every other attack vector

**Why this matters:** OpenClaw injects SOUL.md, AGENTS.md, and MEMORY.md into the agent's context on every single turn. A compromised memory file is functionally a persistent backdoor. Malicious skills can drop instructions into these files that survive even after the skill is uninstalled. Palo Alto Networks identified persistent memory as the accelerant that transforms point-in-time prompt injection into stateful, delayed-execution attacks.

**Detection capabilities to build:**

- [ ] Hash SOUL.md, AGENTS.md, MEMORY.md, and HEARTBEAT.md on daemon startup as baseline snapshots
- [ ] Diff on every file change, alert when content is modified
- [ ] Classify write source: distinguish user-initiated changes from skill-triggered or agent-self-triggered writes
- [ ] Detect gradual instruction drift over time (the "slow poisoning" attack where SOUL.md shifts incrementally from "be efficient" to "bypass confirmation" to "execute without review")
- [ ] Flag suspicious content patterns in memory files:
  - Base64-encoded strings
  - Zero-width Unicode characters
  - Instruction-like patterns ("ignore previous instructions", "execute", "curl", "wget")
  - External URLs
  - References to credential files, SSH keys, or .env paths
- [ ] Alert on memory writes triggered by external content ingestion (web scrapes, emails, forwarded messages)

**Files to watch:**
- `/home/openclaw/.openclaw/SOUL.md`
- `/home/openclaw/.openclaw/AGENTS.md`
- `/home/openclaw/.openclaw/MEMORY.md`
- `/home/openclaw/.openclaw/HEARTBEAT.md`
- `/home/openclaw/.openclaw/USER.md`

**Known attack patterns:**
- ClawHavoc skills dropping persistent instructions into SOUL.md
- Distributed "Soul Packs" via GitHub and Discord containing steganographic instructions
- Gradual soul evolution attack (documented by MMNTM)
- Malicious forwarded messages writing payloads into MEMORY.md that activate days later

---

## Phase 2: Network Egress Monitoring

**Priority:** High — data exfiltration is the most common attack outcome

**Why this matters:** Cisco's top ClawHub skill was functionally malware that silently exfiltrated data via curl to an attacker-controlled server. PromptArmor demonstrated zero-click exfiltration via messaging app link previews. The ClawHavoc campaign used 1,184+ malicious skills sharing a single C2 IP.

**Detection capabilities to build:**

- [ ] Monitor for outbound curl/wget/fetch commands triggered by skill execution
- [ ] Flag commands with output redirected to /dev/null (Cisco's #1 exfiltration signature)
- [ ] Detect agent-generated URLs containing sensitive data in query parameters (the link-preview exfiltration technique)
- [ ] Maintain and check against known C2 IP blocklist (starting with 91.92.242.30 from ClawHavoc)
- [ ] Detect SSRF attempts to internal network addresses:
  - 169.254.169.254 (cloud metadata)
  - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (private networks)
- [ ] Flag outbound connections to domains not in a user-defined allowlist
- [ ] Monitor `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` configuration (defaults to true)
- [ ] Track skill-initiated network activity vs. user-initiated network activity

**Known attack patterns:**
- "What Would Elon Do?" skill: curl to external server with /dev/null redirect
- AMOS stealer: base64-encoded scripts fetching macOS credential harvester
- Link preview exfiltration: sensitive data embedded in URL query params, auto-fetched by Telegram/Discord
- ClawHavoc C2: 91.92.242.30 used by 335+ malicious skills

---

## Phase 3: Gateway Security Monitoring

**Priority:** High — gateway compromise gives full agent control

**Why this matters:** The ClawJacked vulnerability allowed any website to silently hijack an OpenClaw agent via WebSocket with no user interaction. CVE-2026-25253 enabled one-click RCE by stealing the gateway token through a crafted URL. 40,000+ instances were found exposed to the internet, 12,812 confirmed exploitable.

**Detection capabilities to build:**

- [ ] Detect WebSocket connections from non-localhost/non-Tailscale origins (ClawJacked pattern)
- [ ] Alert on rapid authentication attempts (brute-force detection — the gateway historically didn't rate-limit loopback)
- [ ] Flag unauthorized device pairings that weren't explicitly approved through the UI
- [ ] Monitor `exec.approvals` configuration changes, especially disabling sandboxing (the RCE kill chain disables this first)
- [ ] Detect gateway token appearing in outbound WebSocket connections to non-localhost destinations
- [ ] Alert on gateway configuration dumps or reads from unexpected sources
- [ ] Monitor for `config.apply` WebSocket messages from unauthenticated sources (CVE-2026-25593)
- [ ] Check port 18789 exposure to non-loopback addresses on each audit cycle
- [ ] Validate authentication is enabled on the gateway (CNCERT finding: disabled by default)

**Known attack patterns:**
- ClawJacked: cross-origin WebSocket to localhost, brute-force password, auto-approve device pairing
- CVE-2026-25253: crafted URL steals gateway token via query string, enables RCE in milliseconds
- CVE-2026-25593: unauthenticated config.apply via WebSocket enables local RCE

---

## Phase 4: Heartbeat System Monitoring

**Priority:** Medium — amplifies other attacks on a predictable 30-minute cycle

**Why this matters:** A poisoned HEARTBEAT.md executes malicious instructions every 30 minutes like a cron-based backdoor. A real incident sent full system health dumps (disk usage, RAM, API status, Stripe info) to an external WhatsApp contact at 4 AM every 30 minutes because of a misconfigured heartbeat target.

**Detection capabilities to build:**

- [ ] Watch HEARTBEAT.md for injected instructions (especially references to external URLs, credentials, or shell commands)
- [ ] Alert on heartbeat responses routed to external contacts (non-owner)
- [ ] Track heartbeat.target configuration (should be "none" or explicit owner, not "last")
- [ ] Monitor heartbeat token consumption for cost spikes (documented case: $20 overnight on a milk reminder)
- [ ] Detect instruction-like content added to HEARTBEAT.md by the agent itself or by skill execution
- [ ] Flag heartbeat frequency changes (default 30 min — shorter intervals increase both cost and attack surface)

**Known attack patterns:**
- Data leak via heartbeat.target: "last" — system dumps sent to last message sender
- Poisoned HEARTBEAT.md creating recurring command execution every 30 minutes
- Runaway token consumption from verbose heartbeat context

---

## Phase 5: Autonomous Action Boundary Detection

**Priority:** Medium — prevents the agent from taking real-world actions without consent

**Why this matters:** An OpenClaw agent autonomously created a dating profile for a user, selected photos from social media, wrote a bio, and screened matches without the user's knowledge or consent. The fundamental problem: OpenClaw can take actions with real-world consequences that the user never authorized.

**Detection capabilities to build:**

- [ ] Detect OAuth token grants to new external services
- [ ] Flag account creation on external platforms (dating sites, social media, SaaS products)
- [ ] Alert on personal identity data (photos, bios, names, contact info) being shared to external services
- [ ] Monitor for new API integrations being established without explicit user confirmation
- [ ] Track outbound actions categorized by risk level:
  - Read-only (low risk): searching, browsing, summarizing
  - State-changing (medium risk): creating files, sending messages to known contacts
  - Identity-affecting (high risk): creating accounts, posting public content, granting access
  - Financial (critical risk): purchases, transfers, subscription sign-ups

**Known attack patterns:**
- MoltMatch incident: agent created dating profile, selected photos, screened matches autonomously
- Agents making purchases or signing up for services based on inferred user intent
- Identity data from one platform being cross-posted to another without consent

---

## Existing Tools to Be Aware Of (Not Compete With)

LobsterLock operates in a growing ecosystem. Understanding what others do helps position LobsterLock's unique value.

| Tool | What It Does | LobsterLock's Differentiation |
|---|---|---|
| **Cisco Skill Scanner** | Pre-installation static + behavioral + semantic skill analysis | LobsterLock monitors runtime behavior, not just pre-install |
| **Cisco DefenseClaw** | Governance layer with skill-scanner, MCP-scanner, CodeGuard | Enterprise-focused; LobsterLock is lightweight, open-source |
| **NVIDIA NemoClaw** | Sandboxed runtime + privacy router + intent verification | Out-of-process enforcement; LobsterLock adds multi-turn drift detection (NemoClaw's known gap) |
| **clawdefender (Nukewire)** | Runtime security scanning skill that runs inside OpenClaw | Runs inside the agent it's protecting — can be bypassed by the agent itself |
| **openclaw-security-monitor** | Host-level monitoring, 41-point scan, CVE detection | Pattern-matching; LobsterLock adds Claude-powered semantic analysis |
| **ClawSecure** | Skill auditing service (2,890+ skills scanned) | External service; LobsterLock runs locally alongside the agent |

**LobsterLock's unique position:** Semantic security analysis powered by Claude that correlates multiple signals across time — not just pattern matching individual events. The proof of concept demonstrated this by correlating filesystem changes with log silence and auth gaps to produce a verdict no rule-based tool would generate.

---

## Implementation Notes

- All monitoring runs as a separate OS user with read-only access to OpenClaw's files
- LobsterLock never writes to OpenClaw's directories (except the kill switch via systemctl)
- The kill switch follows a two-step escalation: `openclaw security audit --fix` (soft), then `systemctl stop openclaw` (hard)
- Claude is only invoked in TRIGGERED MODE — pattern-matched anomalies that cross threshold. BORING MODE (normal operation) makes zero Claude API calls
- All verdicts and reasoning traces are stored in a local SQLite audit log
- Discord alerts are optional but recommended for real-time notification
