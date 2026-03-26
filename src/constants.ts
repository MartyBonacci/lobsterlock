import type { LobsterLockConfig, Severity } from './types.js';

// File paths (~ resolved at runtime via resolveConfigPath)
export const LOBSTERLOCK_DIR = '~/.lobsterlock';
export const CONFIG_FILE = '~/.lobsterlock/config.json';
export const DB_FILE = '~/.lobsterlock/lobsterlock.db';
export const PID_FILE = '~/.lobsterlock/lobsterlock.pid';
export const KILL_SWITCH_FILE = '~/.lobsterlock/kill';

// Log anomaly patterns for journalctl matching
export const LOG_ANOMALY_PATTERNS: ReadonlyArray<{ pattern: RegExp; severity: Severity }> = [
  // Original v0.1 patterns
  { pattern: /FATAL ERROR/i, severity: 'critical' },
  { pattern: /JavaScript heap out of memory/i, severity: 'critical' },
  { pattern: /heap limit/i, severity: 'critical' },
  { pattern: /SIGKILL|SIGSEGV/i, severity: 'critical' },
  { pattern: /gateway closed with code/i, severity: 'high' },
  { pattern: /auth(?:entication)?\s+fail/i, severity: 'medium' },
  { pattern: /ECONNREFUSED/i, severity: 'low' },
  // v0.2: Network egress patterns (Cisco exfil, AMOS stealer)
  { pattern: /\bcurl\b.*https?:\/\//i, severity: 'high' },
  { pattern: /\bwget\b.*https?:\/\//i, severity: 'high' },
  { pattern: />\s*\/dev\/null/i, severity: 'critical' },
  { pattern: /\bbase64\b.*-d\b/i, severity: 'high' },
  { pattern: /169\.254\.169\.254/, severity: 'critical' },
  // v0.2: Gateway security patterns (ClawJacked, CVEs)
  { pattern: /auth\w*\s+(?:attempt|reject|denied)/i, severity: 'medium' },
  { pattern: /rapid auth|brute.?force|rate.?limit/i, severity: 'high' },
  { pattern: /device\s+pair/i, severity: 'high' },
  { pattern: /config\.apply/i, severity: 'high' },
  { pattern: /exec\.approvals.*(?:off|disabled|false)/i, severity: 'critical' },
  // v0.2: Cross-origin WebSocket detection (ClawJacked)
  { pattern: /\[ws\]\s+\w+\s+connected\b.*\bremote=(?!127\.0\.0\.1\b|::1\b|100\.)\S+/, severity: 'high' },
  { pattern: /\[ws\]\s+.*\bfwd=(?!n\/a\b)\S+/, severity: 'high' },
  // v0.2: Heartbeat response routing anomalies
  { pattern: /\[heartbeat\]\s+(?:deliver|send|route|dispatch)\w*\s+.*\bto\b\s+(?!none\b|owner\b)\S+/i, severity: 'high' },
  { pattern: /\[heartbeat\]\s+.*\btarget=(?!none\b|owner\b)\S+/i, severity: 'high' },
];

// Pattern for detecting OpenClaw restart in journalctl
export const RESTART_PATTERN = /Started openclaw|openclaw\.service: (?:Scheduled restart|Main process exited)/i;

// Process absence threshold (5 minutes)
export const PROCESS_ABSENCE_THRESHOLD_MS = 5 * 60 * 1000;

// Verdict regex for parsing Claude's response
export const VERDICT_REGEX = /^(CLEAR|WATCH\s+.+|ALERT\s+(?:LOW|MEDIUM|HIGH)\s+.+|KILL\s+.+)$/m;

// Shutdown grace period for in-flight reasoning
export const SHUTDOWN_GRACE_MS = 10_000;

// Max retries for log tail child process restart
export const LOG_TAIL_MAX_RETRIES = 3;
export const LOG_TAIL_RETRY_DELAY_MS = 5_000;

// Payload truncation limit in prompts (chars)
export const PAYLOAD_TRUNCATE_CHARS = 500;

// Severity ordering for comparisons
export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// Verdict level ordering for floor comparisons
export const VERDICT_LEVEL_ORDER: Record<string, number> = {
  CLEAR: 0,
  WATCH: 1,
  ALERT: 2,
  KILL: 3,
};

// Default config values
export const DEFAULT_CONFIG: LobsterLockConfig = {
  openclaw_log: 'journalctl',
  openclaw_service: 'openclaw',
  openclaw_cli: '/usr/bin/openclaw',
  skills_watch: [
    '/home/openclaw/.openclaw/workspace/skills',
  ],
  memory_watch: [
    '/home/openclaw/.openclaw/SOUL.md',
    '/home/openclaw/.openclaw/AGENTS.md',
    '/home/openclaw/.openclaw/MEMORY.md',
    '/home/openclaw/.openclaw/HEARTBEAT.md',
    '/home/openclaw/.openclaw/USER.md',
  ],
  alert_channel: 'discord',
  alert_min_severity: 'WATCH',
  kill_on_critical: true,
  kill_requires_confirmation: true,
  model: 'claude-sonnet-4-6',
  reasoning_budget: 500,
  threshold_window_seconds: 60,
  threshold_signal_count: 3,
  audit_poll_interval_seconds: 300,
  trigger_debounce_ms: 3000,
  signal_buffer_max_entries: 500,
  hourly_digest: false,
  openclaw_version_lock: '3.12',
};
