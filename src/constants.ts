import type { LobsterLockConfig, Severity } from './types.js';

// File paths (~ resolved at runtime via resolveConfigPath)
export const LOBSTERLOCK_DIR = '~/.lobsterlock';
export const CONFIG_FILE = '~/.lobsterlock/config.json';
export const DB_FILE = '~/.lobsterlock/lobsterlock.db';
export const PID_FILE = '~/.lobsterlock/lobsterlock.pid';
export const KILL_SWITCH_FILE = '~/.lobsterlock/kill';

// Log anomaly patterns for journalctl matching
export const LOG_ANOMALY_PATTERNS: ReadonlyArray<{ pattern: RegExp; severity: Severity }> = [
  { pattern: /FATAL ERROR/i, severity: 'critical' },
  { pattern: /JavaScript heap out of memory/i, severity: 'critical' },
  { pattern: /heap limit/i, severity: 'critical' },
  { pattern: /SIGKILL|SIGSEGV/i, severity: 'critical' },
  { pattern: /gateway closed with code/i, severity: 'high' },
  { pattern: /auth(?:entication)?\s+fail/i, severity: 'medium' },
  { pattern: /ECONNREFUSED/i, severity: 'low' },
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
