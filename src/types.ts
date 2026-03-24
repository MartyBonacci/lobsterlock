// SignalEntry — the universal currency between collectors and triggers
export type SignalType =
  | 'log_anomaly'
  | 'fs_change'
  | 'audit_finding'
  | 'skills_diff'
  | 'process_event'
  | 'config_change';

export type SignalSource = 'log-tail' | 'fs-watcher' | 'audit' | 'skills';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface SignalEntry {
  id: string;
  type: SignalType;
  source: SignalSource;
  timestamp: number;
  severity: Severity;
  summary: string;
  payload: Record<string, unknown>;
}

// Verdict from reasoning engine
export type VerdictLevel = 'CLEAR' | 'WATCH' | 'ALERT' | 'KILL';
export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH';

export interface Verdict {
  level: VerdictLevel;
  severity: AlertSeverity | null;
  reason: string;
  reasoning: string;
  raw: string;
  timestamp: number;
}

// Trigger event that fires a reasoning invocation
export type TriggerType = 'hard' | 'threshold' | 'scheduled' | 'manual';

export interface TriggerEvent {
  id: string;
  type: TriggerType;
  rule: string;
  source: string;
  severityFloor: VerdictLevel;
  signals: SignalEntry[];
  timestamp: number;
}

// Config shape — fully typed with defaults
export interface LobsterLockConfig {
  openclaw_log: 'journalctl';
  openclaw_service: string;
  openclaw_cli: string;
  skills_watch: string[];
  alert_channel: 'discord';
  alert_min_severity: VerdictLevel;
  kill_on_critical: boolean;
  kill_requires_confirmation: boolean;
  model: string;
  reasoning_budget: number;
  threshold_window_seconds: number;
  threshold_signal_count: number;
  audit_poll_interval_seconds: number;
  trigger_debounce_ms: number;
  signal_buffer_max_entries: number;
  hourly_digest: boolean;
  openclaw_version_lock: string;
  discord_channel_id?: string;
}

// Escalation state persisted in SQLite
export interface EscalationState {
  consecutive_watch_count: number;
  pending_alert_id: string | null;
  paused: boolean;
  last_verdict_level: VerdictLevel | null;
  last_verdict_timestamp: number | null;
}

// Audit log row in SQLite
export interface AuditLogEntry {
  id: string;
  timestamp: number;
  trigger_event: string;
  signal_buffer_snapshot: string;
  prompt_sent: string;
  raw_response: string;
  verdict_level: VerdictLevel;
  verdict_severity: AlertSeverity | null;
  verdict_reason: string;
  escalation_state: string;
  acknowledged: boolean;
  acknowledged_at: number | null;
}

// Reasoning context passed to prompt builder
export interface ReasoningContext {
  triggerEvent: TriggerEvent;
  signalBuffer: SignalEntry[];
  evictedCount: number;
  securityPosture: Record<string, unknown> | null;
  skillInventoryDelta: Record<string, unknown> | null;
  escalationState: EscalationState;
  previousVerdict: Verdict | null;
}

// Status report from orchestrator
export interface StatusReport {
  uptime: number;
  lastTrigger: { type: string; rule: string; timestamp: number } | null;
  lastVerdict: Verdict | null;
  escalation: EscalationState;
  bufferSize: number;
  collectors: Record<string, 'running' | 'stopped' | 'errored'>;
  paused: boolean;
}
