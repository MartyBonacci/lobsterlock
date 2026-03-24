import Database from 'better-sqlite3';
import type {
  AuditLogEntry,
  EscalationState,
  SignalEntry,
} from '../types.js';

const DEFAULT_ESCALATION: EscalationState = {
  consecutive_watch_count: 0,
  pending_alert_id: null,
  paused: false,
  last_verdict_level: null,
  last_verdict_timestamp: null,
};

/**
 * Initialize the SQLite database with required tables.
 */
export function initDatabase(dbPath: string): Database.Database {
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      timestamp INTEGER NOT NULL,
      trigger_event TEXT NOT NULL,
      signal_buffer_snapshot TEXT NOT NULL,
      prompt_sent TEXT NOT NULL,
      raw_response TEXT NOT NULL,
      verdict_level TEXT NOT NULL,
      verdict_severity TEXT,
      verdict_reason TEXT NOT NULL,
      escalation_state TEXT NOT NULL,
      acknowledged INTEGER NOT NULL DEFAULT 0,
      acknowledged_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS escalation_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      consecutive_watch_count INTEGER NOT NULL DEFAULT 0,
      pending_alert_id TEXT,
      paused INTEGER NOT NULL DEFAULT 0,
      last_verdict_level TEXT,
      last_verdict_timestamp INTEGER
    );

    CREATE TABLE IF NOT EXISTS signal_buffer_snapshot (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      signals TEXT NOT NULL,
      saved_at INTEGER NOT NULL
    );
  `);

  return db;
}

/**
 * Insert a reasoning cycle audit entry.
 */
export function insertAuditEntry(
  db: Database.Database,
  entry: AuditLogEntry,
): void {
  const stmt = db.prepare(`
    INSERT INTO audit_log (
      id, timestamp, trigger_event, signal_buffer_snapshot,
      prompt_sent, raw_response, verdict_level, verdict_severity,
      verdict_reason, escalation_state, acknowledged, acknowledged_at
    ) VALUES (
      @id, @timestamp, @trigger_event, @signal_buffer_snapshot,
      @prompt_sent, @raw_response, @verdict_level, @verdict_severity,
      @verdict_reason, @escalation_state, @acknowledged, @acknowledged_at
    )
  `);

  stmt.run({
    ...entry,
    acknowledged: entry.acknowledged ? 1 : 0,
  });
}

/**
 * Get the most recent audit log entry.
 */
export function getLastVerdict(
  db: Database.Database,
): AuditLogEntry | null {
  const row = db.prepare(
    'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 1',
  ).get() as Record<string, unknown> | undefined;

  if (!row) return null;
  return {
    ...row,
    acknowledged: Boolean(row.acknowledged),
  } as AuditLogEntry;
}

/**
 * Get all unacknowledged alerts.
 */
export function getUnacknowledgedAlerts(
  db: Database.Database,
): AuditLogEntry[] {
  const rows = db.prepare(
    `SELECT * FROM audit_log
     WHERE acknowledged = 0
       AND verdict_level IN ('ALERT', 'KILL')
     ORDER BY timestamp DESC`,
  ).all() as Record<string, unknown>[];

  return rows.map((row) => ({
    ...row,
    acknowledged: Boolean(row.acknowledged),
  })) as AuditLogEntry[];
}

/**
 * Acknowledge a specific alert by ID.
 */
export function acknowledgeAlert(
  db: Database.Database,
  id: string,
): void {
  db.prepare(
    'UPDATE audit_log SET acknowledged = 1, acknowledged_at = ? WHERE id = ?',
  ).run(Date.now(), id);
}

/**
 * Acknowledge all pending alerts. Returns count of acknowledged entries.
 */
export function acknowledgeAll(db: Database.Database): number {
  const now = Date.now();
  const result = db.prepare(
    'UPDATE audit_log SET acknowledged = 1, acknowledged_at = ? WHERE acknowledged = 0 AND verdict_level IN (\'ALERT\', \'KILL\')',
  ).run(now);
  return result.changes;
}

/**
 * Save escalation state (upsert single row).
 */
export function saveEscalationState(
  db: Database.Database,
  state: EscalationState,
): void {
  db.prepare(`
    INSERT INTO escalation_state (id, consecutive_watch_count, pending_alert_id, paused, last_verdict_level, last_verdict_timestamp)
    VALUES (1, @consecutive_watch_count, @pending_alert_id, @paused, @last_verdict_level, @last_verdict_timestamp)
    ON CONFLICT(id) DO UPDATE SET
      consecutive_watch_count = @consecutive_watch_count,
      pending_alert_id = @pending_alert_id,
      paused = @paused,
      last_verdict_level = @last_verdict_level,
      last_verdict_timestamp = @last_verdict_timestamp
  `).run({
    ...state,
    paused: state.paused ? 1 : 0,
  });
}

/**
 * Load escalation state. Returns default if no row exists.
 */
export function loadEscalationState(
  db: Database.Database,
): EscalationState {
  const row = db.prepare(
    'SELECT * FROM escalation_state WHERE id = 1',
  ).get() as Record<string, unknown> | undefined;

  if (!row) return { ...DEFAULT_ESCALATION };

  return {
    consecutive_watch_count: row.consecutive_watch_count as number,
    pending_alert_id: row.pending_alert_id as string | null,
    paused: Boolean(row.paused),
    last_verdict_level: row.last_verdict_level as EscalationState['last_verdict_level'],
    last_verdict_timestamp: row.last_verdict_timestamp as number | null,
  };
}

/**
 * Save signal buffer snapshot for crash recovery.
 */
export function saveBufferSnapshot(
  db: Database.Database,
  signals: SignalEntry[],
): void {
  db.prepare(`
    INSERT INTO signal_buffer_snapshot (id, signals, saved_at)
    VALUES (1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET signals = ?, saved_at = ?
  `).run(
    JSON.stringify(signals),
    Date.now(),
    JSON.stringify(signals),
    Date.now(),
  );
}

/**
 * Load signal buffer snapshot. Returns empty array if none exists.
 */
export function loadBufferSnapshot(
  db: Database.Database,
): SignalEntry[] {
  const row = db.prepare(
    'SELECT signals FROM signal_buffer_snapshot WHERE id = 1',
  ).get() as { signals: string } | undefined;

  if (!row) return [];

  try {
    return JSON.parse(row.signals) as SignalEntry[];
  } catch {
    return [];
  }
}
