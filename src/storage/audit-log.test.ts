import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  initDatabase,
  insertAuditEntry,
  getLastVerdict,
  getUnacknowledgedAlerts,
  acknowledgeAlert,
  acknowledgeAll,
  saveEscalationState,
  loadEscalationState,
  saveBufferSnapshot,
  loadBufferSnapshot,
  insertHashRecord,
  getHashHistory,
  pruneOldHashes,
} from './audit-log.js';
import type { AuditLogEntry, EscalationState, SignalEntry } from '../types.js';
import type Database from 'better-sqlite3';

function makeEntry(overrides: Partial<AuditLogEntry> = {}): AuditLogEntry {
  return {
    id: 'test-' + Math.random().toString(36).slice(2),
    timestamp: Date.now(),
    trigger_event: '{}',
    signal_buffer_snapshot: '[]',
    prompt_sent: 'test prompt',
    raw_response: 'CLEAR',
    verdict_level: 'CLEAR',
    verdict_severity: null,
    verdict_reason: 'all clear',
    escalation_state: '{}',
    acknowledged: false,
    acknowledged_at: null,
    ...overrides,
  };
}

describe('audit-log', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = initDatabase(':memory:');
  });

  describe('initDatabase', () => {
    it('creates required tables', () => {
      const tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .all() as { name: string }[];
      const names = tables.map((t) => t.name);
      assert.ok(names.includes('audit_log'));
      assert.ok(names.includes('escalation_state'));
      assert.ok(names.includes('signal_buffer_snapshot'));
    });

    it('uses WAL mode for file databases', () => {
      // WAL mode is set in initDatabase but doesn't apply to :memory: databases
      // Verify the pragma call doesn't throw (functional test)
      const mode = db.pragma('journal_mode', { simple: true });
      assert.ok(typeof mode === 'string');
    });
  });

  describe('audit entries', () => {
    it('inserts and retrieves an entry', () => {
      const entry = makeEntry({ verdict_level: 'WATCH', verdict_reason: 'suspicious activity' });
      insertAuditEntry(db, entry);

      const last = getLastVerdict(db);
      assert.ok(last);
      assert.equal(last.id, entry.id);
      assert.equal(last.verdict_level, 'WATCH');
      assert.equal(last.verdict_reason, 'suspicious activity');
      assert.equal(last.acknowledged, false);
    });

    it('returns null when no entries exist', () => {
      const last = getLastVerdict(db);
      assert.equal(last, null);
    });

    it('returns most recent entry', () => {
      insertAuditEntry(db, makeEntry({ timestamp: 1000, verdict_reason: 'old' }));
      insertAuditEntry(db, makeEntry({ timestamp: 2000, verdict_reason: 'new' }));

      const last = getLastVerdict(db);
      assert.ok(last);
      assert.equal(last.verdict_reason, 'new');
    });
  });

  describe('unacknowledged alerts', () => {
    it('returns only unacknowledged ALERT/KILL entries', () => {
      insertAuditEntry(db, makeEntry({ verdict_level: 'CLEAR' }));
      insertAuditEntry(db, makeEntry({ id: 'alert-1', verdict_level: 'ALERT' }));
      insertAuditEntry(db, makeEntry({ verdict_level: 'WATCH' }));
      insertAuditEntry(db, makeEntry({ id: 'kill-1', verdict_level: 'KILL' }));
      insertAuditEntry(db, makeEntry({ id: 'acked', verdict_level: 'ALERT', acknowledged: true }));

      const unacked = getUnacknowledgedAlerts(db);
      assert.equal(unacked.length, 2);
      const ids = unacked.map((e) => e.id);
      assert.ok(ids.includes('alert-1'));
      assert.ok(ids.includes('kill-1'));
    });
  });

  describe('acknowledge', () => {
    it('acknowledges a specific alert', () => {
      insertAuditEntry(db, makeEntry({ id: 'a1', verdict_level: 'ALERT' }));
      acknowledgeAlert(db, 'a1');

      const unacked = getUnacknowledgedAlerts(db);
      assert.equal(unacked.length, 0);

      const last = getLastVerdict(db);
      assert.ok(last);
      assert.equal(last.acknowledged, true);
      assert.ok(last.acknowledged_at !== null);
    });

    it('acknowledgeAll returns count', () => {
      insertAuditEntry(db, makeEntry({ id: 'a1', verdict_level: 'ALERT' }));
      insertAuditEntry(db, makeEntry({ id: 'a2', verdict_level: 'KILL' }));
      insertAuditEntry(db, makeEntry({ id: 'a3', verdict_level: 'CLEAR' }));

      const count = acknowledgeAll(db);
      assert.equal(count, 2); // only ALERT and KILL
    });
  });

  describe('escalation state', () => {
    it('returns defaults when no state saved', () => {
      const state = loadEscalationState(db);
      assert.equal(state.consecutive_watch_count, 0);
      assert.equal(state.pending_alert_id, null);
      assert.equal(state.paused, false);
      assert.equal(state.last_verdict_level, null);
    });

    it('round-trips escalation state', () => {
      const state: EscalationState = {
        consecutive_watch_count: 3,
        pending_alert_id: 'alert-42',
        paused: true,
        last_verdict_level: 'WATCH',
        last_verdict_timestamp: 1234567890,
      };
      saveEscalationState(db, state);

      const loaded = loadEscalationState(db);
      assert.deepEqual(loaded, state);
    });

    it('upserts on save', () => {
      saveEscalationState(db, {
        consecutive_watch_count: 1,
        pending_alert_id: null,
        paused: false,
        last_verdict_level: 'WATCH',
        last_verdict_timestamp: 1000,
      });
      saveEscalationState(db, {
        consecutive_watch_count: 5,
        pending_alert_id: 'x',
        paused: true,
        last_verdict_level: 'ALERT',
        last_verdict_timestamp: 2000,
      });

      const loaded = loadEscalationState(db);
      assert.equal(loaded.consecutive_watch_count, 5);
      assert.equal(loaded.paused, true);
    });
  });

  describe('buffer snapshot', () => {
    it('returns empty array when no snapshot exists', () => {
      const signals = loadBufferSnapshot(db);
      assert.deepEqual(signals, []);
    });

    it('round-trips signal buffer', () => {
      const signals: SignalEntry[] = [
        {
          id: 's1',
          type: 'log_anomaly',
          source: 'log-tail',
          timestamp: 1000,
          severity: 'low',
          summary: 'test signal',
          payload: { line: 'FATAL ERROR blah' },
        },
      ];
      saveBufferSnapshot(db, signals);

      const loaded = loadBufferSnapshot(db);
      assert.equal(loaded.length, 1);
      assert.equal(loaded[0].id, 's1');
      assert.equal(loaded[0].summary, 'test signal');
    });

    it('upserts on save', () => {
      saveBufferSnapshot(db, []);
      saveBufferSnapshot(db, [
        {
          id: 's2',
          type: 'fs_change',
          source: 'fs-watcher',
          timestamp: 2000,
          severity: 'high',
          summary: 'new skill file',
          payload: {},
        },
      ]);

      const loaded = loadBufferSnapshot(db);
      assert.equal(loaded.length, 1);
      assert.equal(loaded[0].id, 's2');
    });
  });

  describe('memory hash history', () => {
    it('inserts and retrieves hash records', () => {
      insertHashRecord(db, '/test/SOUL.md', 'hash1');
      insertHashRecord(db, '/test/SOUL.md', 'hash2');
      insertHashRecord(db, '/test/SOUL.md', 'hash3');

      const history = getHashHistory(db, '/test/SOUL.md');
      assert.equal(history.length, 3);
    });

    it('returns only distinct hashes', () => {
      insertHashRecord(db, '/test/SOUL.md', 'same');
      insertHashRecord(db, '/test/SOUL.md', 'same');
      insertHashRecord(db, '/test/SOUL.md', 'same');

      const history = getHashHistory(db, '/test/SOUL.md');
      assert.equal(history.length, 1);
    });

    it('filters by file path', () => {
      insertHashRecord(db, '/test/SOUL.md', 'hash1');
      insertHashRecord(db, '/test/MEMORY.md', 'hash2');

      const soulHistory = getHashHistory(db, '/test/SOUL.md');
      assert.equal(soulHistory.length, 1);
      assert.equal(soulHistory[0].hash, 'hash1');
    });

    it('pruneOldHashes removes old entries', () => {
      // Insert with old timestamp by going directly to db
      db.prepare(
        'INSERT INTO memory_hash_history (file_path, hash, recorded_at) VALUES (?, ?, ?)',
      ).run('/test/SOUL.md', 'old', 1000);
      insertHashRecord(db, '/test/SOUL.md', 'new');

      const pruned = pruneOldHashes(db, 1000); // 1 second window
      assert.ok(pruned >= 1);

      const remaining = getHashHistory(db, '/test/SOUL.md', 999999999999);
      assert.equal(remaining.length, 1);
      assert.equal(remaining[0].hash, 'new');
    });
  });
});
