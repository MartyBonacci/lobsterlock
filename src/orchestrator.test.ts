import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { SignalBuffer } from './trigger/buffer.js';
import { TriggerManager } from './trigger/manager.js';
import { ReasoningEngine } from './reasoning/engine.js';
import {
  initDatabase,
  loadEscalationState,
  saveEscalationState,
  saveBufferSnapshot,
  loadBufferSnapshot,
  acknowledgeAll,
  insertAuditEntry,
} from './storage/audit-log.js';
import { DEFAULT_CONFIG } from './constants.js';
import type Database from 'better-sqlite3';
import type { EscalationState, SignalEntry, TriggerEvent, Verdict, LobsterLockConfig } from './types.js';

function makeSignal(overrides: Partial<SignalEntry> = {}): SignalEntry {
  return {
    id: 'sig-' + Math.random().toString(36).slice(2),
    type: 'log_anomaly',
    source: 'log-tail',
    timestamp: Date.now(),
    severity: 'low',
    summary: 'test signal',
    payload: {},
    ...overrides,
  };
}

function makeTrigger(overrides: Partial<TriggerEvent> = {}): TriggerEvent {
  return {
    id: 'trig-1',
    type: 'hard',
    rule: 'new_skill_file',
    source: 'fs-watcher',
    severityFloor: 'WATCH',
    signals: [],
    timestamp: Date.now(),
    ...overrides,
  };
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('Orchestrator state machine', () => {
  let db: Database.Database;
  let buffer: SignalBuffer;
  let config: LobsterLockConfig;

  beforeEach(() => {
    db = initDatabase(':memory:');
    buffer = new SignalBuffer(500);
    config = { ...DEFAULT_CONFIG, trigger_debounce_ms: 20 };
  });

  describe('verdict processing', () => {
    it('CLEAR resets watch count and buffer', async () => {
      const mockClient = {
        messages: { create: async () => ({ content: [{ type: 'text' as const, text: 'CLEAR' }] }) },
      } as unknown as import('@anthropic-ai/sdk').default;

      const engine = new ReasoningEngine(config, db, buffer, mockClient);
      const escalation: EscalationState = {
        consecutive_watch_count: 2,
        pending_alert_id: null,
        paused: false,
        last_verdict_level: 'WATCH',
        last_verdict_timestamp: Date.now(),
      };

      // Add some signals to buffer
      buffer.push(makeSignal());
      buffer.push(makeSignal());
      assert.equal(buffer.size(), 2);

      const verdict = await engine.invoke(makeTrigger(), escalation, null);
      assert.ok(verdict);
      assert.equal(verdict.level, 'CLEAR');

      // Simulate state machine
      if (verdict.level === 'CLEAR') {
        escalation.consecutive_watch_count = 0;
        buffer.reset();
      }

      assert.equal(escalation.consecutive_watch_count, 0);
      assert.equal(buffer.size(), 0);
    });

    it('WATCH increments count and preserves buffer', async () => {
      const mockClient = {
        messages: { create: async () => ({ content: [{ type: 'text' as const, text: 'WATCH something minor' }] }) },
      } as unknown as import('@anthropic-ai/sdk').default;

      const engine = new ReasoningEngine(config, db, buffer, mockClient);
      const escalation: EscalationState = {
        consecutive_watch_count: 1,
        pending_alert_id: null,
        paused: false,
        last_verdict_level: 'WATCH',
        last_verdict_timestamp: Date.now(),
      };

      buffer.push(makeSignal());

      const verdict = await engine.invoke(makeTrigger(), escalation, null);
      assert.ok(verdict);
      assert.equal(verdict.level, 'WATCH');

      if (verdict.level === 'WATCH') {
        escalation.consecutive_watch_count++;
      }

      assert.equal(escalation.consecutive_watch_count, 2);
      assert.equal(buffer.size(), 1); // preserved
    });

    it('ALERT sets pending_alert_id', async () => {
      const mockClient = {
        messages: { create: async () => ({ content: [{ type: 'text' as const, text: 'ALERT LOW suspicious' }] }) },
      } as unknown as import('@anthropic-ai/sdk').default;

      const engine = new ReasoningEngine(config, db, buffer, mockClient);
      const trigger = makeTrigger({ id: 'trig-alert' });
      const escalation: EscalationState = {
        consecutive_watch_count: 0,
        pending_alert_id: null,
        paused: false,
        last_verdict_level: null,
        last_verdict_timestamp: null,
      };

      const verdict = await engine.invoke(trigger, escalation, null);
      assert.ok(verdict);
      assert.equal(verdict.level, 'ALERT');

      if (verdict.level === 'ALERT') {
        escalation.pending_alert_id = trigger.id;
      }

      assert.equal(escalation.pending_alert_id, 'trig-alert');
    });

    it('KILL flushes buffer and pauses', async () => {
      const mockClient = {
        messages: { create: async () => ({ content: [{ type: 'text' as const, text: 'KILL critical breach' }] }) },
      } as unknown as import('@anthropic-ai/sdk').default;

      const engine = new ReasoningEngine(config, db, buffer, mockClient);
      const escalation: EscalationState = {
        consecutive_watch_count: 0,
        pending_alert_id: null,
        paused: false,
        last_verdict_level: null,
        last_verdict_timestamp: null,
      };

      buffer.push(makeSignal({ id: 'keep-me' }));
      buffer.push(makeSignal({ id: 'keep-me-too' }));

      const verdict = await engine.invoke(makeTrigger(), escalation, null);
      assert.ok(verdict);
      assert.equal(verdict.level, 'KILL');

      if (verdict.level === 'KILL') {
        const flushed = buffer.flush();
        saveBufferSnapshot(db, flushed);
        escalation.paused = true;
      }

      assert.equal(buffer.size(), 0);
      assert.equal(escalation.paused, true);

      // Verify buffer was saved to SQLite
      const saved = loadBufferSnapshot(db);
      assert.equal(saved.length, 2);
      assert.equal(saved[0].id, 'keep-me');
    });
  });

  describe('acknowledge flow', () => {
    it('resets escalation and resumes after ack', () => {
      // Set up escalated + paused state
      const escalation: EscalationState = {
        consecutive_watch_count: 4,
        pending_alert_id: 'alert-1',
        paused: true,
        last_verdict_level: 'KILL',
        last_verdict_timestamp: Date.now(),
      };
      saveEscalationState(db, escalation);

      // Insert an unacknowledged alert
      insertAuditEntry(db, {
        id: 'entry-1',
        timestamp: Date.now(),
        trigger_event: '{}',
        signal_buffer_snapshot: '[]',
        prompt_sent: 'test',
        raw_response: 'KILL breach',
        verdict_level: 'KILL',
        verdict_severity: null,
        verdict_reason: 'breach',
        escalation_state: JSON.stringify(escalation),
        acknowledged: false,
        acknowledged_at: null,
      });

      // Simulate ack
      const count = acknowledgeAll(db);
      assert.equal(count, 1);

      // Reset escalation
      escalation.consecutive_watch_count = 0;
      escalation.pending_alert_id = null;
      escalation.paused = false;
      saveEscalationState(db, escalation);

      const loaded = loadEscalationState(db);
      assert.equal(loaded.consecutive_watch_count, 0);
      assert.equal(loaded.paused, false);
      assert.equal(loaded.pending_alert_id, null);
    });
  });
});
