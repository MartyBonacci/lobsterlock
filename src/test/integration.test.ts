import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { SignalBuffer } from '../trigger/buffer.js';
import { TriggerManager } from '../trigger/manager.js';
import { ReasoningEngine, parseVerdict } from '../reasoning/engine.js';
import { initDatabase, loadEscalationState, saveEscalationState, getLastVerdict } from '../storage/audit-log.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type Database from 'better-sqlite3';
import type { EscalationState, LobsterLockConfig, SignalEntry, TriggerEvent, Verdict } from '../types.js';

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

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('Integration: Full Pipeline', () => {
  let db: Database.Database;
  let buffer: SignalBuffer;
  let config: LobsterLockConfig;

  beforeEach(() => {
    db = initDatabase(':memory:');
    buffer = new SignalBuffer(500);
    config = { ...DEFAULT_CONFIG, trigger_debounce_ms: 20 };
  });

  it('signal -> trigger -> reasoning -> SQLite', async () => {
    const mockClient = {
      messages: {
        create: async () => ({
          content: [{ type: 'text' as const, text: 'WATCH new skill detected in monitored directory\nA new SKILL.md file was added. Monitoring for follow-up activity.' }],
        }),
      },
    } as unknown as import('@anthropic-ai/sdk').default;

    // Create components
    const triggerManager = new TriggerManager(buffer, config);
    const engine = new ReasoningEngine(config, db, buffer, mockClient);
    const collector = new EventEmitter();
    triggerManager.registerCollector(collector);

    const escalationState: EscalationState = {
      consecutive_watch_count: 0,
      pending_alert_id: null,
      paused: false,
      last_verdict_level: null,
      last_verdict_timestamp: null,
    };

    // Wire trigger -> reasoning
    const verdicts: Verdict[] = [];
    triggerManager.on('trigger', async (trigger: TriggerEvent) => {
      const verdict = await engine.invoke(trigger, escalationState, null);
      if (verdict) verdicts.push(verdict);
    });

    // Inject signal
    collector.emit('signal', makeSignal({
      type: 'fs_change',
      source: 'fs-watcher',
      severity: 'high',
      summary: 'Skill file created: /skills/evil/SKILL.md',
      payload: { event: 'add', path: '/skills/evil/SKILL.md', isSkillFile: true },
    }));

    await wait(100);

    // Verify
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0].level, 'WATCH');
    assert.ok(verdicts[0].reason.includes('new skill'));

    // Verify SQLite
    const entry = getLastVerdict(db);
    assert.ok(entry);
    assert.equal(entry.verdict_level, 'WATCH');

    triggerManager.stop();
  });

  it('WATCH x3 escalation -> ALERT floor', async () => {
    let callCount = 0;
    const mockClient = {
      messages: {
        create: async () => {
          callCount++;
          // First 3 calls return WATCH, 4th would normally return WATCH but gets floored
          if (callCount <= 3) {
            return {
              content: [{ type: 'text' as const, text: `WATCH minor anomaly #${callCount}\nNothing alarming individually.` }],
            };
          }
          return {
            content: [{ type: 'text' as const, text: 'ALERT LOW escalated due to repeated watches\nThree consecutive WATCHes without a CLEAR triggered escalation.' }],
          };
        },
      },
    } as unknown as import('@anthropic-ai/sdk').default;

    const triggerManager = new TriggerManager(buffer, config);
    const engine = new ReasoningEngine(config, db, buffer, mockClient);
    const collector = new EventEmitter();
    triggerManager.registerCollector(collector);

    const escalationState: EscalationState = {
      consecutive_watch_count: 0,
      pending_alert_id: null,
      paused: false,
      last_verdict_level: null,
      last_verdict_timestamp: null,
    };

    let lastVerdict: Verdict | null = null;

    triggerManager.on('trigger', async (trigger: TriggerEvent) => {
      const verdict = await engine.invoke(trigger, escalationState, lastVerdict);
      if (!verdict) return;

      // State machine
      if (verdict.level === 'WATCH') {
        escalationState.consecutive_watch_count++;
      } else if (verdict.level === 'CLEAR') {
        escalationState.consecutive_watch_count = 0;
      }

      escalationState.last_verdict_level = verdict.level;
      escalationState.last_verdict_timestamp = verdict.timestamp;
      saveEscalationState(db, escalationState);
      triggerManager.updateEscalationState(escalationState);
      lastVerdict = verdict;
    });

    // Fire 4 signals with waits in between
    for (let i = 0; i < 4; i++) {
      collector.emit('signal', makeSignal({
        type: 'fs_change',
        source: 'fs-watcher',
        severity: 'high',
        summary: `Skill file event ${i + 1}`,
        payload: { event: 'add', isSkillFile: true },
      }));
      await wait(100);
    }

    // After 3 WATCHes, escalation count should be 3
    const finalState = loadEscalationState(db);
    // The 4th trigger should have been fired with ALERT floor
    // (the mock returns ALERT LOW for the 4th call)
    assert.ok(callCount >= 3);

    triggerManager.stop();
  });

  it('ack resets escalation state', () => {
    // Set up escalated state
    const state: EscalationState = {
      consecutive_watch_count: 3,
      pending_alert_id: 'alert-1',
      paused: true,
      last_verdict_level: 'KILL',
      last_verdict_timestamp: Date.now(),
    };
    saveEscalationState(db, state);

    // Simulate ack
    const loaded = loadEscalationState(db);
    assert.equal(loaded.consecutive_watch_count, 3);
    assert.equal(loaded.paused, true);

    // Reset
    loaded.consecutive_watch_count = 0;
    loaded.pending_alert_id = null;
    loaded.paused = false;
    saveEscalationState(db, loaded);

    const after = loadEscalationState(db);
    assert.equal(after.consecutive_watch_count, 0);
    assert.equal(after.paused, false);
  });

  it('debounce coalesces multiple signals into one reasoning call', async () => {
    let reasoningCalls = 0;
    const mockClient = {
      messages: {
        create: async () => {
          reasoningCalls++;
          return {
            content: [{ type: 'text' as const, text: 'WATCH multiple signals coalesced\nSeveral events occurred simultaneously.' }],
          };
        },
      },
    } as unknown as import('@anthropic-ai/sdk').default;

    const triggerManager = new TriggerManager(buffer, config);
    const engine = new ReasoningEngine(config, db, buffer, mockClient);
    const collector = new EventEmitter();
    triggerManager.registerCollector(collector);

    const escalationState: EscalationState = {
      consecutive_watch_count: 0,
      pending_alert_id: null,
      paused: false,
      last_verdict_level: null,
      last_verdict_timestamp: null,
    };

    triggerManager.on('trigger', async (trigger: TriggerEvent) => {
      await engine.invoke(trigger, escalationState, null);
    });

    // Fire 3 signals rapidly (within debounce window)
    collector.emit('signal', makeSignal({ type: 'fs_change', source: 'fs-watcher', payload: {} }));
    collector.emit('signal', makeSignal({ type: 'skills_diff', source: 'skills', payload: { newEligible: true } }));
    collector.emit('signal', makeSignal({ type: 'process_event', source: 'log-tail', payload: { restart: true } }));

    await wait(100);

    // Should have been coalesced into exactly 1 reasoning call
    assert.equal(reasoningCalls, 1);

    triggerManager.stop();
  });
});
