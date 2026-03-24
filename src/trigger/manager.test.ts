import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { TriggerManager } from './manager.js';
import { SignalBuffer } from './buffer.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type { SignalEntry, TriggerEvent, LobsterLockConfig } from '../types.js';

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

describe('TriggerManager', () => {
  let buffer: SignalBuffer;
  let config: LobsterLockConfig;
  let manager: TriggerManager;

  beforeEach(() => {
    buffer = new SignalBuffer(500);
    // Very short debounce for fast tests
    config = { ...DEFAULT_CONFIG, trigger_debounce_ms: 20 };
    manager = new TriggerManager(buffer, config);
  });

  afterEach(() => {
    manager.stop();
  });

  describe('registerCollector', () => {
    it('buffers signals from registered collectors', () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      collector.emit('signal', makeSignal({ type: 'process_event', payload: { selfHealth: true } }));

      assert.equal(buffer.size(), 1);
    });
  });

  describe('hard triggers', () => {
    it('fires on new skill file', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({
        type: 'fs_change',
        source: 'fs-watcher',
        severity: 'high',
        summary: 'Skill file created',
        payload: { event: 'add', path: '/skills/evil/SKILL.md', isSkillFile: true },
      }));

      await wait(50);

      assert.equal(triggers.length, 1);
      assert.ok(triggers[0].rule.includes('new_skill_file'));
      assert.equal(triggers[0].severityFloor, 'WATCH');
    });

    it('fires on critical count increase', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({
        type: 'audit_finding',
        source: 'audit',
        severity: 'critical',
        summary: 'Critical finding count increased',
      }));

      await wait(50);

      assert.equal(triggers.length, 1);
      assert.ok(triggers[0].rule.includes('critical_count_increase'));
      assert.equal(triggers[0].severityFloor, 'ALERT');
    });

    it('fires on config change', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({
        type: 'config_change',
        source: 'fs-watcher',
        severity: 'high',
        summary: 'OpenClaw config modified',
        payload: { configChange: true },
      }));

      await wait(50);

      assert.equal(triggers.length, 1);
      assert.ok(triggers[0].rule.includes('config_modified'));
    });

    it('fires on kill switch', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({
        type: 'config_change',
        source: 'fs-watcher',
        severity: 'critical',
        summary: 'External kill switch file detected',
        payload: { killSwitch: true },
      }));

      await wait(50);

      assert.equal(triggers.length, 1);
      assert.ok(triggers[0].rule.includes('kill_switch_file'));
    });

    it('fires on process restart', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({
        type: 'process_event',
        source: 'log-tail',
        severity: 'medium',
        summary: 'OpenClaw restart detected',
        payload: { restart: true },
      }));

      await wait(50);

      assert.equal(triggers.length, 1);
      assert.ok(triggers[0].rule.includes('process_restart'));
    });
  });

  describe('debounce coalescing', () => {
    it('batches multiple signals within debounce window', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({
        type: 'fs_change', source: 'fs-watcher', payload: { isSkillFile: true },
      }));
      collector.emit('signal', makeSignal({
        type: 'skills_diff', source: 'skills', payload: { newEligible: true },
      }));
      collector.emit('signal', makeSignal({
        type: 'process_event', source: 'log-tail', payload: { restart: true },
      }));

      await wait(50);

      assert.equal(triggers.length, 1);
      assert.equal(triggers[0].signals.length, 3);
    });

    it('upgrades severity floor within debounce window', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      // WATCH floor
      collector.emit('signal', makeSignal({
        type: 'fs_change', source: 'fs-watcher', payload: {},
      }));
      // ALERT floor (upgrade)
      collector.emit('signal', makeSignal({
        type: 'audit_finding', source: 'audit', severity: 'critical', payload: {},
      }));

      await wait(50);

      assert.equal(triggers.length, 1);
      assert.equal(triggers[0].severityFloor, 'ALERT');
    });
  });

  describe('threshold triggers', () => {
    it('fires on log anomaly burst', async () => {
      const threshConfig = {
        ...config,
        threshold_window_seconds: 60,
        threshold_signal_count: 3,
      };
      const tm = new TriggerManager(buffer, threshConfig);
      const collector = new EventEmitter();
      tm.registerCollector(collector);

      const triggers: TriggerEvent[] = [];
      tm.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({ type: 'log_anomaly', severity: 'low' }));
      collector.emit('signal', makeSignal({ type: 'log_anomaly', severity: 'low' }));
      collector.emit('signal', makeSignal({ type: 'log_anomaly', severity: 'low' }));

      await wait(50);

      assert.ok(triggers.length >= 1);
      assert.ok(triggers[0].rule.includes('log_anomaly_burst'));
      tm.stop();
    });
  });

  describe('escalation floor', () => {
    it('applies ALERT floor when 3+ consecutive WATCHes', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      manager.updateEscalationState({
        consecutive_watch_count: 3,
        pending_alert_id: null,
        paused: false,
        last_verdict_level: 'WATCH',
        last_verdict_timestamp: Date.now(),
      });

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      // Would normally be WATCH floor
      collector.emit('signal', makeSignal({
        type: 'fs_change', source: 'fs-watcher', payload: {},
      }));

      await wait(50);

      assert.equal(triggers.length, 1);
      assert.equal(triggers[0].severityFloor, 'ALERT');
    });
  });

  describe('pause/resume', () => {
    it('suppresses triggers when paused', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);
      manager.pause();

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({
        type: 'fs_change', source: 'fs-watcher', payload: {},
      }));

      await wait(50);

      assert.equal(triggers.length, 0);
      assert.equal(buffer.size(), 1);
    });

    it('resumes trigger emission after resume', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);
      manager.pause();

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({ type: 'fs_change', source: 'fs-watcher', payload: {} }));
      await wait(50);
      assert.equal(triggers.length, 0);

      manager.resume();

      collector.emit('signal', makeSignal({ type: 'fs_change', source: 'fs-watcher', payload: {} }));
      await wait(50);

      assert.equal(triggers.length, 1);
    });
  });

  describe('non-matching signals', () => {
    it('does not fire trigger for health signals', async () => {
      const collector = new EventEmitter();
      manager.registerCollector(collector);

      const triggers: TriggerEvent[] = [];
      manager.on('trigger', (t: TriggerEvent) => triggers.push(t));

      collector.emit('signal', makeSignal({
        type: 'process_event',
        source: 'audit',
        payload: { selfHealth: true },
      }));

      await wait(50);

      assert.equal(triggers.length, 0);
    });
  });
});
