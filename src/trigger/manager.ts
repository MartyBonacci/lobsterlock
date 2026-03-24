import { EventEmitter } from 'node:events';
import { uuid } from '../util/uuid.js';
import { VERDICT_LEVEL_ORDER } from '../constants.js';
import { SignalBuffer } from './buffer.js';
import type {
  EscalationState,
  LobsterLockConfig,
  SignalEntry,
  TriggerEvent,
  VerdictLevel,
} from '../types.js';

interface TriggerRule {
  name: string;
  severityFloor: VerdictLevel;
  matches: (signal: SignalEntry) => boolean;
}

/**
 * Central trigger manager. Subscribes to collector signals, evaluates
 * hard and threshold trigger rules, and emits coalesced trigger events
 * after a debounce window.
 */
export class TriggerManager extends EventEmitter {
  private buffer: SignalBuffer;
  private config: LobsterLockConfig;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingSignals: SignalEntry[] = [];
  private pendingSeverityFloor: VerdictLevel = 'CLEAR';
  private pendingRules: string[] = [];
  private _paused = false;
  private escalationState: EscalationState = {
    consecutive_watch_count: 0,
    pending_alert_id: null,
    paused: false,
    last_verdict_level: null,
    last_verdict_timestamp: null,
  };

  private readonly hardTriggerRules: TriggerRule[];

  constructor(buffer: SignalBuffer, config: LobsterLockConfig) {
    super();
    this.buffer = buffer;
    this.config = config;

    this.hardTriggerRules = [
      {
        name: 'new_skill_file',
        severityFloor: 'WATCH',
        matches: (s) => s.type === 'fs_change' && s.source === 'fs-watcher',
      },
      {
        name: 'new_eligible_skill',
        severityFloor: 'WATCH',
        matches: (s) =>
          s.type === 'skills_diff' &&
          (s.payload as Record<string, unknown>).newEligible === true,
      },
      {
        name: 'new_audit_finding',
        severityFloor: 'WATCH',
        matches: (s) =>
          s.type === 'audit_finding' && s.severity !== 'critical',
      },
      {
        name: 'critical_count_increase',
        severityFloor: 'ALERT',
        matches: (s) =>
          s.type === 'audit_finding' && s.severity === 'critical',
      },
      {
        name: 'config_modified',
        severityFloor: 'ALERT',
        matches: (s) =>
          s.type === 'config_change' &&
          s.summary.toLowerCase().includes('openclaw') &&
          !(s.payload as Record<string, unknown>).killSwitch,
      },
      {
        name: 'kill_switch_file',
        severityFloor: 'ALERT',
        matches: (s) =>
          s.type === 'config_change' &&
          (s.payload as Record<string, unknown>).killSwitch === true,
      },
      {
        name: 'process_restart',
        severityFloor: 'WATCH',
        matches: (s) =>
          s.type === 'process_event' &&
          (s.payload as Record<string, unknown>).restart === true,
      },
    ];
  }

  get paused(): boolean {
    return this._paused;
  }

  /**
   * Register a collector to listen for signals.
   */
  registerCollector(collector: EventEmitter): void {
    collector.on('signal', (signal: SignalEntry) => this.onSignal(signal));
  }

  /**
   * Update escalation state (called by orchestrator after each verdict).
   */
  updateEscalationState(state: EscalationState): void {
    this.escalationState = state;
  }

  /**
   * Pause trigger emission (after KILL verdict).
   */
  pause(): void {
    this._paused = true;
  }

  /**
   * Resume trigger emission (after ack).
   */
  resume(): void {
    this._paused = false;
  }

  /**
   * Cancel any pending debounce timer and clean up.
   */
  stop(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    this.pendingSignals = [];
    this.pendingRules = [];
  }

  private onSignal(signal: SignalEntry): void {
    // Always buffer the signal regardless of trigger state
    this.buffer.push(signal);

    // Evaluate hard triggers
    const hardResult = this.evaluateHardTriggers(signal);
    if (hardResult) {
      this.startOrExtendDebounce(signal, hardResult.severityFloor, hardResult.name);
      return;
    }

    // Evaluate threshold triggers
    const thresholdResult = this.evaluateThresholdTriggers();
    if (thresholdResult) {
      this.startOrExtendDebounce(signal, thresholdResult.severityFloor, thresholdResult.name);
    }
  }

  private evaluateHardTriggers(
    signal: SignalEntry,
  ): { name: string; severityFloor: VerdictLevel } | null {
    for (const rule of this.hardTriggerRules) {
      if (rule.matches(signal)) {
        return { name: rule.name, severityFloor: rule.severityFloor };
      }
    }
    return null;
  }

  private evaluateThresholdTriggers(): {
    name: string;
    severityFloor: VerdictLevel;
  } | null {
    // Threshold: 3+ low-severity log anomalies in time window
    const windowMs = this.config.threshold_window_seconds * 1000;
    const recent = this.buffer.getRecent(windowMs);
    const lowAnomalies = recent.filter(
      (s) => s.type === 'log_anomaly' && s.severity === 'low',
    );
    if (lowAnomalies.length >= this.config.threshold_signal_count) {
      return { name: 'log_anomaly_burst', severityFloor: 'WATCH' };
    }

    return null;
  }

  private startOrExtendDebounce(
    signal: SignalEntry,
    severityFloor: VerdictLevel,
    ruleName: string,
  ): void {
    this.pendingSignals.push(signal);
    if (!this.pendingRules.includes(ruleName)) {
      this.pendingRules.push(ruleName);
    }

    // Upgrade severity floor if incoming is higher
    if (
      VERDICT_LEVEL_ORDER[severityFloor] >
      VERDICT_LEVEL_ORDER[this.pendingSeverityFloor]
    ) {
      this.pendingSeverityFloor = severityFloor;
    }

    // Start debounce timer if not already running
    if (!this.debounceTimer) {
      this.debounceTimer = setTimeout(
        () => this.fireTrigger(),
        this.config.trigger_debounce_ms,
      );
    }
  }

  private fireTrigger(): void {
    this.debounceTimer = null;

    if (this._paused) {
      this.pendingSignals = [];
      this.pendingRules = [];
      this.pendingSeverityFloor = 'CLEAR';
      return;
    }

    let severityFloor = this.pendingSeverityFloor;

    // Apply escalation floor: 3+ consecutive WATCHes -> floor at ALERT
    if (
      this.escalationState.consecutive_watch_count >= 3 &&
      VERDICT_LEVEL_ORDER[severityFloor] < VERDICT_LEVEL_ORDER['ALERT']
    ) {
      severityFloor = 'ALERT';
    }

    const trigger: TriggerEvent = {
      id: uuid(),
      type: this.pendingRules.some((r) =>
        this.hardTriggerRules.map((h) => h.name).includes(r),
      )
        ? 'hard'
        : 'threshold',
      rule: this.pendingRules.join(', '),
      source: this.pendingSignals.map((s) => s.source).join(', '),
      severityFloor,
      signals: [...this.pendingSignals],
      timestamp: Date.now(),
    };

    // Reset pending state
    this.pendingSignals = [];
    this.pendingRules = [];
    this.pendingSeverityFloor = 'CLEAR';

    this.emit('trigger', trigger);
  }
}
