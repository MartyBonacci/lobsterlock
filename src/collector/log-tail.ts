import { EventEmitter } from 'node:events';
import { createInterface } from 'node:readline';
import { spawnStream, type SpawnFn } from '../util/exec.js';
import { uuid } from '../util/uuid.js';
import {
  LOG_ANOMALY_PATTERNS,
  RESTART_PATTERN,
  PROCESS_ABSENCE_THRESHOLD_MS,
  LOG_TAIL_MAX_RETRIES,
  LOG_TAIL_RETRY_DELAY_MS,
} from '../constants.js';
import type { ChildProcess } from 'node:child_process';
import type { LobsterLockConfig, SignalEntry } from '../types.js';

/**
 * Collector that tails journalctl for OpenClaw log anomalies.
 */
export class LogTailCollector extends EventEmitter {
  private config: LobsterLockConfig;
  private spawnFn: SpawnFn;
  private child: ChildProcess | null = null;
  private lastOutputTime: number = Date.now();
  private absenceTimer: ReturnType<typeof setInterval> | null = null;
  private retryCount = 0;
  private _running = false;

  constructor(config: LobsterLockConfig, spawnFn: SpawnFn = spawnStream) {
    super();
    this.config = config;
    this.spawnFn = spawnFn;
  }

  get running(): boolean {
    return this._running;
  }

  start(): void {
    this._running = true;
    this.retryCount = 0;
    this.spawnChild();
    this.startAbsenceMonitor();
  }

  stop(): void {
    this._running = false;
    if (this.child) {
      this.child.kill('SIGTERM');
      this.child = null;
    }
    if (this.absenceTimer) {
      clearInterval(this.absenceTimer);
      this.absenceTimer = null;
    }
  }

  private spawnChild(): void {
    this.child = this.spawnFn('journalctl', [
      '-u', this.config.openclaw_service,
      '-f',
      '--no-pager',
      '-o', 'short-iso',
    ]);

    if (this.child.stdout) {
      const rl = createInterface({ input: this.child.stdout });
      rl.on('line', (line) => this.processLine(line));
    }

    this.child.on('error', (err) => {
      this.emit('error', err);
    });

    this.child.on('exit', (code) => {
      if (!this._running) return;

      if (this.retryCount < LOG_TAIL_MAX_RETRIES) {
        this.retryCount++;
        setTimeout(() => {
          if (this._running) this.spawnChild();
        }, LOG_TAIL_RETRY_DELAY_MS);
      } else {
        this._running = false;
        this.emit('error', new Error(`journalctl exited with code ${code} after ${LOG_TAIL_MAX_RETRIES} retries`));
        this.emitHealthSignal(`Log tail stopped: journalctl exited after ${LOG_TAIL_MAX_RETRIES} retries`);
      }
    });
  }

  private processLine(line: string): void {
    this.lastOutputTime = Date.now();
    this.retryCount = 0; // Reset retry count on successful output

    // Check for restart pattern
    if (RESTART_PATTERN.test(line)) {
      this.emit('signal', {
        id: uuid(),
        type: 'process_event',
        source: 'log-tail',
        timestamp: Date.now(),
        severity: 'medium',
        summary: `OpenClaw restart detected`,
        payload: { line, restart: true },
      } satisfies SignalEntry);
      return;
    }

    // Check against anomaly patterns
    for (const { pattern, severity } of LOG_ANOMALY_PATTERNS) {
      if (pattern.test(line)) {
        this.emit('signal', {
          id: uuid(),
          type: 'log_anomaly',
          source: 'log-tail',
          timestamp: Date.now(),
          severity,
          summary: `Log anomaly: ${line.slice(0, 120)}`,
          payload: { line, matchedPattern: pattern.source },
        } satisfies SignalEntry);
        return; // Only emit one signal per line (first match wins)
      }
    }
  }

  private startAbsenceMonitor(): void {
    this.lastOutputTime = Date.now();
    this.absenceTimer = setInterval(() => {
      const elapsed = Date.now() - this.lastOutputTime;
      if (elapsed >= PROCESS_ABSENCE_THRESHOLD_MS) {
        this.emit('signal', {
          id: uuid(),
          type: 'process_event',
          source: 'log-tail',
          timestamp: Date.now(),
          severity: 'high',
          summary: `No OpenClaw log output for ${Math.round(elapsed / 60000)} minutes -- process may be down`,
          payload: { absenceMs: elapsed },
        } satisfies SignalEntry);
        // Reset timer to avoid repeated alerts
        this.lastOutputTime = Date.now();
      }
    }, 60_000); // Check every minute
  }

  private emitHealthSignal(summary: string): void {
    this.emit('signal', {
      id: uuid(),
      type: 'process_event',
      source: 'log-tail',
      timestamp: Date.now(),
      severity: 'medium',
      summary,
      payload: { selfHealth: true },
    } satisfies SignalEntry);
  }
}
