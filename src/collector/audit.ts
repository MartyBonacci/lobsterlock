import { EventEmitter } from 'node:events';
import { execCommand, type ExecFn } from '../util/exec.js';
import { uuid } from '../util/uuid.js';
import type { LobsterLockConfig, SignalEntry } from '../types.js';

interface AuditFinding {
  checkId: string;
  severity: string;
  title: string;
  detail: string;
}

interface AuditSnapshot {
  ts: number;
  summary: { critical: number; warn: number; info: number };
  findings: AuditFinding[];
}

/**
 * Collector that periodically runs `openclaw security audit --json`
 * and emits signals when the security posture changes.
 */
export class AuditCollector extends EventEmitter {
  private config: LobsterLockConfig;
  private execFn: ExecFn;
  private interval: ReturnType<typeof setInterval> | null = null;
  private previousSnapshot: AuditSnapshot | null = null;
  private _lastSnapshot: AuditSnapshot | null = null;
  private _running = false;

  constructor(config: LobsterLockConfig, execFn: ExecFn = execCommand) {
    super();
    this.config = config;
    this.execFn = execFn;
  }

  get lastSnapshot(): AuditSnapshot | null {
    return this._lastSnapshot;
  }

  get running(): boolean {
    return this._running;
  }

  async start(): Promise<void> {
    this._running = true;
    await this.poll(true);
    this.interval = setInterval(
      () => void this.poll(false),
      this.config.audit_poll_interval_seconds * 1000,
    );
  }

  stop(): void {
    this._running = false;
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }

  private async poll(isBaseline: boolean): Promise<void> {
    try {
      const result = await this.execFn(this.config.openclaw_cli, [
        'security', 'audit', '--json',
      ]);

      if (result.exitCode !== 0 && !result.stdout) {
        this.emitHealthSignal(`Audit command failed with exit code ${result.exitCode}: ${result.stderr.slice(0, 200)}`);
        return;
      }

      let snapshot: AuditSnapshot;
      try {
        snapshot = JSON.parse(result.stdout) as AuditSnapshot;
      } catch {
        this.emitHealthSignal(`Audit command returned invalid JSON: ${result.stdout.slice(0, 200)}`);
        return;
      }

      this._lastSnapshot = snapshot;

      if (isBaseline) {
        this.previousSnapshot = snapshot;
        this.emit('baseline');
        return;
      }

      if (!this.previousSnapshot) {
        this.previousSnapshot = snapshot;
        return;
      }

      this.diff(this.previousSnapshot, snapshot);
      this.previousSnapshot = snapshot;
    } catch (err) {
      this._running = false;
      this.emit('error', err);
      this.emitHealthSignal(`Audit collector error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private diff(prev: AuditSnapshot, curr: AuditSnapshot): void {
    // Check for critical count increase
    if (curr.summary.critical > prev.summary.critical) {
      this.emit('signal', {
        id: uuid(),
        type: 'audit_finding',
        source: 'audit',
        timestamp: Date.now(),
        severity: 'critical',
        summary: `Critical finding count increased: ${prev.summary.critical} -> ${curr.summary.critical}`,
        payload: { previous: prev.summary, current: curr.summary },
      } satisfies SignalEntry);
    }

    // Check for warn count increase
    if (curr.summary.warn > prev.summary.warn) {
      this.emit('signal', {
        id: uuid(),
        type: 'audit_finding',
        source: 'audit',
        timestamp: Date.now(),
        severity: 'medium',
        summary: `Warning count increased: ${prev.summary.warn} -> ${curr.summary.warn}`,
        payload: { previous: prev.summary, current: curr.summary },
      } satisfies SignalEntry);
    }

    // Check for new findings by checkId
    const prevIds = new Set(prev.findings.map((f) => f.checkId));
    for (const finding of curr.findings) {
      if (!prevIds.has(finding.checkId)) {
        this.emit('signal', {
          id: uuid(),
          type: 'audit_finding',
          source: 'audit',
          timestamp: Date.now(),
          severity: finding.severity === 'critical' ? 'critical'
            : finding.severity === 'warn' ? 'medium'
            : 'low',
          summary: `New audit finding: ${finding.title}`,
          payload: { finding },
        } satisfies SignalEntry);
      }
    }
  }

  private emitHealthSignal(summary: string): void {
    this.emit('signal', {
      id: uuid(),
      type: 'process_event',
      source: 'audit',
      timestamp: Date.now(),
      severity: 'medium',
      summary,
      payload: { selfHealth: true },
    } satisfies SignalEntry);
  }
}
