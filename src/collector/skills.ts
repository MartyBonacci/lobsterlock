import { EventEmitter } from 'node:events';
import { execCommand, type ExecFn } from '../util/exec.js';
import { uuid } from '../util/uuid.js';
import type { LobsterLockConfig, SignalEntry } from '../types.js';

interface SkillInfo {
  name: string;
  eligible: boolean;
  disabled: boolean;
  blockedByAllowlist: boolean;
  bundled: boolean;
  missing: { bins: string[] };
  [key: string]: unknown;
}

/**
 * Collector that periodically snapshots `openclaw skills list --json`
 * and emits signals when the skill inventory changes.
 */
export class SkillsCollector extends EventEmitter {
  private config: LobsterLockConfig;
  private execFn: ExecFn;
  private interval: ReturnType<typeof setInterval> | null = null;
  private previousSnapshot: Map<string, SkillInfo> = new Map();
  private _lastDelta: Record<string, unknown> | null = null;
  private _running = false;

  constructor(config: LobsterLockConfig, execFn: ExecFn = execCommand) {
    super();
    this.config = config;
    this.execFn = execFn;
  }

  get lastDelta(): Record<string, unknown> | null {
    return this._lastDelta;
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

  /**
   * Trigger an immediate recheck (called by fs-watcher).
   */
  async triggerRecheck(): Promise<void> {
    await this.poll(false);
  }

  private async poll(isBaseline: boolean): Promise<void> {
    try {
      const result = await this.execFn(this.config.openclaw_cli, [
        'skills', 'list', '--json',
      ]);

      if (result.exitCode !== 0 && !result.stdout) {
        this.emitHealthSignal(`Skills list command failed with exit code ${result.exitCode}`);
        return;
      }

      let skills: SkillInfo[];
      try {
        const parsed = JSON.parse(result.stdout);
        skills = Array.isArray(parsed) ? parsed : parsed.skills ?? [];
      } catch {
        this.emitHealthSignal(`Skills list returned invalid JSON`);
        return;
      }

      const current = new Map<string, SkillInfo>();
      for (const skill of skills) {
        if (skill.name) {
          current.set(skill.name, skill);
        }
      }

      if (isBaseline) {
        this.previousSnapshot = current;
        this._lastDelta = null;
        this.emit('baseline');
        return;
      }

      this.diff(this.previousSnapshot, current);
      this.previousSnapshot = current;
    } catch (err) {
      this._running = false;
      this.emit('error', err);
      this.emitHealthSignal(`Skills collector error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private diff(
    prev: Map<string, SkillInfo>,
    curr: Map<string, SkillInfo>,
  ): void {
    const delta: {
      newSkills: string[];
      newlyEligible: string[];
      removed: string[];
    } = { newSkills: [], newlyEligible: [], removed: [] };

    // Check for new skills and newly eligible skills
    for (const [name, skill] of curr) {
      const prevSkill = prev.get(name);
      if (!prevSkill) {
        delta.newSkills.push(name);
        this.emit('signal', {
          id: uuid(),
          type: 'skills_diff',
          source: 'skills',
          timestamp: Date.now(),
          severity: 'high',
          summary: `New skill detected: ${name}`,
          payload: { skill, newSkill: true },
        } satisfies SignalEntry);
      } else if (skill.eligible && !prevSkill.eligible) {
        delta.newlyEligible.push(name);
        this.emit('signal', {
          id: uuid(),
          type: 'skills_diff',
          source: 'skills',
          timestamp: Date.now(),
          severity: 'high',
          summary: `Skill became eligible: ${name}`,
          payload: { skill, newEligible: true },
        } satisfies SignalEntry);
      }
    }

    // Check for removed skills
    for (const name of prev.keys()) {
      if (!curr.has(name)) {
        delta.removed.push(name);
        this.emit('signal', {
          id: uuid(),
          type: 'skills_diff',
          source: 'skills',
          timestamp: Date.now(),
          severity: 'medium',
          summary: `Skill removed: ${name}`,
          payload: { skillName: name, removed: true },
        } satisfies SignalEntry);
      }
    }

    if (delta.newSkills.length || delta.newlyEligible.length || delta.removed.length) {
      this._lastDelta = delta;
    }
  }

  private emitHealthSignal(summary: string): void {
    this.emit('signal', {
      id: uuid(),
      type: 'process_event',
      source: 'skills',
      timestamp: Date.now(),
      severity: 'medium',
      summary,
      payload: { selfHealth: true },
    } satisfies SignalEntry);
  }
}
