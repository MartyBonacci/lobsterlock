import { EventEmitter } from 'node:events';
import { watch, type FSWatcher } from 'chokidar';
import { uuid } from '../util/uuid.js';
import { resolveConfigPath } from '../config.js';
import { KILL_SWITCH_FILE } from '../constants.js';
import type { LobsterLockConfig, SignalEntry } from '../types.js';
import type { SkillsCollector } from './skills.js';

const SKILL_FILE_PATTERNS = /\.(ts|js|md)$/i;

/**
 * Collector that watches filesystem for skill file changes,
 * config modifications, and external kill switch files.
 */
export class FsWatcherCollector extends EventEmitter {
  private config: LobsterLockConfig;
  private skillsCollector: SkillsCollector | null;
  private watcher: FSWatcher | null = null;
  private _running = false;

  constructor(
    config: LobsterLockConfig,
    skillsCollector: SkillsCollector | null = null,
  ) {
    super();
    this.config = config;
    this.skillsCollector = skillsCollector;
  }

  get running(): boolean {
    return this._running;
  }

  start(): void {
    this._running = true;

    const watchPaths = [
      ...this.config.skills_watch,
    ];

    // Build list of extra files to watch
    const extraFiles: string[] = [];

    // Watch OpenClaw config
    const openclawConfig = '/home/openclaw/.openclaw/openclaw.json';
    extraFiles.push(openclawConfig);

    // Watch kill switch file location
    const killSwitchDir = resolveConfigPath('~/.lobsterlock');
    extraFiles.push(killSwitchDir);

    this.watcher = watch([...watchPaths, ...extraFiles], {
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 500 },
      ignorePermissionErrors: true,
    });

    this.watcher.on('add', (path) => this.onFileEvent('add', path));
    this.watcher.on('change', (path) => this.onFileEvent('change', path));

    this.watcher.on('error', (err) => {
      this.emit('error', err);
    });
  }

  async stop(): Promise<void> {
    this._running = false;
    if (this.watcher) {
      await this.watcher.close();
      this.watcher = null;
    }
  }

  private onFileEvent(event: string, path: string): void {
    const killSwitchPath = resolveConfigPath(KILL_SWITCH_FILE);

    // Kill switch file
    if (path === killSwitchPath) {
      this.emit('signal', {
        id: uuid(),
        type: 'config_change',
        source: 'fs-watcher',
        timestamp: Date.now(),
        severity: 'critical',
        summary: `External kill switch file detected: ${path}`,
        payload: { event, path, killSwitch: true },
      } satisfies SignalEntry);
      return;
    }

    // OpenClaw config file
    if (path.endsWith('openclaw.json')) {
      this.emit('signal', {
        id: uuid(),
        type: 'config_change',
        source: 'fs-watcher',
        timestamp: Date.now(),
        severity: 'high',
        summary: `OpenClaw config modified: ${path}`,
        payload: { event, path, configChange: true },
      } satisfies SignalEntry);
      return;
    }

    // Skills directory files
    const isSkillsDir = this.config.skills_watch.some((dir) => path.startsWith(dir));
    if (isSkillsDir) {
      const isSkillFile = SKILL_FILE_PATTERNS.test(path);
      this.emit('signal', {
        id: uuid(),
        type: 'fs_change',
        source: 'fs-watcher',
        timestamp: Date.now(),
        severity: isSkillFile ? 'high' : 'medium',
        summary: `Skill ${event === 'add' ? 'file created' : 'file modified'}: ${path}`,
        payload: { event, path, isSkillFile },
      } satisfies SignalEntry);

      // Trigger reactive skills list recheck
      if (this.skillsCollector) {
        void this.skillsCollector.triggerRecheck();
      }
    }
  }
}
