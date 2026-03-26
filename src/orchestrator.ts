import { existsSync, accessSync, constants as fsConstants } from 'node:fs';
import type Database from 'better-sqlite3';
import { resolveConfigPath, ensureConfigDir } from './config.js';
import { DB_FILE } from './constants.js';
import {
  initDatabase,
  loadEscalationState,
  saveEscalationState,
  saveBufferSnapshot,
  getLastVerdict as dbGetLastVerdict,
} from './storage/audit-log.js';
import { SignalBuffer } from './trigger/buffer.js';
import { TriggerManager } from './trigger/manager.js';
import { AuditCollector } from './collector/audit.js';
import { SkillsCollector } from './collector/skills.js';
import { LogTailCollector } from './collector/log-tail.js';
import { FsWatcherCollector } from './collector/fs-watcher.js';
import { MemoryWatcherCollector } from './collector/memory-watcher.js';
import { PortCheckerCollector } from './collector/port-checker.js';
import { ReasoningEngine } from './reasoning/engine.js';
import { AlertDispatcher } from './dispatcher/alert.js';
import { KillHandler } from './dispatcher/kill.js';
import { analyzeConfig } from './analysis/config-analyzer.js';
import { pruneOldHashes } from './storage/audit-log.js';
import { uuid } from './util/uuid.js';
import { writePid, removePid } from './util/pid.js';
import type {
  EscalationState,
  LobsterLockConfig,
  StatusReport,
  TriggerEvent,
  Verdict,
} from './types.js';

/**
 * Central orchestrator that owns all components and wires the event flow.
 */
export class Orchestrator {
  private config: LobsterLockConfig;
  private db!: Database.Database;
  private buffer!: SignalBuffer;
  private triggerManager!: TriggerManager;
  private auditCollector!: AuditCollector;
  private skillsCollector!: SkillsCollector;
  private logTailCollector!: LogTailCollector;
  private fsWatcherCollector!: FsWatcherCollector;
  private memoryWatcherCollector!: MemoryWatcherCollector;
  private portCheckerCollector!: PortCheckerCollector;
  private reasoningEngine!: ReasoningEngine;
  private alertDispatcher!: AlertDispatcher;
  private killHandler!: KillHandler;
  private escalationState!: EscalationState;
  private lastVerdict: Verdict | null = null;
  private lastTrigger: TriggerEvent | null = null;
  private startTime: number = 0;
  private pidPath: string;

  constructor(config: LobsterLockConfig) {
    this.config = config;
    this.pidPath = resolveConfigPath('~/.lobsterlock/lobsterlock.pid');
  }

  async start(): Promise<void> {
    this.startTime = Date.now();
    ensureConfigDir();

    // 0. Validate environment
    if (!process.env.ANTHROPIC_API_KEY) {
      console.error('[FATAL] ANTHROPIC_API_KEY environment variable is required');
      process.exit(1);
    }

    try {
      accessSync(this.config.openclaw_cli, fsConstants.X_OK);
    } catch {
      console.error(`[WARN] openclaw_cli not found or not executable: ${this.config.openclaw_cli}`);
      console.error('[WARN] Collectors will emit health signals on command failures');
    }

    for (const dir of this.config.skills_watch) {
      if (!existsSync(dir)) {
        console.error(`[WARN] Skills watch directory does not exist: ${dir}`);
      }
    }

    // 1. Init SQLite
    const dbPath = resolveConfigPath(DB_FILE);
    this.db = initDatabase(dbPath);

    // 1b. Prune old hash history
    pruneOldHashes(this.db);

    // 2. Restore escalation state
    this.escalationState = loadEscalationState(this.db);

    // 3. Create signal buffer
    this.buffer = new SignalBuffer(this.config.signal_buffer_max_entries);

    // 4. Create collectors
    this.skillsCollector = new SkillsCollector(this.config);
    this.auditCollector = new AuditCollector(this.config);
    this.logTailCollector = new LogTailCollector(this.config);
    this.fsWatcherCollector = new FsWatcherCollector(this.config, this.skillsCollector);
    this.memoryWatcherCollector = new MemoryWatcherCollector(this.config, this.db);
    this.portCheckerCollector = new PortCheckerCollector(this.config);

    // 5. Create trigger manager
    this.triggerManager = new TriggerManager(this.buffer, this.config);
    this.triggerManager.registerCollector(this.auditCollector);
    this.triggerManager.registerCollector(this.skillsCollector);
    this.triggerManager.registerCollector(this.logTailCollector);
    this.triggerManager.registerCollector(this.fsWatcherCollector);
    this.triggerManager.registerCollector(this.memoryWatcherCollector);
    this.triggerManager.registerCollector(this.portCheckerCollector);
    this.triggerManager.updateEscalationState(this.escalationState);

    if (this.escalationState.paused) {
      this.triggerManager.pause();
    }

    // 6. Create reasoning engine
    this.reasoningEngine = new ReasoningEngine(this.config, this.db, this.buffer);

    // 7. Create alert dispatcher
    this.alertDispatcher = new AlertDispatcher(this.config);
    await this.alertDispatcher.init();

    // 8. Create kill handler
    this.killHandler = new KillHandler(
      this.config,
      this.alertDispatcher,
      this.triggerManager,
    );

    // 9. Wire trigger -> reasoning pipeline
    this.triggerManager.on('trigger', (trigger: TriggerEvent) => {
      void this.onTrigger(trigger);
    });

    // 10. Start collectors
    await this.auditCollector.start();
    await this.skillsCollector.start();
    this.logTailCollector.start();
    this.fsWatcherCollector.start();
    this.memoryWatcherCollector.start();
    await this.portCheckerCollector.start();

    // 10b. Run initial config analysis
    const openclawConfigPath = '/home/openclaw/.openclaw/openclaw.json';
    const configFindings = analyzeConfig(openclawConfigPath);
    for (const finding of configFindings) {
      this.buffer.push({
        id: uuid(),
        type: 'config_change',
        source: 'config-analyzer',
        timestamp: Date.now(),
        severity: finding.severity,
        summary: `Dangerous config: ${finding.setting} -- ${finding.description}`,
        payload: { dangerousSetting: true, ...finding },
      });
    }
    if (configFindings.length > 0) {
      console.log(`[WARN] Found ${configFindings.length} dangerous OpenClaw config setting(s)`);
    }

    // 11. Write PID file
    writePid(this.pidPath);

    // 12. Register signal handlers
    const shutdownHandler = () => {
      void this.shutdown();
    };
    process.on('SIGTERM', shutdownHandler);
    process.on('SIGINT', shutdownHandler);

    console.log('[INFO] LobsterLock started');
    if (this.escalationState.paused) {
      console.log('[WARN] System is paused (previous KILL). Run `lobsterlock ack` to resume.');
    }
  }

  private async onTrigger(trigger: TriggerEvent): Promise<void> {
    this.lastTrigger = trigger;

    // Invoke reasoning engine
    const verdict = await this.reasoningEngine.invoke(
      trigger,
      this.escalationState,
      this.lastVerdict,
      this.auditCollector.lastSnapshot as Record<string, unknown> | null,
      this.skillsCollector.lastDelta,
      this.memoryWatcherCollector.getIntegrityState(),
    );

    if (!verdict) {
      // Degraded mode: Claude API unreachable
      await this.alertDispatcher.sendDegradedAlert(
        'LobsterLock reasoning degraded: Claude API unreachable. Signals are being buffered.',
      );
      return;
    }

    // Process verdict through escalation state machine
    switch (verdict.level) {
      case 'CLEAR':
        this.escalationState.consecutive_watch_count = 0;
        this.escalationState.pending_alert_id = null;
        this.escalationState.last_verdict_level = 'CLEAR';
        this.escalationState.last_verdict_timestamp = verdict.timestamp;
        this.buffer.reset();
        break;

      case 'WATCH':
        this.escalationState.consecutive_watch_count++;
        this.escalationState.last_verdict_level = 'WATCH';
        this.escalationState.last_verdict_timestamp = verdict.timestamp;
        // Buffer preserved (no reset)
        break;

      case 'ALERT':
        this.escalationState.pending_alert_id = trigger.id;
        this.escalationState.last_verdict_level = 'ALERT';
        this.escalationState.last_verdict_timestamp = verdict.timestamp;
        // Buffer preserved
        break;

      case 'KILL':
        this.escalationState.paused = true;
        this.escalationState.last_verdict_level = 'KILL';
        this.escalationState.last_verdict_timestamp = verdict.timestamp;
        // Flush buffer to SQLite
        const flushed = this.buffer.flush();
        saveBufferSnapshot(this.db, flushed);
        // Execute kill handler
        await this.killHandler.execute(verdict);
        break;
    }

    // Save escalation state
    saveEscalationState(this.db, this.escalationState);
    this.triggerManager.updateEscalationState(this.escalationState);

    // Dispatch verdict
    await this.alertDispatcher.dispatch(verdict, this.escalationState, trigger);

    this.lastVerdict = verdict;
  }

  /**
   * Acknowledge all pending alerts. Resets escalation.
   */
  async acknowledge(): Promise<{ count: number; resumed: boolean }> {
    const { acknowledgeAll } = await import('./storage/audit-log.js');
    const count = acknowledgeAll(this.db);

    const resumed = this.escalationState.paused;

    this.escalationState.consecutive_watch_count = 0;
    this.escalationState.pending_alert_id = null;
    this.escalationState.paused = false;
    this.escalationState.last_verdict_level = null;
    this.escalationState.last_verdict_timestamp = null;

    saveEscalationState(this.db, this.escalationState);
    this.triggerManager.updateEscalationState(this.escalationState);

    if (resumed) {
      this.triggerManager.resume();
      this.buffer.reset();
    }

    return { count, resumed };
  }

  /**
   * Get current status report.
   */
  getStatus(): StatusReport {
    return {
      uptime: Date.now() - this.startTime,
      lastTrigger: this.lastTrigger
        ? {
            type: this.lastTrigger.type,
            rule: this.lastTrigger.rule,
            timestamp: this.lastTrigger.timestamp,
          }
        : null,
      lastVerdict: this.lastVerdict,
      escalation: this.escalationState,
      bufferSize: this.buffer.size(),
      collectors: {
        audit: this.auditCollector.running ? 'running' : 'stopped',
        skills: this.skillsCollector.running ? 'running' : 'stopped',
        'log-tail': this.logTailCollector.running ? 'running' : 'stopped',
        'fs-watcher': this.fsWatcherCollector.running ? 'running' : 'stopped',
        'memory-watcher': this.memoryWatcherCollector.running ? 'running' : 'stopped',
        'port-checker': this.portCheckerCollector.running ? 'running' : 'stopped',
      },
      paused: this.escalationState.paused,
    };
  }

  /**
   * Graceful shutdown.
   */
  async shutdown(): Promise<void> {
    console.log('[INFO] Shutting down...');

    // 1. Stop triggers
    this.triggerManager.stop();

    // 2. Wait for in-flight reasoning
    await this.reasoningEngine.waitForInflight();

    // 3. Save buffer snapshot
    saveBufferSnapshot(this.db, this.buffer.getAll());

    // 4. Stop collectors
    this.auditCollector.stop();
    this.skillsCollector.stop();
    this.logTailCollector.stop();
    await this.fsWatcherCollector.stop();
    await this.memoryWatcherCollector.stop();
    this.portCheckerCollector.stop();

    // 5. Shutdown Discord
    await this.alertDispatcher.shutdown();

    // 6. Close database
    this.db.close();

    // 7. Remove PID file
    removePid(this.pidPath);

    console.log('[INFO] LobsterLock stopped');
    process.exit(0);
  }
}
