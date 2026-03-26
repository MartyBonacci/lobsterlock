import { EventEmitter } from 'node:events';
import { readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, basename } from 'node:path';
import { watch, type FSWatcher } from 'chokidar';
import { uuid } from '../util/uuid.js';
import { scanContent } from '../analysis/content-patterns.js';
import { insertHashRecord, getHashHistory } from '../storage/audit-log.js';
import type Database from 'better-sqlite3';
import type {
  ContentFinding,
  LobsterLockConfig,
  MemoryIntegrityState,
  SignalEntry,
} from '../types.js';

interface FileState {
  exists: boolean;
  hash: string | null;
  lastModified: number | null;
}

/**
 * Collector that watches OpenClaw memory files (SOUL.md, AGENTS.md, MEMORY.md,
 * HEARTBEAT.md, USER.md) for changes and scans content for suspicious patterns.
 */
export class MemoryWatcherCollector extends EventEmitter {
  private config: LobsterLockConfig;
  private db: Database.Database | null;
  private watcher: FSWatcher | null = null;
  private fileStates: Map<string, FileState> = new Map();
  private recentFindings: ContentFinding[] = [];
  private _running = false;

  constructor(config: LobsterLockConfig, db: Database.Database | null = null) {
    super();
    this.config = config;
    this.db = db;
  }

  get running(): boolean {
    return this._running;
  }

  /**
   * Get current integrity state for reasoning context.
   */
  getIntegrityState(): MemoryIntegrityState {
    const files: Record<string, { exists: boolean; hash: string | null; lastModified: number | null }> = {};
    for (const [path, state] of this.fileStates) {
      files[basename(path)] = state;
    }
    return {
      files,
      suspiciousFindings: [...this.recentFindings],
    };
  }

  start(): void {
    this._running = true;

    // Baseline: hash each configured file
    for (const filePath of this.config.memory_watch) {
      this.baselineFile(filePath);
    }

    // Watch the parent directories for file creation/modification
    const parentDirs = new Set<string>();
    for (const filePath of this.config.memory_watch) {
      parentDirs.add(dirname(filePath));
    }

    const targetFilenames = new Set(
      this.config.memory_watch.map((p) => basename(p)),
    );

    if (parentDirs.size === 0) return;

    this.watcher = watch([...parentDirs], {
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 500 },
      ignorePermissionErrors: true,
      depth: 0, // Only watch direct children
    });

    this.watcher.on('add', (path) => {
      if (targetFilenames.has(basename(path))) {
        this.onFileEvent('add', path);
      }
    });

    this.watcher.on('change', (path) => {
      if (targetFilenames.has(basename(path))) {
        this.onFileEvent('change', path);
      }
    });

    this.watcher.on('error', (err) => {
      this.emit('error', err);
    });

    const watchedCount = this.config.memory_watch.filter(
      (p) => this.fileStates.get(p)?.exists,
    ).length;
    const totalCount = this.config.memory_watch.length;
    console.log(
      `[INFO] Memory watcher: ${watchedCount}/${totalCount} files exist. Watching ${parentDirs.size} director${parentDirs.size === 1 ? 'y' : 'ies'}.`,
    );
  }

  async stop(): Promise<void> {
    this._running = false;
    if (this.watcher) {
      await this.watcher.close();
      this.watcher = null;
    }
  }

  private baselineFile(filePath: string): void {
    try {
      const content = readFileSync(filePath, 'utf-8');
      const hash = this.hashContent(content);
      const stat = statSync(filePath);
      this.fileStates.set(filePath, {
        exists: true,
        hash,
        lastModified: stat.mtimeMs,
      });
      if (this.db) {
        try { insertHashRecord(this.db, filePath, hash); } catch {}
      }
    } catch {
      this.fileStates.set(filePath, {
        exists: false,
        hash: null,
        lastModified: null,
      });
    }
  }

  private onFileEvent(event: string, path: string): void {
    let content: string;
    try {
      content = readFileSync(path, 'utf-8');
    } catch {
      return; // Can't read, skip silently
    }

    const newHash = this.hashContent(content);
    const previousState = this.fileStates.get(path);
    const previousHash = previousState?.hash ?? null;

    // Update state
    try {
      const stat = statSync(path);
      this.fileStates.set(path, {
        exists: true,
        hash: newHash,
        lastModified: stat.mtimeMs,
      });
    } catch {
      this.fileStates.set(path, { exists: true, hash: newHash, lastModified: null });
    }

    // Skip if hash hasn't changed
    if (newHash === previousHash) return;

    const filename = basename(path);

    // Emit memory file change signal
    this.emit('signal', {
      id: uuid(),
      type: 'memory_file_change',
      source: 'memory-watcher',
      timestamp: Date.now(),
      severity: 'critical',
      summary: `Memory file ${event === 'add' ? 'created' : 'modified'}: ${filename}`,
      payload: {
        file: filename,
        path,
        event,
        previousHash,
        currentHash: newHash,
        sizeBytes: content.length,
      },
    } satisfies SignalEntry);

    // Store hash and check for drift
    if (this.db) {
      try {
        insertHashRecord(this.db, path, newHash);
        const history = getHashHistory(this.db, path);
        if (history.length >= 5) {
          const originalHash = history[0]?.hash;
          const returnedToOriginal = history.some(
            (h, i) => i > 0 && h.hash === originalHash,
          );
          if (!returnedToOriginal) {
            this.emit('signal', {
              id: uuid(),
              type: 'memory_file_change',
              source: 'memory-watcher',
              timestamp: Date.now(),
              severity: 'high',
              summary: `Memory drift detected: ${filename} has ${history.length} distinct versions in 7 days without reverting`,
              payload: {
                file: filename,
                path,
                driftDetected: true,
                distinctHashes: history.length,
              },
            } satisfies SignalEntry);
          }
        }
      } catch {}
    }

    // Scan content for suspicious patterns
    const findings = scanContent(content, filename);
    this.recentFindings = findings; // Store for reasoning context

    for (const finding of findings) {
      this.emit('signal', {
        id: uuid(),
        type: 'suspicious_content',
        source: 'memory-watcher',
        timestamp: Date.now(),
        severity: finding.severity,
        summary: `Suspicious content in ${filename}: ${finding.patternName} (line ${finding.lineNumber})`,
        payload: {
          file: filename,
          ...finding,
        },
      } satisfies SignalEntry);
    }
  }

  private hashContent(content: string): string {
    return createHash('sha256').update(content).digest('hex');
  }
}
