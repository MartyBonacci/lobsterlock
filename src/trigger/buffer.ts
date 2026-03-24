import { SEVERITY_ORDER } from '../constants.js';
import type { Severity, SignalEntry } from '../types.js';

/**
 * Ring buffer for accumulating SignalEntry objects between reasoning cycles.
 * Bounded by maxSize to prevent unbounded memory growth on a 256MB heap.
 */
export class SignalBuffer {
  private entries: (SignalEntry | null)[];
  private head = 0;
  private count = 0;
  private _evictedCount = 0;
  private readonly maxSize: number;

  constructor(maxSize: number) {
    this.maxSize = maxSize;
    this.entries = new Array(maxSize).fill(null);
  }

  /**
   * Add a signal to the buffer. Evicts oldest entry if full.
   */
  push(signal: SignalEntry): void {
    if (this.count < this.maxSize) {
      this.entries[(this.head + this.count) % this.maxSize] = signal;
      this.count++;
    } else {
      // Buffer full: overwrite oldest entry
      this.entries[this.head] = signal;
      this.head = (this.head + 1) % this.maxSize;
      this._evictedCount++;
    }
  }

  /**
   * Return all entries in chronological order (oldest first).
   */
  getAll(): SignalEntry[] {
    const result: SignalEntry[] = [];
    for (let i = 0; i < this.count; i++) {
      const entry = this.entries[(this.head + i) % this.maxSize];
      if (entry) result.push(entry);
    }
    return result;
  }

  /**
   * Return entries matching a specific signal type.
   */
  getByType(type: SignalEntry['type']): SignalEntry[] {
    return this.getAll().filter((e) => e.type === type);
  }

  /**
   * Return entries at or above a minimum severity.
   */
  getBySeverity(minSeverity: Severity): SignalEntry[] {
    const minOrder = SEVERITY_ORDER[minSeverity];
    return this.getAll().filter((e) => SEVERITY_ORDER[e.severity] >= minOrder);
  }

  /**
   * Return entries within a time window (ms) from now.
   */
  getRecent(windowMs: number): SignalEntry[] {
    const cutoff = Date.now() - windowMs;
    return this.getAll().filter((e) => e.timestamp >= cutoff);
  }

  /**
   * Clear the buffer entirely. Resets evicted count.
   */
  reset(): void {
    this.entries = new Array(this.maxSize).fill(null);
    this.head = 0;
    this.count = 0;
    this._evictedCount = 0;
  }

  /**
   * Return all entries and reset the buffer (for KILL flow SQLite dump).
   */
  flush(): SignalEntry[] {
    const all = this.getAll();
    this.reset();
    return all;
  }

  /**
   * Current number of entries in the buffer.
   */
  size(): number {
    return this.count;
  }

  /**
   * Number of entries evicted since last reset.
   */
  evicted(): number {
    return this._evictedCount;
  }
}
