import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { SignalBuffer } from './buffer.js';
import type { SignalEntry } from '../types.js';

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

describe('SignalBuffer', () => {
  let buffer: SignalBuffer;

  beforeEach(() => {
    buffer = new SignalBuffer(5);
  });

  describe('push and getAll', () => {
    it('stores and retrieves entries in order', () => {
      buffer.push(makeSignal({ id: 'a' }));
      buffer.push(makeSignal({ id: 'b' }));
      buffer.push(makeSignal({ id: 'c' }));

      const all = buffer.getAll();
      assert.equal(all.length, 3);
      assert.equal(all[0].id, 'a');
      assert.equal(all[1].id, 'b');
      assert.equal(all[2].id, 'c');
    });

    it('returns empty array when empty', () => {
      assert.deepEqual(buffer.getAll(), []);
    });
  });

  describe('ring buffer wrapping', () => {
    it('evicts oldest entries when full', () => {
      for (let i = 0; i < 7; i++) {
        buffer.push(makeSignal({ id: `s${i}` }));
      }

      const all = buffer.getAll();
      assert.equal(all.length, 5);
      // Oldest two (s0, s1) should be evicted
      assert.equal(all[0].id, 's2');
      assert.equal(all[4].id, 's6');
    });

    it('tracks evicted count', () => {
      assert.equal(buffer.evicted(), 0);

      for (let i = 0; i < 5; i++) {
        buffer.push(makeSignal());
      }
      assert.equal(buffer.evicted(), 0);

      buffer.push(makeSignal());
      assert.equal(buffer.evicted(), 1);

      buffer.push(makeSignal());
      assert.equal(buffer.evicted(), 2);
    });
  });

  describe('size', () => {
    it('tracks current count', () => {
      assert.equal(buffer.size(), 0);
      buffer.push(makeSignal());
      assert.equal(buffer.size(), 1);
      buffer.push(makeSignal());
      assert.equal(buffer.size(), 2);
    });

    it('caps at maxSize', () => {
      for (let i = 0; i < 10; i++) {
        buffer.push(makeSignal());
      }
      assert.equal(buffer.size(), 5);
    });
  });

  describe('reset', () => {
    it('clears all entries', () => {
      buffer.push(makeSignal());
      buffer.push(makeSignal());
      buffer.reset();

      assert.equal(buffer.size(), 0);
      assert.equal(buffer.evicted(), 0);
      assert.deepEqual(buffer.getAll(), []);
    });
  });

  describe('flush', () => {
    it('returns entries and resets', () => {
      buffer.push(makeSignal({ id: 'a' }));
      buffer.push(makeSignal({ id: 'b' }));

      const flushed = buffer.flush();
      assert.equal(flushed.length, 2);
      assert.equal(flushed[0].id, 'a');

      assert.equal(buffer.size(), 0);
      assert.deepEqual(buffer.getAll(), []);
    });
  });

  describe('getByType', () => {
    it('filters by type', () => {
      buffer.push(makeSignal({ type: 'log_anomaly', id: 'a' }));
      buffer.push(makeSignal({ type: 'fs_change', id: 'b' }));
      buffer.push(makeSignal({ type: 'log_anomaly', id: 'c' }));

      const result = buffer.getByType('log_anomaly');
      assert.equal(result.length, 2);
      assert.equal(result[0].id, 'a');
      assert.equal(result[1].id, 'c');
    });
  });

  describe('getBySeverity', () => {
    it('filters by minimum severity', () => {
      buffer.push(makeSignal({ severity: 'info', id: 'a' }));
      buffer.push(makeSignal({ severity: 'low', id: 'b' }));
      buffer.push(makeSignal({ severity: 'high', id: 'c' }));
      buffer.push(makeSignal({ severity: 'critical', id: 'd' }));

      const result = buffer.getBySeverity('high');
      assert.equal(result.length, 2);
      assert.equal(result[0].id, 'c');
      assert.equal(result[1].id, 'd');
    });
  });

  describe('getRecent', () => {
    it('filters by time window', () => {
      const now = Date.now();
      buffer.push(makeSignal({ timestamp: now - 10000, id: 'old' }));
      buffer.push(makeSignal({ timestamp: now - 500, id: 'recent1' }));
      buffer.push(makeSignal({ timestamp: now - 100, id: 'recent2' }));

      const result = buffer.getRecent(1000);
      assert.equal(result.length, 2);
      assert.equal(result[0].id, 'recent1');
      assert.equal(result[1].id, 'recent2');
    });
  });
});
