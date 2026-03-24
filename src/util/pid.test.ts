import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writePid, readPid, isProcessRunning, removePid, checkStalePid } from './pid.js';

describe('pid utilities', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'lobsterlock-pid-test-'));
  const pidPath = join(tempDir, 'test.pid');

  afterEach(() => {
    try { unlinkSync(pidPath); } catch {}
  });

  describe('writePid / readPid', () => {
    it('round-trips the current PID', () => {
      writePid(pidPath);
      const pid = readPid(pidPath);
      assert.equal(pid, process.pid);
    });

    it('returns null when file does not exist', () => {
      const pid = readPid(join(tempDir, 'nonexistent.pid'));
      assert.equal(pid, null);
    });
  });

  describe('isProcessRunning', () => {
    it('returns true for current process', () => {
      assert.equal(isProcessRunning(process.pid), true);
    });

    it('returns false for dead PID', () => {
      assert.equal(isProcessRunning(999999), false);
    });
  });

  describe('removePid', () => {
    it('deletes the PID file', () => {
      writePid(pidPath);
      assert.ok(existsSync(pidPath));
      removePid(pidPath);
      assert.ok(!existsSync(pidPath));
    });

    it('does not throw when file does not exist', () => {
      assert.doesNotThrow(() => removePid(join(tempDir, 'nope.pid')));
    });
  });

  describe('checkStalePid', () => {
    it('returns none when no file exists', () => {
      assert.equal(checkStalePid(join(tempDir, 'nope.pid')), 'none');
    });

    it('returns running for current process PID', () => {
      writePid(pidPath);
      assert.equal(checkStalePid(pidPath), 'running');
    });

    it('returns stale for dead PID', () => {
      // Write a PID that is almost certainly not running
      writeFileSync(pidPath, '999999', 'utf-8');
      assert.equal(checkStalePid(pidPath), 'stale');
    });
  });
});
