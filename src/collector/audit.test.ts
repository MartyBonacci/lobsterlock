import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { AuditCollector } from './audit.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type { ExecResult } from '../util/exec.js';
import type { SignalEntry } from '../types.js';

function makeAuditJson(summary = { critical: 0, warn: 0, info: 1 }, findings: object[] = []): string {
  return JSON.stringify({
    ts: Date.now(),
    summary,
    findings: findings.length ? findings : [
      { checkId: 'summary.attack_surface', severity: 'info', title: 'Attack surface summary', detail: 'tools.elevated: enabled' },
    ],
  });
}

function mockExec(stdout: string, exitCode = 0): (cmd: string, args: string[]) => Promise<ExecResult> {
  return async () => ({ stdout, stderr: '', exitCode });
}

describe('AuditCollector', () => {
  it('emits baseline event on start', async () => {
    const collector = new AuditCollector(DEFAULT_CONFIG, mockExec(makeAuditJson()));

    let baselineFired = false;
    collector.on('baseline', () => { baselineFired = true; });

    await collector.start();
    collector.stop();

    assert.ok(baselineFired);
  });

  it('does not emit signals on baseline (first poll)', async () => {
    const signals: SignalEntry[] = [];
    const collector = new AuditCollector(DEFAULT_CONFIG, mockExec(makeAuditJson()));
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    await collector.start();
    collector.stop();

    // No signals on first run (baseline)
    const nonHealthSignals = signals.filter(s => !(s.payload as Record<string,unknown>).selfHealth);
    assert.equal(nonHealthSignals.length, 0);
  });

  it('detects critical count increase', async () => {
    let callCount = 0;
    const exec = async (): Promise<ExecResult> => {
      callCount++;
      if (callCount === 1) {
        return { stdout: makeAuditJson({ critical: 0, warn: 0, info: 1 }), stderr: '', exitCode: 0 };
      }
      return { stdout: makeAuditJson({ critical: 1, warn: 0, info: 1 }), stderr: '', exitCode: 0 };
    };

    const signals: SignalEntry[] = [];
    const config = { ...DEFAULT_CONFIG, audit_poll_interval_seconds: 0.01 };
    const collector = new AuditCollector(config, exec);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    await collector.start();
    // Wait for second poll
    await new Promise((r) => setTimeout(r, 50));
    collector.stop();

    const criticalSignals = signals.filter((s) => s.severity === 'critical');
    assert.ok(criticalSignals.length >= 1);
    assert.ok(criticalSignals[0].summary.includes('Critical finding count increased'));
  });

  it('detects new findings by checkId', async () => {
    let callCount = 0;
    const exec = async (): Promise<ExecResult> => {
      callCount++;
      if (callCount === 1) {
        return {
          stdout: makeAuditJson({ critical: 0, warn: 0, info: 1 }, [
            { checkId: 'existing', severity: 'info', title: 'Existing', detail: '' },
          ]),
          stderr: '', exitCode: 0,
        };
      }
      return {
        stdout: makeAuditJson({ critical: 0, warn: 0, info: 2 }, [
          { checkId: 'existing', severity: 'info', title: 'Existing', detail: '' },
          { checkId: 'new_finding', severity: 'warn', title: 'New Warning', detail: 'bad stuff' },
        ]),
        stderr: '', exitCode: 0,
      };
    };

    const signals: SignalEntry[] = [];
    const config = { ...DEFAULT_CONFIG, audit_poll_interval_seconds: 0.01 };
    const collector = new AuditCollector(config, exec);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    await collector.start();
    await new Promise((r) => setTimeout(r, 50));
    collector.stop();

    const newFindings = signals.filter((s) => s.summary.includes('New audit finding'));
    assert.ok(newFindings.length >= 1);
    assert.ok(newFindings[0].summary.includes('New Warning'));
  });

  it('emits health signal on exec failure', async () => {
    const exec = async (): Promise<ExecResult> => ({
      stdout: '', stderr: 'command not found', exitCode: 127,
    });

    const signals: SignalEntry[] = [];
    const collector = new AuditCollector(DEFAULT_CONFIG, exec);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    await collector.start();
    collector.stop();

    const healthSignals = signals.filter((s) => (s.payload as Record<string, unknown>).selfHealth);
    assert.ok(healthSignals.length >= 1);
  });
});
