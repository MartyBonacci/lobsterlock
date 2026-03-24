import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { KillHandler } from './kill.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type { ExecResult } from '../util/exec.js';
import type { AlertDispatcher } from './alert.js';
import type { TriggerManager } from '../trigger/manager.js';
import type { Verdict } from '../types.js';

function makeVerdict(overrides: Partial<Verdict> = {}): Verdict {
  return {
    level: 'KILL',
    severity: null,
    reason: 'compromised skill detected',
    reasoning: 'Immediate action required.',
    raw: 'KILL compromised skill detected',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('KillHandler', () => {
  it('runs fix command and pauses trigger manager', async () => {
    let fixCalled = false;
    let fixArgs: string[] = [];
    const mockExec = async (cmd: string, args: string[]): Promise<ExecResult> => {
      fixCalled = true;
      fixArgs = args;
      return { stdout: 'fixed', stderr: '', exitCode: 0 };
    };

    let alertSent = false;
    let alertMessage = '';
    const mockDispatcher = {
      sendDegradedAlert: async (msg: string) => {
        alertSent = true;
        alertMessage = msg;
      },
    } as unknown as AlertDispatcher;

    let paused = false;
    const mockTriggerManager = {
      pause: () => { paused = true; },
    } as unknown as TriggerManager;

    const handler = new KillHandler(DEFAULT_CONFIG, mockDispatcher, mockTriggerManager, mockExec);
    await handler.execute(makeVerdict());

    assert.ok(fixCalled, 'fix command should be called');
    assert.deepEqual(fixArgs, ['security', 'audit', '--fix']);
    assert.ok(alertSent, 'Discord alert should be sent');
    assert.ok(alertMessage.includes('KILL verdict executed'));
    assert.ok(alertMessage.includes('lobsterlock ack'));
    assert.ok(paused, 'trigger manager should be paused');
  });

  it('handles fix command failure gracefully', async () => {
    const mockExec = async (): Promise<ExecResult> => {
      throw new Error('command not found');
    };

    let alertSent = false;
    const mockDispatcher = {
      sendDegradedAlert: async () => { alertSent = true; },
    } as unknown as AlertDispatcher;

    let paused = false;
    const mockTriggerManager = {
      pause: () => { paused = true; },
    } as unknown as TriggerManager;

    const handler = new KillHandler(DEFAULT_CONFIG, mockDispatcher, mockTriggerManager, mockExec);

    // Should not throw
    await assert.doesNotReject(() => handler.execute(makeVerdict()));

    // Should still alert and pause even if fix fails
    assert.ok(alertSent);
    assert.ok(paused);
  });
});
