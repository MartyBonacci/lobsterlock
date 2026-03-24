import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { AlertDispatcher } from './alert.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type { EscalationState, Verdict } from '../types.js';

function makeVerdict(overrides: Partial<Verdict> = {}): Verdict {
  return {
    level: 'CLEAR',
    severity: null,
    reason: 'all clear',
    reasoning: 'Everything looks normal.',
    raw: 'CLEAR',
    timestamp: Date.now(),
    ...overrides,
  };
}

const defaultEscalation: EscalationState = {
  consecutive_watch_count: 0,
  pending_alert_id: null,
  paused: false,
  last_verdict_level: null,
  last_verdict_timestamp: null,
};

describe('AlertDispatcher', () => {
  it('logs CLEAR verdicts without attempting Discord', async () => {
    const dispatcher = new AlertDispatcher(DEFAULT_CONFIG);
    // No Discord init -- should not throw
    await assert.doesNotReject(() =>
      dispatcher.dispatch(makeVerdict({ level: 'CLEAR' }), defaultEscalation),
    );
  });

  it('logs WATCH verdicts without attempting Discord', async () => {
    const dispatcher = new AlertDispatcher(DEFAULT_CONFIG);
    await assert.doesNotReject(() =>
      dispatcher.dispatch(
        makeVerdict({ level: 'WATCH', reason: 'minor anomaly' }),
        defaultEscalation,
      ),
    );
  });

  it('falls back to stderr for ALERT when Discord unavailable', async () => {
    const dispatcher = new AlertDispatcher(DEFAULT_CONFIG);
    // No Discord init, so ALERT should fall back to stderr
    await assert.doesNotReject(() =>
      dispatcher.dispatch(
        makeVerdict({ level: 'ALERT', severity: 'HIGH', reason: 'bad stuff' }),
        defaultEscalation,
      ),
    );
  });

  it('falls back to stderr for KILL when Discord unavailable', async () => {
    const dispatcher = new AlertDispatcher(DEFAULT_CONFIG);
    await assert.doesNotReject(() =>
      dispatcher.dispatch(
        makeVerdict({ level: 'KILL', reason: 'critical compromise' }),
        defaultEscalation,
      ),
    );
  });

  it('sendDegradedAlert does not throw without Discord', async () => {
    const dispatcher = new AlertDispatcher(DEFAULT_CONFIG);
    await assert.doesNotReject(() =>
      dispatcher.sendDegradedAlert('Claude API unreachable'),
    );
  });

  it('shutdown does not throw when Discord was never initialized', async () => {
    const dispatcher = new AlertDispatcher(DEFAULT_CONFIG);
    await assert.doesNotReject(() => dispatcher.shutdown());
  });
});
