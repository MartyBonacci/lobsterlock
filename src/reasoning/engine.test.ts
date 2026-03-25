import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { parseVerdict, ReasoningEngine } from './engine.js';
import { buildReasoningPrompt, SYSTEM_PROMPT } from './prompt.js';
import { SignalBuffer } from '../trigger/buffer.js';
import { initDatabase } from '../storage/audit-log.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type Database from 'better-sqlite3';
import type {
  EscalationState,
  ReasoningContext,
  SignalEntry,
  TriggerEvent,
} from '../types.js';

function makeTrigger(overrides: Partial<TriggerEvent> = {}): TriggerEvent {
  return {
    id: 'trig-1',
    type: 'hard',
    rule: 'new_skill_file',
    source: 'fs-watcher',
    severityFloor: 'WATCH',
    signals: [],
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

describe('parseVerdict', () => {
  it('parses CLEAR', () => {
    const result = parseVerdict('CLEAR\nEverything looks normal.');
    assert.equal(result.level, 'CLEAR');
    assert.equal(result.reason, 'all clear');
    assert.ok(result.reasoning?.includes('Everything looks normal'));
  });

  it('parses WATCH with reason', () => {
    const result = parseVerdict('WATCH new skill file detected in skills directory\nThe file was added but appears benign.');
    assert.equal(result.level, 'WATCH');
    assert.equal(result.reason, 'new skill file detected in skills directory');
  });

  it('parses ALERT LOW', () => {
    const result = parseVerdict('ALERT LOW unusual skill installation pattern\nThree skills installed in rapid succession.');
    assert.equal(result.level, 'ALERT');
    assert.equal(result.severity, 'LOW');
    assert.equal(result.reason, 'unusual skill installation pattern');
  });

  it('parses ALERT HIGH', () => {
    const result = parseVerdict('ALERT HIGH critical vulnerability detected\nThe audit found a critical issue.');
    assert.equal(result.level, 'ALERT');
    assert.equal(result.severity, 'HIGH');
    assert.equal(result.reason, 'critical vulnerability detected');
  });

  it('parses KILL', () => {
    const result = parseVerdict('KILL compromised skill executing unauthorized commands\nImmediate action required.');
    assert.equal(result.level, 'KILL');
    assert.equal(result.reason, 'compromised skill executing unauthorized commands');
  });

  it('handles malformed response', () => {
    const result = parseVerdict('I think everything is fine, no worries!');
    assert.equal(result.level, 'WATCH');
    assert.equal(result.reason, 'malformed reasoning output');
  });

  it('handles empty response', () => {
    const result = parseVerdict('');
    assert.equal(result.level, 'WATCH');
    assert.equal(result.reason, 'malformed reasoning output');
  });

  it('extracts verdict from multiline response', () => {
    const response = `Let me analyze the signals...

WATCH unusual outbound connection pattern
The skills directory shows a new file that was created 2 minutes before an outbound connection was detected. While each event is benign individually, the timing correlation is worth monitoring.`;
    const result = parseVerdict(response);
    assert.equal(result.level, 'WATCH');
    assert.equal(result.reason, 'unusual outbound connection pattern');
  });
});

describe('buildReasoningPrompt', () => {
  it('includes all XML sections', () => {
    const context: ReasoningContext = {
      triggerEvent: makeTrigger(),
      signalBuffer: [],
      evictedCount: 0,
      securityPosture: null,
      skillInventoryDelta: null,
      memoryIntegrity: null,
      escalationState: defaultEscalation,
      previousVerdict: null,
    };

    const prompt = buildReasoningPrompt(context);

    assert.ok(prompt.includes('<trigger_event>'));
    assert.ok(prompt.includes('</trigger_event>'));
    assert.ok(prompt.includes('<signal_buffer>'));
    assert.ok(prompt.includes('</signal_buffer>'));
    assert.ok(prompt.includes('<security_posture>'));
    assert.ok(prompt.includes('</security_posture>'));
    assert.ok(prompt.includes('<skill_inventory_delta>'));
    assert.ok(prompt.includes('</skill_inventory_delta>'));
    assert.ok(prompt.includes('<escalation_context>'));
    assert.ok(prompt.includes('</escalation_context>'));
    assert.ok(prompt.includes('<previous_verdict>'));
    assert.ok(prompt.includes('</previous_verdict>'));
  });

  it('includes evicted count when > 0', () => {
    const context: ReasoningContext = {
      triggerEvent: makeTrigger(),
      signalBuffer: [],
      evictedCount: 47,
      securityPosture: null,
      skillInventoryDelta: null,
      memoryIntegrity: null,
      escalationState: defaultEscalation,
      previousVerdict: null,
    };

    const prompt = buildReasoningPrompt(context);
    assert.ok(prompt.includes('47 additional entries'));
  });

  it('handles null previous verdict', () => {
    const context: ReasoningContext = {
      triggerEvent: makeTrigger(),
      signalBuffer: [],
      evictedCount: 0,
      securityPosture: null,
      skillInventoryDelta: null,
      memoryIntegrity: null,
      escalationState: defaultEscalation,
      previousVerdict: null,
    };

    const prompt = buildReasoningPrompt(context);
    assert.ok(prompt.includes('No previous verdict'));
  });

  it('includes escalation warning when watch count >= 3', () => {
    const context: ReasoningContext = {
      triggerEvent: makeTrigger(),
      signalBuffer: [],
      evictedCount: 0,
      securityPosture: null,
      skillInventoryDelta: null,
      memoryIntegrity: null,
      escalationState: { ...defaultEscalation, consecutive_watch_count: 3 },
      previousVerdict: null,
    };

    const prompt = buildReasoningPrompt(context);
    assert.ok(prompt.includes('floors at ALERT LOW'));
  });
});

describe('ReasoningEngine', () => {
  let db: Database.Database;
  let buffer: SignalBuffer;

  beforeEach(() => {
    db = initDatabase(':memory:');
    buffer = new SignalBuffer(500);
  });

  it('invokes Claude and returns parsed verdict', async () => {
    const mockClient = {
      messages: {
        create: async () => ({
          content: [{ type: 'text' as const, text: 'WATCH suspicious activity\nA new skill was installed.' }],
        }),
      },
    } as unknown as import('@anthropic-ai/sdk').default;

    const engine = new ReasoningEngine(DEFAULT_CONFIG, db, buffer, mockClient);
    const verdict = await engine.invoke(makeTrigger(), defaultEscalation, null);

    assert.ok(verdict);
    assert.equal(verdict.level, 'WATCH');
    assert.equal(verdict.reason, 'suspicious activity');
  });

  it('handles malformed Claude response', async () => {
    const mockClient = {
      messages: {
        create: async () => ({
          content: [{ type: 'text' as const, text: 'I am not sure what to think about this.' }],
        }),
      },
    } as unknown as import('@anthropic-ai/sdk').default;

    const engine = new ReasoningEngine(DEFAULT_CONFIG, db, buffer, mockClient);
    const verdict = await engine.invoke(makeTrigger(), defaultEscalation, null);

    assert.ok(verdict);
    assert.equal(verdict.level, 'WATCH');
    assert.equal(verdict.reason, 'malformed reasoning output');
  });

  it('returns null on API failure (degraded mode)', async () => {
    let callCount = 0;
    const mockClient = {
      messages: {
        create: async () => {
          callCount++;
          throw new Error('API unavailable');
        },
      },
    } as unknown as import('@anthropic-ai/sdk').default;

    const config = { ...DEFAULT_CONFIG };
    const engine = new ReasoningEngine(config, db, buffer, mockClient);
    const verdict = await engine.invoke(makeTrigger(), defaultEscalation, null);

    assert.equal(verdict, null);
    assert.equal(callCount, 2); // Original + 1 retry
  });

  it('returns busy verdict when already processing', async () => {
    let resolveCall: ((value: unknown) => void) | null = null;
    const mockClient = {
      messages: {
        create: () => new Promise((resolve) => { resolveCall = resolve; }),
      },
    } as unknown as import('@anthropic-ai/sdk').default;

    const engine = new ReasoningEngine(DEFAULT_CONFIG, db, buffer, mockClient);

    // Start first call (will hang)
    const first = engine.invoke(makeTrigger(), defaultEscalation, null);

    // Second call should get busy verdict
    const second = await engine.invoke(makeTrigger(), defaultEscalation, null);
    assert.ok(second);
    assert.equal(second.level, 'WATCH');
    assert.equal(second.reason, 'reasoning engine busy');

    // Clean up
    resolveCall!({
      content: [{ type: 'text', text: 'CLEAR' }],
    });
    await first;
  });

  it('logs audit entry to SQLite', async () => {
    const mockClient = {
      messages: {
        create: async () => ({
          content: [{ type: 'text' as const, text: 'ALERT LOW suspicious pattern\nMultiple signals correlate.' }],
        }),
      },
    } as unknown as import('@anthropic-ai/sdk').default;

    const engine = new ReasoningEngine(DEFAULT_CONFIG, db, buffer, mockClient);
    await engine.invoke(makeTrigger(), defaultEscalation, null);

    const row = db.prepare('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 1').get() as Record<string, unknown>;
    assert.ok(row);
    assert.equal(row.verdict_level, 'ALERT');
    assert.equal(row.verdict_severity, 'LOW');
  });
});
