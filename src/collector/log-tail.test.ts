import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { LogTailCollector } from './log-tail.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type { SignalEntry } from '../types.js';
import type { ChildProcess } from 'node:child_process';

function createMockChild(): { child: ChildProcess; pushLine: (line: string) => void } {
  const stdout = new Readable({ read() {} });
  const child = Object.assign(new EventEmitter(), {
    stdout,
    stderr: new Readable({ read() {} }),
    stdin: null,
    stdio: [null, stdout, null] as const,
    pid: 12345,
    connected: true,
    exitCode: null,
    signalCode: null,
    killed: false,
    kill: () => true,
    send: () => false,
    disconnect: () => {},
    unref: () => child,
    ref: () => child,
    [Symbol.dispose]: () => {},
  }) as unknown as ChildProcess;

  const pushLine = (line: string) => {
    stdout.push(line + '\n');
  };

  return { child, pushLine };
}

describe('LogTailCollector', () => {
  it('detects FATAL ERROR log lines', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: FATAL ERROR: something went wrong');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.ok(signals.length >= 1);
    assert.equal(signals[0].type, 'log_anomaly');
    assert.equal(signals[0].severity, 'critical');
    assert.ok(signals[0].summary.includes('FATAL ERROR'));
  });

  it('detects heap limit errors', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: JavaScript heap out of memory');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.ok(signals.length >= 1);
    assert.equal(signals[0].severity, 'critical');
  });

  it('detects gateway closed with code', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: gateway closed with code 1006');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.ok(signals.length >= 1);
    assert.equal(signals[0].severity, 'high');
  });

  it('detects auth failure', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: authentication failure for user X');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.ok(signals.length >= 1);
    assert.equal(signals[0].severity, 'medium');
  });

  it('detects OpenClaw restart', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host systemd[1]: Started openclaw');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.ok(signals.length >= 1);
    assert.equal(signals[0].type, 'process_event');
    assert.ok(signals[0].summary.includes('restart'));
  });

  it('ignores normal log lines', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: Processing message from user');
    pushLine('2026-03-24T12:00:01-0600 host openclaw[1234]: Skill execution completed');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.equal(signals.length, 0);
  });

  it('detects cross-origin WebSocket connection', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: [ws] webchat connected conn=abc123 remote=203.0.113.5 client=unknown');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.ok(signals.length >= 1);
    assert.equal(signals[0].severity, 'high');
  });

  it('ignores localhost WebSocket connection', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: [ws] webchat connected conn=abc123 remote=127.0.0.1 client=openclaw-control-ui');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.equal(signals.length, 0);
  });

  it('ignores Tailscale WebSocket connection', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: [ws] webchat connected conn=abc remote=100.64.0.1 client=ts');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.equal(signals.length, 0);
  });

  it('detects heartbeat delivery to non-owner', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: [heartbeat] delivering response to external-user');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.ok(signals.length >= 1);
    assert.equal(signals[0].severity, 'high');
  });

  it('ignores heartbeat delivery to none', async () => {
    const { child, pushLine } = createMockChild();
    const spawnFn = () => child;

    const signals: SignalEntry[] = [];
    const collector = new LogTailCollector(DEFAULT_CONFIG, spawnFn);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();

    pushLine('2026-03-24T12:00:00-0600 host openclaw[1234]: [heartbeat] delivering response to none');
    await new Promise((r) => setTimeout(r, 20));

    collector.stop();

    assert.equal(signals.length, 0);
  });
});
