import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PortCheckerCollector } from './port-checker.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type { ExecResult } from '../util/exec.js';
import type { SignalEntry } from '../types.js';

const LOOPBACK_OUTPUT = `State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN 0      511     127.0.0.1:18789     0.0.0.0:*
LISTEN 0      511     [::1]:18789         [::]:*
LISTEN 0      4096    0.0.0.0:22          0.0.0.0:*`;

const EXPOSED_OUTPUT = `State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN 0      511     0.0.0.0:18789       0.0.0.0:*
LISTEN 0      511     [::]:18789          [::]:*
LISTEN 0      4096    0.0.0.0:22          0.0.0.0:*`;

const SPECIFIC_IP_OUTPUT = `State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN 0      511     192.168.1.100:18789  0.0.0.0:*
LISTEN 0      4096    0.0.0.0:22           0.0.0.0:*`;

function mockExec(stdout: string): (cmd: string, args: string[]) => Promise<ExecResult> {
  return async () => ({ stdout, stderr: '', exitCode: 0, timedOut: false });
}

describe('PortCheckerCollector', () => {
  describe('parseBindings', () => {
    it('parses loopback bindings', () => {
      const collector = new PortCheckerCollector(DEFAULT_CONFIG);
      const bindings = collector.parseBindings(LOOPBACK_OUTPUT);
      const gateway = bindings.filter((b) => b.port === 18789);
      assert.equal(gateway.length, 2);
      assert.equal(gateway[0].address, '127.0.0.1');
      assert.equal(gateway[1].address, '[::1]');
    });

    it('parses wildcard bindings', () => {
      const collector = new PortCheckerCollector(DEFAULT_CONFIG);
      const bindings = collector.parseBindings(EXPOSED_OUTPUT);
      const gateway = bindings.filter((b) => b.port === 18789);
      assert.equal(gateway.length, 2);
      assert.equal(gateway[0].address, '0.0.0.0');
    });

    it('parses specific IP bindings', () => {
      const collector = new PortCheckerCollector(DEFAULT_CONFIG);
      const bindings = collector.parseBindings(SPECIFIC_IP_OUTPUT);
      const gateway = bindings.filter((b) => b.port === 18789);
      assert.equal(gateway.length, 1);
      assert.equal(gateway[0].address, '192.168.1.100');
    });
  });

  describe('exposure detection', () => {
    it('does not alert when port is loopback-only', async () => {
      const signals: SignalEntry[] = [];
      const collector = new PortCheckerCollector(DEFAULT_CONFIG, mockExec(LOOPBACK_OUTPUT));
      collector.on('signal', (s: SignalEntry) => signals.push(s));

      await collector.start();
      collector.stop();

      const exposureSignals = signals.filter(
        (s) => (s.payload as Record<string, unknown>).portExposed,
      );
      assert.equal(exposureSignals.length, 0);
    });

    it('alerts on baseline when port is already exposed', async () => {
      const signals: SignalEntry[] = [];
      const collector = new PortCheckerCollector(DEFAULT_CONFIG, mockExec(EXPOSED_OUTPUT));
      collector.on('signal', (s: SignalEntry) => signals.push(s));

      await collector.start();
      collector.stop();

      const exposureSignals = signals.filter(
        (s) => (s.payload as Record<string, unknown>).portExposed,
      );
      assert.ok(exposureSignals.length >= 1);
      assert.equal(exposureSignals[0].severity, 'critical');
      assert.ok(exposureSignals[0].summary.includes('18789'));
    });

    it('alerts on transition from safe to exposed', async () => {
      let callCount = 0;
      const exec = async (): Promise<ExecResult> => {
        callCount++;
        return {
          stdout: callCount === 1 ? LOOPBACK_OUTPUT : EXPOSED_OUTPUT,
          stderr: '', exitCode: 0, timedOut: false,
        };
      };

      const signals: SignalEntry[] = [];
      const config = { ...DEFAULT_CONFIG, audit_poll_interval_seconds: 0.01 };
      const collector = new PortCheckerCollector(config, exec);
      collector.on('signal', (s: SignalEntry) => signals.push(s));

      await collector.start();
      await new Promise((r) => setTimeout(r, 50));
      collector.stop();

      const exposureSignals = signals.filter(
        (s) => (s.payload as Record<string, unknown>).portExposed,
      );
      assert.ok(exposureSignals.length >= 1);
      assert.equal(exposureSignals[0].severity, 'critical');
    });

    it('detects specific non-loopback IP', async () => {
      const signals: SignalEntry[] = [];
      const collector = new PortCheckerCollector(DEFAULT_CONFIG, mockExec(SPECIFIC_IP_OUTPUT));
      collector.on('signal', (s: SignalEntry) => signals.push(s));

      await collector.start();
      collector.stop();

      const exposureSignals = signals.filter(
        (s) => (s.payload as Record<string, unknown>).portExposed,
      );
      assert.ok(exposureSignals.length >= 1);
      assert.ok(exposureSignals[0].summary.includes('192.168.1.100'));
    });

    it('emits health signal on ss failure', async () => {
      const exec = async (): Promise<ExecResult> => ({
        stdout: '', stderr: 'command not found', exitCode: 127, timedOut: false,
      });

      const signals: SignalEntry[] = [];
      const collector = new PortCheckerCollector(DEFAULT_CONFIG, exec);
      collector.on('signal', (s: SignalEntry) => signals.push(s));

      await collector.start();
      collector.stop();

      const health = signals.filter(
        (s) => (s.payload as Record<string, unknown>).selfHealth,
      );
      assert.ok(health.length >= 1);
    });
  });
});
