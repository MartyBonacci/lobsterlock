import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { analyzeConfig } from './config-analyzer.js';

describe('config-analyzer', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'lobsterlock-config-test-'));
  const configPath = join(tempDir, 'openclaw.json');

  afterEach(() => {
    try { unlinkSync(configPath); } catch {}
  });

  it('returns empty for missing file', () => {
    const findings = analyzeConfig('/nonexistent/path.json');
    assert.equal(findings.length, 0);
  });

  it('returns parse error for invalid JSON', () => {
    writeFileSync(configPath, 'not json!');
    const findings = analyzeConfig(configPath);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].setting, 'config_parse_error');
  });

  it('detects dangerouslyAllowPrivateNetwork', () => {
    writeFileSync(configPath, JSON.stringify({
      browser: { ssrfPolicy: { dangerouslyAllowPrivateNetwork: true } },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting.includes('dangerouslyAllowPrivateNetwork'));
    assert.ok(match);
    assert.equal(match.severity, 'critical');
  });

  it('detects disabled exec.approvals', () => {
    writeFileSync(configPath, JSON.stringify({
      exec: { approvals: { set: 'off' } },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'exec.approvals');
    assert.ok(match);
    assert.equal(match.severity, 'critical');
  });

  it('detects heartbeat.target "last"', () => {
    writeFileSync(configPath, JSON.stringify({
      heartbeat: { target: 'last' },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'heartbeat.target');
    assert.ok(match);
    assert.equal(match.severity, 'high');
  });

  it('detects missing gateway auth', () => {
    writeFileSync(configPath, JSON.stringify({
      gateway: { bind: '127.0.0.1', port: 18789 },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'gateway.auth');
    assert.ok(match);
    assert.equal(match.severity, 'high');
  });

  it('detects short heartbeat interval', () => {
    writeFileSync(configPath, JSON.stringify({
      heartbeat: { interval: 5 },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'heartbeat.interval');
    assert.ok(match);
    assert.equal(match.severity, 'medium');
  });

  it('returns empty for safe config', () => {
    writeFileSync(configPath, JSON.stringify({
      gateway: { auth: { token: 'secret123' }, bind: '127.0.0.1' },
      heartbeat: { target: 'none', interval: 30 },
      exec: { approvals: { set: 'on' } },
      browser: { ssrfPolicy: { dangerouslyAllowPrivateNetwork: false } },
    }));
    const findings = analyzeConfig(configPath);
    assert.equal(findings.length, 0);
  });
});
