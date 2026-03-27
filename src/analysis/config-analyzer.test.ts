import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { analyzeConfig, hasDockerSandbox } from './config-analyzer.js';

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

  it('detects exec host mode', () => {
    writeFileSync(configPath, JSON.stringify({
      tools: { exec: { host: true } },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'tools.exec.host');
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

  it('detects missing gateway auth at medium severity', () => {
    writeFileSync(configPath, JSON.stringify({
      gateway: { bind: '127.0.0.1', port: 18789 },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'gateway.auth' && f.severity !== 'info');
    assert.ok(match);
    assert.equal(match.severity, 'medium');
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

  // --- Positive findings ---

  it('confirms gateway auth when token is set', () => {
    writeFileSync(configPath, JSON.stringify({
      gateway: { auth: { token: 'secret123' } },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'gateway.auth' && f.severity === 'info');
    assert.ok(match);
    assert.ok(match.description.includes('token'));
    assert.equal(match.currentValue, '[REDACTED]');
  });

  it('confirms sandbox mode all', () => {
    writeFileSync(configPath, JSON.stringify({
      agents: { defaults: { sandbox: { mode: 'all' } } },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'sandbox.mode');
    assert.ok(match);
    assert.equal(match.severity, 'info');
  });

  it('confirms trusted proxies', () => {
    writeFileSync(configPath, JSON.stringify({
      gateway: { auth: { token: 'x' }, trustedProxies: ['127.0.0.1', '::1'] },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'gateway.trustedProxies');
    assert.ok(match);
    assert.equal(match.severity, 'info');
  });

  it('confirms Docker sandbox configured', () => {
    writeFileSync(configPath, JSON.stringify({
      agents: { defaults: { sandbox: { docker: { network: 'bridge' } } } },
    }));
    const findings = analyzeConfig(configPath);
    const match = findings.find((f) => f.setting === 'sandbox.docker');
    assert.ok(match);
    assert.equal(match.severity, 'info');
  });

  it('returns mixed danger + safe findings', () => {
    writeFileSync(configPath, JSON.stringify({
      gateway: { auth: { token: 'secret' }, trustedProxies: ['127.0.0.1'] },
      browser: { ssrfPolicy: { dangerouslyAllowPrivateNetwork: true } },
      agents: { defaults: { sandbox: { mode: 'all', docker: { network: 'bridge' } } } },
    }));
    const findings = analyzeConfig(configPath);
    const dangers = findings.filter((f) => f.severity !== 'info');
    const safe = findings.filter((f) => f.severity === 'info');
    assert.ok(dangers.length >= 1); // dangerouslyAllowPrivateNetwork
    assert.ok(safe.length >= 3); // auth, sandbox, docker, proxies
  });

  it('returns no danger findings for fully safe config', () => {
    writeFileSync(configPath, JSON.stringify({
      gateway: { auth: { token: 'secret123' }, bind: '127.0.0.1', trustedProxies: ['127.0.0.1'] },
      heartbeat: { target: 'none', interval: 30 },
      exec: { approvals: { set: 'on' } },
      browser: { ssrfPolicy: { dangerouslyAllowPrivateNetwork: false } },
      agents: { defaults: { sandbox: { mode: 'all' } } },
    }));
    const findings = analyzeConfig(configPath);
    const dangers = findings.filter((f) => f.severity !== 'info');
    assert.equal(dangers.length, 0);
  });
});

describe('hasDockerSandbox', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'lobsterlock-docker-test-'));
  const configPath = join(tempDir, 'openclaw.json');

  afterEach(() => {
    try { unlinkSync(configPath); } catch {}
  });

  it('returns true when Docker sandbox configured', () => {
    writeFileSync(configPath, JSON.stringify({
      agents: { defaults: { sandbox: { docker: { network: 'bridge' } } } },
    }));
    assert.equal(hasDockerSandbox(configPath), true);
  });

  it('returns false when no Docker sandbox', () => {
    writeFileSync(configPath, JSON.stringify({
      agents: { defaults: { sandbox: { mode: 'all' } } },
    }));
    assert.equal(hasDockerSandbox(configPath), false);
  });

  it('returns false for missing file', () => {
    assert.equal(hasDockerSandbox('/nonexistent'), false);
  });
});
