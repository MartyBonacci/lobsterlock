import { readFileSync } from 'node:fs';
import type { ConfigFinding } from '../types.js';

/**
 * Analyze an OpenClaw config file for dangerous settings.
 * Returns findings for each dangerous configuration detected.
 */
export function analyzeConfig(configPath: string): ConfigFinding[] {
  let raw: string;
  try {
    raw = readFileSync(configPath, 'utf-8');
  } catch {
    return [];
  }

  let config: Record<string, unknown>;
  try {
    config = JSON.parse(raw);
  } catch {
    return [{
      setting: 'config_parse_error',
      severity: 'medium',
      description: 'OpenClaw config file contains invalid JSON',
      currentValue: null,
    }];
  }

  const findings: ConfigFinding[] = [];

  // 1. SSRF policy: dangerouslyAllowPrivateNetwork (critical)
  const browser = config.browser as Record<string, unknown> | undefined;
  const ssrfPolicy = browser?.ssrfPolicy as Record<string, unknown> | undefined;
  if (ssrfPolicy?.dangerouslyAllowPrivateNetwork === true) {
    findings.push({
      setting: 'browser.ssrfPolicy.dangerouslyAllowPrivateNetwork',
      severity: 'critical',
      description: 'SSRF policy allows access to private/internal network addresses. Agents can reach cloud metadata (169.254.169.254) and internal services.',
      currentValue: true,
    });
  }

  // 2. Execution approvals disabled (critical)
  const exec = config.exec as Record<string, unknown> | undefined;
  const approvals = exec?.approvals as Record<string, unknown> | undefined;
  if (approvals?.set === 'off' || approvals?.set === false || exec?.approvals === false) {
    findings.push({
      setting: 'exec.approvals',
      severity: 'critical',
      description: 'Execution approvals are disabled. The agent can run commands without sandboxing. This is the first step in the RCE kill chain (CVE-2026-25253).',
      currentValue: approvals?.set ?? exec?.approvals,
    });
  }

  // 3. Heartbeat target set to "last" (high)
  const heartbeat = config.heartbeat as Record<string, unknown> | undefined;
  if (heartbeat?.target === 'last') {
    findings.push({
      setting: 'heartbeat.target',
      severity: 'high',
      description: 'Heartbeat target is "last" -- system health dumps will be sent to whoever last messaged the agent, including unknown external contacts.',
      currentValue: 'last',
    });
  }

  // 4. Gateway auth disabled (high)
  const gateway = config.gateway as Record<string, unknown> | undefined;
  const auth = gateway?.auth as Record<string, unknown> | undefined;
  if (gateway && !auth?.token && !auth?.password) {
    findings.push({
      setting: 'gateway.auth',
      severity: 'high',
      description: 'Gateway authentication is not configured. Any local process or SSRF can interact with the agent without credentials.',
      currentValue: null,
    });
  }

  // 5. Heartbeat interval below default (medium)
  if (heartbeat?.interval !== undefined) {
    const interval = Number(heartbeat.interval);
    if (!isNaN(interval) && interval < 30) {
      findings.push({
        setting: 'heartbeat.interval',
        severity: 'medium',
        description: `Heartbeat interval is ${interval} minutes (default: 30). Shorter intervals increase token cost and attack surface for heartbeat-based exploits.`,
        currentValue: interval,
      });
    }
  }

  return findings;
}
