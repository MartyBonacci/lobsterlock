import { readFileSync } from 'node:fs';
import type { ConfigFinding } from '../types.js';

/**
 * Analyze an OpenClaw config file for dangerous settings and confirmed-safe settings.
 * Returns findings for each: dangerous settings get high/critical severity,
 * confirmed-safe settings get info severity (used as ground truth by the reasoning engine).
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

  // --- Danger checks ---

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

  // 3. Exec host mode (critical) -- sub-agents bypass approvals
  const tools = config.tools as Record<string, unknown> | undefined;
  const toolsExec = tools?.exec as Record<string, unknown> | undefined;
  if (toolsExec?.host === true || toolsExec?.mode === 'host') {
    findings.push({
      setting: 'tools.exec.host',
      severity: 'critical',
      description: 'Exec tool is configured for host mode. Commands run without container isolation, bypassing sandbox protections.',
      currentValue: toolsExec.host ?? toolsExec.mode,
    });
  }

  // 4. Heartbeat target set to "last" (high)
  const heartbeat = config.heartbeat as Record<string, unknown> | undefined;
  if (heartbeat?.target === 'last') {
    findings.push({
      setting: 'heartbeat.target',
      severity: 'high',
      description: 'Heartbeat target is "last" -- system health dumps will be sent to whoever last messaged the agent, including unknown external contacts.',
      currentValue: 'last',
    });
  }

  // 5. Gateway auth disabled (medium -- lowered for v2026.3.22+ where auth is default)
  const gateway = config.gateway as Record<string, unknown> | undefined;
  const auth = gateway?.auth as Record<string, unknown> | undefined;
  if (gateway && !auth?.token && !auth?.password) {
    findings.push({
      setting: 'gateway.auth',
      severity: 'medium',
      description: 'Gateway authentication is not configured. On OpenClaw v2026.3.22+ this is unusual since auth is enabled by default.',
      currentValue: null,
    });
  }

  // 6. Heartbeat interval below default (medium)
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

  // --- Confirmed safe checks (info severity) ---

  // Gateway auth IS configured
  if (auth?.token || auth?.password) {
    findings.push({
      setting: 'gateway.auth',
      severity: 'info',
      description: `Gateway authentication is configured (${auth.token ? 'token' : 'password'}-based)`,
      currentValue: '[REDACTED]',
    });
  }

  // Sandbox mode enabled
  const agents = config.agents as Record<string, unknown> | undefined;
  const defaults = agents?.defaults as Record<string, unknown> | undefined;
  const sandbox = defaults?.sandbox as Record<string, unknown> | undefined;
  const topSandbox = config.sandbox as Record<string, unknown> | undefined;
  const sandboxMode = sandbox?.mode ?? topSandbox?.mode;
  if (sandboxMode === 'all') {
    findings.push({
      setting: 'sandbox.mode',
      severity: 'info',
      description: 'Sandbox mode is enabled for all operations',
      currentValue: 'all',
    });
  }

  // Trusted proxies configured
  const trustedProxies = gateway?.trustedProxies;
  if (Array.isArray(trustedProxies) && trustedProxies.length > 0) {
    findings.push({
      setting: 'gateway.trustedProxies',
      severity: 'info',
      description: `Trusted proxies configured: ${trustedProxies.join(', ')}`,
      currentValue: trustedProxies,
    });
  }

  // Docker sandbox configured
  const dockerSandbox = sandbox?.docker ?? topSandbox?.docker;
  if (dockerSandbox && typeof dockerSandbox === 'object') {
    findings.push({
      setting: 'sandbox.docker',
      severity: 'info',
      description: 'Docker sandbox is configured for container isolation',
      currentValue: { configured: true },
    });
  }

  return findings;
}

/**
 * Check whether the OpenClaw config has Docker sandbox configured.
 */
export function hasDockerSandbox(configPath: string): boolean {
  try {
    const raw = readFileSync(configPath, 'utf-8');
    const config = JSON.parse(raw) as Record<string, unknown>;
    const agents = config.agents as Record<string, unknown> | undefined;
    const defaults = agents?.defaults as Record<string, unknown> | undefined;
    const sandbox = defaults?.sandbox as Record<string, unknown> | undefined;
    const topSandbox = config.sandbox as Record<string, unknown> | undefined;
    return !!(sandbox?.docker || topSandbox?.docker);
  } catch {
    return false;
  }
}
