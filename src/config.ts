import { readFileSync, mkdirSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from './constants.js';
import type { LobsterLockConfig } from './types.js';

/**
 * Resolve ~ to the user's home directory.
 */
export function resolveConfigPath(p: string): string {
  if (p.startsWith('~/') || p === '~') {
    return join(homedir(), p.slice(1));
  }
  return p;
}

/**
 * Ensure the ~/.lobsterlock directory exists.
 */
export function ensureConfigDir(): string {
  const dir = resolveConfigPath('~/.lobsterlock');
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  return dir;
}

/**
 * Load configuration from ~/.lobsterlock/config.json.
 * Deep-merges with DEFAULT_CONFIG. Missing file uses pure defaults.
 * Malformed JSON causes process exit with clear error.
 */
export function loadConfig(configPath?: string): LobsterLockConfig {
  const path = configPath ?? resolveConfigPath('~/.lobsterlock/config.json');

  if (!existsSync(path)) {
    ensureConfigDir();
    console.error(`[WARN] Config file not found at ${path}, using defaults`);
    return { ...DEFAULT_CONFIG };
  }

  let raw: string;
  try {
    raw = readFileSync(path, 'utf-8');
  } catch (err) {
    console.error(`[FATAL] Cannot read config file: ${path}`);
    console.error(err);
    process.exit(1);
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw);
  } catch {
    console.error(`[FATAL] Malformed JSON in config file: ${path}`);
    process.exit(1);
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    console.error(`[FATAL] Config file must contain a JSON object: ${path}`);
    process.exit(1);
  }

  // Validate known fields have correct types
  const validators: Record<string, string> = {
    openclaw_service: 'string',
    openclaw_cli: 'string',
    model: 'string',
    openclaw_version_lock: 'string',
    discord_channel_id: 'string',
    kill_on_critical: 'boolean',
    kill_requires_confirmation: 'boolean',
    hourly_digest: 'boolean',
    reasoning_budget: 'number',
    threshold_window_seconds: 'number',
    threshold_signal_count: 'number',
    audit_poll_interval_seconds: 'number',
    trigger_debounce_ms: 'number',
    signal_buffer_max_entries: 'number',
  };

  for (const [key, expectedType] of Object.entries(validators)) {
    if (key in parsed && typeof parsed[key] !== expectedType) {
      console.error(`[FATAL] Config field "${key}" must be a ${expectedType}, got ${typeof parsed[key]}`);
      process.exit(1);
    }
  }

  if ('skills_watch' in parsed && !Array.isArray(parsed.skills_watch)) {
    console.error(`[FATAL] Config field "skills_watch" must be an array`);
    process.exit(1);
  }

  // Deep merge with defaults (one level deep is sufficient for this config shape)
  return { ...DEFAULT_CONFIG, ...parsed } as LobsterLockConfig;
}
