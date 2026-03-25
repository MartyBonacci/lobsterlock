#!/usr/bin/env node

import { config as loadDotenv } from 'dotenv';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Command } from 'commander';
import { loadConfig, resolveConfigPath, ensureConfigDir } from './config.js';
import { DB_FILE, PID_FILE } from './constants.js';

// Load .env from ~/.lobsterlock/.env (override existing env vars)
loadDotenv({ path: join(homedir(), '.lobsterlock', '.env'), override: true });
import {
  initDatabase,
  getLastVerdict,
  getUnacknowledgedAlerts,
  acknowledgeAll,
  loadEscalationState,
  saveEscalationState,
} from './storage/audit-log.js';
import { Orchestrator } from './orchestrator.js';
import { checkStalePid, readPid, removePid } from './util/pid.js';

const program = new Command();

program
  .name('lobsterlock')
  .description('Semantic security orchestrator for OpenClaw deployments')
  .version('0.1.0');

program
  .command('start')
  .description('Start the LobsterLock monitoring daemon')
  .action(async () => {
    const pidPath = resolveConfigPath(PID_FILE);
    const pidState = checkStalePid(pidPath);

    if (pidState === 'running') {
      const pid = readPid(pidPath);
      console.error(`LobsterLock is already running (PID ${pid})`);
      process.exit(1);
    }

    if (pidState === 'stale') {
      console.log('[WARN] Recovered from unclean shutdown (stale PID file)');
      removePid(pidPath);
    }

    const config = loadConfig();
    const orchestrator = new Orchestrator(config);
    await orchestrator.start();
  });

program
  .command('status')
  .description('Show current LobsterLock status')
  .action(() => {
    const pidPath = resolveConfigPath(PID_FILE);
    const pidState = checkStalePid(pidPath);

    if (pidState !== 'running') {
      console.log('LobsterLock is not running');
      process.exit(0);
    }

    const pid = readPid(pidPath);
    const dbPath = resolveConfigPath(DB_FILE);

    try {
      const db = initDatabase(dbPath);
      const escalation = loadEscalationState(db);
      const lastEntry = getLastVerdict(db);
      const unacked = getUnacknowledgedAlerts(db);

      console.log(`LobsterLock is running (PID ${pid})`);
      console.log();
      console.log('Escalation State:');
      console.log(`  Consecutive WATCH count: ${escalation.consecutive_watch_count}`);
      console.log(`  Paused: ${escalation.paused}`);
      console.log(`  Pending alerts: ${unacked.length}`);

      if (lastEntry) {
        const ts = new Date(lastEntry.timestamp).toISOString();
        console.log();
        console.log('Last Verdict:');
        console.log(`  Level: ${lastEntry.verdict_level}${lastEntry.verdict_severity ? ` ${lastEntry.verdict_severity}` : ''}`);
        console.log(`  Reason: ${lastEntry.verdict_reason}`);
        console.log(`  Time: ${ts}`);
        console.log(`  Acknowledged: ${lastEntry.acknowledged}`);
      } else {
        console.log();
        console.log('No reasoning cycles recorded yet');
      }

      db.close();
    } catch (err) {
      console.error('Failed to read status:', err);
      process.exit(1);
    }
  });

program
  .command('last')
  .description('Show the most recent reasoning cycle')
  .action(() => {
    ensureConfigDir();
    const dbPath = resolveConfigPath(DB_FILE);

    try {
      const db = initDatabase(dbPath);
      const entry = getLastVerdict(db);

      if (!entry) {
        console.log('No reasoning cycles recorded yet');
        db.close();
        return;
      }

      const ts = new Date(entry.timestamp).toISOString();
      console.log(`Verdict: ${entry.verdict_level}${entry.verdict_severity ? ` ${entry.verdict_severity}` : ''}`);
      console.log(`Reason: ${entry.verdict_reason}`);
      console.log(`Time: ${ts}`);
      console.log(`Acknowledged: ${entry.acknowledged}`);
      console.log();

      // Show raw response
      console.log('Raw Response:');
      console.log(entry.raw_response);

      // Show trigger info
      try {
        const trigger = JSON.parse(entry.trigger_event);
        console.log();
        console.log('Trigger:');
        console.log(`  Type: ${trigger.type}`);
        console.log(`  Rule: ${trigger.rule}`);
        console.log(`  Source: ${trigger.source}`);
      } catch {
        // Skip if malformed
      }

      db.close();
    } catch (err) {
      console.error('Failed to read last verdict:', err);
      process.exit(1);
    }
  });

program
  .command('check')
  .description('Run a one-shot security check (does not require running daemon)')
  .action(async () => {
    if (!process.env.ANTHROPIC_API_KEY) {
      console.error('ANTHROPIC_API_KEY environment variable is required');
      process.exit(1);
    }

    const config = loadConfig();

    console.log('Running one-shot security check...');
    console.log();

    // Import the reasoning pieces
    const { execCommand } = await import('./util/exec.js');
    const { buildReasoningPrompt, SYSTEM_PROMPT } = await import('./reasoning/prompt.js');
    const { parseVerdict } = await import('./reasoning/engine.js');
    const { default: Anthropic } = await import('@anthropic-ai/sdk');

    // Gather fresh data
    let auditData: Record<string, unknown> | null = null;
    let skillsData: Record<string, unknown> | null = null;

    try {
      const auditResult = await execCommand(config.openclaw_cli, ['security', 'audit', '--json']);
      if (auditResult.stdout) {
        auditData = JSON.parse(auditResult.stdout);
        console.log('Audit data collected');
      }
    } catch (err) {
      console.error('Failed to run security audit:', err);
    }

    try {
      const skillsResult = await execCommand(config.openclaw_cli, ['skills', 'list', '--json']);
      if (skillsResult.stdout) {
        skillsData = { skills: JSON.parse(skillsResult.stdout) };
        console.log('Skills data collected');
      }
    } catch (err) {
      console.error('Failed to list skills:', err);
    }

    // Build prompt
    const context = {
      triggerEvent: {
        id: 'manual-check',
        type: 'manual' as const,
        rule: 'lobsterlock_check',
        source: 'cli',
        severityFloor: 'WATCH' as const,
        signals: [],
        timestamp: Date.now(),
      },
      signalBuffer: [],
      evictedCount: 0,
      securityPosture: auditData,
      skillInventoryDelta: skillsData,
      memoryIntegrity: null,
      escalationState: {
        consecutive_watch_count: 0,
        pending_alert_id: null,
        paused: false,
        last_verdict_level: null,
        last_verdict_timestamp: null,
      },
      previousVerdict: null,
    };

    const prompt = buildReasoningPrompt(context);

    // Call Claude
    try {
      const client = new Anthropic();
      const response = await client.messages.create({
        model: config.model,
        max_tokens: config.reasoning_budget,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: prompt }],
      });

      const textBlock = response.content.find((b) => b.type === 'text');
      const responseText = textBlock ? textBlock.text : '';

      console.log();
      console.log('--- Claude Response ---');
      console.log(responseText);
      console.log();

      const verdict = parseVerdict(responseText);
      console.log(`Verdict: ${verdict.level}${verdict.severity ? ` ${verdict.severity}` : ''}`);
      console.log(`Reason: ${verdict.reason}`);
    } catch (err) {
      console.error('Failed to call Claude:', err);
      process.exit(1);
    }
  });

program
  .command('ack')
  .description('Acknowledge all pending alerts and reset escalation')
  .action(() => {
    ensureConfigDir();
    const dbPath = resolveConfigPath(DB_FILE);

    try {
      const db = initDatabase(dbPath);
      const count = acknowledgeAll(db);

      // Reset escalation state
      const escalation = loadEscalationState(db);
      escalation.consecutive_watch_count = 0;
      escalation.pending_alert_id = null;
      escalation.paused = false;
      saveEscalationState(db, escalation);

      console.log(`Acknowledged ${count} alert(s). Escalation reset.`);
      if (escalation.paused) {
        console.log('Monitoring will resume on next trigger.');
      }

      db.close();
    } catch (err) {
      console.error('Failed to acknowledge:', err);
      process.exit(1);
    }
  });

program.parse();
