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

    // Analyze actual OpenClaw config file (ground truth)
    const { analyzeConfig } = await import('./analysis/config-analyzer.js');
    const { OPENCLAW_CONFIG_PATH } = await import('./constants.js');
    const configFindings = analyzeConfig(OPENCLAW_CONFIG_PATH);
    const dangers = configFindings.filter((f) => f.severity !== 'info');
    const safe = configFindings.filter((f) => f.severity === 'info');
    console.log(`Config analysis: ${dangers.length} warning(s), ${safe.length} confirmed safe`);

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
      configAnalysis: configFindings,
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

program
  .command('install-service')
  .description('Install LobsterLock as a systemd service')
  .action(async () => {
    const { existsSync, copyFileSync } = await import('node:fs');
    const { execSync } = await import('node:child_process');
    const serviceSrc = join(process.cwd(), 'lobsterlock.service');
    const serviceDest = '/etc/systemd/system/lobsterlock.service';

    if (!existsSync(serviceSrc)) {
      console.error(`Service file not found: ${serviceSrc}`);
      console.error('Run this command from the lobsterlock project directory.');
      process.exit(1);
    }

    // Check if we can write to systemd directory
    try {
      copyFileSync(serviceSrc, serviceDest);
      execSync('systemctl daemon-reload');
      execSync('systemctl enable lobsterlock');
      execSync('systemctl start lobsterlock');
      console.log('LobsterLock service installed and started.');
      console.log();
      console.log('  systemctl status lobsterlock   # check status');
      console.log('  journalctl -u lobsterlock -f   # follow logs');
      console.log('  systemctl stop lobsterlock     # stop');
    } catch {
      console.log('Could not install automatically (requires root). Run these commands manually:');
      console.log();
      console.log(`  sudo cp ${serviceSrc} ${serviceDest}`);
      console.log('  sudo systemctl daemon-reload');
      console.log('  sudo systemctl enable lobsterlock');
      console.log('  sudo systemctl start lobsterlock');
    }
  });

program
  .command('test-kill')
  .description('Test the kill switch against the live OpenClaw instance')
  .option('--dry-run', 'Show what would happen without executing')
  .option('--restore', 'Restore OpenClaw after a test kill')
  .action(async (opts) => {
    const { execCommand } = await import('./util/exec.js');
    const readline = await import('node:readline');
    const config = loadConfig();

    const ask = (question: string): Promise<string> => {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      return new Promise((resolve) => {
        rl.question(question, (answer) => {
          rl.close();
          resolve(answer.trim().toLowerCase());
        });
      });
    };

    if (opts.restore) {
      console.log('Restoring OpenClaw...');
      if (opts.dryRun) {
        console.log('[DRY RUN] Would run: systemctl start ' + config.openclaw_service);
        return;
      }
      try {
        const result = await execCommand('systemctl', ['start', config.openclaw_service]);
        console.log(`systemctl start exited with code ${result.exitCode}`);
        // Verify
        const status = await execCommand('systemctl', ['is-active', config.openclaw_service]);
        console.log(`OpenClaw status: ${status.stdout.trim()}`);
      } catch (err) {
        console.error('Failed to restore. Try manually: sudo systemctl start ' + config.openclaw_service);
      }
      return;
    }

    console.log('=== LobsterLock Kill Switch Test ===');
    console.log();
    console.log('This will test the two-step kill switch against the LIVE OpenClaw instance.');
    console.log('Step 1 (soft): ' + config.openclaw_cli + ' security audit --fix');
    console.log('Step 2 (hard): systemctl stop ' + config.openclaw_service);
    console.log();

    if (opts.dryRun) {
      console.log('[DRY RUN] No commands will be executed.');
      console.log();
      console.log('Step 1 would run: ' + config.openclaw_cli + ' security audit --fix');
      console.log('Step 2 would run: systemctl stop ' + config.openclaw_service);
      console.log('Restore would run: systemctl start ' + config.openclaw_service);
      return;
    }

    // Step 1: Soft kill
    const answer1 = await ask('Run SOFT kill (security audit --fix)? [y/N] ');
    if (answer1 !== 'y' && answer1 !== 'yes') {
      console.log('Aborted.');
      return;
    }

    console.log('Running soft kill...');
    try {
      const fixResult = await execCommand(config.openclaw_cli, ['security', 'audit', '--fix']);
      console.log(`Exit code: ${fixResult.exitCode}`);
      if (fixResult.stdout) console.log('stdout: ' + fixResult.stdout.slice(0, 500));
      if (fixResult.stderr) console.log('stderr: ' + fixResult.stderr.slice(0, 500));
    } catch (err) {
      console.error('Soft kill failed:', err);
    }

    // Check if OpenClaw is still running
    try {
      const status = await execCommand('systemctl', ['is-active', config.openclaw_service]);
      console.log(`OpenClaw status after soft kill: ${status.stdout.trim()}`);
    } catch {
      console.log('Could not check OpenClaw status.');
    }
    console.log();

    // Step 2: Hard kill
    const answer2 = await ask('Run HARD kill (systemctl stop)? This will stop OpenClaw. [y/N] ');
    if (answer2 !== 'y' && answer2 !== 'yes') {
      console.log('Skipped hard kill. OpenClaw is still running.');
      return;
    }

    console.log('Running hard kill...');
    try {
      const stopResult = await execCommand('systemctl', ['stop', config.openclaw_service]);
      console.log(`Exit code: ${stopResult.exitCode}`);
    } catch (err) {
      console.error('Hard kill failed:', err);
      console.error('Try manually: sudo systemctl stop ' + config.openclaw_service);
    }

    // Verify
    try {
      const status = await execCommand('systemctl', ['is-active', config.openclaw_service]);
      console.log(`OpenClaw status after hard kill: ${status.stdout.trim()}`);
    } catch {
      console.log('OpenClaw appears to be stopped (could not query status).');
    }

    console.log();
    console.log('To restore OpenClaw: lobsterlock test-kill --restore');
  });

program
  .command('init')
  .description('Initialize LobsterLock configuration')
  .action(async () => {
    const { existsSync, writeFileSync, readFileSync } = await import('node:fs');
    const readline = await import('node:readline');

    const ask = (question: string, defaultValue = ''): Promise<string> => {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      const prompt = defaultValue ? `${question} [${defaultValue}] ` : `${question} `;
      return new Promise((resolve) => {
        rl.question(prompt, (answer) => {
          rl.close();
          resolve(answer.trim() || defaultValue);
        });
      });
    };

    console.log('=== LobsterLock Setup ===');
    console.log();

    // 1. Create directory
    const configDir = resolveConfigPath('~/.lobsterlock');
    ensureConfigDir();
    console.log(`Config directory: ${configDir}`);

    // 2. Detect OpenClaw CLI path
    let defaultCli = '/usr/bin/openclaw';
    if (existsSync('/opt/openclaw-cli.sh')) {
      defaultCli = '/opt/openclaw-cli.sh';
    }
    if (existsSync('/usr/bin/openclaw')) {
      defaultCli = '/usr/bin/openclaw';
    }

    const openclawCli = await ask('OpenClaw CLI path:', defaultCli);

    // 3. Service name
    const openclawService = await ask('OpenClaw service name:', 'openclaw');

    // 4. Skills watch path - try to auto-detect
    let defaultSkillsPath = '/home/openclaw/.openclaw/workspace/skills';
    try {
      const configPath = '/home/openclaw/.openclaw/openclaw.json';
      if (existsSync(configPath)) {
        const raw = readFileSync(configPath, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed.agents?.defaults?.sandbox?.docker?.binds) {
          // Auto-detected from config
        }
      }
    } catch {
      // Use default
    }

    const skillsPath = await ask('Skills watch path:', defaultSkillsPath);

    // 5. Discord (optional)
    console.log();
    console.log('Discord alerts are optional. Press Enter to skip.');
    const discordToken = await ask('Discord bot token (optional):');
    const discordChannel = discordToken ? await ask('Discord channel ID:') : '';

    // 6. Write config.json
    const configPath = join(configDir, 'config.json');
    if (existsSync(configPath)) {
      const overwrite = await ask('config.json already exists. Overwrite? [y/N]');
      if (overwrite !== 'y' && overwrite !== 'yes') {
        console.log('Keeping existing config.json');
      } else {
        writeConfig();
      }
    } else {
      writeConfig();
    }

    function writeConfig() {
      const config: Record<string, unknown> = {
        openclaw_cli: openclawCli,
        openclaw_service: openclawService,
        skills_watch: [skillsPath],
      };
      if (discordChannel) {
        config.discord_channel_id = discordChannel;
      }
      writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
      console.log(`Wrote ${configPath}`);
    }

    // 7. Write .env if it doesn't exist
    const envPath = join(configDir, '.env');
    if (!existsSync(envPath)) {
      let envContent = 'ANTHROPIC_API_KEY=\n';
      if (discordToken) {
        envContent += `DISCORD_BOT_TOKEN=${discordToken}\n`;
      }
      writeFileSync(envPath, envContent, { mode: 0o600 });
      console.log(`Wrote ${envPath} (mode 600)`);
      console.log();
      console.log('IMPORTANT: Edit ~/.lobsterlock/.env and add your Anthropic API key.');
    } else {
      console.log(`.env already exists at ${envPath}`);
    }

    // 8. Validate paths
    console.log();
    console.log('Validating...');

    if (existsSync(openclawCli)) {
      console.log(`  [ok] OpenClaw CLI found: ${openclawCli}`);
    } else {
      console.log(`  [!!] OpenClaw CLI not found: ${openclawCli}`);
    }

    if (existsSync(skillsPath)) {
      console.log(`  [ok] Skills directory found: ${skillsPath}`);
    } else {
      console.log(`  [!!] Skills directory not found: ${skillsPath}`);
    }

    // 9. Connectivity tests
    const openclawConfig = '/home/openclaw/.openclaw/openclaw.json';
    if (existsSync(openclawConfig)) {
      console.log(`  [ok] OpenClaw config readable: ${openclawConfig}`);
    } else {
      console.log(`  [!!] Cannot read OpenClaw config: ${openclawConfig}`);
      console.log('       (Add this user to the openclaw group for read access)');
    }

    try {
      const { execSync } = await import('node:child_process');
      execSync('journalctl -u openclaw -n 1 --no-pager 2>/dev/null', { stdio: 'pipe' });
      console.log('  [ok] Can read OpenClaw journal logs');
    } catch {
      console.log('  [!!] Cannot read OpenClaw journal logs');
      console.log('       (Add this user to the systemd-journal group)');
    }

    // 10. Summary
    console.log();
    console.log('=== Setup Complete ===');
    console.log();
    console.log('Next steps:');
    console.log('  1. Add your Anthropic API key to ~/.lobsterlock/.env');
    console.log('  2. Run: lobsterlock check    (one-shot security scan)');
    console.log('  3. Run: lobsterlock start    (start monitoring daemon)');
    console.log();
    console.log('For production, install as a systemd service:');
    console.log('  lobsterlock install-service');
  });

program.parse();
