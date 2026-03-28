import { execCommand, type ExecFn } from '../util/exec.js';
import { KILL_SOFT_TIMEOUT_MS } from '../constants.js';
import type { AlertDispatcher } from './alert.js';
import type { TriggerManager } from '../trigger/manager.js';
import type { LobsterLockConfig, Verdict } from '../types.js';

/**
 * Handles KILL verdict execution:
 * 1. Runs `openclaw security audit --fix` (30s timeout)
 * 2. Stops the OpenClaw service via `systemctl stop openclaw`
 * 3. Sends Discord alert
 * 4. Pauses the trigger manager
 */
export class KillHandler {
  private config: LobsterLockConfig;
  private execFn: ExecFn;
  private dispatcher: AlertDispatcher;
  private triggerManager: TriggerManager;

  constructor(
    config: LobsterLockConfig,
    dispatcher: AlertDispatcher,
    triggerManager: TriggerManager,
    execFn: ExecFn = execCommand,
  ) {
    this.config = config;
    this.execFn = execFn;
    this.dispatcher = dispatcher;
    this.triggerManager = triggerManager;
  }

  async execute(verdict: Verdict): Promise<void> {
    console.log('[KILL] Executing security fix (30s timeout)...');

    // Step 1: Soft kill with timeout
    let softKillTimedOut = false;
    try {
      const result = await this.execFn(this.config.openclaw_cli, [
        'security', 'audit', '--fix',
      ], KILL_SOFT_TIMEOUT_MS);

      if (result.timedOut) {
        softKillTimedOut = true;
        console.error('[KILL] Soft kill timed out after 30s. Escalating to hard kill.');
      } else {
        console.log(`[KILL] Fix command exited with code ${result.exitCode}`);
        if (result.stdout) console.log(`[KILL] stdout: ${result.stdout.slice(0, 500)}`);
        if (result.stderr) console.error(`[KILL] stderr: ${result.stderr.slice(0, 500)}`);
      }
    } catch (err) {
      console.error('[KILL] Fix command failed:', err);
    }

    // Step 2: Hard kill (always runs -- the soft kill is best-effort)
    console.log('[KILL] Stopping OpenClaw service...');
    try {
      const stopResult = await this.execFn('systemctl', ['stop', this.config.openclaw_service], 15_000);
      if (stopResult.timedOut) {
        console.error('[KILL] systemctl stop timed out after 15s');
      } else {
        console.log(`[KILL] systemctl stop exited with code ${stopResult.exitCode}`);
      }
    } catch (err) {
      console.error('[KILL] Failed to stop OpenClaw service:', err);
    }

    // Notify via Discord
    const timeoutNote = softKillTimedOut
      ? '\n`security audit --fix` timed out after 30s and was skipped.\n'
      : '\n`openclaw security audit --fix` has been run.\n';

    await this.dispatcher.sendDegradedAlert(
      `**KILL verdict executed**\nReason: ${verdict.reason}\n` +
      timeoutNote +
      `OpenClaw service has been stopped via \`systemctl stop\`.\n` +
      `Monitoring is **paused**. Run \`lobsterlock ack\` to resume.`,
    );

    // Pause the trigger manager
    this.triggerManager.pause();
    console.log('[KILL] Monitoring paused. Run `lobsterlock ack` to resume.');
  }
}
