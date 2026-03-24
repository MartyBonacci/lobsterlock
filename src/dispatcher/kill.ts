import { execCommand, type ExecFn } from '../util/exec.js';
import type { AlertDispatcher } from './alert.js';
import type { TriggerManager } from '../trigger/manager.js';
import type { LobsterLockConfig, Verdict } from '../types.js';

/**
 * Handles KILL verdict execution:
 * 1. Runs `openclaw security audit --fix`
 * 2. Sends Discord alert
 * 3. Pauses the trigger manager
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
    console.log('[KILL] Executing security fix...');

    // Run the fix command
    try {
      const result = await this.execFn(this.config.openclaw_cli, [
        'security', 'audit', '--fix',
      ]);
      console.log(`[KILL] Fix command exited with code ${result.exitCode}`);
      if (result.stdout) console.log(`[KILL] stdout: ${result.stdout.slice(0, 500)}`);
      if (result.stderr) console.error(`[KILL] stderr: ${result.stderr.slice(0, 500)}`);
    } catch (err) {
      console.error('[KILL] Fix command failed:', err);
    }

    // Notify via Discord
    await this.dispatcher.sendDegradedAlert(
      `**KILL verdict executed**\nReason: ${verdict.reason}\n\n` +
      `\`openclaw security audit --fix\` has been run.\n` +
      `Monitoring is **paused**. Run \`lobsterlock ack\` to resume.`,
    );

    // Pause the trigger manager
    this.triggerManager.pause();
    console.log('[KILL] Monitoring paused. Run `lobsterlock ack` to resume.');
  }
}
