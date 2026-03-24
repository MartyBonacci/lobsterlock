import {
  Client,
  GatewayIntentBits,
  EmbedBuilder,
  type TextChannel,
} from 'discord.js';
import type {
  EscalationState,
  LobsterLockConfig,
  TriggerEvent,
  Verdict,
} from '../types.js';

/**
 * Alert dispatcher that routes verdicts to Discord and stdout.
 */
export class AlertDispatcher {
  private config: LobsterLockConfig;
  private discordClient: Client | null = null;
  private discordReady = false;
  private channel: TextChannel | null = null;

  constructor(config: LobsterLockConfig) {
    this.config = config;
  }

  /**
   * Initialize Discord connection if bot token is available.
   */
  async init(): Promise<void> {
    const token = process.env.DISCORD_BOT_TOKEN;
    if (!token) {
      console.error('[WARN] DISCORD_BOT_TOKEN not set, alerts will be log-only');
      return;
    }

    try {
      this.discordClient = new Client({
        intents: [GatewayIntentBits.Guilds],
      });

      await this.discordClient.login(token);

      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Discord ready timeout')), 15000);
        this.discordClient!.once('ready', () => {
          clearTimeout(timeout);
          this.discordReady = true;

          // Try to find the configured channel
          if (this.config.discord_channel_id) {
            const ch = this.discordClient!.channels.cache.get(this.config.discord_channel_id);
            if (ch && ch.isTextBased() && 'send' in ch) {
              this.channel = ch as TextChannel;
            }
          }

          resolve();
        });
      });

      console.log('[INFO] Discord connected');
    } catch (err) {
      console.error('[WARN] Discord connection failed, alerts will be log-only:', err);
      this.discordClient = null;
      this.discordReady = false;
    }
  }

  /**
   * Dispatch a verdict to the appropriate channel.
   */
  async dispatch(
    verdict: Verdict,
    escalationState: EscalationState,
    trigger?: TriggerEvent,
  ): Promise<void> {
    const ts = new Date(verdict.timestamp).toISOString();
    const severityStr = verdict.severity ? ` ${verdict.severity}` : '';

    // Always log to stdout
    console.log(
      `[${ts}] [${verdict.level}${severityStr}] ${verdict.reason}`,
    );

    if (verdict.level === 'CLEAR' || verdict.level === 'WATCH') {
      return;
    }

    // ALERT or KILL -> send to Discord
    await this.sendDiscordAlert(verdict, escalationState, trigger);
  }

  /**
   * Send a degraded mode alert (bypasses reasoning).
   */
  async sendDegradedAlert(reason: string): Promise<void> {
    const message = `**LobsterLock System Alert**\n${reason}`;
    console.error(`[SYSTEM] ${reason}`);

    if (this.discordReady && this.channel) {
      try {
        await this.channel.send(message);
      } catch (err) {
        console.error('[ERROR] Failed to send degraded alert to Discord:', err);
      }
    }
  }

  /**
   * Destroy the Discord client.
   */
  async shutdown(): Promise<void> {
    if (this.discordClient) {
      this.discordClient.destroy();
      this.discordClient = null;
      this.discordReady = false;
    }
  }

  private async sendDiscordAlert(
    verdict: Verdict,
    escalationState: EscalationState,
    trigger?: TriggerEvent,
  ): Promise<void> {
    const color =
      verdict.level === 'KILL' ? 0xff0000
      : verdict.severity === 'HIGH' ? 0xff4500
      : verdict.severity === 'MEDIUM' ? 0xffa500
      : 0xffff00;

    const embed = new EmbedBuilder()
      .setTitle(`LobsterLock ${verdict.level}${verdict.severity ? ` ${verdict.severity}` : ''}`)
      .setDescription(verdict.reason)
      .setColor(color)
      .addFields(
        {
          name: 'Reasoning',
          value: verdict.reasoning.slice(0, 1024) || 'No reasoning provided',
        },
        {
          name: 'Trigger',
          value: trigger?.rule ?? 'unknown',
          inline: true,
        },
        {
          name: 'Escalation',
          value: `WATCH count: ${escalationState.consecutive_watch_count}`,
          inline: true,
        },
      )
      .setTimestamp(new Date(verdict.timestamp))
      .setFooter({ text: 'Run `lobsterlock ack` to acknowledge' });

    if (!this.discordReady || !this.channel) {
      console.error(
        `[${verdict.level}] Discord unavailable -- alert logged to stderr only`,
      );
      console.error(`  Reason: ${verdict.reason}`);
      console.error(`  Reasoning: ${verdict.reasoning}`);
      return;
    }

    try {
      await this.channel.send({ embeds: [embed] });
    } catch (err) {
      console.error('[ERROR] Failed to send Discord alert:', err);
      console.error(`  Fallback -- ${verdict.level}: ${verdict.reason}`);
    }
  }
}
