import { EventEmitter } from 'node:events';
import { execCommand, type ExecFn } from '../util/exec.js';
import { uuid } from '../util/uuid.js';
import type { LobsterLockConfig, SignalEntry } from '../types.js';

interface PortBinding {
  address: string;
  port: number;
}

/**
 * Collector that periodically checks whether port 18789 (OpenClaw gateway)
 * is bound to a non-loopback address, indicating network exposure.
 */
export class PortCheckerCollector extends EventEmitter {
  private config: LobsterLockConfig;
  private execFn: ExecFn;
  private interval: ReturnType<typeof setInterval> | null = null;
  private previousExposed = false;
  private _running = false;

  constructor(config: LobsterLockConfig, execFn: ExecFn = execCommand) {
    super();
    this.config = config;
    this.execFn = execFn;
  }

  get running(): boolean {
    return this._running;
  }

  async start(): Promise<void> {
    this._running = true;
    await this.poll(true);
    this.interval = setInterval(
      () => void this.poll(false),
      this.config.audit_poll_interval_seconds * 1000,
    );
  }

  stop(): void {
    this._running = false;
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }

  private async poll(isBaseline: boolean): Promise<void> {
    try {
      const result = await this.execFn('ss', ['-tln']);

      if (result.exitCode !== 0) {
        this.emit('signal', {
          id: uuid(),
          type: 'process_event',
          source: 'port-checker',
          timestamp: Date.now(),
          severity: 'medium',
          summary: `ss command failed with exit code ${result.exitCode}`,
          payload: { selfHealth: true },
        } satisfies SignalEntry);
        return;
      }

      const bindings = this.parseBindings(result.stdout);
      const gatewayBindings = bindings.filter((b) => b.port === 18789);
      const exposed = gatewayBindings.some((b) => !this.isLoopback(b.address));

      if (isBaseline) {
        this.previousExposed = exposed;
        if (exposed) {
          this.emitExposureSignal(gatewayBindings, 'critical');
        }
        return;
      }

      if (exposed && !this.previousExposed) {
        // Newly exposed
        this.emitExposureSignal(gatewayBindings, 'critical');
      } else if (exposed && this.previousExposed) {
        // Persistently exposed
        this.emitExposureSignal(gatewayBindings, 'medium');
      }

      this.previousExposed = exposed;
    } catch (err) {
      this._running = false;
      this.emit('error', err);
    }
  }

  /**
   * Parse ss -tln output into port bindings. Public for testing.
   */
  parseBindings(ssOutput: string): PortBinding[] {
    const bindings: PortBinding[] = [];
    for (const line of ssOutput.split('\n')) {
      if (!line.startsWith('LISTEN')) continue;
      const fields = line.trim().split(/\s+/);
      if (fields.length < 4) continue;

      const localAddr = fields[3];
      const lastColon = localAddr.lastIndexOf(':');
      if (lastColon === -1) continue;

      const address = localAddr.slice(0, lastColon);
      const port = parseInt(localAddr.slice(lastColon + 1), 10);
      if (isNaN(port)) continue;

      bindings.push({ address, port });
    }
    return bindings;
  }

  private isLoopback(address: string): boolean {
    const cleaned = address.replace(/^\[|\]$/g, '');
    return cleaned === '127.0.0.1'
      || cleaned === '::1'
      || cleaned.startsWith('127.');
  }

  private emitExposureSignal(
    bindings: PortBinding[],
    severity: 'critical' | 'medium',
  ): void {
    const addresses = bindings
      .filter((b) => !this.isLoopback(b.address))
      .map((b) => b.address);

    this.emit('signal', {
      id: uuid(),
      type: 'audit_finding',
      source: 'port-checker',
      timestamp: Date.now(),
      severity,
      summary: `Gateway port 18789 exposed on non-loopback address: ${addresses.join(', ')}`,
      payload: {
        portExposed: true,
        port: 18789,
        exposedAddresses: addresses,
        allBindings: bindings,
      },
    } satisfies SignalEntry);
  }
}
