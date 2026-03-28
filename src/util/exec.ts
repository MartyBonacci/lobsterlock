import { execFile, spawn, type ChildProcess } from 'node:child_process';

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

/**
 * Execute a command and return the result (batch mode).
 * Optional timeout in milliseconds. On timeout, returns timedOut: true with exitCode -1.
 * Injectable for testing.
 */
export function execCommand(cmd: string, args: string[], timeoutMs?: number): Promise<ExecResult> {
  return new Promise((resolve) => {
    const opts: Record<string, unknown> = { maxBuffer: 1024 * 1024 };
    if (timeoutMs !== undefined) {
      opts.timeout = timeoutMs;
    }
    execFile(cmd, args, opts, (error, stdout, stderr) => {
      if (error && error.killed) {
        // Process was killed (timeout or external signal)
        resolve({
          stdout: stdout ?? '',
          stderr: stderr ?? '',
          exitCode: -1,
          timedOut: true,
        });
        return;
      }
      resolve({
        stdout: stdout ?? '',
        stderr: stderr ?? '',
        exitCode: error?.code !== undefined ? (typeof error.code === 'number' ? error.code : 1) : 0,
        timedOut: false,
      });
    });
  });
}

export type ExecFn = typeof execCommand;

/**
 * Spawn a streaming command (e.g., journalctl -f).
 * Injectable for testing.
 */
export function spawnStream(cmd: string, args: string[]): ChildProcess {
  return spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
}

export type SpawnFn = typeof spawnStream;
