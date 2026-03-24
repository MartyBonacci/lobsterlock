import { execFile, spawn, type ChildProcess } from 'node:child_process';

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Execute a command and return the result (batch mode).
 * Injectable for testing.
 */
export function execCommand(cmd: string, args: string[]): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
      if (error && error.killed) {
        reject(error);
        return;
      }
      resolve({
        stdout: stdout ?? '',
        stderr: stderr ?? '',
        exitCode: error?.code !== undefined ? (typeof error.code === 'number' ? error.code : 1) : 0,
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
