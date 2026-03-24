import { readFileSync, writeFileSync, unlinkSync, existsSync } from 'node:fs';

/**
 * Write the current process PID to a file.
 */
export function writePid(pidPath: string): void {
  writeFileSync(pidPath, String(process.pid), 'utf-8');
}

/**
 * Read a PID from a file. Returns null if file doesn't exist.
 */
export function readPid(pidPath: string): number | null {
  if (!existsSync(pidPath)) return null;
  try {
    const content = readFileSync(pidPath, 'utf-8').trim();
    const pid = parseInt(content, 10);
    return isNaN(pid) ? null : pid;
  } catch {
    return null;
  }
}

/**
 * Check if a process with the given PID is running.
 */
export function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Remove a PID file.
 */
export function removePid(pidPath: string): void {
  try {
    if (existsSync(pidPath)) {
      unlinkSync(pidPath);
    }
  } catch {
    // Best effort
  }
}

/**
 * Check the state of a PID file.
 * Returns 'running' if PID is active, 'stale' if PID file exists but process is dead, 'none' if no file.
 */
export function checkStalePid(pidPath: string): 'running' | 'stale' | 'none' {
  const pid = readPid(pidPath);
  if (pid === null) return 'none';
  return isProcessRunning(pid) ? 'running' : 'stale';
}
