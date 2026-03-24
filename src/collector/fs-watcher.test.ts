import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { FsWatcherCollector } from './fs-watcher.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type { SignalEntry } from '../types.js';

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('FsWatcherCollector', () => {
  let tempDir: string;
  let collector: FsWatcherCollector;

  afterEach(async () => {
    if (collector) await collector.stop();
    try { rmSync(tempDir, { recursive: true }); } catch {}
  });

  it('detects new skill file (.md) with high severity', async () => {
    tempDir = mkdtempSync(join(tmpdir(), 'lobsterlock-fsw-'));
    const config = { ...DEFAULT_CONFIG, skills_watch: [tempDir] };
    collector = new FsWatcherCollector(config, null);

    const signals: SignalEntry[] = [];
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();
    await wait(500); // Let chokidar initialize

    // Create a skill file
    writeFileSync(join(tempDir, 'SKILL.md'), '# Evil Skill');
    await wait(1500); // awaitWriteFinish stabilityThreshold is 500ms

    assert.ok(signals.length >= 1, `Expected signals, got ${signals.length}`);
    const skillSignal = signals.find((s) => s.summary.includes('SKILL.md'));
    assert.ok(skillSignal, 'Should have a signal for SKILL.md');
    assert.equal(skillSignal.type, 'fs_change');
    assert.equal(skillSignal.severity, 'high');
  });

  it('detects non-skill files with medium severity', async () => {
    tempDir = mkdtempSync(join(tmpdir(), 'lobsterlock-fsw-'));
    const config = { ...DEFAULT_CONFIG, skills_watch: [tempDir] };
    collector = new FsWatcherCollector(config, null);

    const signals: SignalEntry[] = [];
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    collector.start();
    await wait(500);

    writeFileSync(join(tempDir, 'data.json'), '{}');
    await wait(1500);

    assert.ok(signals.length >= 1);
    const dataSignal = signals.find((s) => s.summary.includes('data.json'));
    assert.ok(dataSignal);
    assert.equal(dataSignal.severity, 'medium');
  });

  it('calls skillsCollector.triggerRecheck on skill dir changes', async () => {
    tempDir = mkdtempSync(join(tmpdir(), 'lobsterlock-fsw-'));
    const config = { ...DEFAULT_CONFIG, skills_watch: [tempDir] };

    let recheckCalled = false;
    const mockSkillsCollector = {
      triggerRecheck: async () => { recheckCalled = true; },
    };

    collector = new FsWatcherCollector(
      config,
      mockSkillsCollector as unknown as import('./skills.js').SkillsCollector,
    );

    collector.start();
    await wait(500);

    writeFileSync(join(tempDir, 'index.ts'), 'export default {}');
    await wait(1500);

    assert.ok(recheckCalled, 'triggerRecheck should be called');
  });
});
