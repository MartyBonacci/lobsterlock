import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SkillsCollector } from './skills.js';
import { DEFAULT_CONFIG } from '../constants.js';
import type { ExecResult } from '../util/exec.js';
import type { SignalEntry } from '../types.js';

function makeSkillsJson(skills: object[]): string {
  return JSON.stringify(skills);
}

const baselineSkills = [
  { name: 'healthcheck', eligible: true, disabled: false, blockedByAllowlist: false, bundled: true, missing: { bins: [] } },
  { name: 'tmux', eligible: true, disabled: false, blockedByAllowlist: false, bundled: true, missing: { bins: [] } },
];

describe('SkillsCollector', () => {
  it('emits baseline event on start', async () => {
    const exec = async (): Promise<ExecResult> => ({
      stdout: makeSkillsJson(baselineSkills), stderr: '', exitCode: 0, timedOut: false,
    });

    let baselineFired = false;
    const collector = new SkillsCollector(DEFAULT_CONFIG, exec);
    collector.on('baseline', () => { baselineFired = true; });

    await collector.start();
    collector.stop();

    assert.ok(baselineFired);
  });

  it('detects new skill', async () => {
    let callCount = 0;
    const exec = async (): Promise<ExecResult> => {
      callCount++;
      if (callCount === 1) {
        return { stdout: makeSkillsJson(baselineSkills), stderr: '', exitCode: 0, timedOut: false };
      }
      return {
        stdout: makeSkillsJson([
          ...baselineSkills,
          { name: 'suspicious-skill', eligible: true, disabled: false, blockedByAllowlist: false, bundled: false, missing: { bins: [] } },
        ]),
        stderr: '', exitCode: 0, timedOut: false,
      };
    };

    const signals: SignalEntry[] = [];
    const config = { ...DEFAULT_CONFIG, audit_poll_interval_seconds: 0.01 };
    const collector = new SkillsCollector(config, exec);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    await collector.start();
    await new Promise((r) => setTimeout(r, 50));
    collector.stop();

    const newSkills = signals.filter((s) => s.summary.includes('New skill detected'));
    assert.ok(newSkills.length >= 1);
    assert.ok(newSkills[0].summary.includes('suspicious-skill'));
    assert.equal(newSkills[0].severity, 'high');
  });

  it('detects newly eligible skill', async () => {
    let callCount = 0;
    const exec = async (): Promise<ExecResult> => {
      callCount++;
      if (callCount === 1) {
        return {
          stdout: makeSkillsJson([
            ...baselineSkills,
            { name: 'coding-agent', eligible: false, disabled: true, blockedByAllowlist: false, bundled: false, missing: { bins: [] } },
          ]),
          stderr: '', exitCode: 0, timedOut: false,
        };
      }
      return {
        stdout: makeSkillsJson([
          ...baselineSkills,
          { name: 'coding-agent', eligible: true, disabled: false, blockedByAllowlist: false, bundled: false, missing: { bins: [] } },
        ]),
        stderr: '', exitCode: 0, timedOut: false,
      };
    };

    const signals: SignalEntry[] = [];
    const config = { ...DEFAULT_CONFIG, audit_poll_interval_seconds: 0.01 };
    const collector = new SkillsCollector(config, exec);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    await collector.start();
    await new Promise((r) => setTimeout(r, 50));
    collector.stop();

    const eligible = signals.filter((s) => s.summary.includes('became eligible'));
    assert.ok(eligible.length >= 1);
    assert.ok(eligible[0].summary.includes('coding-agent'));
  });

  it('detects removed skill', async () => {
    let callCount = 0;
    const exec = async (): Promise<ExecResult> => {
      callCount++;
      if (callCount === 1) {
        return { stdout: makeSkillsJson(baselineSkills), stderr: '', exitCode: 0, timedOut: false };
      }
      return {
        stdout: makeSkillsJson([baselineSkills[0]]), // removed tmux
        stderr: '', exitCode: 0, timedOut: false,
      };
    };

    const signals: SignalEntry[] = [];
    const config = { ...DEFAULT_CONFIG, audit_poll_interval_seconds: 0.01 };
    const collector = new SkillsCollector(config, exec);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    await collector.start();
    await new Promise((r) => setTimeout(r, 50));
    collector.stop();

    const removed = signals.filter((s) => s.summary.includes('Skill removed'));
    assert.ok(removed.length >= 1);
    assert.ok(removed[0].summary.includes('tmux'));
  });

  it('triggerRecheck runs immediate poll', async () => {
    let callCount = 0;
    const exec = async (): Promise<ExecResult> => {
      callCount++;
      if (callCount <= 1) {
        return { stdout: makeSkillsJson(baselineSkills), stderr: '', exitCode: 0, timedOut: false };
      }
      return {
        stdout: makeSkillsJson([
          ...baselineSkills,
          { name: 'new-one', eligible: true, disabled: false, blockedByAllowlist: false, bundled: false, missing: { bins: [] } },
        ]),
        stderr: '', exitCode: 0, timedOut: false,
      };
    };

    const signals: SignalEntry[] = [];
    const config = { ...DEFAULT_CONFIG, audit_poll_interval_seconds: 999 }; // Long interval
    const collector = new SkillsCollector(config, exec);
    collector.on('signal', (s: SignalEntry) => signals.push(s));

    await collector.start();
    await collector.triggerRecheck();
    collector.stop();

    const newSkills = signals.filter((s) => s.summary.includes('New skill detected'));
    assert.ok(newSkills.length >= 1);
  });
});
