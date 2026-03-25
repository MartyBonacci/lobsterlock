import Anthropic from '@anthropic-ai/sdk';
import { VERDICT_REGEX } from '../constants.js';
import { insertAuditEntry } from '../storage/audit-log.js';
import { uuid } from '../util/uuid.js';
import { buildReasoningPrompt, SYSTEM_PROMPT } from './prompt.js';
import { SignalBuffer } from '../trigger/buffer.js';
import type Database from 'better-sqlite3';
import type {
  AlertSeverity,
  AuditLogEntry,
  EscalationState,
  LobsterLockConfig,
  ReasoningContext,
  TriggerEvent,
  Verdict,
  VerdictLevel,
} from '../types.js';

/**
 * Reasoning engine that invokes Claude via the Anthropic API
 * to analyze security signals and produce a verdict.
 */
export class ReasoningEngine {
  private config: LobsterLockConfig;
  private db: Database.Database;
  private buffer: SignalBuffer;
  private client: Anthropic;
  private busy = false;
  private inflightPromise: Promise<Verdict | null> | null = null;

  constructor(
    config: LobsterLockConfig,
    db: Database.Database,
    buffer: SignalBuffer,
    client?: Anthropic,
  ) {
    this.config = config;
    this.db = db;
    this.buffer = buffer;
    this.client = client ?? new Anthropic();
  }

  /**
   * Invoke the reasoning engine. Returns null on degraded mode (API failure).
   */
  async invoke(
    trigger: TriggerEvent,
    escalationState: EscalationState,
    previousVerdict: Verdict | null,
    securityPosture: Record<string, unknown> | null = null,
    skillInventoryDelta: Record<string, unknown> | null = null,
    memoryIntegrity: import('../types.js').MemoryIntegrityState | null = null,
  ): Promise<Verdict | null> {
    if (this.busy) {
      return {
        level: 'WATCH',
        severity: null,
        reason: 'reasoning engine busy',
        reasoning: 'A reasoning call is already in flight. This signal has been buffered and will be included in the next invocation.',
        raw: '',
        timestamp: Date.now(),
      };
    }

    this.busy = true;
    const promise = this.doInvoke(
      trigger,
      escalationState,
      previousVerdict,
      securityPosture,
      skillInventoryDelta,
      memoryIntegrity,
    );
    this.inflightPromise = promise;

    try {
      return await promise;
    } finally {
      this.busy = false;
      this.inflightPromise = null;
    }
  }

  /**
   * Wait for any in-flight reasoning call to complete (for graceful shutdown).
   */
  async waitForInflight(timeoutMs: number = 10_000): Promise<void> {
    if (!this.inflightPromise) return;

    await Promise.race([
      this.inflightPromise.catch(() => {}),
      new Promise((resolve) => setTimeout(resolve, timeoutMs)),
    ]);
  }

  private async doInvoke(
    trigger: TriggerEvent,
    escalationState: EscalationState,
    previousVerdict: Verdict | null,
    securityPosture: Record<string, unknown> | null,
    skillInventoryDelta: Record<string, unknown> | null,
    memoryIntegrity: import('../types.js').MemoryIntegrityState | null = null,
  ): Promise<Verdict | null> {
    const context: ReasoningContext = {
      triggerEvent: trigger,
      signalBuffer: this.buffer.getAll(),
      evictedCount: this.buffer.evicted(),
      securityPosture,
      skillInventoryDelta,
      memoryIntegrity,
      escalationState,
      previousVerdict,
    };

    const prompt = buildReasoningPrompt(context);

    let responseText: string;
    try {
      responseText = await this.callClaude(prompt);
    } catch (firstError) {
      // Retry once after 2 seconds
      try {
        await new Promise((r) => setTimeout(r, 2000));
        responseText = await this.callClaude(prompt);
      } catch {
        // Degraded mode
        return null;
      }
    }

    const verdict = parseVerdict(responseText);
    const fullVerdict: Verdict = {
      level: verdict.level ?? 'WATCH',
      severity: verdict.severity ?? null,
      reason: verdict.reason ?? 'malformed reasoning output',
      reasoning: verdict.reasoning ?? responseText,
      raw: responseText,
      timestamp: Date.now(),
    };

    // Log to SQLite
    const entry: AuditLogEntry = {
      id: uuid(),
      timestamp: fullVerdict.timestamp,
      trigger_event: JSON.stringify(trigger),
      signal_buffer_snapshot: JSON.stringify(context.signalBuffer),
      prompt_sent: `${SYSTEM_PROMPT}\n\n${prompt}`,
      raw_response: responseText,
      verdict_level: fullVerdict.level,
      verdict_severity: fullVerdict.severity,
      verdict_reason: fullVerdict.reason,
      escalation_state: JSON.stringify(escalationState),
      acknowledged: false,
      acknowledged_at: null,
    };

    try {
      insertAuditEntry(this.db, entry);
    } catch (err) {
      console.error('[ERROR] Failed to log audit entry:', err);
    }

    return fullVerdict;
  }

  private async callClaude(prompt: string): Promise<string> {
    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: this.config.reasoning_budget,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
    });

    const textBlock = response.content.find((b) => b.type === 'text');
    return textBlock ? textBlock.text : '';
  }
}

/**
 * Parse a verdict from Claude's raw response text.
 * Exported for testing.
 */
export function parseVerdict(raw: string): Partial<Verdict> {
  const match = VERDICT_REGEX.exec(raw);
  if (!match) {
    return {
      level: 'WATCH',
      severity: null,
      reason: 'malformed reasoning output',
      reasoning: raw,
    };
  }

  const verdictLine = match[1].trim();
  const restOfText = raw.slice(raw.indexOf(verdictLine) + verdictLine.length).trim();

  if (verdictLine === 'CLEAR') {
    return {
      level: 'CLEAR',
      severity: null,
      reason: 'all clear',
      reasoning: restOfText,
    };
  }

  if (verdictLine.startsWith('WATCH')) {
    return {
      level: 'WATCH',
      severity: null,
      reason: verdictLine.slice(6).trim(),
      reasoning: restOfText,
    };
  }

  if (verdictLine.startsWith('ALERT')) {
    const alertMatch = /^ALERT\s+(LOW|MEDIUM|HIGH)\s+(.+)$/.exec(verdictLine);
    if (alertMatch) {
      return {
        level: 'ALERT',
        severity: alertMatch[1] as AlertSeverity,
        reason: alertMatch[2].trim(),
        reasoning: restOfText,
      };
    }
  }

  if (verdictLine.startsWith('KILL')) {
    return {
      level: 'KILL',
      severity: null,
      reason: verdictLine.slice(5).trim(),
      reasoning: restOfText,
    };
  }

  return {
    level: 'WATCH',
    severity: null,
    reason: 'malformed reasoning output',
    reasoning: raw,
  };
}
