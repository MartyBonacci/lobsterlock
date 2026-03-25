import type { ContentFinding, Severity } from '../types.js';

interface PatternDef {
  name: string;
  severity: Severity;
  pattern: RegExp;
}

const PATTERNS: PatternDef[] = [
  // 1. Base64 blobs (AMOS stealer, Soul Pack steganography)
  {
    name: 'base64_blob',
    severity: 'medium',
    pattern: /[A-Za-z0-9+/]{40,}={0,2}/,
  },
  // 2. Zero-width Unicode (steganographic injection)
  {
    name: 'zero_width_unicode',
    severity: 'high',
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF]/,
  },
  // 3. Instruction injection (prompt injection taxonomy)
  {
    name: 'instruction_injection',
    severity: 'high',
    pattern: /\b(?:ignore (?:previous|all|above) instructions|you are now|execute the following|bypass (?:safety|security|confirmation)|override safety|disregard (?:previous|above)|new system prompt|do not (?:mention|reveal|tell))\b/i,
  },
  // 4. Credential path references (Cisco YARA rules)
  {
    name: 'credential_path',
    severity: 'high',
    pattern: /(?:~\/\.ssh|\.env\b|id_rsa|id_ed25519|credentials|keychain|\/etc\/shadow|AWS_SECRET|ANTHROPIC_API_KEY|DISCORD_BOT_TOKEN|OPENAI_API_KEY|api[_-]?key|private[_-]?key)/i,
  },
  // 5. Suspicious commands (Cisco exfil pattern)
  {
    name: 'suspicious_command',
    severity: 'high',
    pattern: /(?:\bcurl\b|\bwget\b|\beval\s*\(|\bexec\s*\(|child_process|spawn\s*\(|\/dev\/null|\bbase64\s+-d\b|\bbash\s+-c\b|\bchmod\s+[0-7]{3,4}\b|\brm\s+-rf\b)/i,
  },
  // 6. External URLs (potential exfil targets in memory files)
  {
    name: 'external_url',
    severity: 'medium',
    pattern: /https?:\/\/(?!localhost|127\.0\.0\.1|::1)[^\s"')<>]{5,}/i,
  },
  // 7. SSRF target IPs (cloud metadata, private networks)
  {
    name: 'ssrf_target',
    severity: 'critical',
    pattern: /\b(?:169\.254\.169\.254|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/,
  },
  // 8. Known C2 IPs (ClawHavoc campaign)
  {
    name: 'known_c2_ip',
    severity: 'critical',
    pattern: /\b91\.92\.242\.30\b/,
  },
];

/**
 * Scan text content for suspicious patterns.
 * Returns an array of findings, one per pattern match per line.
 */
export function scanContent(content: string, filename: string): ContentFinding[] {
  const findings: ContentFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { name, severity, pattern } of PATTERNS) {
      const match = pattern.exec(line);
      if (match) {
        findings.push({
          patternName: name,
          severity,
          matchedText: match[0].slice(0, 100),
          lineNumber: i + 1,
          context: `${filename}:${i + 1}: ${line.slice(0, 200)}`,
        });
      }
    }
  }

  return findings;
}

/**
 * Get pattern names for reference/testing.
 */
export function getPatternNames(): string[] {
  return PATTERNS.map((p) => p.name);
}
