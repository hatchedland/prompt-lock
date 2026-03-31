/**
 * PromptLock — Anti-prompt injection SDK. Runs locally, no network calls.
 *
 * @example
 * ```ts
 * import { Shield } from 'promptlock';
 *
 * const shield = new Shield({ level: 'balanced', redactPII: true });
 *
 * const safe = await shield.protect(userInput);
 * const clean = await shield.verifyContext(ragChunks);
 * ```
 */

import patterns from "./patterns.json";

export interface ShieldOptions {
  level?: "basic" | "balanced" | "aggressive";
  redactPII?: boolean;
  onViolation?: (error: PromptLockError) => void;
}

export interface Violation {
  rule: string;
  category: string;
  severity: string;
  matched: string;
  confidence: number;
  weight: number;
}

export interface ScanResult {
  output: string;
  clean: boolean;
  score: number;
  verdict: string;
  violations: Violation[];
  redactions: Array<{ type: string; placeholder: string; offset: number; length: number }>;
  latencyMs: number;
}

export class PromptLockError extends Error {
  public readonly score: number;
  public readonly verdict: string;
  public readonly violations: Violation[];

  constructor(score: number, verdict: string, violations: Violation[]) {
    super(`Input blocked (verdict=${verdict}, score=${score})`);
    this.name = "PromptLockError";
    this.score = score;
    this.verdict = verdict;
    this.violations = violations;
  }
}

// --- Sanitizer ---

const INVISIBLE_RANGES: [number, number][] = [
  [0x0000, 0x0008], [0x000b, 0x000c], [0x000e, 0x001f],
  [0x007f, 0x009f], [0x200b, 0x200d], [0x202a, 0x202e],
  [0x2066, 0x2069], [0xfe00, 0xfe0f], [0xfeff, 0xfeff],
];

function shouldStrip(cp: number): boolean {
  for (const [lo, hi] of INVISIBLE_RANGES) {
    if (cp >= lo && cp <= hi) return true;
  }
  return false;
}

function sanitize(text: string): string {
  // NFKC normalization
  let result = text.normalize("NFKC");
  // Strip invisible characters (preserve \t \n \r)
  let out = "";
  for (const ch of result) {
    const cp = ch.codePointAt(0)!;
    if (!shouldStrip(cp)) out += ch;
  }
  return out;
}

// --- PII Redaction ---

const PII_PATTERNS: [string, RegExp][] = [
  ["EMAIL", /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g],
  ["PHONE", /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g],
  ["SSN", /\b\d{3}-\d{2}-\d{4}\b/g],
  ["API_KEY", /(?:sk-[a-zA-Z0-9]{20,}|key-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})/g],
  ["IP_ADDRESS", /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g],
];

interface RedactedEntity {
  type: string;
  placeholder: string;
  offset: number;
  length: number;
}

function redactPII(text: string): { output: string; redactions: RedactedEntity[] } {
  const matches: { start: number; end: number; type: string; value: string }[] = [];

  for (const [type, pattern] of PII_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      matches.push({ start: m.index, end: m.index + m[0].length, type, value: m[0] });
    }
  }

  if (matches.length === 0) return { output: text, redactions: [] };

  // Sort by position, remove overlaps
  matches.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const filtered: typeof matches = [];
  let lastEnd = 0;
  for (const m of matches) {
    if (m.start >= lastEnd) {
      filtered.push(m);
      lastEnd = m.end;
    }
  }

  const counters: Record<string, number> = {};
  const valueMap: Record<string, string> = {};
  const redactions: RedactedEntity[] = [];

  let result = text;
  for (let i = filtered.length - 1; i >= 0; i--) {
    const { start, end, type, value } = filtered[i];
    if (!(value in valueMap)) {
      counters[type] = (counters[type] || 0) + 1;
      valueMap[value] = `[${type}_${counters[type]}]`;
    }
    const placeholder = valueMap[value];
    result = result.slice(0, start) + placeholder + result.slice(end);
    redactions.unshift({ type, placeholder, offset: start, length: end - start });
  }

  return { output: result, redactions };
}

// --- Severity helpers ---

const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const SEVERITY_CONFIDENCE: Record<string, number> = { critical: 0.95, high: 0.85, medium: 0.70, low: 0.50 };

function verdictFromScore(score: number): string {
  if (score >= 70) return "malicious";
  if (score >= 40) return "likely";
  if (score >= 15) return "suspicious";
  return "clean";
}

function isBlocked(level: string, verdict: string): boolean {
  const verdicts = ["clean", "suspicious", "likely", "malicious"];
  const idx = verdicts.indexOf(verdict);
  if (level === "basic") return idx >= 3;
  if (level === "balanced") return idx >= 2;
  return idx >= 1; // aggressive
}

// --- Compiled rule ---

interface CompiledRule {
  id: string;
  compiled: RegExp;
  category: string;
  severity: string;
  weight: number;
}

// --- Shield ---

export class Shield {
  private readonly level: string;
  private readonly pii: boolean;
  private readonly onViolation?: (error: PromptLockError) => void;
  private readonly rules: CompiledRule[];

  constructor(options: ShieldOptions = {}) {
    this.level = options.level || "balanced";
    this.pii = options.redactPII || false;
    this.onViolation = options.onViolation;

    // Load and compile patterns once
    this.rules = [];
    for (const p of (patterns as any).patterns) {
      if (!p.enabled) continue;
      try {
        this.rules.push({
          id: p.id,
          compiled: new RegExp(p.regex),
          category: p.category,
          severity: p.severity,
          weight: p.weight,
        });
      } catch {
        // Skip invalid regex
      }
    }

    // Sort by severity descending
    this.rules.sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0));
  }

  /**
   * Scan input for prompt injections. Returns sanitized output.
   * @throws {PromptLockError} If the input is blocked.
   */
  protect(input: string): string {
    const result = this.run(input);
    if (isBlocked(this.level, result.verdict)) {
      const err = new PromptLockError(result.score, result.verdict, result.violations);
      this.onViolation?.(err);
      throw err;
    }
    return result.output;
  }

  /** Scan input and return full scan details. */
  protectDetailed(input: string): ScanResult {
    return this.run(input);
  }

  /** Verify RAG context chunks. Malicious chunks are filtered out. */
  verifyContext(chunks: string[]): string[] {
    return chunks
      .map((chunk) => this.run(chunk))
      .filter((result) => !isBlocked(this.level, result.verdict))
      .map((result) => result.output);
  }

  private run(input: string): ScanResult {
    const start = performance.now();

    // 1. Sanitize
    const sanitized = sanitize(input);

    // 2. Detect
    const violations: Violation[] = [];
    for (const rule of this.rules) {
      if (this.level === "basic" && (SEVERITY_RANK[rule.severity] || 0) < 2) continue;

      const m = rule.compiled.exec(sanitized);
      if (!m) continue;

      let matched = m[0];
      if (matched.length > 100) {
        matched = matched.slice(0, 50) + "..." + matched.slice(-50);
      }

      violations.push({
        rule: rule.id,
        category: rule.category,
        severity: rule.severity,
        matched,
        confidence: SEVERITY_CONFIDENCE[rule.severity] || 0.5,
        weight: rule.weight,
      });

      if (rule.severity === "critical" && (this.level === "basic" || this.level === "aggressive")) {
        break;
      }
    }

    // 3. Score
    const score = violations.reduce((sum, v) => sum + v.weight, 0);
    const verdict = verdictFromScore(score);

    // 4. PII
    let output = sanitized;
    let redactions: RedactedEntity[] = [];
    if (this.pii) {
      const r = redactPII(output);
      output = r.output;
      redactions = r.redactions;
    }

    const latencyMs = Math.round((performance.now() - start) * 100) / 100;

    return { output, clean: verdict === "clean", score, verdict, violations, redactions, latencyMs };
  }
}
