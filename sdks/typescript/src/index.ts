/**
 * PromptLock — Anti-prompt injection SDK for TypeScript/Node.js.
 *
 * @example
 * ```ts
 * import { Shield } from 'promptlock';
 *
 * const shield = new Shield({ level: 'balanced', redactPII: true });
 *
 * const safeQuery = await shield.protect(userInput);
 * const context = await vectorDb.query(safeQuery);
 * const cleanContext = await shield.verifyContext(context);
 * const response = await llm.generate(safeQuery, cleanContext);
 * ```
 */

export interface ShieldOptions {
  /** Security level. Default: "balanced" */
  level?: "basic" | "balanced" | "aggressive";
  /** Enable PII redaction. Default: false */
  redactPII?: boolean;
  /** PromptLock server URL. Default: "https://shield.cawght.com" */
  serverUrl?: string;
  /** Callback fired when a violation is detected */
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
  redactions: Array<{
    type: string;
    placeholder: string;
    offset: number;
    length: number;
  }>;
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

export class Shield {
  private readonly url: string;
  private readonly onViolation?: (error: PromptLockError) => void;

  constructor(options: ShieldOptions = {}) {
    this.url = (options.serverUrl || "https://shield.cawght.com").replace(/\/$/, "");
    this.onViolation = options.onViolation;
  }

  /**
   * Scan input for prompt injections. Returns sanitized output.
   * @throws {PromptLockError} If the input is blocked.
   *
   * @example
   * ```ts
   * const safe = await shield.protect("What is the weather?");
   * ```
   */
  async protect(input: string): Promise<string> {
    const resp = await this.post("/v1/protect", { input });

    if (resp.blocked) {
      const err = new PromptLockError(resp.score, resp.verdict, resp.violations || []);
      this.onViolation?.(err);
      throw err;
    }

    return resp.output;
  }

  /**
   * Scan input and return full scan details.
   *
   * @example
   * ```ts
   * const result = await shield.protectDetailed(input);
   * if (!result.clean) {
   *   console.log("Violations:", result.violations);
   * }
   * ```
   */
  async protectDetailed(input: string): Promise<ScanResult> {
    const resp = await this.post("/v1/protect/detailed", { input });

    return {
      output: resp.output || "",
      clean: resp.clean ?? false,
      score: resp.score ?? 0,
      verdict: resp.verdict ?? "unknown",
      violations: resp.violations || [],
      redactions: resp.redactions || [],
      latencyMs: resp.latency_ms ?? 0,
    };
  }

  /**
   * Verify RAG-retrieved context chunks for indirect injections.
   * Malicious chunks are silently filtered out.
   *
   * @example
   * ```ts
   * const chunks = await vectorDb.query(query);
   * const clean = await shield.verifyContext(chunks);
   * ```
   */
  async verifyContext(chunks: string[]): Promise<string[]> {
    const resp = await this.post("/v1/verify-context", { chunks });
    return resp.clean_chunks || [];
  }

  private async post(path: string, body: Record<string, unknown>): Promise<any> {
    const resp = await fetch(this.url + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new Error(`PromptLock server error: ${resp.status} ${resp.statusText}`);
    }
    return resp.json();
  }
}
