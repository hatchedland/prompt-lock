# PromptLock

Anti-prompt injection engine for LLM applications. Defense-in-depth protection against jailbreaks, instruction override, PII leaks, and token smuggling.

Built by [Cawght](https://www.cawght.com) — AI-powered security testing.

## What It Does

PromptLock sits between user input and your LLM. It sanitizes, detects, and blocks prompt injection attempts in under 10ms.

```
User Input → Sanitize → Detect → Block/Allow → LLM
```

**Three detection layers:**
- **Pattern matching** — 70+ regex rules covering jailbreaks, injections, prompt leaks, token smuggling (< 5ms)
- **Vector similarity** — 200 attack embeddings, cosine similarity catches paraphrased attacks (< 100ms)
- **Judge LLM** — optional shadow model classifies novel attacks (< 200ms)

## Quick Start

### Go

```bash
go get github.com/rajanyadav/promptlock
```

```go
shield, _ := promptlock.New(
    promptlock.WithLevel(promptlock.Balanced),
    promptlock.WithRedactPII(true),
)

safe, err := shield.Protect(ctx, userInput)
if err != nil {
    // blocked — prompt injection detected
}
```

### Python

```bash
pip install promptlock-py
```

```python
from promptlock import Shield

shield = Shield(level="balanced", redact_pii=True)

safe = shield.protect(user_input)             # raises PromptLockError if blocked
clean = shield.verify_context(rag_chunks)     # filters malicious RAG context
```

### TypeScript

```bash
npm install @rajanydv/prompt-lock
```

```typescript
import { Shield } from 'promptlock';

const shield = new Shield({ level: 'balanced', redactPII: true });

const safe = await shield.protect(userInput);
const clean = await shield.verifyContext(ragChunks);
```

### REST API (any language)

```bash
# Start server
go run ./cmd/promptlock-server/

# Use from any language
curl -X POST localhost:8080/v1/protect \
  -H "Content-Type: application/json" \
  -d '{"input": "user query here"}'
```

## Wrapping a Search + LLM Flow

```python
from promptlock import Shield

shield = Shield()

def secure_search(query):
    safe_query = shield.protect(query)              # 1. protect input
    chunks = vector_db.query(safe_query)            # 2. search
    clean_chunks = shield.verify_context(chunks)    # 3. verify context
    return llm.generate(safe_query, clean_chunks)   # 4. generate
```

## Features

| Feature | Description |
|---------|-------------|
| **Unicode normalization** | NFKC — blocks homoglyph attacks (Cyrillic а → Latin a) |
| **Invisible char stripping** | Removes zero-width spaces, bidi overrides, control chars |
| **Format decoding** | Auto-decodes Base64, Hex, Leetspeak payloads |
| **70+ attack patterns** | Jailbreaks, injection, prompt leaks, token smuggling, context overflow |
| **PII redaction** | Email, phone, credit card (Luhn), SSN, API keys, IP addresses |
| **Security delimiters** | Randomized XML tags to separate trusted/untrusted content |
| **Vector similarity** | 200 attack embeddings for semantic detection (optional, via Ollama) |
| **Shadow LLM judge** | Classify novel attacks with a local model (optional) |
| **HTTP interceptor** | `http.RoundTripper` middleware for OpenAI/Anthropic/Gemini/Ollama |

## Security Levels

| Level | Patterns | Judge | Delimiters | Blocks At |
|-------|----------|-------|------------|-----------|
| `basic` | High + Critical only | Off | Off | Score ≥ 70 |
| `balanced` | All | On large inputs | On | Score ≥ 40 |
| `aggressive` | All | Always | On | Score ≥ 15 |

## Performance

Benchmarked on Apple M4:

| Component | Latency |
|-----------|---------|
| Full pipeline (4KB input, 70 patterns) | **7.4ms** |
| Sanitizer only | 0.2ms |
| Pattern detector only | 1.9ms |
| PII redaction | 0.4ms |
| Delimiter wrapping | 0.7μs |

## Architecture

```
promptlock/           Go SDK (core engine)
├── sanitizer/        Unicode, invisible chars, format decoding
├── detector/         Pattern matching, vector similarity, composite
├── registry/         70+ attack patterns (JSON, embedded)
├── vault/            PII detection and redaction
├── delimiter/        Randomized security tag wrapping
├── judge/            Shadow LLM classification
├── interceptor/      HTTP middleware for LLM APIs
├── server/           REST + gRPC server
├── gateway/          API auth, rate limiting, metering (SaaS mode)
└── sdks/
    ├── python/       pip install promptlock-py
    └── typescript/   npm install @rajanydv/prompt-lock
```

## Self-Hosted Server

```bash
# Standalone (no auth)
go run ./cmd/promptlock-server/ --level balanced --redact-pii

# With gateway (auth + rate limiting + usage metering)
go run ./cmd/promptlock-server/ --gateway --db promptlock.db

# Docker
docker compose up
```

## Contributing

PRs welcome. Run tests before submitting:

```bash
go test ./...
```

## License

MIT — see [LICENSE](LICENSE).

Built by [Cawght](https://www.cawght.com).
