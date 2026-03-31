"""Core Shield class — runs detection engine locally. No network calls."""

from __future__ import annotations

import json
import math
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


@dataclass
class Violation:
    """A detected prompt injection threat."""
    rule: str
    category: str
    severity: str
    matched: str
    confidence: float
    weight: int


@dataclass
class ScanResult:
    """Full scan result from protect_detailed()."""
    output: str
    clean: bool
    score: int
    verdict: str
    violations: list[Violation] = field(default_factory=list)
    redactions: list[dict] = field(default_factory=list)
    latency_ms: float = 0


class PromptLockError(Exception):
    """Raised when input is blocked due to detected prompt injection."""

    def __init__(self, score: int, verdict: str, violations: list[Violation], message: str = ""):
        self.score = score
        self.verdict = verdict
        self.violations = violations
        self.message = message or f"Input blocked (verdict={verdict}, score={score})"
        super().__init__(self.message)


# --- Sanitizer ---

_INVISIBLE_RANGES = [
    (0x0000, 0x0008), (0x000B, 0x000C), (0x000E, 0x001F),
    (0x007F, 0x009F), (0x200B, 0x200D), (0x202A, 0x202E),
    (0x2066, 0x2069), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xE0001, 0xE007F),
]


def _should_strip(c: str) -> bool:
    cp = ord(c)
    for lo, hi in _INVISIBLE_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def _sanitize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if not _should_strip(c))
    return text


# --- PII Redaction ---

_PII_PATTERNS = [
    ("EMAIL", re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')),
    ("PHONE", re.compile(r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')),
    ("SSN", re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    ("API_KEY", re.compile(r'(?:sk-[a-zA-Z0-9]{20,}|key-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})')),
    ("IP_ADDRESS", re.compile(r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')),
]


def _redact_pii(text: str) -> tuple[str, list[dict]]:
    entities = []
    counters: dict[str, int] = {}
    value_map: dict[str, str] = {}
    matches = []
    for pii_type, pattern in _PII_PATTERNS:
        for m in pattern.finditer(text):
            matches.append((m.start(), m.end(), pii_type, m.group()))
    if not matches:
        return text, []
    matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    filtered = []
    last_end = 0
    for start, end, pii_type, value in matches:
        if start >= last_end:
            filtered.append((start, end, pii_type, value))
            last_end = end
    result = text
    for start, end, pii_type, value in reversed(filtered):
        if value not in value_map:
            counters[pii_type] = counters.get(pii_type, 0) + 1
            value_map[value] = f"[{pii_type}_{counters[pii_type]}]"
        placeholder = value_map[value]
        result = result[:start] + placeholder + result[end:]
        entities.append({"type": pii_type, "placeholder": placeholder, "offset": start, "length": end - start})
    entities.reverse()
    return result, entities


# --- Vector Similarity ---

def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b) or len(a) == 0:
        return 0.0
    dot = sum(ai * bi for ai, bi in zip(a, b))
    norm_a = math.sqrt(sum(ai * ai for ai in a))
    norm_b = math.sqrt(sum(bi * bi for bi in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _load_corpus() -> list[dict]:
    """Load embedded attack corpus for vector similarity."""
    corpus_file = Path(__file__).parent / "corpus.json"
    if not corpus_file.exists():
        return []
    with open(corpus_file) as f:
        return json.load(f)


# --- Ollama Embedder ---

def ollama_embedder(model: str = "nomic-embed-text", endpoint: str = "http://localhost:11434") -> Callable[[str], list[float]]:
    """Create an embedder function that uses a local Ollama instance.

    Usage:
        shield = Shield(embedder=ollama_embedder())
    """
    import urllib.request

    def embed(text: str) -> list[float]:
        body = json.dumps({"model": model, "prompt": text}).encode()
        req = urllib.request.Request(
            f"{endpoint}/api/embeddings",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return data["embedding"]

    return embed


# --- Pattern Loading ---

def _load_patterns() -> list[dict]:
    patterns_file = Path(__file__).parent / "patterns.json"
    with open(patterns_file) as f:
        data = json.load(f)
    return data["patterns"]


# --- Severity/Verdict helpers ---

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SEVERITY_CONFIDENCE = {"critical": 0.95, "high": 0.85, "medium": 0.70, "low": 0.50}


def _verdict_from_score(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "likely"
    if score >= 15:
        return "suspicious"
    return "clean"


def _is_blocked(level: str, verdict: str) -> bool:
    verdicts = ["clean", "suspicious", "likely", "malicious"]
    v_idx = verdicts.index(verdict) if verdict in verdicts else 0
    if level == "basic":
        return v_idx >= 3
    if level == "balanced":
        return v_idx >= 2
    return v_idx >= 1


# --- Shield ---

class Shield:
    """PromptLock Shield — runs locally, no network calls.

    Args:
        level: Security level — "basic", "balanced", or "aggressive".
        redact_pii: Enable PII redaction (email, phone, SSN, etc.).
        embedder: Optional embedding function for vector similarity detection.
                  Signature: (text: str) -> list[float].
                  Use ollama_embedder() for local Ollama.
        similarity_threshold: Cosine similarity threshold for vector matches. Default: 0.82.

    Usage:
        # Regex only (default)
        shield = Shield(level="balanced")

        # With vector similarity (requires Ollama)
        from promptlock import Shield, ollama_embedder
        shield = Shield(embedder=ollama_embedder())
    """

    def __init__(
        self,
        level: str = "balanced",
        redact_pii: bool = False,
        embedder: Optional[Callable[[str], list[float]]] = None,
        similarity_threshold: float = 0.82,
    ):
        self._level = level
        self._redact_pii = redact_pii
        self._on_violation = None
        self._embedder = embedder
        self._threshold = similarity_threshold

        # Load and compile regex patterns
        raw = _load_patterns()
        self._rules = []
        for p in raw:
            if not p.get("enabled", True):
                continue
            try:
                compiled = re.compile(p["regex"])
            except re.error:
                continue
            self._rules.append({
                "id": p["id"],
                "compiled": compiled,
                "category": p["category"],
                "severity": p["severity"],
                "weight": p["weight"],
            })
        self._rules.sort(key=lambda r: -_SEVERITY_RANK.get(r["severity"], 0))

        # Vector similarity state (lazy init)
        self._corpus = _load_corpus() if embedder else []
        self._corpus_embeddings: list[tuple[dict, list[float]]] | None = None

    def _init_vectors(self):
        """Lazy-initialize corpus embeddings on first use."""
        if self._corpus_embeddings is not None:
            return
        self._corpus_embeddings = []
        for sample in self._corpus:
            try:
                emb = self._embedder(sample["text"])
                self._corpus_embeddings.append((sample, emb))
            except Exception:
                continue

    def protect(self, input: str) -> str:
        """Scan input for prompt injections. Returns sanitized output.

        Raises:
            PromptLockError: If the input is blocked.
        """
        result = self._run(input)
        if _is_blocked(self._level, result.verdict):
            err = PromptLockError(
                score=result.score,
                verdict=result.verdict,
                violations=result.violations,
            )
            if self._on_violation:
                self._on_violation(err)
            raise err
        return result.output

    def protect_detailed(self, input: str) -> ScanResult:
        """Scan input and return full scan details."""
        return self._run(input)

    def verify_context(self, chunks: list[str]) -> list[str]:
        """Verify RAG context chunks. Malicious chunks are filtered out."""
        clean = []
        for chunk in chunks:
            result = self._run(chunk)
            if not _is_blocked(self._level, result.verdict):
                clean.append(result.output)
        return clean

    def on_violation(self, callback):
        """Register a violation callback."""
        self._on_violation = callback
        return callback

    def _run(self, input: str) -> ScanResult:
        start = time.monotonic()

        # 1. Sanitize
        sanitized = _sanitize(input)

        # 2. Pattern detection
        violations = []
        for rule in self._rules:
            if self._level == "basic" and _SEVERITY_RANK.get(rule["severity"], 0) < 2:
                continue
            m = rule["compiled"].search(sanitized)
            if not m:
                continue
            matched = m.group()
            if len(matched) > 100:
                matched = matched[:50] + "..." + matched[-50:]
            violations.append(Violation(
                rule=rule["id"],
                category=rule["category"],
                severity=rule["severity"],
                matched=matched,
                confidence=_SEVERITY_CONFIDENCE.get(rule["severity"], 0.5),
                weight=rule["weight"],
            ))
            if rule["severity"] == "critical" and self._level in ("basic", "aggressive"):
                break

        # 3. Vector similarity detection
        if self._embedder and self._corpus:
            self._init_vectors()
            try:
                input_emb = self._embedder(sanitized)
                seen = set()
                for sample, corpus_emb in self._corpus_embeddings:
                    sim = cosine_similarity(input_emb, corpus_emb)
                    if sim < self._threshold:
                        continue
                    rule_id = f"VECTOR_{sample['label']}"
                    if rule_id in seen:
                        continue
                    seen.add(rule_id)
                    violations.append(Violation(
                        rule=rule_id,
                        category=sample.get("category", "injection"),
                        severity="high",
                        matched=f"similar to {sample['label']} ({sim:.0%})",
                        confidence=sim,
                        weight=int(sim * 70),
                    ))
            except Exception:
                pass  # Vector detection failure is non-fatal

        # 4. Score
        score = sum(v.weight for v in violations)
        verdict = _verdict_from_score(score)

        # 5. PII redaction
        output = sanitized
        redactions = []
        if self._redact_pii:
            output, redactions = _redact_pii(output)

        elapsed = (time.monotonic() - start) * 1000

        return ScanResult(
            output=output,
            clean=verdict == "clean",
            score=score,
            verdict=verdict,
            violations=violations,
            redactions=redactions,
            latency_ms=round(elapsed, 2),
        )
