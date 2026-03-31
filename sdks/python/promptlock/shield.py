"""Core Shield class — runs detection engine locally. No network calls."""

from __future__ import annotations

import json
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path


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

# Zero-width and invisible character ranges to strip
_INVISIBLE_RANGES = [
    (0x0000, 0x0008),   # C0 control (before \t)
    (0x000B, 0x000C),   # VT, FF
    (0x000E, 0x001F),   # C0 control (after \r)
    (0x007F, 0x009F),   # Delete + C1 control
    (0x200B, 0x200D),   # Zero-width space/joiner
    (0x202A, 0x202E),   # Bidi overrides
    (0x2066, 0x2069),   # Bidi isolates
    (0xFE00, 0xFE0F),   # Variation selectors
    (0xFEFF, 0xFEFF),   # BOM
    (0xE0001, 0xE007F), # Tag characters
]


def _should_strip(c: str) -> bool:
    cp = ord(c)
    for lo, hi in _INVISIBLE_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def _sanitize(text: str) -> str:
    """Unicode NFKC normalization + invisible character stripping."""
    # NFKC normalization (handles homoglyphs, fullwidth, ligatures)
    text = unicodedata.normalize("NFKC", text)
    # Strip invisible characters (preserve \t \n \r)
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
    """Detect and replace PII with placeholders."""
    entities = []
    counters: dict[str, int] = {}
    value_map: dict[str, str] = {}

    matches = []
    for pii_type, pattern in _PII_PATTERNS:
        for m in pattern.finditer(text):
            matches.append((m.start(), m.end(), pii_type, m.group()))

    if not matches:
        return text, []

    # Sort by position, remove overlaps
    matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    filtered = []
    last_end = 0
    for start, end, pii_type, value in matches:
        if start >= last_end:
            filtered.append((start, end, pii_type, value))
            last_end = end

    # Replace from end to preserve offsets
    result = text
    for start, end, pii_type, value in reversed(filtered):
        if value not in value_map:
            counters[pii_type] = counters.get(pii_type, 0) + 1
            value_map[value] = f"[{pii_type}_{counters[pii_type]}]"
        placeholder = value_map[value]
        result = result[:start] + placeholder + result[end:]
        entities.append({
            "type": pii_type,
            "placeholder": placeholder,
            "offset": start,
            "length": end - start,
        })

    entities.reverse()
    return result, entities


# --- Pattern Loading ---

def _load_patterns() -> list[dict]:
    """Load embedded attack patterns."""
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
        return v_idx >= 3  # malicious only
    if level == "balanced":
        return v_idx >= 2  # likely+
    return v_idx >= 1  # suspicious+ (aggressive)


# --- Shield ---

class Shield:
    """PromptLock Shield — runs locally, no network calls.

    Args:
        level: Security level — "basic", "balanced", or "aggressive".
        redact_pii: Enable PII redaction (email, phone, SSN, etc.).

    Usage:
        shield = Shield(level="balanced", redact_pii=True)

        safe = shield.protect(user_input)
        clean = shield.verify_context(rag_chunks)
    """

    def __init__(self, level: str = "balanced", redact_pii: bool = False):
        self._level = level
        self._redact_pii = redact_pii
        self._on_violation = None

        # Load and compile patterns once
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

        # Sort by severity descending (critical first)
        self._rules.sort(key=lambda r: -_SEVERITY_RANK.get(r["severity"], 0))

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

        # 2. Detect
        violations = []
        for rule in self._rules:
            # Basic mode: skip below high
            if self._level == "basic" and _SEVERITY_RANK.get(rule["severity"], 0) < 2:
                continue

            m = rule["compiled"].search(sanitized)
            if not m:
                continue

            matched = m.group()
            if len(matched) > 100:
                half = 50
                matched = matched[:half] + "..." + matched[-half:]

            violations.append(Violation(
                rule=rule["id"],
                category=rule["category"],
                severity=rule["severity"],
                matched=matched,
                confidence=_SEVERITY_CONFIDENCE.get(rule["severity"], 0.5),
                weight=rule["weight"],
            ))

            # Short-circuit on critical in basic/aggressive
            if rule["severity"] == "critical" and self._level in ("basic", "aggressive"):
                break

        # 3. Score
        score = sum(v.weight for v in violations)
        verdict = _verdict_from_score(score)

        # 4. PII redaction
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
