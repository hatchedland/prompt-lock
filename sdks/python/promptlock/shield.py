"""Core Shield class — the one-line integration point."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

import requests


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
    latency_ms: int = 0


class PromptLockError(Exception):
    """Raised when input is blocked due to detected prompt injection."""

    def __init__(self, score: int, verdict: str, violations: list[Violation], message: str = ""):
        self.score = score
        self.verdict = verdict
        self.violations = violations
        self.message = message or f"Input blocked (verdict={verdict}, score={score})"
        super().__init__(self.message)


class Shield:
    """PromptLock Shield — defense-in-depth for LLM applications.

    Args:
        level: Security level — "basic", "balanced", or "aggressive".
        redact_pii: Enable PII redaction (email, phone, SSN, etc.).
        server_url: PromptLock server URL. Default: http://localhost:8080.
        timeout: Request timeout in seconds. Default: 5.

    Usage:
        shield = Shield(level="balanced", redact_pii=True)

        # One-line protection
        safe = shield.protect(user_input)

        # RAG context verification
        clean_chunks = shield.verify_context(retrieved_chunks)

        # Full scan details
        result = shield.protect_detailed(user_input)
    """

    def __init__(
        self,
        level: str = "balanced",
        redact_pii: bool = False,
        server_url: str = "http://localhost:8080",
        timeout: float = 5.0,
    ):
        self._url = server_url.rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    def protect(self, input: str) -> str:
        """Scan input for prompt injections. Returns sanitized output.

        Raises:
            PromptLockError: If the input is blocked.

        Example:
            safe_query = shield.protect("What is the weather?")
            # Use safe_query with your LLM
        """
        resp = self._post("/v1/protect", {"input": input})

        if resp["blocked"]:
            violations = [Violation(**v) for v in resp.get("violations", [])]
            raise PromptLockError(
                score=resp["score"],
                verdict=resp["verdict"],
                violations=violations,
            )

        return resp["output"]

    def protect_detailed(self, input: str) -> ScanResult:
        """Scan input and return full scan details.

        Returns a ScanResult even if the input is blocked (check result.clean).

        Example:
            result = shield.protect_detailed(user_input)
            if not result.clean:
                log_security_event(result.violations)
        """
        resp = self._post("/v1/protect/detailed", {"input": input})

        violations = [Violation(**v) for v in resp.get("violations", [])]
        return ScanResult(
            output=resp.get("output", ""),
            clean=resp.get("clean", False),
            score=resp.get("score", 0),
            verdict=resp.get("verdict", "unknown"),
            violations=violations,
            redactions=resp.get("redactions", []),
            latency_ms=resp.get("latency_ms", 0),
        )

    def verify_context(self, chunks: list[str]) -> list[str]:
        """Verify RAG-retrieved context chunks for indirect injections.

        Malicious chunks are silently filtered out.

        Example:
            context = vector_db.query(query)
            clean = shield.verify_context(context)
            # Only clean chunks are passed to the LLM
        """
        resp = self._post("/v1/verify-context", {"chunks": chunks})
        return resp.get("clean_chunks", [])

    def on_violation(self, callback):
        """Decorator to register a violation callback.

        Example:
            @shield.on_violation
            def handle(error: PromptLockError):
                log.warning(f"Blocked: {error.verdict}")
        """
        self._violation_callback = callback
        return callback

    def _post(self, path: str, body: dict) -> dict:
        url = self._url + path
        resp = self._session.post(url, json=body, timeout=self._timeout)
        resp.raise_for_status()
        return resp.json()
