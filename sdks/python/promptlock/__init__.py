"""PromptLock — Anti-prompt injection SDK for Python.

Usage:
    from promptlock import Shield

    shield = Shield(level="balanced", redact_pii=True)
    safe_query = shield.protect(user_query)

With vector similarity (requires Ollama):
    from promptlock import Shield, ollama_embedder

    shield = Shield(embedder=ollama_embedder())
"""

from promptlock.shield import Shield, PromptLockError, ScanResult, Violation, ollama_embedder, cosine_similarity

__all__ = ["Shield", "PromptLockError", "ScanResult", "Violation", "ollama_embedder", "cosine_similarity"]
__version__ = "1.1.0"
