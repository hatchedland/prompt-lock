"""PromptLock — Anti-prompt injection SDK for Python.

Usage:
    from promptlock import Shield
    shield = Shield(level="balanced", redact_pii=True)
    safe = shield.protect(user_input)

With vector similarity + judge (requires Ollama):
    from promptlock import Shield, ollama_embedder, ollama_judge
    shield = Shield(embedder=ollama_embedder(), judge=ollama_judge())

With HTTP interceptor:
    from promptlock import Shield, Interceptor
    session = Interceptor(Shield()).session()
"""

from promptlock.shield import (
    Shield, PromptLockError, ScanResult, Violation,
    ollama_embedder, ollama_judge, cosine_similarity, Interceptor,
)

__all__ = [
    "Shield", "PromptLockError", "ScanResult", "Violation",
    "ollama_embedder", "ollama_judge", "cosine_similarity", "Interceptor",
]
__version__ = "1.2.0"
