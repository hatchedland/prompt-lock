"""PromptLock — Anti-prompt injection SDK for Python.

Usage:
    from promptlock import Shield

    shield = Shield(level="balanced", redact_pii=True)

    # Wrap your search + LLM flow
    safe_query = shield.protect(user_query)
    context = vector_db.query(safe_query)
    clean_context = shield.verify_context(context)
    response = llm.generate(safe_query, clean_context)
"""

from promptlock.shield import Shield, PromptLockError, ScanResult, Violation

__all__ = ["Shield", "PromptLockError", "ScanResult", "Violation"]
__version__ = "1.0.0"
