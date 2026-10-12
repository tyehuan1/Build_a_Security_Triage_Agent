"""Shared types for tools. A tool turns validated arguments into its contract output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


class InvalidArguments(ValueError):
    """Arguments break the tool contract. Returned to the model for one correction."""


@dataclass
class ToolOutput:
    result: dict                         # contract output, returned to the model
    status: str                          # found | not_found | failed
    mode: Optional[str]                  # live | cached | mixed | simulated | None
    attempts: int = 1
    fallback_used: bool = False
    summary: str = ""
    error: Optional[str] = None
    receipts: list = field(default_factory=list)   # provenance from the source layer
    source_raw: dict = field(default_factory=dict) # raw source data saved with the call


def receipt_of(res) -> dict:
    """Provenance of one SourceResult for the tool trace."""
    return {
        "source": res.source,
        "status": res.status,
        "mode": res.mode,
        "url": res.url,
        "retrieved_at": res.retrieved_at,
        "attempts": res.attempts,
        "fallback_reason": res.fallback_reason,
        "error": res.error,
        **res.receipt,
    }
