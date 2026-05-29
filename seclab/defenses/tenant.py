"""Tenant isolation enforced AT the retrieval layer — not via prompt wording.
A document is visible only to its owning tenant (or if public).
"""
from __future__ import annotations

from ..schemas import RetrievedDoc


def isolate(docs: list[RetrievedDoc], user_id: str) -> list[RetrievedDoc]:
    return [d for d in docs if d.tenant in (user_id, "public")]
