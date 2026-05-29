"""Document corpus + naive keyword retrieval. Tenant is the parent directory
name under data/corpus/ (alice, bob, public). Some public docs are poisoned.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..schemas import RetrievedDoc

_ROOT = Path(__file__).resolve().parent.parent.parent / "data" / "corpus"
_WORD = re.compile(r"[a-z]{3,}")


def _tokens(s: str) -> set[str]:
    return set(_WORD.findall(s.lower()))


class Corpus:
    def __init__(self, docs: list[RetrievedDoc]) -> None:
        self.docs = docs

    @classmethod
    def load(cls, root: Path | None = None) -> "Corpus":
        root = root or _ROOT
        docs: list[RetrievedDoc] = []
        for path in sorted(root.rglob("*.txt")):
            tenant = path.parent.name
            docs.append(RetrievedDoc(
                doc_id=str(path.relative_to(root)).replace("\\", "/"),
                tenant=tenant,
                source=path.name,
                text=path.read_text(encoding="utf-8"),
            ))
        return cls(docs)

    def search(self, query: str, k: int = 3) -> list[RetrievedDoc]:
        q = _tokens(query)
        scored = []
        for d in self.docs:
            overlap = len(q & _tokens(d.text))
            if overlap:
                scored.append((overlap, d))
        scored.sort(key=lambda x: (-x[0], x[1].doc_id))
        return [d for _, d in scored[:k]]
