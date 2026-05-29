"""Spotlighting: mark untrusted retrieved content as DATA so the model treats
instructions inside it as inert. Defangs indirect (document-borne) injection.
"""
from __future__ import annotations

import re

from ..schemas import RetrievedDoc

START = "<<UNTRUSTED_DATA>>"
END = "<</UNTRUSTED_DATA>>"
_BLOCK = re.compile(re.escape(START) + r".*?" + re.escape(END), re.S)


def apply(docs: list[RetrievedDoc]) -> str:
    return "\n".join(f"{START}\n{d.text}\n{END}" for d in docs)


def strip(context: str) -> str:
    """Remove spotlighted regions for the purpose of instruction-scanning.
    When spotlighting is off there are no markers and this is a no-op, so
    document instructions are scanned (and obeyed by a gullible model)."""
    return _BLOCK.sub("", context)
