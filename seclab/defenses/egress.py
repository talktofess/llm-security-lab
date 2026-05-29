"""Egress control: strip auto-rendered images and non-allowlisted outbound URLs
from the output — closing the classic markdown-image exfiltration channel.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..constants import EXFILTRATION
from ..schemas import SecurityEvent

ALLOWED_HOSTS = {"acme.example"}
_IMG = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_URL = re.compile(r"https?://[^\s)]+", re.I)


def sanitize(answer: str, events=None) -> str:
    flagged = False
    out = _IMG.sub("[image removed]", answer)

    def repl(m: re.Match) -> str:
        nonlocal flagged
        host = (urlparse(m.group(0)).hostname or "").lower()
        if host in ALLOWED_HOSTS:
            return m.group(0)
        flagged = True
        return "[external link removed]"

    out = _URL.sub(repl, out)
    if flagged and events is not None:
        events.add(SecurityEvent(attack_class=EXFILTRATION, severity="high",
                                 signal="blocked external URL/image in output"))
    return out
