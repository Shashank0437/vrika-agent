"""Normalize user-supplied targets for nmap (host/IP/CIDR), not full URLs."""

from __future__ import annotations

from urllib.parse import urlparse


def normalize_nmap_target(raw: object) -> str:
    """
    Strip ``http://``, ``https://``, and similar so ``https://example.com/path``
    becomes ``example.com``. Leaves bare hostnames, IPs, and CIDR unchanged.
    """
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raw = str(raw)
    s = raw.strip()
    if not s:
        return ""

    if "://" in s:
        parsed = urlparse(s)
        if parsed.hostname:
            return parsed.hostname
    if s.startswith("//"):
        parsed = urlparse("http:" + s)
        if parsed.hostname:
            return parsed.hostname

    return s
