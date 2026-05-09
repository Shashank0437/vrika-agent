"""Resolve third-party CLI binaries and wordlists across dev machines (PATH, Go bin, Homebrew)."""

from __future__ import annotations

import os
import shutil
from typing import Iterable, Optional
from urllib.parse import urlparse

_AGENT_CORE_DIR = os.path.dirname(os.path.abspath(__file__))
BUNDLED_MINIMAL_DIR_WORDLIST = os.path.join(
    _AGENT_CORE_DIR,
    "data",
    "nyxstrike_default_dir_wordlist.txt",
)


def resolve_cli_tool(*names: str) -> Optional[str]:
    """
    Return an absolute executable path for the first available candidate name.

    Checks PATH, then ``$GOPATH/bin`` / ``~/go/bin``, then ``/usr/local/bin`` and
    ``/opt/homebrew/bin`` (macOS Homebrew).
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for n in names:
        if not n or n in seen:
            continue
        seen.add(n)
        ordered.append(n)

    for name in ordered:
        w = shutil.which(name)
        if w:
            return w

    gopath = (os.environ.get("GOPATH") or "").strip() or os.path.expanduser(os.path.join("~", "go"))
    go_bins = (
        os.path.join(gopath, "bin"),
        os.path.expanduser("~/go/bin"),
    )
    for bindir in go_bins:
        for name in ordered:
            p = os.path.join(bindir, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p

    for extra in ("/usr/local/bin", "/opt/homebrew/bin"):
        for name in ordered:
            p = os.path.join(extra, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p

    return None


def resolve_wordlist_path(
    requested: Optional[str],
    *,
    catalog_paths: Iterable[Optional[str]],
) -> str:
    """
    Prefer ``requested`` if it exists on disk, else the first existing catalog path,
    else the bundled minimal directory list shipped with NyxStrike.
    """
    if requested and isinstance(requested, str):
        r = requested.strip()
        if r and os.path.isfile(r):
            return r
    for p in catalog_paths:
        if p and isinstance(p, str) and os.path.isfile(p):
            return p
    if os.path.isfile(BUNDLED_MINIMAL_DIR_WORDLIST):
        return BUNDLED_MINIMAL_DIR_WORDLIST
    # Last resort: return requested or first catalog path even if missing (caller may surface error)
    if requested and str(requested).strip():
        return str(requested).strip()
    for p in catalog_paths:
        if p:
            return p
    return BUNDLED_MINIMAL_DIR_WORDLIST


def scope_to_domain(val: Optional[str]) -> str:
    """Strip http(s) URL to hostname, or return bare host/domain unchanged."""
    if val is None:
        return ""
    v = str(val).strip()
    if not v:
        return ""
    if "://" in v:
        host = urlparse(v).hostname
        return (host or "").strip() or v
    return v
