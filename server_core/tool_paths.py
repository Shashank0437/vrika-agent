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
BUNDLED_X8_PARAMS_WORDLIST = os.path.join(
    _AGENT_CORE_DIR,
    "data",
    "x8_default_params.txt",
)

# Common on-disk locations for x8 / SecLists parameter name lists (before bundled fallback).
_X8_WORDLIST_CATALOG: tuple[str, ...] = (
    "/usr/share/wordlists/x8/params.txt",
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "/opt/seclists/Discovery/Web-Content/burp-parameter-names.txt",
)


def resolve_x8_wordlist(requested: Optional[str]) -> Optional[str]:
    """
    Pick the first existing parameter wordlist for x8: user path, then catalog paths,
    then the bundled minimal list shipped with the agent.
    """
    if requested and isinstance(requested, str):
        r = requested.strip()
        if r and os.path.isfile(r):
            return r
    for p in _X8_WORDLIST_CATALOG:
        if os.path.isfile(p):
            return p
    if os.path.isfile(BUNDLED_X8_PARAMS_WORDLIST):
        return BUNDLED_X8_PARAMS_WORDLIST
    return None


def resolve_cli_tool(*names: str) -> Optional[str]:
    """
    Return an absolute executable path for the first available candidate name.

    Checks PATH, then ``$GOPATH/bin`` / ``~/go/bin``, ``~/.cargo/bin`` (Rust / cargo),
    then ``/usr/local/bin`` and ``/opt/homebrew/bin`` (macOS Homebrew).
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
    cargo_bin = os.path.join(os.path.expanduser("~"), ".cargo", "bin")
    for bindir in (*go_bins, cargo_bin):
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


def resolve_cli_tool_go_paths_first(*names: str) -> Optional[str]:
    """
    Resolve a binary preferring Go installs (``$GOPATH/bin``, ``~/go/bin``) and common
    Homebrew prefixes **before** ``shutil.which`` (system PATH).

    Use when the same executable name is shadowed by an unrelated tool earlier on PATH
    (e.g. PyPI ``httpx`` vs ProjectDiscovery ``httpx``).
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for n in names:
        if not n or n in seen:
            continue
        seen.add(n)
        ordered.append(n)

    gopath = (os.environ.get("GOPATH") or "").strip() or os.path.expanduser(os.path.join("~", "go"))
    go_bins = (
        "/root/go/bin",
        os.path.join(gopath, "bin"),
        os.path.expanduser("~/go/bin"),
        "/usr/local/go/bin",
    )
    for bindir in go_bins:
        for name in ordered:
            p = os.path.join(bindir, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p

    for extra in ("/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"):
        for name in ordered:
            p = os.path.join(extra, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                # If name is httpx and it's a python script (PyPI httpx), skip it in favor of ProjectDiscovery httpx
                if name == "httpx":
                    try:
                        with open(p, "rb") as f:
                            head = f.read(128)
                            if b"python" in head:
                                continue
                    except Exception:
                        pass
                return p

    for name in ordered:
        w = shutil.which(name)
        if w:
            return w

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
