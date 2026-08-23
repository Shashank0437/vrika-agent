"""
server_core/adk/tools.py

Canonical parameter normalization for the ADK orchestration layer.
"""

from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse

from tool_registry import TOOLS


def normalize_tool_parameters(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize model argument aliases against the canonical registry schema."""
    clean_name = tool_name.strip().lower()
    out = dict(args)
    tool_def = TOOLS.get(clean_name) or {}
    accepted = set((tool_def.get("params") or {}).keys()) | set((tool_def.get("optional") or {}).keys())

    # Models commonly use one generic target field while the registry uses
    # url/domain/input/host.  Map only to an actual schema field; this prevents
    # silently forwarding unsupported aliases to the execution API.
    target_value = next(
        (
            out[key]
            for key in ("target", "url", "domain", "host", "input")
            if isinstance(out.get(key), str) and out[key].strip()
        ),
        None,
    )
    if isinstance(target_value, str):
        address_fields = [field for field in ("target", "url", "domain", "host", "input") if field in accepted]
        if len(address_fields) == 1:
            out[address_fields[0]] = target_value
        elif "target" in accepted and "target" not in out:
            out["target"] = target_value

    # 1. Target URL/Host normalization for raw port scanners
    if clean_name in ("nmap", "nmap_advanced", "masscan", "rustscan", "amass", "subfinder"):
        target = out.get("target") or out.get("domain") or out.get("host") or out.get("url") or out.get("input")
        if isinstance(target, str) and (target.startswith("http://") or target.startswith("https://")):
            parsed = urlparse(target)
            host_only = parsed.netloc.split(":")[0]
            for field in ("target", "domain", "host", "input"):
                if field in accepted and (field in out or len([f for f in ("target", "domain", "host", "input") if f in accepted]) == 1):
                    out[field] = host_only
                    break

    # Never forward model-invented keys when a registry schema is known.
    if accepted:
        out = {key: value for key, value in out.items() if key in accepted}

    # 2. Boolean strings
    for k, v in list(out.items()):
        if isinstance(v, str):
            if v.lower() == "true":
                out[k] = True
            elif v.lower() == "false":
                out[k] = False

    return out
