"""Assemble web-referenced catalog narratives for arsenal_user_documentation.json.

``tool_web_sources.json`` holds per-tool authoritative URLs and summaries. Regenerate it with::

    python agent/server_api/tools_catalog/emit_tool_web_sources.py

Then regenerate the catalog::

    python agent/scripts/generate_arsenal_user_documentation.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_CORE_SAFETY = (
    "Operate only inside authorized penetration tests or sanctioned lab networks. Respect stop "
    "conditions, lawful intercept rules, and internal change windows. Sensitive parameters are "
    "captured in CipherStrike tenant execution logs alongside NyxStrike response snippets — "
    "avoid pasting production secrets when alternatives exist."
)

_CATEGORY_RIDERS: dict[str, str] = {
    "wifi_pentest": "Wireless emissions are regulated regionally — test only labs you legally control.",
    "exploitation": "Exploit payloads can corrupt live services; segregate workloads and snapshots before running.",
    "brute_force": "Credential guesses can trigger lockouts — coordinate with defenders and throttle attempts.",
    "web_vuln": "Active scanning can fuzz production forms; throttle requests and replay only consented payloads.",
    "network_recon": "Port scanners are noisy — obtain written scope describing address ranges explicitly.",
    "intelligence": "AI-assisted chaining must still respect data handling policies for scraped content.",
    "ai_assist": "LLM-assisted analysis may memorize sensitive pasted text — sanitize inputs beforehand.",
    "vulnerability_intelligence": "CVE feeds and vendor text may carry license constraints — verify reuse rules.",
    "forensics": "Forensic tooling may process sensitive evidence — encrypt exports at rest.",
    "active_directory": "AD tooling can authenticate across trusts — misuse may trip detection.",
    "database": "Database clients may send credentials in JSON — purge debug logs after drills.",
}


def _load_sources() -> dict[str, dict[str, str]]:
    path = Path(__file__).with_name("tool_web_sources.json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, str]] = {}
    for name, row in raw.items():
        if isinstance(row, dict):
            out[name] = {
                "url": str(row.get("url") or ""),
                "summary": str(row.get("summary") or "").strip(),
            }
    return out


_SOURCES: dict[str, dict[str, str]] | None = None


def web_sources() -> dict[str, dict[str, str]]:
    global _SOURCES
    if _SOURCES is None:
        _SOURCES = _load_sources()
    return _SOURCES


def tools_with_weak_public_docs() -> list[str]:
    """Tool slugs with no curated documentation URL (CipherStrike-only or unknown upstream)."""
    return sorted(name for name, row in web_sources().items() if not (row.get("url") or "").strip())


def _format_usage(name: str, meta: dict[str, Any]) -> str:
    params = list((meta.get("params") or {}).keys())
    optional = list((meta.get("optional") or {}).keys())
    req_txt = ", ".join(f"`{p}`" for p in params) if params else "(none)"
    if len(optional) <= 18:
        opt_txt = ", ".join(f"`{p}`" for p in optional) if optional else "(none)"
    else:
        opt_txt = ", ".join(f"`{p}`" for p in optional[:18]) + ", …"
    return (
        "Use only for systems and data sources you are explicitly authorized to assess. "
        f"In this catalog entry, required JSON keys are: {req_txt}. Optional keys include: {opt_txt}. "
        "Map your intent to those fields—the NyxStrike connector turns them into the packaged CLI or "
        "API call; use `additional_args` only for tokens your team has validated against that wrapper. "
        "Optional empty scalars are typically omitted from the proxied body."
    )


def build_tool_bundle(name: str, meta: dict[str, Any]) -> tuple[str, str, str]:
    row = web_sources().get(name) or {}
    url = (row.get("url") or "").strip()
    summary = (row.get("summary") or "").strip()
    desc = (meta.get("desc") or "").strip()
    if not summary:
        summary = desc or f"The `{name}` connector on the agent."
    doc_clause = f" Authoritative reference: {url}." if url else ""
    ep = meta.get("endpoint") or ""
    long_description = (
        f"{summary}{doc_clause} In CipherStrike, `{name}` POSTs to `{ep}`; the workspace sends your JSON "
        "body to the NyxStrike agent, which validates parameters and invokes the bundled integration."
    )
    usage = _format_usage(name, meta)
    cat = meta.get("category") or ""
    rider = _CATEGORY_RIDERS.get(cat, "")
    safety = _CORE_SAFETY if not rider else f"{_CORE_SAFETY} {rider}"
    return long_description, usage, safety
