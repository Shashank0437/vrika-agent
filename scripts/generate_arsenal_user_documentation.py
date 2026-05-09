#!/usr/bin/env python3
"""
Generate agent/server_api/tools_catalog/arsenal_user_documentation.json

Run from repo root: python agent/scripts/generate_arsenal_user_documentation.py

Validates: every tool_registry.TOOLS name has tool docs; every param key appearing
anywhere in params/optional has an entry under parameter_keys.
"""

from __future__ import annotations

import json
from pathlib import Path


def snake_title(s: str) -> str:
    return " ".join(w.capitalize() for w in s.replace("-", "_").split("_") if w)


def collect_keys(tools: dict) -> list[str]:
    keys: set[str] = set()
    for meta in tools.values():
        keys.update(meta.get("params") or {})
        keys.update(meta.get("optional") or {})
    return sorted(keys)


def infer_value_hint(key: str) -> str:
    kl = key.lower()
    if kl in {"os_detection", "version_detection", "aggressive", "stealth", "headless", "verify_ip", "https", "debug"}:
        return "boolean"
    if kl in {"port", "count", "depth", "timeout", "threads", "workers", "max_tools", "max_pages", "max_depth"}:
        return "number_or_string"
    if "port" in kl and kl != "export":
        return "number_or_string"
    return "string"


def infer_source(key: str) -> str:
    kl = key.lower()
    if any(x in kl for x in ("password", "token", "secret", "api_key", "auth_key", "jwt", "wep_key", "aes_key", "passphrase")):
        return "request_json_secrets"
    if any(kl.endswith(x) for x in ("_file", "_path")) or kl in {"file_path", "wordlist"}:
        return "agent_local_path_or_reference"
    if "cookie" in kl:
        return "request_json_sensitive"
    return "request_json_body"


def synthesize_parameter_doc(key: str) -> dict:
    """Return user-facing docs for catalog JSON bodies (no undocumented CLI specifics)."""
    kl = key.lower()
    label = snake_title(key)
    source = infer_source(key)
    vh = infer_value_hint(key)

    specifics: dict[str, str | None | list[str]] = {}

    families: tuple[tuple[callable[..., bool], str], ...] = (
        (lambda: "target" in kl or kl in {"domain", "host", "hostname", "targets"}, "Hosts, domains, subnets, or CIDR blocks the underlying scanner will touch."),
        (
            lambda: "url" in kl or kl in {"endpoint", "endpoints"},
            "Fully qualified URLs or endpoints the HTTP-oriented wrapper will fetch or fuzz.",
        ),
        (lambda: kl in {"additional_args", "extra_args", "extra_options"}, "Additional tokens appended when the Flask wrapper builds its shell invocation; keep values conservative."),
        (
            lambda: kl in {"ports", "port", "timing", "scan_type", "threads", "timeout", "interface", "channel"},
            "Execution tuning passed verbatim into the bundled command template for this connector.",
        ),
        (lambda: "wordlist" in kl or "_file" in kl or kl.endswith("_path"), "Path or locator the agent resolves on the bastion/container filesystem—not an automatic browser upload."),
        (lambda: "password" in kl or "passwd" in kl, "Secrets belong in guarded channels; omit from shared logs when possible."),
        (lambda: "token" in kl or "jwt" in kl or "api_key" in kl or kl.endswith("_key"), "Privileged material—rotate if leaked."),
        (lambda: kl in {"json", "body", "headers", "cookies", "cookie"}, "Structured HTTP/material supplied as JSON/strings for API helpers."),
        (lambda: kl in {"query", "command", "script", "module"}, "Core instruction passed to interpreters or scanners owned by this route."),
        (lambda: "output" in kl or kl.endswith("_dir"), "Filesystem destination folders or prefixes rendered by wrappers that support exporting artifacts."),
        (lambda: kl in {"session_id", "session_name"}, "References server-side CipherStrike/NyxStrike session handles where applicable."),
    )

    for pred, txt in families:
        if pred():
            specifics.setdefault("purpose", txt)
            break

    if not specifics.get("purpose"):
        specifics["purpose"] = (
            f"Forwarded as `{key}` in the JSON POST body accepted by this tool connector on the agent host—the workspace "
            "sends values unchanged aside from stripping empty optional scalar fields."
        )

    extras: list[str] = []
    if vh == "boolean":
        extras.append("Send JSON boolean true/false (checkboxes serialize to booleans automatically in the CipherStrike modal).")
    elif vh == "number_or_string":
        extras.append("Numbers are accepted as numeric JSON or textual digits depending on upstream validation.")

    help_text = specifics["purpose"]
    if extras:
        help_text = help_text.rstrip(".") + ". " + " ".join(extras)

    example: str | None
    examples_by_shape: dict[str, str | None] = {
        "boolean": None,
        "number_or_string": None,
        "string": "",
    }

    mapping = (
        ("target", "scanme.nmap.org"),
        ("additional_args", "-Pn"),
        ("ports", "80,443"),
        ("url", "https://example.com"),
        ("base_url", "https://api.example.com"),
        ("domain", "example.com"),
        ("wordlist", "/usr/share/wordlists/dirb/common.txt"),
        ("output_dir", "/tmp/cs-run"),
        ("session_id", "507f1f77bcf86cd799439011"),
    )
    for suffix, hint in mapping:
        if suffix in kl:
            example = hint
            break
    else:
        example = examples_by_shape[vh]

    return {
        "label": label,
        "help": help_text.strip(),
        "source": source,
        "value_type": vh,
        "example": example,
    }


def category_safety_rider(cat: str) -> str | None:
    riders = {
        "wifi_pentest": "Wireless emissions are regulated regionally — test only labs you legally control.",
        "exploitation": "Exploit payloads can corrupt live services; segregate workloads and snapshots before running.",
        "brute_force": "Credential guesses can trigger lockouts — coordinate with defenders and throttle attempts.",
        "web_vuln": "Active scanning can fuzz production forms; throttle requests and replay only consented payloads.",
        "network_recon": "Port scanners are noisy — obtain written scope describing address ranges explicitly.",
        "essential": "",
        "osint": "",
        "intelligence": "AI-assisted chaining must still respect data handling policies for scraped content.",
        "ai_assist": "LLM-assisted analysis may memorize sensitive pasted text — sanitize inputs beforehand.",
        "vulnerability_intelligence": "Fetching CVE feeds may embed vendor advisories restricted by license — verify redistribution rules.",
        "forensics": "Forensic payloads may handle sensitive evidence disks — encrypt exports at rest.",
        "binary": "",
        "cloud": "",
        "api": "",
        "active_directory": "AD tooling can authenticate with domain trusts — misuse may trip detection.",
        "database": "Database clients authenticate with plaintext credentials in JSON — purge logs after drills.",
        "monitoring": "",
        "essential": "",
    }
    v = riders.get(cat, "")
    return v or None


def build_tool_bundle(name: str, meta: dict) -> tuple[str, str, str]:
    desc = meta.get("desc") or name.replace("_", " ")
    ep = meta.get("endpoint") or ""
    method = meta.get("method") or "POST"
    cat = meta.get("category") or "uncategorized"

    long_desc = (
        f"{desc.rstrip('.')}. "
        f"This catalog entry (`{name}`) targets `{ep}` over HTTP {method}; the CipherStrike workspace forwards your JSON "
        "body to the NyxStrike agent, which performs final validation before invoking the packaged wrapper or integration."
    )

    usage = (
        "Fill the parameters below and choose Execute. Required fields mirror the catalog contract; optional fields may be "
        "left blank to omit them from the proxied JSON (empty strings are dropped for optional scalar fields unless the modal "
        f"shows a preset default mirrored from `{name}`'s arsenal definition). Responses return structured stdout/stderr plus "
        "metadata from the subprocess runner."
    )

    core_safety = (
        "Operate only inside authorized penetration tests or sanctioned lab networks. Respect stop conditions, lawful intercept "
        "rules, and internal change windows. Sensitive parameters are captured in CipherStrike tenant execution logs alongside "
        "NyxStrike response snippets — avoid pasting production secrets when alternatives exist."
    )
    rider = category_safety_rider(cat)
    safety = core_safety if not rider else f"{core_safety} {rider}"

    return long_desc, usage, safety


def main() -> None:
    here = Path(__file__).resolve()
    repo = here.parent.parent.parent if here.parent.name == "scripts" else here.parent.parent
    agent_root = repo / "agent"
    registry_path = agent_root / "tool_registry.py"
    if registry_path.exists():
        import sys

        sys.path.insert(0, str(agent_root))
    import tool_registry as tr
    import importlib.util

    nar_path = agent_root / "server_api" / "tools_catalog" / "arsenal_web_narratives.py"
    spec = importlib.util.spec_from_file_location("arsenal_web_narratives_gen", nar_path)
    assert spec and spec.loader
    _nar = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_nar)
    web_build_tool_bundle = _nar.build_tool_bundle

    tools = tr.TOOLS
    keys = collect_keys(tools)
    pk_docs = {k: synthesize_parameter_doc(k) for k in keys}
    catalog_root = Path(__file__).resolve().parent.parent / "server_api" / "tools_catalog"
    param_help_overlay = catalog_root / "param_key_help.json"
    if param_help_overlay.exists():
        overlay = json.loads(param_help_overlay.read_text(encoding="utf-8"))
        for pk, meta in overlay.items():
            doc = pk_docs.setdefault(pk, synthesize_parameter_doc(pk))
            h = str((meta or {}).get("help") or "").strip()
            if h:
                doc["help"] = h

    td: dict[str, dict[str, str]] = {}
    tool_docs_overlay_path = catalog_root / "tool_catalog_docs.json"
    tool_overlay: dict[str, dict[str, str]] = {}
    if tool_docs_overlay_path.exists():
        tool_overlay = json.loads(tool_docs_overlay_path.read_text(encoding="utf-8"))
    for name in sorted(tools.keys()):
        if name in tool_overlay:
            blk = tool_overlay[name]
            td[name] = {
                "long_description": str(blk.get("long_description") or "").strip(),
                "usage": str(blk.get("usage") or "").strip(),
                "safety": str(blk.get("safety") or "").strip(),
            }
            continue
        ld, u, s = web_build_tool_bundle(name, tools[name])
        td[name] = {"long_description": ld, "usage": u, "safety": s}

    doc = {"parameter_keys": pk_docs, "tools": td}

    out = Path(__file__).resolve().parent.parent / "server_api" / "tools_catalog" / "arsenal_user_documentation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    assert len(td) == len(tools), f"tools mismatch {len(td)} vs registry {len(tools)}"

    leftover_keys = []
    tool_names = sorted(tools)
    merged_param_keys = set()
    for n in tool_names:
        m = tools[n]
        for k in list((m.get("params") or {}).keys()) + list((m.get("optional") or {}).keys()):
            merged_param_keys.add(k)
            if k not in pk_docs:
                leftover_keys.append((n, k))
    assert not leftover_keys, leftover_keys[:20]

    print(f"Wrote {out} ({len(td)} tools, {len(pk_docs)} parameter docs)")


if __name__ == "__main__":
    main()
