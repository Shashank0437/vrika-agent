"""Load generated user-facing documentation for the full NyxStrike catalog."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _doc_source_urls() -> dict[str, str]:
    """Optional per-tool authoritative URLs — local JSON avoids importing heavy server_api graph."""
    p = Path(__file__).with_name("tool_web_sources.json")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except OSError:
        return {}
    out: dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    for name, row in raw.items():
        if isinstance(row, dict):
            u = str(row.get("url") or "").strip()
            if u:
                out[name] = u
    return out


@lru_cache(maxsize=1)
def _dataset() -> dict[str, Any]:
    path = Path(__file__).with_name("arsenal_user_documentation.json")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("catalog_user_docs: could not read %s: %s", path, exc)
        return {"parameter_keys": {}, "tools": {}}
    return json.loads(raw)


def _infer_runtime_type(default_value: Any) -> str:
    if isinstance(default_value, bool):
        return "boolean"
    if isinstance(default_value, (int, float)) and not isinstance(default_value, bool):
        return "number"
    return "string"


def build_parameter_documentation(tool_name: str, meta: dict[str, Any]) -> dict[str, Any]:
    """Merge registry params/optional with generated key-level documentation."""
    data = _dataset()
    key_docs: dict[str, Any] = data.get("parameter_keys") or {}
    out: dict[str, Any] = {}

    params = meta.get("params") or {}
    optional = meta.get("optional") or {}

    for key, spec in params.items():
        base = dict(key_docs.get(key) or {})
        req = bool(isinstance(spec, dict) and spec.get("required"))
        base["required"] = req
        if "label" not in base:
            base["label"] = key.replace("_", " ").title()
        if "catalog_default" in base:
            del base["catalog_default"]
        out[key] = base

    for key, def_val in optional.items():
        if key in out:
            continue
        base = dict(key_docs.get(key) or {})
        base["required"] = False
        if "label" not in base:
            base["label"] = key.replace("_", " ").title()
        rt = _infer_runtime_type(def_val)
        if rt in ("boolean", "number"):
            base["value_type"] = rt
        elif not base.get("value_type"):
            base["value_type"] = rt
        if def_val is not None and def_val != "":
            base["catalog_default"] = def_val
        out[key] = base

    if tool_name not in (data.get("tools") or {}):
        logger.warning("catalog_user_docs: missing tool bundle for %r", tool_name)

    return out


def tool_narrative_blocks(tool_name: str) -> dict[str, str]:
    data = _dataset()
    blocks = (data.get("tools") or {}).get(tool_name) or {}
    return {
        "long_description": str(blocks.get("long_description") or ""),
        "usage": str(blocks.get("usage") or ""),
        "safety": str(blocks.get("safety") or ""),
    }


def augment_catalog_row(name: str, row: dict[str, Any]) -> None:
    """Mutate a tools array element from get_tools with documentation fields."""
    meta = {
        "params": row.get("params") or {},
        "optional": row.get("optional") or {},
    }
    narrative = tool_narrative_blocks(name)
    row["long_description"] = narrative["long_description"]
    row["usage"] = narrative["usage"]
    row["safety"] = narrative["safety"]
    row["parameter_documentation"] = build_parameter_documentation(name, meta)
    row["documentation_url"] = _doc_source_urls().get(name, "")
