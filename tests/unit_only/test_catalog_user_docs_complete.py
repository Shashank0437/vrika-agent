"""Ensure generated documentation covers the full NyxStrike registry."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import tool_registry as tr


def _load_catalog_user_docs():
    agent_root = Path(__file__).resolve().parents[2]
    py_path = agent_root / "server_api/tools_catalog/catalog_user_docs.py"
    spec = importlib.util.spec_from_file_location("catalog_user_docs_isolated", py_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_json_covers_all_tools_and_param_keys() -> None:
    agent_root = Path(__file__).resolve().parents[2]
    path = agent_root / "server_api/tools_catalog/arsenal_user_documentation.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    tool_names = set(tr.TOOLS.keys())
    assert set(data["tools"].keys()) == tool_names

    merged_keys: set[str] = set()
    for meta in tr.TOOLS.values():
        merged_keys.update(meta.get("params") or {})
        merged_keys.update(meta.get("optional") or {})
    assert set(data["parameter_keys"].keys()) == merged_keys


def test_augment_row_covers_every_tool() -> None:
    cud = _load_catalog_user_docs()
    cud._dataset.cache_clear()

    missing: list[str] = []
    for tool_name in sorted(tr.TOOLS.keys()):
        meta = tr.TOOLS[tool_name]
        row = {
            "name": tool_name,
            "desc": meta.get("desc", ""),
            "category": meta.get("category", ""),
            "endpoint": meta.get("endpoint", ""),
            "method": meta.get("method", "POST"),
            "params": meta.get("params", {}),
            "optional": meta.get("optional", {}),
            "effectiveness": 0.5,
            "effectiveness_runs": 0,
            "effectiveness_live": False,
            "parent_tool": None,
        }
        cud.augment_catalog_row(tool_name, row)
        assert isinstance(row.get("documentation_url"), str)
        if not row["long_description"].strip() or not row["usage"].strip() or not row["safety"].strip():
            missing.append(tool_name)
            continue
        pdoc = row["parameter_documentation"]
        assert isinstance(pdoc, dict)
        for k in meta.get("params") or {}:
            if k not in pdoc:
                missing.append(f"{tool_name}:param:{k}")
                continue
            if not str(pdoc[k].get("help") or "").strip():
                missing.append(f"{tool_name}:param_help:{k}")
        for k in meta.get("optional") or {}:
            if k not in pdoc:
                missing.append(f"{tool_name}:opt:{k}")
                continue
            if not str(pdoc[k].get("help") or "").strip():
                missing.append(f"{tool_name}:opt_help:{k}")
    assert not missing, missing[:50]
