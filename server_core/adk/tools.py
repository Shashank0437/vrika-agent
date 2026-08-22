"""
server_core/adk/tools.py

Typed Tool Definitions and Schemas for Google ADK Agents.
Translates NyxStrike tool_registry into validated OpenAI/Gemini/ADK tool declarations.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from tool_registry import TOOLS
from server_core.adk.state import TargetKnowledgeState, extract_state_from_tool_output


# Parameter overrides for security tools
_PARAM_OVERRIDES: Dict[tuple[str, str], str] = {
    ("nmap", "target"): "Hostname, IP, CIDR, or URL (URL scheme is stripped automatically)",
    ("masscan", "target"): "Hostname, IP, CIDR, or URL",
    ("rustscan", "target"): "Hostname, IP, or URL",
    ("nuclei", "target"): "Target URL (e.g. https://example.com) or IP address",
    ("httpx", "target"): "Target URL or hostname to probe",
    ("wafw00f", "url"): "Target URL to test for WAF (e.g. https://example.com)",
    ("penetration-report", "session_id"): "Optional session ID for report generation",
}


def _infer_json_schema_type(val: Any) -> str:
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, (int, float)):
        return "number"
    return "string"


def normalize_tool_parameters(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Clean and normalize parameters before execution (e.g. strip URL scheme for nmap)."""
    clean_name = tool_name.strip().lower()
    out = dict(args)

    # 1. Target URL/Host normalization for raw port scanners
    if clean_name in ("nmap", "nmap_advanced", "masscan", "rustscan", "amass", "subfinder"):
        target = out.get("target") or out.get("domain") or out.get("host")
        if isinstance(target, str) and (target.startswith("http://") or target.startswith("https://")):
            parsed = urlparse(target)
            host_only = parsed.netloc.split(":")[0]
            if "target" in out:
                out["target"] = host_only
            elif "domain" in out:
                out["domain"] = host_only

    # 2. Boolean strings
    for k, v in list(out.items()):
        if isinstance(v, str):
            if v.lower() == "true":
                out[k] = True
            elif v.lower() == "false":
                out[k] = False

    return out


def get_adk_tool_declaration(tool_name: str) -> Optional[Dict[str, Any]]:
    """Build OpenAI/Gemini/ADK-compliant function tool schema from tool_registry.TOOLS."""
    defn = TOOLS.get(tool_name)
    if not defn:
        return None

    properties: Dict[str, Any] = {}
    required: List[str] = []

    # Required params
    for param_name, param_meta in defn.get("params", {}).items():
        desc = _PARAM_OVERRIDES.get((tool_name, param_name), f"{param_name} (required)")
        properties[param_name] = {
            "type": "string",
            "description": desc,
        }
        required.append(param_name)

    # Optional params
    for param_name, default_val in defn.get("optional", {}).items():
        p_type = _infer_json_schema_type(default_val)
        desc = _PARAM_OVERRIDES.get((tool_name, param_name), f"{param_name} (optional, default: {default_val})")
        properties[param_name] = {
            "type": p_type,
            "description": desc,
        }

    return {
        "type": "function",
        "function": {
            "name": tool_name,
            "description": defn.get("desc", ""),
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


def get_adk_tools_for_names(tool_names: List[str]) -> List[Dict[str, Any]]:
    """Return tool declarations for a list of tool names."""
    declarations = []
    seen = set()
    for name in tool_names:
        clean = name.strip()
        if clean and clean not in seen:
            seen.add(clean)
            decl = get_adk_tool_declaration(clean)
            if decl:
                declarations.append(decl)
    return declarations
