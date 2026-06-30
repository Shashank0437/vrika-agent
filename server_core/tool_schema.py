"""
server_core/tool_schema.py

Converts NyxStrike tool_registry entries into OpenAI-style function tools.

The registry is already categorised and effectiveness-sorted.  This module
provides one entry point used by the chat layer:

  build_tool_schemas(tools) -> List[dict]

Where ``tools`` is the list returned by ``get_tools_for_category()`` or a
hand-picked subset.  The output is OpenAI-style function tools, consumed by
Gemini (functionDeclarations) and OpenAI backends via ``LLMClient.chat(tools=…)``.
"""

from typing import Any, Dict, List


# Parameter type hints: registry values look like "REQUIRED" or "default=X".
# We map them to JSON-schema "string" by default; numeric defaults get "number".
# Per-tool parameter hints for the LLM (compact catalog path).
_PARAM_DESCRIPTION_OVERRIDES: Dict[tuple[str, str], str] = {
    ("nmap", "target"): (
        "Hostname, IP, CIDR, or URL (e.g. https://example.com — backend strips to host automatically)"
    ),
    ("nmap_advanced", "target"): (
        "Hostname, IP, CIDR, or URL (e.g. https://example.com — backend strips to host automatically)"
    ),
    ("masscan", "target"): "Hostname, IP, CIDR, or URL (URL normalized to host)",
    ("rustscan", "target"): "Hostname, IP, or URL (URL normalized to host)",
    ("radare2", "commands"): "Semicolon-separated list of r2 commands to execute (e.g., 'aaa; afl; pdf @ main'). CRITICAL for meaningful output.",
    ("radare2", "additional_args"): "Additional radare2 CLI flags (e.g., '-e bin.relocs.apply=true').",
    ("ropper", "additional_args"): "Additional ropper CLI flags.",
    ("ropper", "search"): "Specific gadget instruction sequence to search for (e.g., 'pop rdi; ret').",
    ("ropper", "architecture"): "Target architecture (e.g., 'x86', 'x86_64').",
}


def _param_description(tool_name: str, param_name: str, *, required: bool, default_str: str = "") -> str:
    override = _PARAM_DESCRIPTION_OVERRIDES.get((tool_name, param_name))
    if override:
        return override
    if required:
        return f"{param_name} (required)"
    return f"{param_name} (optional, default: {default_str})"


def _infer_type(default_value: Any) -> str:
  if isinstance(default_value, bool):
    return "boolean"
  if isinstance(default_value, int):
    return "number"
  if isinstance(default_value, float):
    return "number"
  return "string"


def _registry_entry_to_schema(name: str, tool_def: Dict[str, Any]) -> Dict[str, Any]:
  """Convert a single full registry entry (from TOOLS dict) into OpenAI-style function tool schema."""
  properties: Dict[str, Any] = {}
  required: List[str] = []

  # Required params (params dict — keys are param names, values are {required:True} or similar)
  for param_name, param_meta in tool_def.get("params", {}).items():
    properties[param_name] = {
      "type": "string",
      "description": _param_description(name, param_name, required=True),
    }
    required.append(param_name)

  # Optional params (optional dict — keys are param names, values are defaults)
  for param_name, default_val in tool_def.get("optional", {}).items():
    param_type = _infer_type(default_val)
    default_str = str(default_val).replace("default=", "", 1) if str(default_val).startswith("default=") else str(default_val)
    properties[param_name] = {
      "type": param_type,
      "description": _param_description(name, param_name, required=False, default_str=default_str),
    }

  return {
    "type": "function",
    "function": {
      "name": name,
      "description": tool_def.get("desc", ""),
      "parameters": {
        "type": "object",
        "properties": properties,
        "required": required,
      },
    },
  }


def build_tool_schemas(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
  """Convert compact registry tool dicts into OpenAI-format function tools.

  Each item in ``tools`` is the shape returned by ``get_tools_for_category()``:

    {"name": str, "desc": str, "endpoint": str, "method": str, "params": dict}

  The ``params`` dict merges required and optional keys as "REQUIRED" or
  "default=…" strings. Returns ``{"type":"function","function":{…}}`` list;
  ``LLMClient`` maps these to Gemini ``functionDeclarations`` when needed.
  """
  schemas = []
  for t in tools:
    name = t.get("name", "")
    desc = t.get("desc", "")
    params_compact = t.get("params", {})

    properties: Dict[str, Any] = {}
    required: List[str] = []

    for param_name, param_val in params_compact.items():
      if param_val == "REQUIRED":
        properties[param_name] = {
          "type": "string",
          "description": _param_description(name, param_name, required=True),
        }
        required.append(param_name)
      else:
        # "default=X" string — extract default for description
        default_str = str(param_val).replace("default=", "", 1) if str(param_val).startswith("default=") else str(param_val)
        
        # Infer parameter type from default string value
        param_type = "string"
        lower_def = default_str.strip().lower()
        if lower_def in ("true", "false"):
          param_type = "boolean"
        elif lower_def.isdigit():
          param_type = "integer"
        else:
          try:
            float(lower_def)
            param_type = "number"
          except ValueError:
            pass

        properties[param_name] = {
          "type": param_type,
          "description": _param_description(name, param_name, required=False, default_str=default_str),
        }

    schemas.append({
      "type": "function",
      "function": {
        "name": name,
        "description": desc,
        "parameters": {
          "type": "object",
          "properties": properties,
          "required": required,
        },
      },
    })

  return schemas
