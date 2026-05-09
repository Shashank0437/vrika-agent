"""Internal authenticated route to invoke catalog tools with optional Redis-backed live logs."""

from __future__ import annotations

import logging
import os
from typing import Any

from flask import Blueprint, current_app, jsonify, request

from server_core.tool_run_context import stream_run_scope
from server_core.tool_run_stream import publish_terminal

logger = logging.getLogger(__name__)

api_internal_tool_run_bp = Blueprint("internal_tool_run", __name__)

# Mirrors ``agent_client._AGENT_TOOL_ROUTE_PREFIXES`` on the FastAPI server.
_INTERNAL_ALLOWED_PREFIXES: tuple[str, ...] = (
    "/api/tools/",
    "/api/osint/tools/",
    "/api/intelligence/",
    "/api/vuln-intel/",
    "/api/tool/",
    "/api/bot/",
)


def _normalize_path(path: str) -> str | None:
    if not isinstance(path, str) or not path.strip():
        return None
    ep = path.strip()
    if not ep.startswith("/"):
        ep = "/" + ep
    ep = ep.split("?", 1)[0].strip() or "/"
    if ".." in ep or "\x00" in ep:
        return None
    return ep


def _path_allowed(ep: str) -> bool:
    return any(ep.startswith(prefix) for prefix in _INTERNAL_ALLOWED_PREFIXES)


def _nested_invoke_headers() -> dict[str, str]:
    """Re-send credentials so nested ``test_client`` POSTs satisfy ``optional_bearer_auth``."""
    h: dict[str, str] = {}
    tok = (os.environ.get("NYXSTRIKE_API_TOKEN") or "").strip()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    bridge = (os.environ.get("CIPHERSTRIKE_BRIDGE_SECRET") or "").strip()
    if bridge:
        h["X-CipherStrike-Bridge-Secret"] = bridge
    return h


@api_internal_tool_run_bp.route("/api/internal/tool-run", methods=["POST"])
def internal_tool_run():
    """
    Body JSON: ``{"path": "/api/tools/foo", "json": {...}, "stream_run_id": "uuid"}``.
    Executes the inner catalog POST under ``stream_run_scope`` so ``execute_command`` can emit Redis chunks.
    """
    data = request.get_json(force=True, silent=True) or {}
    raw_path = data.get("path")
    ep = _normalize_path(str(raw_path or ""))
    if not ep:
        return jsonify({"success": False, "error": "Invalid path"}), 400
    if not _path_allowed(ep):
        return jsonify({"success": False, "error": "Tool path is not allowed for internal invoke"}), 400

    inner_json = data.get("json")
    if inner_json is None:
        inner_body: dict[str, Any] = {}
    elif isinstance(inner_json, dict):
        inner_body = inner_json
    else:
        return jsonify({"success": False, "error": "json field must be an object when provided"}), 400

    stream_run_id = data.get("stream_run_id")
    sr_id = str(stream_run_id).strip() if stream_run_id else ""

    status_code = 500
    body_out: Any = {"success": False, "error": "internal_tool_run failed"}

    try:
        with stream_run_scope(sr_id if sr_id else None):
            with current_app.test_client() as client:
                resp = client.post(ep, json=inner_body, headers=_nested_invoke_headers())
        status_code = int(resp.status_code)
        parsed = resp.get_json(silent=True)
        body_out = parsed if parsed is not None else {"raw": resp.get_data(as_text=True)}
        if status_code >= 400 and isinstance(body_out, dict) and body_out.get("success") is None:
            body_out.setdefault("success", False)
    except Exception as exc:  # pragma: no cover
        logger.exception("internal_tool_run")
        status_code = 500
        body_out = {"success": False, "error": str(exc)}
    finally:
        if sr_id:
            publish_terminal(sr_id, status_code, body_out)

    return jsonify(body_out), status_code
