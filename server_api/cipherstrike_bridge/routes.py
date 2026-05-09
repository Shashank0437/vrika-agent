"""
Stateless LLM bridge for CipherStrike FastAPI — no SQLite chat persistence.

Endpoints:
  POST /api/cipherstrike/schemas-from-tools
  POST /api/cipherstrike/llm-chat
  POST /api/cipherstrike/llm-stream  (SSE)
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from typing import Any, Dict, List

from flask import Blueprint, Response, jsonify, request, stream_with_context

from server_core.singletons import llm_client
from server_core.tool_schema import build_tool_schemas

logger = logging.getLogger(__name__)

api_cipherstrike_bridge_bp = Blueprint("api_cipherstrike_bridge", __name__)


def _bridge_authorized() -> bool:
    secret = (os.environ.get("CIPHERSTRIKE_BRIDGE_SECRET") or "").strip()
    if not secret:
        return True
    token = request.headers.get("X-CipherStrike-Bridge-Secret") or ""
    if len(token) != len(secret):
        return False
    return hmac.compare_digest(token.encode("utf-8"), secret.encode("utf-8"))


def _require_bridge():
    if not _bridge_authorized():
        return jsonify({"success": False, "error": "Unauthorized bridge request"}), 401
    return None


def _iter_sse_text_chunks(text: str, chunk_chars: int = 72):
    if not text:
        return
    step = max(chunk_chars, 1)
    for i in range(0, len(text), step):
        yield text[i : i + step]


def _stream_llm_sse(messages: List[Dict[str, Any]]):
    full_response: List[str] = []
    response_stats = None
    try:
        yield "data: [THINKING]\n\n"
        for chunk in llm_client.stream_chat(messages):
            if isinstance(chunk, dict):
                if chunk.get("type") == "thinking":
                    yield f"data: [THINK_TOKEN] {json.dumps(chunk.get('content', ''))}\n\n"
                    continue
                response_stats = chunk
                yield f"data: [STATS] {json.dumps(chunk)}\n\n"
                continue
            full_response.append(chunk)
            yield f"data: {json.dumps(chunk)}\n\n"
        yield "data: [DONE]\n\n"
    except GeneratorExit:
        raise
    except Exception as exc:
        logger.error("cipherstrike_bridge llm-stream: %s", exc)
        yield f"data: [ERROR] {str(exc)}\n\n"


@api_cipherstrike_bridge_bp.route("/api/cipherstrike/schemas-from-tools", methods=["POST"])
def schemas_from_tools():
    blocked = _require_bridge()
    if blocked:
        return blocked
    try:
        body = request.get_json(force=True, silent=True) or {}
        tools = body.get("tools")
        if not isinstance(tools, list):
            return jsonify({"success": False, "error": "tools must be a list"}), 400
        schemas = build_tool_schemas(tools)
        return jsonify({"success": True, "schemas": schemas})
    except Exception as exc:
        logger.exception("cipherstrike_bridge schemas-from-tools")
        return jsonify({"success": False, "error": str(exc)}), 500


@api_cipherstrike_bridge_bp.route("/api/cipherstrike/llm-chat", methods=["POST"])
def llm_chat():
    blocked = _require_bridge()
    if blocked:
        return blocked
    if not llm_client.is_available():
        return jsonify({"success": False, "error": "LLM is not available"}), 503
    try:
        body = request.get_json(force=True, silent=True) or {}
        messages = body.get("messages")
        if not isinstance(messages, list):
            return jsonify({"success": False, "error": "messages must be a list"}), 400
        tools = body.get("tools")
        tool_list = tools if isinstance(tools, list) and tools else None

        result = llm_client.chat(messages, tools=tool_list)

        if isinstance(result, dict):
            out = {
                "success": True,
                "content": result.get("content") if isinstance(result.get("content"), str) else "",
                "tool_calls": result.get("tool_calls"),
                "thinking_content": result.get("thinking_content"),
            }
            return jsonify(out)

        text = result if isinstance(result, str) else ("" if result is None else str(result))
        return jsonify({"success": True, "content": text.strip(), "tool_calls": None})
    except RuntimeError as exc:
        return jsonify({"success": False, "error": str(exc)}), 503
    except Exception as exc:
        logger.exception("cipherstrike_bridge llm-chat")
        return jsonify({"success": False, "error": str(exc)}), 500


@api_cipherstrike_bridge_bp.route("/api/cipherstrike/llm-stream", methods=["POST"])
def llm_stream():
    blocked = _require_bridge()
    if blocked:
        return blocked
    if not llm_client.is_available():
        return jsonify({"success": False, "error": "LLM is not available"}), 503
    try:
        body = request.get_json(force=True, silent=True) or {}
        messages = body.get("messages")
        if not isinstance(messages, list):
            return jsonify({"success": False, "error": "messages must be a list"}), 400

        return Response(
            stream_with_context(_stream_llm_sse(messages)),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )
    except Exception as exc:
        logger.exception("cipherstrike_bridge llm-stream")
        return jsonify({"success": False, "error": str(exc)}), 500


@api_cipherstrike_bridge_bp.route("/api/cipherstrike/llm-chat-with-tools-stream-text", methods=["POST"])
def llm_chat_tools_then_chunk():
    """
    Non-streaming llm chat with tools; if plain text response, emit SSE chunks like chat.py.
    If tool_calls, emit TOOL_CALL_PENDING (caller persists — no pending store here).
    """
    blocked = _require_bridge()
    if blocked:
        return blocked
    if not llm_client.is_available():
        return jsonify({"success": False, "error": "LLM is not available"}), 503

    try:
        body = request.get_json(force=True, silent=True) or {}
        messages = body.get("messages")
        schemas = body.get("schemas")
        if not isinstance(messages, list):
            return jsonify({"success": False, "error": "messages must be a list"}), 400
        if not isinstance(schemas, list) or not schemas:
            return jsonify({"success": False, "error": "schemas must be a non-empty list"}), 400

        def gen():
            try:
                yield "data: [THINKING]\n\n"
                result = llm_client.chat(messages, tools=schemas)
                tool_calls = result.get("tool_calls") if isinstance(result, dict) else None
                _raw = result.get("content", "") if isinstance(result, dict) else result
                content = _raw if isinstance(_raw, str) else ("" if _raw is None else str(_raw))
                _think = result.get("thinking_content") if isinstance(result, dict) else None
                thinking_extra = _think.strip() if isinstance(_think, str) else ""
                if thinking_extra:
                    yield f"data: [THINK_TOKEN] {json.dumps(thinking_extra)}\n\n"

                if tool_calls:
                    tc = tool_calls[0]
                    fn = tc.get("function", {})
                    tool_name = fn.get("name", "")
                    arguments = fn.get("arguments", {})
                    from tool_registry import get_tool

                    tool_def = get_tool(tool_name)
                    if tool_def:
                        pending_payload = {
                            "tool_name": tool_name,
                            "arguments": arguments if isinstance(arguments, dict) else {},
                            "description": tool_def.get("desc", ""),
                            "endpoint": tool_def.get("endpoint", ""),
                        }
                        yield f"data: [TOOL_CALL_PENDING] {json.dumps(pending_payload)}\n\n"
                        yield "data: [DONE]\n\n"
                        return
                    logger.warning(
                        "cipherstrike_bridge: unknown tool %r from model, falling back to text",
                        tool_name,
                    )

                if content:
                    for chunk in _iter_sse_text_chunks(content):
                        yield f"data: {json.dumps(chunk)}\n\n"
                yield "data: [DONE]\n\n"
            except GeneratorExit:
                return
            except Exception as exc:
                logger.error("cipherstrike_bridge llm-chat-with-tools-stream: %s", exc)
                yield f"data: [ERROR] {str(exc)}\n\n"

        return Response(
            stream_with_context(gen()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )
    except Exception as exc:
        logger.exception("cipherstrike_bridge llm-chat-with-tools-stream-text")
        return jsonify({"success": False, "error": str(exc)}), 500
