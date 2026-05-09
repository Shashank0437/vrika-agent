"""
Stateless LLM bridge for CipherStrike FastAPI — no SQLite chat persistence.

Endpoints:
  POST /api/cipherstrike/schemas-from-tools
  POST /api/cipherstrike/route-intent  (JSON — operational vs conversational + tool shortlist)
  POST /api/cipherstrike/llm-chat
  POST /api/cipherstrike/llm-stream  (SSE; optional JSON ``schemas`` for tool-bound Gemini streaming)
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
from typing import Any, Dict, Generator, List

from flask import Blueprint, Response, jsonify, request, stream_with_context

from server_core.singletons import llm_client
from server_core.tool_schema import build_tool_schemas

logger = logging.getLogger(__name__)

_MAX_MULTI_TOOL_CALLS = max(1, int(os.environ.get("CIPHERSTRIKE_MAX_MULTI_TOOL_CALLS", "8")))

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


def _extract_json_object(text: str) -> Dict[str, Any] | None:
    """Best-effort parse JSON object from LLM output (strip fences / prose)."""
    if not text or not isinstance(text, str):
        return None
    raw = text.strip()
    fence = re.search(r"\{[\s\S]*\}", raw)
    if fence:
        raw = fence.group(0)
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


_ROUTER_SYSTEM_TEMPLATE = """You are a router for CipherStrike (authorized security testing assistant).

Given the user message and the compact tool list below, respond with **only** valid JSON (no markdown):
{{"intent":"operational"|"conversational","tool_names":[],"reply":""}}

Rules:
- intent **operational** when the user wants scans, enumeration, exploitation workflows, CVE lookup, concrete tooling on targets, URLs/hosts to assess, penetration tests, or any request where starting security tools would help (even if they also ask "how" or "can you").
- If the message contains **http:// or https://** and asks for testing, assessment, or a pentest → **operational** and pick suitable tools from the list (e.g. HTTP probe, tech fingerprint, vuln templates, web scanner — use names that exist below).
- intent **conversational** only for pure greetings, thanks, meta chat, or conceptual questions with **no target** and **no request to run or plan tooling**.
- **tool_names**: when operational, include 1–{max_tools} tool **names** chosen ONLY from the list below (exact spelling). Prefer a minimal set that can **start** the assessment (do not leave tool_names empty when intent is operational).
- **reply**: when conversational, a short helpful reply (1–6 sentences). When operational, usually "" unless one short clarifying question is essential.

Available tools (name: short description):
{catalog}
"""


@api_cipherstrike_bridge_bp.route("/api/cipherstrike/route-intent", methods=["POST"])
def route_intent():
    """LLM router — operational vs conversational + subset of tool names from caller-supplied catalog."""
    blocked = _require_bridge()
    if blocked:
        return blocked
    if not llm_client.is_available():
        return jsonify({"success": False, "error": "LLM is not available"}), 503
    try:
        body = request.get_json(force=True, silent=True) or {}
        message = body.get("message")
        if not isinstance(message, str) or not message.strip():
            return jsonify({"success": False, "error": "message is required"}), 400
        tools = body.get("tools")
        if not isinstance(tools, list):
            return jsonify({"success": False, "error": "tools must be a list"}), 400
        max_pick = max(1, min(int(body.get("max_tool_names") or 12), 24))
        allowed_names = {
            str(t.get("name") or "").strip()
            for t in tools
            if isinstance(t, dict) and str(t.get("name") or "").strip()
        }
        catalog_lines: List[str] = []
        for t in tools:
            if not isinstance(t, dict):
                continue
            name = str(t.get("name") or "").strip()
            if not name:
                continue
            desc = str(t.get("desc") or "").strip().replace("\n", " ")
            if len(desc) > 100:
                desc = desc[:97] + "..."
            catalog_lines.append(f"- {name}: {desc}")
        catalog_text = "\n".join(catalog_lines) if catalog_lines else "(no tools)"
        sys_prompt = _ROUTER_SYSTEM_TEMPLATE.format(max_tools=max_pick, catalog=catalog_text)
        result = llm_client.chat(
            [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": message.strip()},
            ],
            tools=None,
        )
        text_out = result if isinstance(result, str) else str((result or {}).get("content") or "")
        parsed = _extract_json_object(text_out) or {}
        intent = str(parsed.get("intent") or "conversational").lower().strip()
        if intent not in ("operational", "conversational"):
            intent = "conversational"
        raw_names = parsed.get("tool_names") or []
        tool_names: List[str] = []
        if isinstance(raw_names, list) and intent == "operational":
            for n in raw_names[:max_pick]:
                if isinstance(n, str) and n.strip() in allowed_names:
                    tool_names.append(n.strip())
        reply = parsed.get("reply")
        reply_str = reply.strip() if isinstance(reply, str) else ""
        return jsonify(
            {
                "success": True,
                "intent": intent,
                "tool_names": tool_names,
                "reply": reply_str,
            },
        )
    except Exception as exc:
        logger.exception("cipherstrike_bridge route-intent")
        return jsonify({"success": False, "error": str(exc)}), 500


def _yield_cipherstrike_tool_pending_sse(tool_calls: List[Dict[str, Any]]) -> Generator[str, None, None]:
    """Emit TOOL_CALL_PENDING / TOOL_CALL_BATCH_PENDING SSE frames for registry-resolved tools."""
    from tool_registry import get_tool

    batch_payloads: List[Dict[str, Any]] = []
    if not isinstance(tool_calls, list):
        return
    for tc in tool_calls[:_MAX_MULTI_TOOL_CALLS]:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function", {})
        if not isinstance(fn, dict):
            continue
        tool_name = str(fn.get("name") or "").strip()
        arguments = fn.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}
        tool_def = get_tool(tool_name)
        if tool_def:
            batch_payloads.append(
                {
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "description": str(tool_def.get("desc") or ""),
                    "endpoint": str(tool_def.get("endpoint") or ""),
                },
            )
        else:
            logger.warning(
                "cipherstrike_bridge: unknown tool %r from model, skipping",
                tool_name,
            )

    if len(batch_payloads) == 1:
        yield f"data: [TOOL_CALL_PENDING] {json.dumps(batch_payloads[0])}\n\n"
        return
    if len(batch_payloads) > 1:
        envelope = {"calls": batch_payloads}
        yield f"data: [TOOL_CALL_BATCH_PENDING] {json.dumps(envelope)}\n\n"
        return
    if tool_calls:
        tc0 = tool_calls[0]
        fn0 = tc0.get("function", {}) if isinstance(tc0, dict) else {}
        logger.warning(
            "cipherstrike_bridge: tool_calls present but none resolved via registry (first=%r)",
            fn0.get("name") if isinstance(fn0, dict) else None,
        )


def _stream_tools_blocking_sse(messages: List[Dict[str, Any]], schemas: List[Dict[str, Any]]) -> Generator[str, None, None]:
    """Non-streaming chat + tools (OpenAI/Anthropic or fallback); replay assistant text as SSE chunks.

    Operational turns with tool schemas on non-Gemini providers take this path: the model runs to
    completion (tools may block), then assistant text is chunked into SSE events. There is no live
    token stream until after ``llm_client.chat`` returns — expect a pause after ``[THINKING]``,
    then batched ``data:`` lines (still chunked for SSE framing, but not token-real-time).
    """
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
            pending_sse = list(_yield_cipherstrike_tool_pending_sse(tool_calls if isinstance(tool_calls, list) else []))
            if pending_sse:
                for ln in pending_sse:
                    yield ln
                yield "data: [DONE]\n\n"
                return

        if content:
            for chunk in _iter_sse_text_chunks(content):
                yield f"data: {json.dumps(chunk)}\n\n"
        yield "data: [DONE]\n\n"
    except GeneratorExit:
        raise
    except Exception as exc:
        logger.error("cipherstrike_bridge blocking tools stream: %s", exc)
        yield f"data: [ERROR] {str(exc)}\n\n"


def _stream_llm_sse(
    messages: List[Dict[str, Any]],
    schemas: List[Dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Stream tokens from the configured LLM; optional ``schemas`` enables tool mode."""
    backend = getattr(llm_client, "_backend", None)
    provider = getattr(backend, "provider", None) if backend else None
    schemas_ok = isinstance(schemas, list) and len(schemas) > 0

    if schemas_ok and provider not in ("gemini", "openai"):
        yield from _stream_tools_blocking_sse(messages, schemas)
        return

    tools_arg = schemas if schemas_ok else None
    try:
        yield "data: [THINKING]\n\n"
        for chunk in llm_client.stream_chat(messages, tools=tools_arg):
            if isinstance(chunk, dict):
                if chunk.get("type") == "thinking":
                    yield f"data: [THINK_TOKEN] {json.dumps(chunk.get('content', ''))}\n\n"
                    continue
                if chunk.get("type") == "_cipherstrike_tool_calls":
                    tcalls = chunk.get("tool_calls") or []
                    pending_sse = list(_yield_cipherstrike_tool_pending_sse(tcalls if isinstance(tcalls, list) else []))
                    if pending_sse:
                        for ln in pending_sse:
                            yield ln
                    yield "data: [DONE]\n\n"
                    return
                yield f"data: [STATS] {json.dumps(chunk)}\n\n"
                continue
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
        schemas = body.get("schemas")
        if schemas is not None and not isinstance(schemas, list):
            return jsonify({"success": False, "error": "schemas must be a list when supplied"}), 400

        return Response(
            stream_with_context(_stream_llm_sse(messages, schemas if isinstance(schemas, list) else None)),
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
    """Compatibility alias — same as POST /llm-stream with a non-empty schemas list (blocking tools on non-Gemini)."""
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

        return Response(
            stream_with_context(_stream_llm_sse(messages, schemas)),
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
