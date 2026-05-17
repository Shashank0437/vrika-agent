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

_MAX_MULTI_TOOL_CALLS = max(1, int(os.environ.get("CIPHERSTRIKE_MAX_MULTI_TOOL_CALLS", "16")))

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


_PENETRATION_REPORT_SCHEMA_NUDGE = (
    "CipherStrike backend: PDF generation runs via the penetration-report tool on this agent host; "
    "ReportLab is installed. When the user wants a PDF or penetration-test report from this session, "
    "you MUST call the penetration-report function (empty {} arguments if nothing is required). "
    "Do not refuse by claiming reportlab or Python dependencies are missing—that is wrong for this system."
)

_NMAP_TARGET_SCHEMA_NUDGE = (
    "CipherStrike nmap accepts target as hostname, IP, CIDR, or full URL. "
    "When the user says run nmap on https://example.com (or http://…), call the nmap function immediately "
    'with target set to that URL string (e.g. "https://example.com"). Do not ask them to reformat—the agent '
    "strips the scheme and path to the host before running nmap. Never reply that only bare hostnames are allowed."
)


def _schemas_include_tool_name(schemas: List[Dict[str, Any]] | None, tool_name: str) -> bool:
    want = tool_name.strip()
    if not want or not isinstance(schemas, list):
        return False
    for s in schemas:
        if not isinstance(s, dict):
            continue
        fn = s.get("function")
        if isinstance(fn, dict) and str(fn.get("name") or "").strip() == want:
            return True
    return False


def _messages_with_schema_nudges(
    messages: List[Dict[str, Any]],
    schemas: List[Dict[str, Any]] | None,
) -> List[Dict[str, Any]]:
    out = list(messages)
    if _schemas_include_tool_name(schemas, "penetration-report"):
        out.append({"role": "system", "content": _PENETRATION_REPORT_SCHEMA_NUDGE})
    if _schemas_include_tool_name(schemas, "nmap"):
        out.append({"role": "system", "content": _NMAP_TARGET_SCHEMA_NUDGE})
    return out


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


from tool_registry import CATEGORIES

_ROUTER_CATEGORY_ENUM = ", ".join(sorted(CATEGORIES.keys()))

_ROUTER_SYSTEM_TEMPLATE = """You are a router for CipherStrike (authorized security testing assistant).

Given the user message and the compact tool list below, respond with **only** valid JSON (no markdown):
{{"intent":"operational"|"conversational","tool_names":[],"reply":"","category":"<slug>"}}

Rules:
- intent **operational** when the user wants scans, enumeration, exploitation workflows, CVE lookup, concrete tooling on targets, URLs/hosts to assess, penetration tests, or any request where starting security tools would help (even if they also ask "how" or "can you").
- If the user asks for a **penetration test report**, **security report**, **PDF report**, **executive summary / write-up** of findings, or to **create / generate / export a report** from the session → **operational**, **category** **reporting**, and include **penetration-report** in **tool_names** when that exact name appears in the tool list (often as the only tool for that request).
- If the message contains **http:// or https://** and asks for testing, assessment, or a pentest → **operational** and pick suitable tools from the list (e.g. HTTP probe, tech fingerprint, vuln templates, web scanner — use names that exist below).
- If the user asks to **run nmap** (or port scan) on a **URL, hostname, or IP** → **operational**, **category** **network_recon** (or **essential**), and include **nmap** in **tool_names** when listed. URLs are valid targets for the backend.
- If the user gives a **short affirmation** (e.g. "yes", "ok", "use both", "run them") after the assistant already named specific tools → **operational** and put **those exact tool names** in **tool_names** (e.g. assistant offered amass and subfinder → include both).
- intent **conversational** only for pure greetings, thanks, meta chat, or conceptual questions with **no target** and **no request to run or plan tooling**. Do not ask what "both" means when the prior assistant message already named two tools.
- **category**: exactly **one** workflow slug when intent is **operational**, chosen from: {categories}. Pick the best primary fit (e.g. web pentest with vuln scanners → web_vuln; passive subdomain gathering → osint). When intent is **conversational**, use **""** (empty string) for category.
- **tool_names**: when operational, include **as many distinct complementary tools as fit the ask**, up to **{max_tools}** names from the list (exact spelling). Use **several** tools for routine checks; for **full / comprehensive pentests** or explicit requests to run many scanners, prefer **closer to {max_tools}** parallel starters covering different roles (probe, fingerprint, vuln templates, crawling/dirs, DNS/subdomain, ports, auth, etc.) **when those names exist**.
- Prefer **several complementary discrete scanners** over relying on **only** meta-orchestrators such as **smart-scan** or **analyze-target**. Use **smart-scan** (alone or in the mix) only when the user explicitly asks for an intelligent / smart / orchestrated / automated scan, or when discrete scanners are not available below.
- If fewer than two suitable discrete scanners appear in the list, include every relevant tool available (even if that is a single meta-tool).
- Do not leave tool_names empty when intent is operational.
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
        allowed_categories = frozenset(CATEGORIES.keys())
        sys_prompt = _ROUTER_SYSTEM_TEMPLATE.format(
            max_tools=max_pick,
            catalog=catalog_text,
            categories=_ROUTER_CATEGORY_ENUM,
        )
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
        category_slug = ""
        raw_cat = parsed.get("category")
        if isinstance(raw_cat, str):
            cand = raw_cat.strip().lower().replace(" ", "_").replace("-", "_")
            if cand in allowed_categories:
                category_slug = cand
        return jsonify(
            {
                "success": True,
                "intent": intent,
                "tool_names": tool_names,
                "reply": reply_str,
                "category": category_slug,
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
        messages_adj = _messages_with_schema_nudges(messages, schemas)
        result = llm_client.chat(messages_adj, tools=schemas)
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
        yield "data: [DONE]\n\n"


def _stream_llm_sse(
    messages: List[Dict[str, Any]],
    schemas: List[Dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Stream tokens from the configured LLM; optional ``schemas`` enables tool mode."""
    backend = getattr(llm_client, "_backend", None)
    provider = getattr(backend, "provider", None) if backend else None
    schemas_ok = isinstance(schemas, list) and len(schemas) > 0

    if schemas_ok and provider not in ("gemini", "openai", "openrouter"):
        yield from _stream_tools_blocking_sse(messages, schemas)
        return

    tools_arg = schemas if schemas_ok else None
    messages_adj = _messages_with_schema_nudges(messages, schemas if schemas_ok else None)
    try:
        yield "data: [THINKING]\n\n"
        for chunk in llm_client.stream_chat(messages_adj, tools=tools_arg):
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
        yield "data: [DONE]\n\n"


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
