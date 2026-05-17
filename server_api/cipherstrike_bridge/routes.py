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

Given the recent conversation context (if any), the latest user message, and the compact tool list below, respond with **only** valid JSON (no markdown):
{{"intent":"operational"|"conversational","tool_names":[],"reply":"","category":"<slug>"}}

Rules:
- intent **operational** when the user wants scans, enumeration, exploitation workflows, CVE lookup, concrete tooling on targets, URLs/hosts to assess, penetration tests, or any request where starting security tools would help (even if they also ask "how" or "can you").
- If the user asks for a **penetration test report**, **security report**, **PDF report**, **executive summary / write-up** of findings, or to **create / generate / export a report** from the session → **operational**, **category** **reporting**, and include **penetration-report** in **tool_names** when that exact name appears in the tool list (often as the only tool for that request).
- If the message contains **http:// or https://** and asks for testing, assessment, or a pentest → **operational** and pick suitable tools from the list (e.g. HTTP probe, tech fingerprint, vuln templates, web scanner — use names that exist below).
- If the user asks to **run nmap** (or port scan) on a **URL, hostname, or IP** → **operational**, **category** **network_recon** (or **essential**), and include **nmap** in **tool_names** when listed. URLs are valid targets for the backend.
- If the user uses pronouns or shortcuts like **"same"**, **"this"**, **"that"**, **"it"**, **"the target"**, **"same target"** (e.g. "run dig on same", "scan it with nuclei", "try nikto on the target") → resolve them using the conversation context above. If a target (URL/host/IP) was mentioned in the recent context, treat the request as **operational** on that same target. Do NOT ask "what target?" when the answer is obvious from the prior turns.
- **CRITICAL CONTEXT RULE**: If the conversation context contains a line starting with **"Most recent target(s) in this conversation:"** the user's current request is on that target **even if the request does NOT explicitly name a target**. Examples that MUST be treated as operational on the recent target: "run nuclei", "do a comprehensive scan", "full network scan", "scan it", "run all the tools", "pentest this". Never ask the user to re-specify a target that is already listed in the context. Pick suitable tools and respond with **operational** + appropriate **tool_names**.
- If the user gives a **short affirmation** (e.g. "yes", "ok", "use both", "run them", "ok fine use those tools") after the assistant already named specific tools → **operational** and put **those exact tool names** in **tool_names** (e.g. assistant offered amass and subfinder → include both; user approving after batch rejections → only the rejected scanner names, not tools already executed).
- If the user asks **which tool(s)** to use (recommendation) without asking to **run/execute/scan** them now → **conversational**, suggest tool names in **reply**, leave **tool_names** empty.
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
        context_str = body.get("context")
        if not isinstance(context_str, str):
            context_str = ""
        context_str = context_str.strip()
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
        chat_messages: List[Dict[str, Any]] = [{"role": "system", "content": sys_prompt}]
        if context_str:
            # Trim defensively; the server already caps this, but be safe.
            ctx_trim = context_str if len(context_str) <= 2000 else context_str[-2000:]
            chat_messages.append({
                "role": "system",
                "content": f"Recent conversation context (most recent last):\n{ctx_trim}",
            })
        chat_messages.append({"role": "user", "content": message.strip()})
        result = llm_client.chat(chat_messages, tools=None)
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


def _resolve_tool_name(raw_name: str) -> tuple[str, Any]:
    """Resolve a model-emitted tool name to (canonical_name, tool_def).
    Handles Gemini's namespaced output (e.g. 'default_api.httpx', 'tools.nmap'),
    case differences, and hyphen/underscore swaps. Returns ('', None) if not found.
    """
    from tool_registry import get_tool, TOOLS  # TOOLS is the registry dict
    if not raw_name:
        return "", None
    candidates: list[str] = []
    n = raw_name.strip()
    candidates.append(n)
    # Strip common namespace prefixes (e.g. "default_api.httpx", "tools.nmap", "functions.nmap")
    if "." in n:
        candidates.append(n.rsplit(".", 1)[-1])
    # Try a few normalizations
    for base in list(candidates):
        b = base.strip()
        if not b:
            continue
        candidates.append(b.lower())
        candidates.append(b.replace("_", "-"))
        candidates.append(b.replace("-", "_"))
        candidates.append(b.lower().replace("_", "-"))
        candidates.append(b.lower().replace("-", "_"))
    seen: set[str] = set()
    for c in candidates:
        if not c or c in seen:
            continue
        seen.add(c)
        td = get_tool(c)
        if td:
            return c, td
    # Last resort: case-insensitive scan of registry keys
    rn_lower = (candidates[-1] if candidates else n).lower()
    for k in TOOLS.keys():
        if k.lower() == rn_lower:
            return k, TOOLS[k]
    return "", None


def _yield_cipherstrike_tool_pending_sse(tool_calls: List[Dict[str, Any]]) -> Generator[str, None, None]:
    """Emit TOOL_CALL_PENDING / TOOL_CALL_BATCH_PENDING SSE frames for registry-resolved tools."""
    batch_payloads: List[Dict[str, Any]] = []
    if not isinstance(tool_calls, list):
        return
    for tc in tool_calls[:_MAX_MULTI_TOOL_CALLS]:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function", {})
        if not isinstance(fn, dict):
            continue
        raw_tool_name = str(fn.get("name") or "").strip()
        arguments = fn.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}
        canonical_name, tool_def = _resolve_tool_name(raw_tool_name)
        if tool_def:
            if canonical_name != raw_tool_name:
                logger.info(
                    "cipherstrike_bridge: normalized tool name %r -> %r",
                    raw_tool_name,
                    canonical_name,
                )
            batch_payloads.append(
                {
                    "tool_name": canonical_name,
                    "arguments": arguments,
                    "description": str(tool_def.get("desc") or ""),
                    "endpoint": str(tool_def.get("endpoint") or ""),
                },
            )
        else:
            logger.warning(
                "cipherstrike_bridge: unknown tool %r from model (no normalization match), skipping",
                raw_tool_name,
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


_THOUGHT_ONLY_FALLBACK_NUDGE = (
    "Your previous turn produced only internal thinking and no tool_call or visible reply. "
    "The user's request requires an action. You MUST now either: "
    "(a) emit a tool_call using one of the available tools, OR "
    "(b) reply with a short user-visible message asking for clarification. "
    "Do not produce only thinking content again."
)


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
    saw_visible_output = False
    stream_tool_call_chunk_seen = False
    stream_tool_call_count = 0
    stream_text_chars = 0
    try:
        yield "data: [THINKING]\n\n"
        for chunk in llm_client.stream_chat(messages_adj, tools=tools_arg):
            if isinstance(chunk, dict):
                if chunk.get("type") == "thinking":
                    yield f"data: [THINK_TOKEN] {json.dumps(chunk.get('content', ''))}\n\n"
                    continue
                if chunk.get("type") == "_cipherstrike_tool_calls":
                    stream_tool_call_chunk_seen = True
                    tcalls = chunk.get("tool_calls") or []
                    stream_tool_call_count = len(tcalls) if isinstance(tcalls, list) else 0
                    raw_names = [
                        str(((tc or {}).get("function") or {}).get("name") or "")
                        for tc in (tcalls if isinstance(tcalls, list) else [])
                    ]
                    logger.info(
                        "cipherstrike_bridge: stream tool_calls received count=%d raw_names=%s",
                        stream_tool_call_count, raw_names,
                    )
                    pending_sse = list(_yield_cipherstrike_tool_pending_sse(tcalls if isinstance(tcalls, list) else []))
                    if pending_sse:
                        saw_visible_output = True
                        for ln in pending_sse:
                            yield ln
                    else:
                        logger.warning(
                            "cipherstrike_bridge: stream tool_calls present but ALL dropped by _yield_cipherstrike_tool_pending_sse (raw_names=%s)",
                            raw_names,
                        )
                    yield "data: [DONE]\n\n"
                    return
                yield f"data: [STATS] {json.dumps(chunk)}\n\n"
                continue
            saw_visible_output = True
            stream_text_chars += len(chunk) if isinstance(chunk, str) else 0
            yield f"data: {json.dumps(chunk)}\n\n"

        # Stream ended with no visible output (only thinking or nothing). If tools were
        # offered AND nothing actionable was produced, retry once non-streaming with a
        # strict nudge so the model emits either a tool_call or a visible reply.
        if not saw_visible_output and schemas_ok:
            logger.info(
                "cipherstrike_bridge: thought-only response (tool_chunk_seen=%s text_chars=%d) with %d tools; retrying non-stream with strict nudge",
                stream_tool_call_chunk_seen, stream_text_chars, len(schemas or []),
            )
            try:
                retry_msgs = list(messages_adj) + [
                    {"role": "system", "content": _THOUGHT_ONLY_FALLBACK_NUDGE},
                ]
                result = llm_client.chat(retry_msgs, tools=tools_arg, think=False)
                logger.info(
                    "cipherstrike_bridge: retry result type=%s keys=%s",
                    type(result).__name__,
                    list(result.keys()) if isinstance(result, dict) else None,
                )
                if isinstance(result, dict):
                    retry_tcalls = result.get("tool_calls") or []
                    retry_text = result.get("content") if isinstance(result.get("content"), str) else ""
                    retry_raw_names = [
                        str(((tc or {}).get("function") or {}).get("name") or "")
                        for tc in (retry_tcalls if isinstance(retry_tcalls, list) else [])
                    ]
                    logger.info(
                        "cipherstrike_bridge: retry returned tool_calls=%d raw_names=%s text_len=%d",
                        len(retry_tcalls) if isinstance(retry_tcalls, list) else 0,
                        retry_raw_names,
                        len(retry_text or ""),
                    )
                    if retry_tcalls:
                        pending_sse = list(_yield_cipherstrike_tool_pending_sse(retry_tcalls))
                        if pending_sse:
                            for ln in pending_sse:
                                yield ln
                        else:
                            logger.warning(
                                "cipherstrike_bridge: retry tool_calls present but ALL dropped by _yield_cipherstrike_tool_pending_sse (raw_names=%s)",
                                retry_raw_names,
                            )
                            # Emit a clearer prompt naming the offered tools.
                            offered = [
                                str((s.get("function") or {}).get("name") or s.get("name") or "")
                                for s in (schemas or [])
                                if isinstance(s, dict)
                            ]
                            offered = [n for n in offered if n][:6]
                            fallback = (
                                f"The model requested tools that I couldn't resolve ({', '.join(retry_raw_names) or 'unknown names'}). "
                                f"Try again, or call one of these directly: {', '.join(offered) if offered else '(no tools available)'}"
                            )
                            for slice_ in _iter_sse_text_chunks(fallback):
                                yield f"data: {json.dumps(slice_)}\n\n"
                    elif retry_text.strip():
                        for slice_ in _iter_sse_text_chunks(retry_text):
                            yield f"data: {json.dumps(slice_)}\n\n"
                    else:
                        # Last resort: emit a visible prompt asking what they want.
                        fallback = (
                            "I have tools available but I'm not sure how to act on this. "
                            "Could you rephrase or pick a specific tool to run?"
                        )
                        for slice_ in _iter_sse_text_chunks(fallback):
                            yield f"data: {json.dumps(slice_)}\n\n"
            except Exception as retry_exc:
                logger.warning("cipherstrike_bridge: thought-only retry failed: %s", retry_exc)

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
