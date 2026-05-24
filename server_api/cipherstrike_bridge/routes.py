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

_MAX_MULTI_TOOL_CALLS = max(1, int(os.environ.get("CIPHERSTRIKE_MAX_MULTI_TOOL_CALLS", "30")))

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


# Tool names that depend on scan results and must NOT run in parallel with scan tools.
# They are deferred to the follow-up LLM turn after scan results are available.
_DEFERRED_POST_SCAN_TOOLS: frozenset[str] = frozenset({"penetration-report"})

_PENETRATION_REPORT_SCHEMA_NUDGE = (
    "CipherStrike backend: PDF generation runs via the penetration-report tool on this agent host; "
    "ReportLab is installed. When the user wants a PDF or penetration-test report from this session, "
    "you MUST call the penetration-report function (empty {} arguments if nothing is required). "
    "Do not refuse by claiming reportlab or Python dependencies are missing—that is wrong for this system. "
    "CRITICAL SEQUENCING RULE: penetration-report MUST NEVER be called in the same turn as scan/recon tools "
    "(e.g. httpx, nmap, nuclei, nikto, whatweb, ffuf, etc.). It depends on scan results to produce a "
    "meaningful report. When the user asks to 'scan X and generate a report', call ONLY the scan tool(s) first. "
    "After you receive the scan results, THEN call penetration-report in a separate follow-up turn."
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
        max_pick = max(1, min(int(body.get("max_tool_names") or 12), 30))
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


_TOOL_NAME_PREFIX_STRIPS = (
    "run_", "run-",
    "execute_", "execute-",
    "exec_", "exec-",
    "launch_", "launch-",
    "start_", "start-",
    "call_", "call-",
    "do_", "do-",
    "tool_", "tool-",
    "use_", "use-",
)

_GENERIC_SINGLE_TOOL_NAMES = frozenset({"run", "execute", "call", "tool", "function"})


def _schema_tool_names(schemas: List[Dict[str, Any]] | None) -> list[str]:
    out: list[str] = []
    if not isinstance(schemas, list):
        return out
    for s in schemas:
        if not isinstance(s, dict):
            continue
        fn = s.get("function")
        name = ""
        if isinstance(fn, dict):
            name = str(fn.get("name") or "").strip()
        if not name:
            name = str(s.get("name") or "").strip()
        if name:
            out.append(name)
    return out


def _resolve_tool_name(raw_name: str) -> tuple[str, Any]:
    """Resolve a model-emitted tool name to (canonical_name, tool_def).

    Handles common model name variations:
      - Namespace prefixes: 'default_api.httpx', 'tools.nmap', 'functions.nmap'
      - Verb prefixes:      'run_httpx', 'execute-nmap', 'launch_nuclei', 'call_dig'
      - Case differences:   'HTTPX', 'Nmap'
      - Hyphen/underscore swaps: 'graphql-scanner' <-> 'graphql_scanner'

    Returns ('', None) if no normalization matches a registry entry.
    """
    from tool_registry import get_tool, TOOLS  # TOOLS is the registry dict
    if not raw_name:
        return "", None
    n = raw_name.strip()
    candidates: list[str] = [n]

    # Strip namespace prefix once (e.g. "default_api.httpx" -> "httpx").
    if "." in n:
        candidates.append(n.rsplit(".", 1)[-1])

    # For every candidate so far, also produce verb-prefix-stripped variants.
    verb_stripped: list[str] = []
    for base in candidates:
        b_lower = base.lower()
        for pfx in _TOOL_NAME_PREFIX_STRIPS:
            if b_lower.startswith(pfx) and len(base) > len(pfx):
                verb_stripped.append(base[len(pfx):])
                break
    candidates.extend(verb_stripped)

    # Case + hyphen/underscore variations for every candidate.
    expanded: list[str] = []
    for base in candidates:
        b = base.strip()
        if not b:
            continue
        expanded.extend([
            b,
            b.lower(),
            b.replace("_", "-"),
            b.replace("-", "_"),
            b.lower().replace("_", "-"),
            b.lower().replace("-", "_"),
        ])

    seen: set[str] = set()
    for c in expanded:
        if not c or c in seen:
            continue
        seen.add(c)
        td = get_tool(c)
        if td:
            return c, td

    # Last resort: case-insensitive scan of every registry key.
    target_lower = (expanded[-1] if expanded else n).lower()
    for k in TOOLS.keys():
        if k.lower() == target_lower:
            return k, TOOLS[k]
    return "", None


def _yield_cipherstrike_tool_pending_sse(
    tool_calls: List[Dict[str, Any]],
    schemas: List[Dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Emit TOOL_CALL_PENDING / TOOL_CALL_BATCH_PENDING SSE frames for registry-resolved tools."""
    from tool_registry import get_tool

    batch_payloads: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    duplicate_count = 0
    offered_tool_names = _schema_tool_names(schemas)
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
        if not tool_def and raw_tool_name.lower() in _GENERIC_SINGLE_TOOL_NAMES and len(offered_tool_names) == 1:
            canonical_name = offered_tool_names[0]
            tool_def = get_tool(canonical_name)
            if tool_def:
                logger.info(
                    "cipherstrike_bridge: normalized generic tool name %r -> sole offered tool %r",
                    raw_tool_name,
                    canonical_name,
                )
        if tool_def:
            if canonical_name != raw_tool_name:
                logger.info(
                    "cipherstrike_bridge: normalized tool name %r -> %r",
                    raw_tool_name,
                    canonical_name,
                )
            try:
                args_key = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
            except Exception:
                args_key = str(arguments)
            dedupe_key = (canonical_name.strip().lower(), args_key)
            if dedupe_key in seen:
                duplicate_count += 1
                continue
            seen.add(dedupe_key)
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

    if duplicate_count:
        logger.info("cipherstrike_bridge: dropped %d duplicate tool_calls before SSE emit", duplicate_count)

    # --- Defer post-scan tools (e.g. penetration-report) when batched with scan tools ---
    # These tools need scan results to work properly. If the LLM emitted them alongside
    # scan tools, strip them from this batch; they will be picked up in the follow-up
    # LLM turn after scan results are available.
    if len(batch_payloads) > 1:
        has_scan = any(
            p["tool_name"].strip().lower() not in _DEFERRED_POST_SCAN_TOOLS
            for p in batch_payloads
        )
        has_deferred = any(
            p["tool_name"].strip().lower() in _DEFERRED_POST_SCAN_TOOLS
            for p in batch_payloads
        )
        if has_scan and has_deferred:
            deferred_names = [
                p["tool_name"] for p in batch_payloads
                if p["tool_name"].strip().lower() in _DEFERRED_POST_SCAN_TOOLS
            ]
            logger.info(
                "cipherstrike_bridge: deferring post-scan tools %s from parallel batch (will run after scan results)",
                deferred_names,
            )
            batch_payloads = [
                p for p in batch_payloads
                if p["tool_name"].strip().lower() not in _DEFERRED_POST_SCAN_TOOLS
            ]

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
            pending_sse = list(_yield_cipherstrike_tool_pending_sse(tool_calls if isinstance(tool_calls, list) else [], schemas))
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
    "You MUST now emit a function call using one of the available tools. "
    "If the user named a target, pass it as the tool's target/url argument. "
    "Do not produce only thinking content again."
)


def _force_tool_call_retry(messages: List[Dict[str, Any]], tools: List[Dict[str, Any]] | None) -> Dict[str, Any]:
    """Force the model to emit a function call by setting tool_choice='required'.

    Bypasses LLMClient.chat (which hardcodes tool_choice='auto') to talk to the OpenAI-compatible
    client directly. Falls back to LLMClient.chat with 'auto' if the direct call fails.
    """
    backend = getattr(llm_client, "_backend", None)
    inner_client = getattr(backend, "_client", None)
    model = getattr(backend, "_model", None)
    if inner_client is None or not model:
        # Backend doesn't expose an OpenAI-compatible client — fall back to abstract chat.
        try:
            res = llm_client.chat(messages, tools=tools, think=False)
            return res if isinstance(res, dict) else {"content": str(res or ""), "tool_calls": None}
        except Exception as exc:
            logger.warning("force_tool_call_retry: abstract chat failed: %s", exc)
            return {"content": "", "tool_calls": None}

    try:
        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": _normalize_openai_compatible_messages_local(messages),
            "max_tokens": 4096,
            "temperature": 0.3,  # low temperature to keep it focused on tool selection
        }
        if tools:
            kwargs["tools"] = tools
            # CRITICAL: force the model to emit a function call (cannot return empty).
            kwargs["tool_choice"] = "required"
        resp = inner_client.chat.send(**kwargs)
        msg = resp.choices[0].message
        content = (msg.content or "").strip() if hasattr(msg, "content") else ""
        out_calls: List[Dict[str, Any]] = []
        for tc in getattr(msg, "tool_calls", None) or []:
            args = tc.function.arguments
            if isinstance(args, str):
                try:
                    parsed = json.loads(args)
                except json.JSONDecodeError:
                    parsed = {"_raw": args}
            else:
                parsed = dict(args) if isinstance(args, dict) else {}
            out_calls.append(
                {
                    "id": str(getattr(tc, "id", "") or ""),
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": parsed},
                }
            )
        return {"content": content, "tool_calls": out_calls or None}
    except Exception as exc:
        logger.warning("force_tool_call_retry: direct OpenAI client call failed: %s; falling back to auto", exc)
        try:
            res = llm_client.chat(messages, tools=tools, think=False)
            return res if isinstance(res, dict) else {"content": str(res or ""), "tool_calls": None}
        except Exception as exc2:
            logger.warning("force_tool_call_retry: abstract chat also failed: %s", exc2)
            return {"content": "", "tool_calls": None}


def _normalize_openai_compatible_messages_local(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Mirror LLMClient's tool-message normalization so a direct call uses the same shape."""
    out: List[Dict[str, Any]] = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        if str(m.get("role") or "") != "tool":
            out.append(dict(m))
            continue
        nm = dict(m)
        if not nm.get("tool_call_id") and not nm.get("name"):
            content = nm.get("content", "")
            if not isinstance(content, str):
                content = json.dumps(content)
            out.append({"role": "user", "content": f"[Tool result]\n{content}"})
            continue
        out.append(nm)
    return out


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
    # Log the offered tool names and the user message that triggered this stream so we can
    # diagnose "model produced nothing" cases from agent logs alone.
    try:
        offered_names_dbg = [
            str((s.get("function") or {}).get("name") or s.get("name") or "")
            for s in (schemas or [])
            if isinstance(s, dict)
        ]
        last_user_dbg = ""
        for _m in reversed(messages_adj):
            if isinstance(_m, dict) and str(_m.get("role") or "") == "user":
                last_user_dbg = str(_m.get("content") or "")[:200]
                break
        logger.info(
            "cipherstrike_bridge: llm-stream start provider=%s schemas=%d offered=%s last_user=%r",
            provider, len(schemas or []), offered_names_dbg[:8], last_user_dbg,
        )
    except Exception:
        pass

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
                    if "usage" in chunk:
                        usage_chunk = {"type": "usage", "usage": chunk["usage"]}
                        yield f"data: [STATS] {json.dumps(usage_chunk)}\n\n"
                    pending_sse = list(_yield_cipherstrike_tool_pending_sse(tcalls if isinstance(tcalls, list) else [], schemas))
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
        # offered AND nothing actionable was produced, retry once non-streaming with
        # tool_choice="required" so the model is FORCED to emit a function call.
        if not saw_visible_output and schemas_ok:
            logger.info(
                "cipherstrike_bridge: thought-only response (tool_chunk_seen=%s text_chars=%d) with %d tools; retrying non-stream with tool_choice=required",
                stream_tool_call_chunk_seen, stream_text_chars, len(schemas or []),
            )
            try:
                retry_msgs = list(messages_adj) + [
                    {"role": "system", "content": _THOUGHT_ONLY_FALLBACK_NUDGE},
                ]
                result = _force_tool_call_retry(retry_msgs, tools_arg)
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
                        pending_sse = list(_yield_cipherstrike_tool_pending_sse(retry_tcalls, schemas))
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

        elif (
            saw_visible_output
            and not stream_tool_call_chunk_seen
            and schemas_ok
        ):
            schema_names = _schema_tool_names(schemas)
            all_deferred = (
                bool(schema_names)
                and all(n.strip().lower() in _DEFERRED_POST_SCAN_TOOLS for n in schema_names)
            )
            if all_deferred:
                logger.info(
                    "cipherstrike_bridge: LLM produced text but skipped deferred tools %s; forcing tool_choice=required retry",
                    schema_names,
                )
                try:
                    retry_msgs = list(messages_adj) + [
                        {
                            "role": "system",
                            "content": (
                                "You just summarized tool results, but the user's original request ALSO asked "
                                "for a report/PDF. You MUST now call the penetration-report tool immediately. "
                                "Do NOT produce text — emit a tool_call."
                            ),
                        },
                    ]
                    result = _force_tool_call_retry(retry_msgs, tools_arg)
                    if isinstance(result, dict):
                        retry_tcalls = result.get("tool_calls") or []
                        if retry_tcalls:
                            retry_raw_names = [
                                str(((tc or {}).get("function") or {}).get("name") or "")
                                for tc in retry_tcalls
                            ]
                            logger.info(
                                "cipherstrike_bridge: deferred-tool retry returned tool_calls=%d raw_names=%s",
                                len(retry_tcalls), retry_raw_names,
                            )
                            pending_sse = list(_yield_cipherstrike_tool_pending_sse(retry_tcalls, schemas))
                            for ln in pending_sse:
                                yield ln
                            # Replace the [DONE] with a tool-call flow — need to return before the final DONE.
                            yield "data: [DONE]\n\n"
                            return
                except Exception as retry_exc:
                    logger.warning("cipherstrike_bridge: deferred-tool retry failed: %s", retry_exc)

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
            if "usage" in result:
                out["usage"] = result["usage"]
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
