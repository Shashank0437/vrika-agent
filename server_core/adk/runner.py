"""
server_core/adk/runner.py

Event-Driven Agent Runner for Google ADK in Vrika.
Executes streaming turns, handles tool calls, updates state, and emits standard Vrika SSE tokens.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Generator, List, Optional

from server_core.singletons import llm_client
from server_core.adk.state import VrikaAgentState, extract_state_from_tool_output
from server_core.adk.prompts import build_consolidated_system_prompt
from server_core.adk.tools import get_adk_tools_for_names, normalize_tool_parameters
from server_core.adk.summarizer import compact_dialogue_turns

logger = logging.getLogger(__name__)


def stream_adk_agent_turn(
    messages: List[Dict[str, Any]],
    state: VrikaAgentState,
    role: str = "supervisor",
    tool_names: Optional[List[str]] = None,
    skill_instructions: Optional[str] = None,
    page_context: Optional[str] = None,
) -> Generator[str, None, None]:
    """Execute an event-driven agent stream using Google ADK abstractions."""

    # 1. Compact older conversation turns into structured memory
    active_messages, rolling_summary = compact_dialogue_turns(
        messages,
        state.knowledge,
        max_active_turns=12,
    )
    if rolling_summary:
        state.rolling_summary = rolling_summary

    # 2. Build multi-tier consolidated system prompt (placed strictly at messages[0])
    system_prompt = build_consolidated_system_prompt(
        role=role,
        knowledge=state.knowledge,
        skill_instructions=skill_instructions,
        active_tools=tool_names,
        rolling_summary=state.rolling_summary,
        page_context=page_context,
    )

    # 3. Assemble clean message array for the model
    adk_messages: List[Dict[str, Any]] = [{"role": "system", "content": system_prompt}]
    for m in active_messages:
        r = str(m.get("role") or "").lower()
        if r != "system":
            adk_messages.append({"role": r, "content": m.get("content", "")})

    # 4. Resolve tools
    tools_arg = get_adk_tools_for_names(tool_names) if tool_names else None

    yield "data: [THINKING]\n\n"

    try:
        # 5. Stream from active LLM engine (Google Gemini, Local vLLM, OpenRouter, etc.)
        for chunk in llm_client.stream_chat(adk_messages, tools=tools_arg):
            if isinstance(chunk, dict):
                chunk_type = chunk.get("type")

                # Thinking / Reasoning tokens
                if chunk_type == "thinking":
                    yield f"data: [THINK_TOKEN] {json.dumps(chunk.get('content', ''))}\n\n"
                    continue

                # Tool Calls received from model
                if chunk_type == "_cipherstrike_tool_calls":
                    tool_calls = chunk.get("tool_calls") or []
                    for tc in tool_calls:
                        fn = tc.get("function") or {}
                        raw_name = fn.get("name", "")
                        raw_args = fn.get("arguments", {})
                        if isinstance(raw_args, str):
                            try:
                                raw_args = json.loads(raw_args)
                            except Exception:
                                raw_args = {"_raw": raw_args}

                        norm_args = normalize_tool_parameters(raw_name, raw_args if isinstance(raw_args, dict) else {})
                        pending_payload = {
                            "tool_name": raw_name,
                            "parameters": norm_args,
                            "tool_call_id": tc.get("id", ""),
                        }
                        yield f"data: [TOOL_PENDING] {json.dumps(pending_payload)}\n\n"

                    if "usage" in chunk:
                        yield f"data: [STATS] {json.dumps({'type': 'usage', 'usage': chunk['usage']})}\n\n"
                    yield "data: [DONE]\n\n"
                    return

                # Usage stats
                if chunk_type == "usage":
                    yield f"data: [STATS] {json.dumps(chunk)}\n\n"
                    continue

            # Standard text token
            if isinstance(chunk, str) and chunk:
                yield f"data: {json.dumps(chunk)}\n\n"

        yield "data: [DONE]\n\n"

    except Exception as exc:
        logger.exception("stream_adk_agent_turn error: %s", exc)
        yield f"data: [ERROR] {str(exc)}\n\n"
        yield "data: [DONE]\n\n"
