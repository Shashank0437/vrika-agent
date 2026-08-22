"""
server_core/adk/summarizer.py

Intelligent Context Summarization & Token Budgeting for Google ADK Agents.
Maintains stateful memory across long-running penetration testing sessions.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from server_core.adk.state import TargetKnowledgeState

logger = logging.getLogger(__name__)


def compact_dialogue_turns(
    messages: List[Dict[str, Any]],
    knowledge: TargetKnowledgeState,
    max_active_turns: int = 10,
) -> tuple[List[Dict[str, Any]], str]:
    """Compacts older dialogue turns into a structured summary + active window.
    
    Returns:
        (compacted_messages, rolling_summary_text)
    """
    if len(messages) <= max_active_turns:
        return messages, ""

    # Split into older turns and active recent turns
    older_turns = messages[:-max_active_turns]
    recent_turns = messages[-max_active_turns:]

    summary_bullets: List[str] = []
    for m in older_turns:
        role = str(m.get("role") or "").lower()
        content = str(m.get("content") or "").strip()
        if not content:
            continue

        if role == "user":
            if len(content) > 120:
                content = content[:117] + "..."
            summary_bullets.append(f"User requested: {content}")
        elif role == "tool":
            summary_bullets.append(f"Tool output received: {content[:100]}...")
        elif role == "assistant":
            # Extract key takeaways
            if len(content) > 150:
                content = content[:147] + "..."
            summary_bullets.append(f"Assistant: {content}")

    rolling_summary = "Earlier turn recap:\n" + "\n".join(summary_bullets[-15:])
    return recent_turns, rolling_summary
