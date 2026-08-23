"""
server_core/adk/telemetry.py

Langfuse & OpenTelemetry Observability Subsystem for Google ADK in Vrika.
Captures agent reasoning, multi-turn state evolution, and offensive tool execution metrics.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Langfuse global client singleton
_langfuse_client = None
_langfuse_initialized = False


def get_langfuse():
    """Retrieve initialized Langfuse client or None if unconfigured."""
    global _langfuse_client, _langfuse_initialized
    if _langfuse_initialized:
        return _langfuse_client

    _langfuse_initialized = True
    public_key = (os.environ.get("LANGFUSE_PUBLIC_KEY") or "").strip()
    secret_key = (os.environ.get("LANGFUSE_SECRET_KEY") or "").strip()
    host = (os.environ.get("LANGFUSE_HOST") or os.environ.get("LANGFUSE_BASEURL") or "http://localhost:3030").strip()

    if public_key and secret_key:
        try:
            from langfuse import Langfuse
            _langfuse_client = Langfuse(
                public_key=public_key,
                secret_key=secret_key,
                host=host,
            )
            logger.info("📡 Langfuse telemetry initialized successfully at %s", host)
        except Exception as exc:
            logger.warning("Failed to initialize Langfuse client: %s", exc)
            _langfuse_client = None
    else:
        logger.debug("Langfuse telemetry disabled (keys not configured).")

    return _langfuse_client


class TraceContext:
    """Scoped trace context for ADK agent executions."""
    def __init__(self, trace_id: str, name: str, user_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        self.trace_id = trace_id
        self.name = name
        self.user_id = user_id
        self.metadata = metadata or {}
        self._trace = None

        lf = get_langfuse()
        if lf:
            try:
                self._trace = lf.trace(
                    id=trace_id,
                    name=name,
                    user_id=user_id,
                    metadata=self.metadata,
                )
            except Exception as e:
                logger.debug("Langfuse trace creation skipped: %s", e)

    def span(self, name: str, input_data: Any = None):
        if self._trace:
            try:
                return self._trace.span(name=name, input=input_data)
            except Exception:
                pass
        return None

    def log_tool_execution(self, tool_name: str, args: Dict[str, Any], output: Any, status: str = "success"):
        if self._trace:
            try:
                self._trace.generation(
                    name=f"tool:{tool_name}",
                    input=args,
                    output=str(output)[:2000],
                    metadata={"tool_name": tool_name, "status": status},
                )
            except Exception as e:
                logger.debug("Langfuse tool logging error: %s", e)

    def log_llm_response(self, model: str, prompt: Any, response: str, thinking: str = "", metadata: Optional[Dict[str, Any]] = None):
        if self._trace:
            try:
                self._trace.generation(
                    name="llm_reasoning",
                    model=model,
                    input=prompt,
                    output=response,
                    metadata={"thinking": thinking, **(metadata or {})},
                )
            except Exception as e:
                logger.debug("Langfuse LLM logging error: %s", e)

    def flush(self):
        lf = get_langfuse()
        if lf:
            try:
                lf.flush()
            except Exception:
                pass


def trace_turn(session_id: str, name: str = "vrika_agent_turn", metadata: Optional[Dict[str, Any]] = None) -> TraceContext:
    """Create a trace context for a turn."""
    return TraceContext(trace_id=session_id, name=name, metadata=metadata)

