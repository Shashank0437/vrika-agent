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


class SpanContext:
    """A nestable observation (trace-root or span) that can host child spans/generations.

    Wraps whichever Langfuse stateful client sits at this level (``StatefulTraceClient`` or
    ``StatefulSpanClient`` — both expose the same ``.span()``/``.generation()`` shape) so callers
    can build a real parent/child tree: ``trace.span("adk_orchestrator").span("adk_tool_selection")
    .log_tool_execution(...)`` — matching how Langfuse expects nested spans/generations rather than
    everything logged flat as siblings directly on the trace root.
    """

    def __init__(self, client: Any):
        self._client = client

    def span(self, name: str, input_data: Any = None, metadata: Optional[Dict[str, Any]] = None) -> "SpanContext":
        if self._client:
            try:
                child = self._client.span(name=name, input=input_data, metadata=metadata)
                return SpanContext(child)
            except Exception as e:
                logger.warning("Langfuse span creation failed: %s", e)
        return SpanContext(None)

    def end(self, *, output: Any = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        if not self._client or not hasattr(self._client, "end"):
            return
        try:
            kwargs: Dict[str, Any] = {}
            if output is not None:
                kwargs["output"] = output
            if metadata:
                kwargs["metadata"] = metadata
            self._client.end(**kwargs)
        except Exception as e:
            logger.warning("Langfuse span end failed: %s", e)

    def log_tool_execution(self, tool_name: str, args: Dict[str, Any], output: Any, status: str = "success"):
        if self._client:
            try:
                self._client.generation(
                    name=f"tool:{tool_name}",
                    input=args,
                    output=str(output)[:2000],
                    metadata={"tool_name": tool_name, "status": status},
                )
            except Exception as e:
                logger.warning("Langfuse tool logging error: %s", e)

    def log_llm_response(self, model: str, prompt: Any, response: str, thinking: str = "", metadata: Optional[Dict[str, Any]] = None):
        if self._client:
            try:
                self._client.generation(
                    name="llm_call",
                    model=model,
                    input=prompt,
                    output=response,
                    metadata={"thinking": thinking, **(metadata or {})},
                )
            except Exception as e:
                logger.warning("Langfuse LLM logging error: %s", e)


class TraceContext(SpanContext):
    """Scoped trace context for ADK agent executions — the root of a nested span tree.

    ``trace_id`` uniquely identifies this call (route-intent, one llm-stream
    turn, a report generation, ...); ``chat_session_id`` is the durable chat
    session id from vrika-server and is passed as Langfuse's own
    ``session_id`` so the Langfuse Sessions view groups every trace from one
    chat conversation together. Passing the chat session id as ``id=`` instead
    (the previous behavior) makes every call with the same id upsert into a
    single trace and never populates Langfuse's session grouping at all.
    """
    def __init__(
        self,
        trace_id: str,
        name: str,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        input_data: Any = None,
        chat_session_id: Optional[str] = None,
    ):
        self.trace_id = trace_id
        self.name = name
        self.user_id = user_id
        self.metadata = metadata or {}
        trace_client = None

        lf = get_langfuse()
        if lf:
            try:
                trace_client = lf.trace(
                    id=trace_id,
                    name=name,
                    user_id=user_id,
                    metadata=self.metadata,
                    input=input_data,
                    session_id=chat_session_id or None,
                )
            except Exception as e:
                logger.warning("Langfuse trace creation failed: %s", e)
        super().__init__(trace_client)
        self._trace = trace_client  # kept for update()/flush() below

    def update(self, *, output: Any = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Set the trace-level output (and optionally merge metadata) once the turn concludes."""
        if not self._trace:
            return
        try:
            kwargs: Dict[str, Any] = {}
            if output is not None:
                kwargs["output"] = output
            if metadata:
                kwargs["metadata"] = {**self.metadata, **metadata}
            if kwargs:
                self._trace.update(**kwargs)
        except Exception as e:
            logger.warning("Langfuse trace update failed: %s", e)

    def flush(self):
        lf = get_langfuse()
        if lf:
            try:
                lf.flush()
            except Exception:
                pass


def trace_turn(
    session_id: str,
    name: str = "vrika_agent_turn",
    metadata: Optional[Dict[str, Any]] = None,
    input_data: Any = None,
    chat_session_id: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> TraceContext:
    """Create (or resume) a trace context.

    ``session_id`` is the durable vrika-server chat session id (spans many
    turns) and is passed as Langfuse's own ``session_id`` so the Sessions view
    groups every trace from one conversation together.

    Each call gets its OWN fresh Langfuse trace id by default (so unrelated
    calls sharing the same chat session — e.g. two separate messages, or a
    summarization call — don't collapse into one trace). Pass ``trace_id``
    explicitly when you want this call to join an EXISTING trace instead: e.g.
    route-intent, the tool-call llm-stream turn, and the later tool-confirm
    follow-up all pass the same per-user-message id (vrika-server mints it once
    and persists it as ``turn_id`` on the pending tool-call row so the separate
    confirm/reject request can resume it) so all three nest into one trace.
    """
    import uuid as _uuid

    resolved_trace_id = trace_id or (
        f"{session_id}:{_uuid.uuid4().hex[:12]}" if session_id else _uuid.uuid4().hex
    )
    return TraceContext(
        trace_id=resolved_trace_id,
        name=name,
        metadata=metadata,
        input_data=input_data,
        chat_session_id=chat_session_id or session_id or None,
    )

