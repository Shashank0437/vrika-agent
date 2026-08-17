"""Publish incremental tool execution events to Redis Streams."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

import redis

from server_core import config_core

logger = logging.getLogger(__name__)

_STREAM_MAXLEN = int(os.environ.get("TOOL_RUN_STREAM_MAXLEN", "5000"))
_STREAM_EXPIRE = int(os.environ.get("TOOL_RUN_STREAM_EXPIRE_SECONDS", "3600"))
_FLUSH_INTERVAL_SEC = float(os.environ.get("TOOL_RUN_STREAM_FLUSH_INTERVAL", "0.2"))
_FLUSH_MAX_BYTES = int(os.environ.get("TOOL_RUN_STREAM_FLUSH_BYTES", "8192"))

_redis_client: redis.Redis | None | bool = False
_redis_url_override = ""


def _redis_url() -> str:
    return (
        _redis_url_override
        or os.environ.get("REDIS_URL", "").strip()
        or str(config_core.get("REDIS_URL", "") or "").strip()
    )


def configure_redis_url(url: str | None) -> None:
    """Set/clear a process-local Redis URL override for live tool-run streams."""
    global _redis_client, _redis_url_override
    next_url = str(url or "").strip()
    if next_url == _redis_url_override:
        return
    _redis_url_override = next_url
    if isinstance(_redis_client, redis.Redis):
        try:
            _redis_client.close()
        except Exception:
            pass
    _redis_client = False


def _get_redis() -> redis.Redis | None:
    global _redis_client
    if _redis_client is False:
        url = _redis_url()
        if not url:
            _redis_client = None
        else:
            try:
                client = redis.Redis.from_url(url, decode_responses=True)
                client.ping()
                _redis_client = client
            except Exception as exc:  # pragma: no cover - env dependent
                logger.warning("tool_run_stream: Redis unavailable (%s); live logs disabled", exc)
                _redis_client = None
    return _redis_client if isinstance(_redis_client, redis.Redis) else None


def stream_key(stream_run_id: str) -> str:
    return f"vrika:toolrun:{stream_run_id}"


def publish_event(stream_run_id: str, payload: dict[str, Any]) -> None:
    r = _get_redis()
    if not r:
        return
    try:
        r.xadd(
            stream_key(stream_run_id),
            {"d": json.dumps(payload, default=str)},
            maxlen=_STREAM_MAXLEN,
            approximate=True,
        )
    except Exception as exc:  # pragma: no cover
        logger.debug("tool_run_stream XADD failed: %s", exc)


def publish_terminal(stream_run_id: str, http_status: int, body: Any) -> None:
    publish_event(stream_run_id, {"type": "terminal", "http_status": http_status, "body": body})
    r = _get_redis()
    if r:
        try:
            r.expire(stream_key(stream_run_id), _STREAM_EXPIRE)
        except Exception:
            pass


class ToolRunStreamPublisher:
    """Batch stdout/stderr lines and publish UI log/progress events (thread-safe)."""

    def __init__(self, stream_run_id: str):
        self.stream_run_id = stream_run_id
        self._lock = threading.Lock()
        self._stdout_buf: list[str] = []
        self._stderr_buf: list[str] = []
        self._pending_bytes = 0
        self._last_flush = time.monotonic()

    def push_stdout(self, text: str) -> None:
        if not text:
            return
        self._push("stdout", text)

    def push_stderr(self, text: str) -> None:
        if not text:
            return
        self._push("stderr", text)

    def push_log(self, text: str) -> None:
        if not text:
            return
        publish_event(self.stream_run_id, {"type": "log", "text": text})

    def push_progress(self, text: str) -> None:
        if not text:
            return
        publish_event(self.stream_run_id, {"type": "progress", "text": text})

    def _push(self, channel: str, text: str) -> None:
        with self._lock:
            if channel == "stdout":
                self._stdout_buf.append(text)
            else:
                self._stderr_buf.append(text)
            self._pending_bytes += len(text.encode("utf-8", errors="replace"))
            now = time.monotonic()
            if self._pending_bytes >= _FLUSH_MAX_BYTES or (now - self._last_flush) >= _FLUSH_INTERVAL_SEC:
                self._flush_unlocked()

    def flush(self, *, force: bool = False) -> None:
        with self._lock:
            if force or self._stdout_buf or self._stderr_buf:
                self._flush_unlocked()

    def _flush_unlocked(self) -> None:
        if self._stdout_buf:
            chunk = "".join(self._stdout_buf)
            self._stdout_buf.clear()
            publish_event(self.stream_run_id, {"type": "stdout", "text": chunk})
        if self._stderr_buf:
            chunk = "".join(self._stderr_buf)
            self._stderr_buf.clear()
            publish_event(self.stream_run_id, {"type": "stderr", "text": chunk})
        self._pending_bytes = 0
        self._last_flush = time.monotonic()
