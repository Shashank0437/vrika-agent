"""Thread-local scope for streaming tool runs (Redis chunks keyed by stream_run_id)."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

_tls = threading.local()


def current_stream_run_id() -> str | None:
    return getattr(_tls, "stream_run_id", None)


@contextmanager
def stream_run_scope(stream_run_id: str | None) -> Iterator[None]:
    if not stream_run_id:
        yield
        return
    prev = getattr(_tls, "stream_run_id", None)
    _tls.stream_run_id = stream_run_id
    try:
        yield
    finally:
        _tls.stream_run_id = prev
