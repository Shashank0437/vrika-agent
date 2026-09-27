import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from server_api.cipherstrike_bridge import routes
from server_core.tool_schema import _registry_entry_to_schema
from tool_registry import TOOLS


def schemas(*names):
    return [_registry_entry_to_schema(n, TOOLS[n]) for n in names]


def call(name="zaproxy", arguments=None):
    return {"function": {"name": name, "arguments": arguments if arguments is not None else {"target": "https://example.test"}}}


class Client:
    _backend = SimpleNamespace(provider="openrouter")

    def __init__(self, chunks, retry=None):
        self.chunks = chunks
        self.retry = retry or {"content": "I cannot make a call", "tool_calls": None}
        self.retries = 0

    def stream_chat(self, _messages, tools=None):
        yield from self.chunks

    def chat(self, _messages, tools=None, think=None):
        self.retries += 1
        return self.retry


@pytest.fixture(autouse=True)
def no_external_traces(monkeypatch):
    trace = MagicMock()
    trace.span.return_value = trace
    monkeypatch.setattr(routes, "trace_turn", lambda *_args, **_kwargs: trace)


def stream(client, offered=None, required=False):
    return "".join(routes._stream_adk_orchestrated_sse(
        [{"role": "user", "content": "run zaproxy on https://example.test"}],
        schemas("zaproxy") if offered is None else offered,
        active_client=client, require_tool_call=required,
    ))


@pytest.mark.parametrize("chunks", [
    ["I'll launch a scan. ", "<｜DS", 'ML｜ invoke name="zaproxy_scan">fake</｜DSML｜ invoke>'],
    ["<tool_", 'call>{"name":"zaproxy_scan"}</tool_call>'],
    ["Launching the scan now."],
])
def test_missing_or_fabricated_call_repaired_once_without_showing_raw_text(chunks):
    client = Client(chunks, retry={"tool_calls": [call()]})
    output = stream(client, required=True)
    assert "[TOOL_CALL_PENDING]" in output
    assert '"tool_name": "zaproxy"' in output
    assert "Launching" not in output
    assert "zaproxy_scan" not in output
    assert "DSML" not in output
    assert client.retries == 1


def test_failed_repair_is_explicit_error_not_fake_success():
    client = Client(["Starting now."])
    output = stream(client, required=True)
    assert "[ERROR]" in output
    assert "[TOOL_CALL_PENDING]" not in output
    assert "Starting now" not in output
    assert client.retries == 1


def test_markup_without_tools_is_not_displayed_or_executed():
    client = Client(['<｜DSML｜ invoke name="zaproxy_scan">fake'])
    output = stream(client, offered=[])
    assert "[ERROR]" in output
    assert "zaproxy_scan" not in output
    assert client.retries == 0


@pytest.mark.parametrize("bad_call", [
    call("nuclei"),
    call("zaproxy_scan"),
    call(arguments={"_raw": "not-json"}),
    call(arguments={}),
    call(arguments={"target": " "}),
    call(arguments={"target": ["example.test"]}),
    call(arguments={"target": "https://example.test", "port": 8090}),
])
def test_invalid_native_call_cannot_become_an_approval(bad_call):
    with pytest.raises(ValueError):
        list(routes._yield_cipherstrike_tool_pending_sse([bad_call], schemas("zaproxy")))


def test_invalid_native_call_retries_using_only_offered_tool():
    client = Client(
        [{"type": "_cipherstrike_tool_calls", "tool_calls": [call("nuclei")]}],
        retry={"tool_calls": [call()]},
    )
    output = stream(client)
    assert '"tool_name": "zaproxy"' in output
    assert '"tool_name": "nuclei"' not in output
    assert client.retries == 1


def test_mixed_valid_and_invalid_batch_is_atomic():
    with pytest.raises(ValueError):
        list(routes._yield_cipherstrike_tool_pending_sse(
            [call(), call("nuclei")], schemas("zaproxy"),
        ))


def test_duplicates_normalization_and_report_deferral_preserved():
    output = "".join(routes._yield_cipherstrike_tool_pending_sse(
        [call("Nmap"), call("nmap"), call("penetration-report", {})],
        schemas("nmap", "penetration-report"),
    ))
    assert output.count("[TOOL_CALL_PENDING]") == 1
    payload = json.loads(output.split("[TOOL_CALL_PENDING] ", 1)[1])
    assert payload["tool_name"] == "nmap"
    assert payload["arguments"]["target"] == "example.test"


def test_conversational_reply_without_tools_remains_available():
    client = Client(["Hello", " there."])
    assert '"Hello"' in stream(client, offered=[])
    assert client.retries == 0


def test_missing_target_can_be_clarified_without_forced_execution():
    client = Client(["Which target should I scan?"])
    output = stream(client)
    assert "Which target" in output
    assert "[TOOL_CALL_PENDING]" not in output
    assert client.retries == 0


def test_blocking_provider_uses_same_repair_boundary():
    client = Client([], retry={"tool_calls": [call("nuclei")]})
    output = "".join(routes._stream_tools_blocking_sse(
        [{"role": "user", "content": "run zaproxy on example.test"}],
        schemas("zaproxy"), active_client=client, require_tool_call=True,
    ))
    assert "[ERROR]" in output
    assert "[TOOL_CALL_PENDING]" not in output
    assert client.retries == 2  # Initial blocking request, followed by one repair.


def test_burp_description_discloses_alternative():
    description = schemas("burpsuite")[0]["function"]["description"]
    assert "alternative" in description
    assert "NOT the PortSwigger" in description


def test_valid_followup_summary_is_preserved_before_next_tool():
    client = Client([
        "Previous scan found no issues.",
        {"type": "_cipherstrike_tool_calls", "tool_calls": [call()]},
    ])
    output = stream(client)
    assert "Previous scan found no issues." in output
    assert output.index("Previous scan") < output.index("[TOOL_CALL_PENDING]")
    assert client.retries == 0


def test_thought_only_repair_does_not_emit_fabricated_prose():
    client = Client(
        [{"type": "thinking", "content": "Selecting a tool"}],
        retry={"content": '<tool_call>fake</tool_call>', "tool_calls": None},
    )
    output = stream(client)
    assert "[ERROR]" in output
    assert "<tool_call>" not in output
    assert client.retries == 1


def test_empty_native_tool_chunk_is_repaired():
    client = Client(
        [{"type": "_cipherstrike_tool_calls", "tool_calls": []}],
        retry={"tool_calls": [call()]},
    )
    assert "[TOOL_CALL_PENDING]" in stream(client)
    assert client.retries == 1
