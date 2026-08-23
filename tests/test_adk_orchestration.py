"""Regression coverage for the live ADK orchestration boundary."""

from flask import Flask

from server_api.cipherstrike_bridge import routes
from server_core.adk.tools import normalize_tool_parameters


class _RouterClient:
    def is_available(self):
        return True

    def chat(self, messages, tools=None):
        # The test deliberately reaches the LLM path (rather than an ADK
        # shortcut) to catch regressions such as the former catalog_text error.
        return '{"intent":"operational","tool_names":["nmap"],"reply":"","category":"network_recon"}'


class _EmptyOperationalRouterClient(_RouterClient):
    def chat(self, messages, tools=None):
        return '{"intent":"operational","tool_names":[],"reply":"","category":"web_vuln"}'


def _client(monkeypatch, llm):
    monkeypatch.setattr(routes, "llm_client", llm)
    app = Flask(__name__)
    app.register_blueprint(routes.api_cipherstrike_bridge_bp)
    return app.test_client()


def test_route_intent_uses_llm_before_adk_fallback(monkeypatch):
    response = _client(monkeypatch, _RouterClient()).post(
        "/api/cipherstrike/route-intent",
        json={
            "message": "run nmap against https://example.com",
            "tools": [{"name": "nmap", "desc": "port scanner"}],
        },
    )

    assert response.status_code == 200
    assert response.get_json()["tool_names"] == ["nmap"]


def test_route_intent_uses_catalog_aware_adk_only_for_empty_operational_plan(monkeypatch):
    response = _client(monkeypatch, _EmptyOperationalRouterClient()).post(
        "/api/cipherstrike/route-intent",
        json={
            "message": "scan https://example.com",
            "tools": [
                {"name": "httpx", "desc": "HTTP probe"},
                {"name": "nuclei", "desc": "vulnerability scanner"},
            ],
        },
    )

    data = response.get_json()
    assert response.status_code == 200
    assert data["intent"] == "operational"
    assert set(data["tool_names"]).issubset({"httpx", "nuclei"})
    assert data["tool_names"]


def test_tool_parameter_normalization_maps_aliases_and_strips_port_scan_urls():
    assert normalize_tool_parameters("nmap", {"url": "https://example.com/path"}) == {
        "target": "example.com"
    }
    assert normalize_tool_parameters("wafw00f", {"target": "https://example.com"}) == {
        "url": "https://example.com"
    }
    assert normalize_tool_parameters("subfinder", {"target": "https://example.com/a"}) == {
        "domain": "example.com"
    }
