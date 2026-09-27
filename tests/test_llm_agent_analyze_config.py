"""The analyze-session endpoint must use the caller's per-request LLM config."""

from flask import Flask

import server_core.llm_agent as llm_agent
import server_core.llm_client as llm_client_module
from server_api.ai_assist import llm_agent_api


class _Client:
  def __init__(self, name):
    self.name = name


def _client(monkeypatch, captured):
  def fake_analyze_session(**kwargs):
    captured["llm_client"] = kwargs["llm_client"]
    return {"success": True, "summary": "ok"}

  def fake_create_llm_client(cfg):
    captured["llm_config"] = cfg
    return _Client("per-request")

  monkeypatch.setattr(llm_agent, "analyze_session", fake_analyze_session)
  monkeypatch.setattr(llm_client_module, "create_llm_client", fake_create_llm_client)
  monkeypatch.setattr(llm_agent_api, "llm_client", _Client("global"))
  app = Flask(__name__)
  app.register_blueprint(llm_agent_api.api_ai_assist_llm_agent_bp)
  return app.test_client()


def test_analyze_session_uses_request_llm_config(monkeypatch):
  captured = {}
  cfg = {"provider": "openrouter", "model": "test-model"}

  response = _client(monkeypatch, captured).post(
    "/api/intelligence/analyze-session",
    json={"session_id": "s1", "logs": [], "llm_config": cfg},
  )

  assert response.status_code == 200
  assert captured["llm_config"] == cfg
  assert captured["llm_client"].name == "per-request"


def test_analyze_session_falls_back_to_global_client(monkeypatch):
  captured = {}

  response = _client(monkeypatch, captured).post(
    "/api/intelligence/analyze-session",
    json={"session_id": "s1", "logs": []},
  )

  assert response.status_code == 200
  assert "llm_config" not in captured
  assert captured["llm_client"].name == "global"


def test_analyze_session_rejects_malformed_llm_config(monkeypatch):
  captured = {}

  response = _client(monkeypatch, captured).post(
    "/api/intelligence/analyze-session",
    json={"session_id": "s1", "logs": [], "llm_config": "not-an-object"},
  )

  assert response.status_code == 400
  assert "llm_client" not in captured
