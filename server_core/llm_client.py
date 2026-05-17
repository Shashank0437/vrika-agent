"""
server_core/llm_client.py

Provider-agnostic LLM adapter for NyxStrike.

Reads configuration from env vars, config_local.json, and config.py defaults.

Supported backends:
  openrouter  — OpenRouter (OpenAI-compatible). API key: NYXSTRIKE_LLM_API_KEY, GOOGLE_API_KEY, or OPENROUTER_API_KEY
  gemini      — Google Generative AI (Gemini direct). API key: NYXSTRIKE_LLM_API_KEY, GOOGLE_API_KEY, or GEMINI_API_KEY
  openai      — OpenAI or Azure OpenAI via the openai SDK
  anthropic   — Anthropic Claude via the anthropic SDK

Config keys:
  NYXSTRIKE_LLM_PROVIDER       openrouter | gemini | openai | anthropic
  NYXSTRIKE_LLM_MODEL          e.g. google/gemini-2.5-flash-lite, gpt-4o, claude-3-5-sonnet-latest
  NYXSTRIKE_LLM_URL            OpenRouter / OpenAI base URL (default https://openrouter.ai/api/v1 for openrouter)
  NYXSTRIKE_LLM_API_KEY        primary secret (also checks provider-specific env vars)
  NYXSTRIKE_LLM_MAX_LOOPS
  NYXSTRIKE_LLM_TIMEOUT
  NYXSTRIKE_LLM_NUM_CTX        max output-ish hint for Gemini / context sizing hints
  NYXSTRIKE_LLM_THINK          enable reasoning (OpenRouter reasoning API / Gemini thoughts)
  NYXSTRIKE_LLM_REASONING_MAX_TOKENS  OpenRouter reasoning.max_tokens (default 1000 for Gemini)
  NYXSTRIKE_LLM_REASONING_EFFORT  optional OpenRouter effort (overrides max_tokens if set)
"""

import logging
import json
import os
import time
import uuid
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import quote

import requests

import server_core.config_core as config_core

logger = logging.getLogger(__name__)


def _slice_stream_text(text: str, max_chars: int = 48) -> Generator[str, None, None]:
  """Split large model deltas into smaller SSE chunks so the UI can render progressively."""
  if not text:
    return
  step = max(1, max_chars)
  for i in range(0, len(text), step):
    yield text[i : i + step]


def _cfg(key: str, default: str = "") -> str:
  """Read config as a string: env var overrides config_core, which overrides default.

  ``config_core.get()`` can return arbitrary JSON-ish types (bool, int, None).
  Callers here always want a string — coerce so downstream ``.strip()`` / ``.lower()``
  never crash on e.g. ``True`` (``(True or '')`` stays ``True``).
  """
  env_val = os.environ.get(key)
  if env_val is not None:
    return env_val
  raw = config_core.get(key, default)
  if raw is None or raw is False:
    return ""
  if isinstance(raw, str):
    return raw
  return str(raw)


# Legacy default URL from older setups — treat as «no OpenAI override»
# Treat empty or common non-OpenAI URLs as «use default OpenAI endpoint»
_LEGACY_OPENAI_BASE_IGNORE = frozenset({
  "", "http://localhost:11434", "http://127.0.0.1:11434",
})

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"
OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"


def _resolve_openrouter_api_key(api_key: str) -> str:
  """OpenRouter key from config or legacy env names (GOOGLE_API_KEY holds the OpenRouter key)."""
  return (
    (api_key or "").strip()
    or (os.environ.get("NYXSTRIKE_LLM_API_KEY") or "").strip()
    or (os.environ.get("GOOGLE_API_KEY") or "").strip()
    or (os.environ.get("OPENROUTER_API_KEY") or "").strip()
  )


def _want_thoughts(think: Optional[bool]) -> bool:
  if think is not None:
    return bool(think)
  raw = _cfg("NYXSTRIKE_LLM_THINK")
  if isinstance(raw, bool):
    return raw
  return str(raw or "").strip().lower() in ("1", "true", "yes", "y")


def _openrouter_reasoning_extra(model: str = "") -> Dict[str, Any]:
  """OpenRouter unified reasoning param (Gemini: reasoning.max_tokens → thinking_budget)."""
  effort = (_cfg("NYXSTRIKE_LLM_REASONING_EFFORT") or "").strip().lower()
  if effort in ("xhigh", "high", "medium", "low", "minimal", "none"):
    return {"reasoning": {"effort": effort, "exclude": False}}

  max_tokens = 0
  raw_max = _cfg("NYXSTRIKE_LLM_REASONING_MAX_TOKENS")
  if raw_max not in ("", None, False):
    try:
      max_tokens = int(raw_max)
    except (TypeError, ValueError):
      max_tokens = 0

  if max_tokens <= 0 and "gemini" in (model or "").lower():
    max_tokens = 1000

  if max_tokens > 0:
    return {"reasoning": {"max_tokens": max_tokens, "exclude": False}}
  return {"reasoning": {"enabled": True, "exclude": False}}


def _reasoning_text_from_message(msg: Any) -> str:
  if msg is None:
    return ""
  for attr in ("reasoning", "reasoning_content"):
    val = getattr(msg, attr, None)
    if isinstance(val, str) and val.strip():
      return val.strip()
  details = getattr(msg, "reasoning_details", None)
  return _reasoning_text_from_details(details)


def _reasoning_text_from_details(details: Any) -> str:
  if not details:
    return ""
  parts: List[str] = []
  for item in details:
    if isinstance(item, dict):
      txt = item.get("text") or item.get("content")
      if txt:
        parts.append(str(txt))
    else:
      txt = getattr(item, "text", None) or getattr(item, "content", None)
      if txt:
        parts.append(str(txt))
  return "".join(parts).strip()


def _reasoning_text_from_delta(delta_obj: Any) -> str:
  if delta_obj is None:
    return ""
  for attr in ("reasoning", "reasoning_content"):
    val = getattr(delta_obj, attr, None)
    if isinstance(val, str) and val:
      return val
  return _reasoning_text_from_details(getattr(delta_obj, "reasoning_details", None))


def _normalize_openrouter_model_id(model: str) -> str:
  m = (model or "").strip()
  if not m:
    return "google/gemini-2.5-flash-lite"
  if "/" in m:
    return m
  if m.startswith("gemini-"):
    return f"google/{m}"
  return m


def _normalize_gemini_model_id(model: str) -> str:
  m = (model or "").strip()
  if m.startswith("models/"):
    m = m[len("models/") :]
  return m


class GeminiBackend:
  """Google Gemini via Generative Language REST API (API key authentication)."""

  def __init__(self, model: str, api_key: str, timeout: int, max_output_tokens: int = 8192) -> None:
    key = (api_key or "").strip()
    self._model = _normalize_gemini_model_id(model)
    self._api_key = key
    self._timeout = timeout
    self._max_output_tokens = min(max(max_output_tokens, 256), 8192)

  def _endpoint(self, action: str) -> str:
    mid = quote(self._model, safe="/")
    return f"{GEMINI_API_BASE}/models/{mid}:{action}?key={self._api_key}"

  @staticmethod
  def _http_error(exc: requests.exceptions.HTTPError) -> RuntimeError:
    if not isinstance(exc, requests.exceptions.HTTPError) or not exc.response:
      return RuntimeError(f"Gemini API error: {exc}")
    r = exc.response
    try:
      body = (r.text or "")[:800]
    except Exception:
      body = ""
    return RuntimeError(f"Gemini HTTP {r.status_code} for {r.url}: {body!r}")

  @staticmethod
  def _build_contents(messages: List[Dict[str, Any]]) -> tuple[str, List[Dict[str, Any]]]:
    """Fold NyxStrike-style messages into Gemini ``contents`` + ``systemInstruction`` text."""
    system_parts: List[str] = []
    contents: List[Dict[str, Any]] = []
    user_buffer: List[str] = []

    def flush_user() -> None:
      if user_buffer:
        text = "\n\n".join(user_buffer)
        contents.append({"role": "user", "parts": [{"text": text}]})
        user_buffer.clear()

    for m in messages:
      role = m.get("role", "user")
      content = m.get("content", "")
      if not isinstance(content, str):
        content = json.dumps(content)
      if role == "system":
        system_parts.append(content)
      elif role == "user":
        user_buffer.append(content)
      elif role == "assistant":
        flush_user()
        contents.append({"role": "model", "parts": [{"text": content}]})
      elif role == "tool":
        flush_user()
        contents.append({"role": "user", "parts": [{"text": f"[Tool result]\n{content}"}]})
      else:
        user_buffer.append(f"[{role}]\n{content}")
    flush_user()
    sys_text = "\n\n".join(system_parts).strip()
    return sys_text, contents

  @staticmethod
  def _openai_tools_to_gemini_declarations(schemas: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert OpenAI-style ``tools`` entries to Gemini ``functionDeclarations``."""
    decls: List[Dict[str, Any]] = []
    for schema in schemas:
      fn = schema.get("function") or schema
      name = fn.get("name")
      if not name:
        continue
      params = fn.get("parameters") or {"type": "OBJECT", "properties": {}}
      decls.append({
        "name": name,
        "description": fn.get("description", "")[:4000],
        "parameters": params,
      })
    return decls

  @staticmethod
  def _parse_tool_calls_from_parts(parts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not parts:
      return out
    for part in parts:
      fc = part.get("functionCall")
      if not fc:
        continue
      raw_args = fc.get("args", {})
      if isinstance(raw_args, str):
        try:
          args = json.loads(raw_args)
        except json.JSONDecodeError:
          args = {"_raw": raw_args}
      else:
        args = dict(raw_args) if isinstance(raw_args, dict) else {}
      out.append({
        "id": fc.get("id") or uuid.uuid4().hex,
        "type": "function",
        "function": {"name": fc.get("name", ""), "arguments": args},
      })
    return out

  @staticmethod
  def _extract_text(parts: List[Dict[str, Any]]) -> str:
    texts = [p["text"] for p in parts if "text" in p]
    return "".join(texts).strip()

  @staticmethod
  def _split_thought_and_answer(parts: List[Dict[str, Any]]) -> tuple[str, str]:
    """Separate Gemini thought summaries from visible answer text."""
    thought_chunks: List[str] = []
    answer_chunks: List[str] = []
    for p in parts:
      if not isinstance(p, dict):
        continue
      txt = p.get("text")
      if not txt:
        continue
      if p.get("thought"):
        thought_chunks.append(txt)
      else:
        answer_chunks.append(txt)
    return "".join(thought_chunks).strip(), "".join(answer_chunks).strip()

  def _apply_thinking_config(self, gen_cfg: Dict[str, Any], want: bool) -> None:
    if not want:
      return
    gen_cfg["thinkingConfig"] = {"includeThoughts": True}

  def chat(
    self,
    messages: List[Dict[str, Any]],
    stop: List[str] = [],
    think: Optional[bool] = None,
    num_ctx: Optional[int] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
  ) -> Dict[str, Any]:
    sys_text, contents = self._build_contents(messages)
    want_thoughts = _want_thoughts(think)
    gen_cfg: Dict[str, Any] = {
      "temperature": 0.7,
      "maxOutputTokens": self._max_output_tokens,
    }
    self._apply_thinking_config(gen_cfg, want_thoughts)
    body: Dict[str, Any] = {
      "contents": contents,
      "generationConfig": gen_cfg,
    }
    if sys_text:
      body["systemInstruction"] = {"parts": [{"text": sys_text}]}
    if stop:
      body["generationConfig"]["stopSequences"] = stop[:5]

    gemini_tools: List[Dict[str, Any]] = []
    if tools:
      decls = self._openai_tools_to_gemini_declarations(tools)
      if decls:
        gemini_tools.append({"functionDeclarations": decls})
        body["tools"] = gemini_tools
        body["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}

    url = self._endpoint("generateContent")

    def _post(b: Dict[str, Any]) -> requests.Response:
      return requests.post(url, json=b, timeout=self._timeout)

    try:
      resp = _post(body)
      if resp.status_code == 400 and want_thoughts:
        logger.info("gemini: generateContent failed with thoughts — retrying without thinkingConfig")
        gen_cfg.pop("thinkingConfig", None)
        resp = _post(body)
      resp.raise_for_status()
      data = resp.json()
    except requests.exceptions.Timeout:
      raise RuntimeError(f"Gemini request timed out after {self._timeout}s")
    except requests.exceptions.HTTPError as exc:
      raise self._http_error(exc)
    except requests.exceptions.ConnectionError as exc:
      raise RuntimeError(f"Cannot reach Gemini API: {exc}") from exc

    cands = data.get("candidates") or []
    if not cands:
      err = data.get("error", {})
      raise RuntimeError(f"Gemini returned no candidates: {err!r}")

    parts = ((cands[0].get("content") or {}).get("parts")) or []
    thought_text, answer_text = self._split_thought_and_answer(parts)
    if not thought_text and not answer_text:
      answer_text = self._extract_text(parts)
    non_thought_parts = [p for p in parts if isinstance(p, dict) and not p.get("thought")]
    tool_calls = self._parse_tool_calls_from_parts(non_thought_parts)
    tool_calls_norm = tool_calls if tool_calls else None
    out: Dict[str, Any] = {"content": answer_text, "tool_calls": tool_calls_norm}
    if thought_text:
      out["thinking_content"] = thought_text
    return out

  def stream_chat(
    self,
    messages: List[Dict[str, Any]],
    num_ctx: Optional[int] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
  ) -> Generator:
    sys_text, contents = self._build_contents(messages)
    mo = min(max((num_ctx or self._max_output_tokens), 256), 8192)
    want_thoughts = _want_thoughts(None)
    gen_cfg: Dict[str, Any] = {"temperature": 0.7, "maxOutputTokens": mo}
    self._apply_thinking_config(gen_cfg, want_thoughts)
    body: Dict[str, Any] = {
      "contents": contents,
      "generationConfig": gen_cfg,
    }
    if sys_text:
      body["systemInstruction"] = {"parts": [{"text": sys_text}]}

    had_tools = bool(tools)
    if tools:
      decls = self._openai_tools_to_gemini_declarations(tools)
      if decls:
        body["tools"] = [{"functionDeclarations": decls}]
        body["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}

    url = self._endpoint("streamGenerateContent") + "&alt=sse"

    def _run_stream(b: Dict[str, Any]) -> tuple[requests.Response, float]:
      t0 = time.perf_counter()
      resp = requests.post(url, json=b, stream=True, timeout=self._timeout)
      if resp.status_code == 400 and want_thoughts and b.get("generationConfig", {}).get("thinkingConfig"):
        resp.close()
        logger.info("gemini: streamGenerateContent failed with thoughts — retrying without thinkingConfig")
        b = json.loads(json.dumps(b))
        b["generationConfig"].pop("thinkingConfig", None)
        t0 = time.perf_counter()
        resp = requests.post(url, json=b, stream=True, timeout=self._timeout)
      return resp, t0

    try:
      resp, stream_t0 = _run_stream(body)
      with resp:
        resp.raise_for_status()
        last_usage: Dict[str, Any] = {}
        last_parts: List[Dict[str, Any]] = []
        function_call_parts: List[Dict[str, Any]] = []
        for raw in resp.iter_lines(decode_unicode=True):
          if not raw or not isinstance(raw, str):
            continue
          line = raw.strip()
          if not line.startswith("data: "):
            continue
          payload = line[6:].strip()
          if payload in ("", "[DONE]"):
            continue
          try:
            data = json.loads(payload)
          except json.JSONDecodeError:
            continue
          meta = data.get("usageMetadata")
          if isinstance(meta, dict):
            last_usage.update(meta)

          for cand in data.get("candidates") or []:
            parts = (cand.get("content") or {}).get("parts") or []
            if parts:
              last_parts = parts
            for part in parts:
              if isinstance(part, dict) and part.get("functionCall"):
                function_call_parts.append(part)
              txt = part.get("text") if isinstance(part, dict) else None
              if not txt:
                continue
              if part.get("thought"):
                yield {"type": "thinking", "content": txt}
              else:
                yield from _slice_stream_text(txt)

        tool_calls_norm: Optional[List[Dict[str, Any]]] = None
        if had_tools:
          if function_call_parts:
            parsed_fc = self._parse_tool_calls_from_parts(function_call_parts)
            tool_calls_norm = parsed_fc if parsed_fc else None
          if tool_calls_norm is None and last_parts:
            non_thought_parts = [p for p in last_parts if isinstance(p, dict) and not p.get("thought")]
            parsed = self._parse_tool_calls_from_parts(non_thought_parts)
            tool_calls_norm = parsed if parsed else None

        if tool_calls_norm:
          yield {"type": "_cipherstrike_tool_calls", "tool_calls": tool_calls_norm}
          return

        elapsed = max(time.perf_counter() - stream_t0, 1e-9)
        prompt = int(last_usage.get("promptTokenCount") or 0)
        total = int(last_usage.get("totalTokenCount") or 0)
        cand_tokens = max(total - prompt, 0) if total else int(last_usage.get("candidatesTokenCount") or 0)
        tps = cand_tokens / elapsed if cand_tokens else 0.0
        yield {
          "eval_count": cand_tokens,
          "prompt_eval_count": prompt,
          "total_duration_s": round(elapsed, 3),
          "eval_duration_s": round(elapsed, 3),
          "tokens_per_sec": round(tps, 2),
        }
    except requests.exceptions.Timeout:
      raise RuntimeError(f"Gemini stream timed out after {self._timeout}s")
    except requests.exceptions.HTTPError as exc:
      raise self._http_error(exc)
    except requests.exceptions.ConnectionError as exc:
      raise RuntimeError(f"Cannot reach Gemini API: {exc}") from exc

  def generate_summary(self, messages: List[Dict[str, Any]]) -> str:
    conversation = "\n".join(f"{m['role'].capitalize()}: {m['content']}" for m in messages)
    summary_prompt = (
      "Summarize the following conversation in 2-3 sentences, "
      "preserving key facts, targets, commands, and findings. "
      "Be concise and technical.\n\n" + conversation
    )
    r = self.chat([{"role": "user", "content": summary_prompt}], think=False)
    if isinstance(r, dict):
      c = r.get("content")
      return c.strip() if isinstance(c, str) else str(c or "").strip()
    return str(r)

  def warm_up(self) -> None:
    try:
      self.chat([{"role": "user", "content": "Say OK"}], think=False)
    except Exception as exc:
      logger.warning("Gemini warm-up failed (non-fatal): %s", exc)

  def is_available(self) -> bool:
    """True if ``GOOGLE_API_KEY`` works and ``GET …/models/{id}`` succeeds."""
    if not self._api_key:
      return False
    try:
      mid = quote(self._model, safe="/")
      u = f"{GEMINI_API_BASE}/models/{mid}?key={self._api_key}"
      resp = requests.get(u, timeout=10)
      return resp.status_code == 200
    except Exception:
      return False

  @property
  def provider(self) -> str:
    return "gemini"

  @property
  def model(self) -> str:
    return self._model


class OpenAIBackend:
  """OpenAI-compatible backend (OpenAI, Azure, OpenRouter) via the openai SDK."""

  def __init__(
    self,
    model: str,
    api_key: str,
    base_url: Optional[str],
    timeout: int,
    *,
    provider_label: str = "openai",
  ) -> None:
    self._model = model
    self._timeout = timeout
    self._provider_label = provider_label
    try:
      import openai  # noqa: F401 — optional dependency
      self._openai = openai
      kwargs: Dict[str, Any] = {"api_key": api_key}
      if base_url:
        kwargs["base_url"] = base_url
      self._client = openai.OpenAI(**kwargs)
    except ImportError:
      raise RuntimeError(
        "openai SDK not installed. Run: pip install openai"
      )

  def _apply_openrouter_reasoning(self, kwargs: Dict[str, Any], think: Optional[bool]) -> None:
    if self._provider_label != "openrouter" or not _want_thoughts(think):
      return
    extra = dict(kwargs.get("extra_body") or {})
    extra.update(_openrouter_reasoning_extra(self._model))
    kwargs["extra_body"] = extra

  def chat(
    self,
    messages: List[Dict[str, Any]],
    stop: List[str] = [],
    think: Optional[bool] = None,
    num_ctx: Optional[int] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
  ) -> Any:
    kwargs: Dict[str, Any] = {
      "model": self._model,
      "messages": messages,
      "max_tokens": 4096,
      "temperature": 0.7,
    }
    if stop:
      kwargs["stop"] = stop
    if tools:
      kwargs["tools"] = tools
      kwargs["tool_choice"] = "auto"
    self._apply_openrouter_reasoning(kwargs, think)
    try:
      resp = self._client.chat.completions.create(**kwargs)
      msg = resp.choices[0].message
      thought_text = _reasoning_text_from_message(msg)
      if getattr(msg, "tool_calls", None):
        tcs = []
        for tc in msg.tool_calls:
          args = tc.function.arguments
          if isinstance(args, str):
            try:
              ad = json.loads(args)
            except json.JSONDecodeError:
              ad = {"_raw": args}
          else:
            ad = dict(args) if isinstance(args, dict) else {}
          tcs.append({"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": ad}})
        out: Dict[str, Any] = {"content": (msg.content or "").strip(), "tool_calls": tcs}
        if thought_text:
          out["thinking_content"] = thought_text
        return out
      out = {"content": (msg.content or "").strip(), "tool_calls": None}
      if thought_text:
        out["thinking_content"] = thought_text
      return out
    except Exception as exc:
      raise RuntimeError(f"OpenAI API error: {exc}")

  def stream_chat(
    self,
    messages: List[Dict[str, Any]],
    num_ctx: Optional[int] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
    think: Optional[bool] = None,
  ) -> Generator[Any, None, None]:
    kwargs: Dict[str, Any] = {
      "model": self._model,
      "messages": messages,
      "max_tokens": 4096,
      "temperature": 0.7,
      "stream": True,
    }
    if tools:
      kwargs["tools"] = tools
      kwargs["tool_choice"] = "auto"
    self._apply_openrouter_reasoning(kwargs, think)
    try:
      stream = self._client.chat.completions.create(**kwargs)
      tool_call_parts: Dict[int, Dict[str, Any]] = {}
      for chunk in stream:
        if not chunk.choices:
          continue
        delta_obj = chunk.choices[0].delta
        reasoning_delta = _reasoning_text_from_delta(delta_obj)
        if reasoning_delta:
          for piece in _slice_stream_text(reasoning_delta, max_chars=48):
            yield {"type": "thinking", "content": piece}
        delta = getattr(delta_obj, "content", None)
        if delta:
          yield delta

        for tc_delta in getattr(delta_obj, "tool_calls", None) or []:
          idx = int(getattr(tc_delta, "index", 0) or 0)
          slot = tool_call_parts.setdefault(
            idx,
            {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
          )
          tc_id = getattr(tc_delta, "id", None)
          if tc_id:
            slot["id"] = tc_id
          tc_type = getattr(tc_delta, "type", None)
          if tc_type:
            slot["type"] = tc_type
          fn_delta = getattr(tc_delta, "function", None)
          if fn_delta is None:
            continue
          name_delta = getattr(fn_delta, "name", None)
          if name_delta:
            slot["function"]["name"] += name_delta
          args_delta = getattr(fn_delta, "arguments", None)
          if args_delta:
            slot["function"]["arguments"] += args_delta

      if tool_call_parts:
        parsed_tool_calls = []
        for _, tc in sorted(tool_call_parts.items()):
          fn = tc.get("function") if isinstance(tc, dict) else None
          if not isinstance(fn, dict):
            continue
          raw_args = str(fn.get("arguments") or "")
          try:
            parsed_args = json.loads(raw_args) if raw_args else {}
          except json.JSONDecodeError:
            parsed_args = {"_raw": raw_args}
          parsed_tool_calls.append({
            "id": str(tc.get("id") or ""),
            "type": str(tc.get("type") or "function"),
            "function": {
              "name": str(fn.get("name") or ""),
              "arguments": parsed_args if isinstance(parsed_args, dict) else {"_value": parsed_args},
            },
          })
        if parsed_tool_calls:
          yield {"type": "_cipherstrike_tool_calls", "tool_calls": parsed_tool_calls}
    except Exception as exc:
      raise RuntimeError(f"OpenAI streaming error: {exc}")

  def generate_summary(self, messages: List[Dict[str, Any]]) -> str:
    conversation = "\n".join(f"{m['role'].capitalize()}: {m['content']}" for m in messages)
    summary_prompt = (
      "Summarize the following conversation in 2-3 sentences, "
      "preserving key facts, targets, commands, and findings. "
      "Be concise and technical.\n\n" + conversation
    )
    r = self.chat([{"role": "user", "content": summary_prompt}])
    return r["content"] if isinstance(r, dict) else str(r)

  def is_available(self) -> bool:
    return True

  @property
  def provider(self) -> str:
    return self._provider_label

  @property
  def model(self) -> str:
    return self._model


class OpenRouterBackend(OpenAIBackend):
  """OpenRouter — OpenAI-compatible API for routed models (e.g. google/gemini-2.5-flash-lite)."""

  def __init__(self, model: str, api_key: str, base_url: Optional[str], timeout: int) -> None:
    url = (base_url or "").strip() or OPENROUTER_API_BASE
    super().__init__(
      _normalize_openrouter_model_id(model),
      api_key,
      url,
      timeout,
      provider_label="openrouter",
    )


def _anthropic_tools_from_openai_schemas(openai_tools: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
  """Map OpenAI-style ``{"type":"function","function":{...}}`` entries to Anthropic ``tools`` API shape."""
  if not openai_tools:
    return []
  out: List[Dict[str, Any]] = []
  for item in openai_tools:
    if not isinstance(item, dict) or item.get("type") != "function":
      continue
    fn = item.get("function")
    if not isinstance(fn, dict):
      continue
    nm = str(fn.get("name") or "").strip()
    if not nm:
      continue
    desc = str(fn.get("description") or "")
    params = fn.get("parameters")
    if not isinstance(params, dict):
      params = {"type": "object", "properties": {}, "required": []}
    out.append({"name": nm, "description": desc, "input_schema": params})
  return out


class AnthropicBackend:
  """Anthropic Claude backend via the anthropic SDK."""

  def __init__(self, model: str, api_key: str, timeout: int) -> None:
    self._model = model
    self._timeout = timeout
    try:
      import anthropic  # noqa: F401 — optional dependency
      self._client = anthropic.Anthropic(api_key=api_key)
    except ImportError:
      raise RuntimeError(
        "anthropic SDK not installed. Run: pip install anthropic"
      )

  def chat(
    self,
    messages: List[Dict[str, Any]],
    stop: List[str] = [],
    think: Optional[bool] = None,
    num_ctx: Optional[int] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
  ) -> Any:
    system_parts = [m["content"] for m in messages if m["role"] == "system"]
    user_messages = [m for m in messages if m["role"] != "system"]
    system_text = "\n\n".join(system_parts)
    kwargs: Dict[str, Any] = {
      "model": self._model,
      "max_tokens": 4096,
      "messages": user_messages,
    }
    if system_text:
      kwargs["system"] = system_text
    if stop:
      kwargs["stop_sequences"] = stop
    anthropic_tools = _anthropic_tools_from_openai_schemas(tools)
    if anthropic_tools:
      kwargs["tools"] = anthropic_tools
    try:
      resp = self._client.messages.create(**kwargs)
    except Exception as exc:
      raise RuntimeError(f"Anthropic API error: {exc}")

    text_parts: List[str] = []
    tool_calls_out: List[Dict[str, Any]] = []
    for block in resp.content:
      btype = getattr(block, "type", None)
      if btype == "text":
        text_parts.append(str(getattr(block, "text", "") or ""))
      elif btype == "tool_use":
        raw_input = getattr(block, "input", None)
        args = dict(raw_input) if isinstance(raw_input, dict) else {}
        tool_calls_out.append(
            {
              "id": str(getattr(block, "id", "") or ""),
              "type": "function",
              "function": {
                "name": str(getattr(block, "name", "") or ""),
                "arguments": args,
              },
            },
        )

    content = "".join(text_parts).strip()
    if tool_calls_out:
      return {"content": content, "tool_calls": tool_calls_out}
    return content

  def stream_chat(self, messages: List[Dict[str, Any]], num_ctx: Optional[int] = None) -> Generator[str, None, None]:
    system_parts = [m["content"] for m in messages if m["role"] == "system"]
    user_messages = [m for m in messages if m["role"] != "system"]
    system_text = "\n\n".join(system_parts)
    kwargs: Dict[str, Any] = {
      "model": self._model,
      "max_tokens": 4096,
      "messages": user_messages,
    }
    if system_text:
      kwargs["system"] = system_text
    try:
      with self._client.messages.stream(**kwargs) as stream:
        for text in stream.text_stream:
          if text:
            yield text
    except Exception as exc:
      raise RuntimeError(f"Anthropic streaming error: {exc}")

  def generate_summary(self, messages: List[Dict[str, Any]]) -> str:
    conversation = "\n".join(f"{m['role'].capitalize()}: {m['content']}" for m in messages)
    summary_prompt = (
      "Summarize the following conversation in 2-3 sentences, "
      "preserving key facts, targets, commands, and findings. "
      "Be concise and technical.\n\n" + conversation
    )
    return self.chat([{"role": "user", "content": summary_prompt}])

  def is_available(self) -> bool:
    try:
      self._client.models.list()
      return True
    except Exception:
      return False

  @property
  def provider(self) -> str:
    return "anthropic"

  @property
  def model(self) -> str:
    return self._model


class LLMClient:
  """Provider-agnostic LLM client."""

  def __init__(self) -> None:
    self.max_loops: int = int(_cfg("NYXSTRIKE_LLM_MAX_LOOPS") or 9)
    self._backend: Any = None
    self._init_error: str = ""

    provider = (_cfg("NYXSTRIKE_LLM_PROVIDER") or "openrouter").lower()
    model = _cfg("NYXSTRIKE_LLM_MODEL") or "google/gemini-2.5-flash-lite"
    base_url = (_cfg("NYXSTRIKE_LLM_URL") or "").strip()
    api_key = (_cfg("NYXSTRIKE_LLM_API_KEY") or "").strip()
    timeout = int(_cfg("NYXSTRIKE_LLM_TIMEOUT") or 300)
    num_ctx = int(_cfg("NYXSTRIKE_LLM_NUM_CTX") or 8192)
    self._num_ctx_analyse = int(_cfg("NYXSTRIKE_LLM_NUM_CTX_ANALYSE") or 16384)

    gemini_key = api_key or (os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY") or "").strip()
    openrouter_key = _resolve_openrouter_api_key(api_key)
    openai_key = api_key or openrouter_key

    openai_base: Optional[str] = None
    if base_url and base_url.strip() not in _LEGACY_OPENAI_BASE_IGNORE:
      openai_base = base_url.strip()

    try:
      if provider == "openrouter":
        self._backend = OpenRouterBackend(model, openrouter_key, openai_base, timeout)
      elif provider == "gemini":
        self._backend = GeminiBackend(model, gemini_key, timeout, max_output_tokens=num_ctx)
      elif provider == "openai":
        self._backend = OpenAIBackend(model, openai_key, openai_base, timeout)
      elif provider == "anthropic":
        self._backend = AnthropicBackend(model, api_key, timeout)
      else:
        raise ValueError(
          f"Unknown LLM provider: {provider!r}. Choose: openrouter, gemini, openai, anthropic",
        )

      logger.info(
        "llm_client: initialized provider=%s model=%s",
        self._backend.provider,
        self._backend.model,
      )
    except Exception as exc:
      self._init_error = str(exc)
      logger.warning("llm_client: initialization failed — %s", exc)

  @property
  def provider(self) -> str:
    return self._backend.provider if self._backend else "none"

  @property
  def model(self) -> str:
    return self._backend.model if self._backend else ""

  @property
  def num_ctx_analyse(self) -> int:
    return getattr(self, '_num_ctx_analyse', 16384)

  def is_available(self) -> bool:
    if self._backend is None:
      return False
    try:
      return self._backend.is_available()
    except Exception:
      return False

  def warm_up(self) -> None:
    if self._backend is None:
      return
    if hasattr(self._backend, "warm_up"):
      self._backend.warm_up()

  def chat(
    self,
    messages: List[Dict[str, Any]],
    stop: List[str] = [],
    think: Optional[bool] = None,
    num_ctx: Optional[int] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
  ) -> Any:
    if self._backend is None:
      raise RuntimeError(
        f"LLM client not initialized: {self._init_error or 'unknown error'}"
      )
    if tools and hasattr(self._backend, "chat"):
      try:
        result = self._backend.chat(messages, stop, think=think, num_ctx=num_ctx, tools=tools)
      except TypeError:
        result = self._backend.chat(messages, stop, think=think, num_ctx=num_ctx)
      if isinstance(result, str):
        return result
      return result

    result = self._backend.chat(messages, stop, think=think, num_ctx=num_ctx)
    if isinstance(result, dict):
      c = result.get("content")
      if isinstance(c, str):
        return c
      if c is None:
        return ""
      return str(c)
    if isinstance(result, str):
      return result
    return str(result) if result is not None else ""

  def stream_chat(
    self,
    messages: List[Dict[str, Any]],
    num_ctx: Optional[int] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
  ) -> Generator:
    if self._backend is None:
      raise RuntimeError(
        f"LLM client not initialized: {self._init_error or 'unknown error'}"
      )
    if not hasattr(self._backend, "stream_chat"):
      raise RuntimeError(f"Backend {self.provider!r} does not support streaming")
    sc = self._backend.stream_chat
    try:
      yield from sc(messages, num_ctx=num_ctx, tools=tools)
    except TypeError:
      if tools is not None:
        raise RuntimeError(
          f"Backend {self.provider!r} does not support streaming with tools",
        ) from None
      yield from sc(messages, num_ctx=num_ctx)

  def generate_summary(self, messages: List[Dict[str, Any]]) -> str:
    if self._backend is None:
      raise RuntimeError(
        f"LLM client not initialized: {self._init_error or 'unknown error'}"
      )
    if hasattr(self._backend, "generate_summary"):
      return self._backend.generate_summary(messages)
    conversation = "\n".join(
      f"{m['role'].capitalize()}: {m['content']}" for m in messages
    )
    prompt = (
      "Summarize the following conversation in 2-3 sentences, "
      "preserving key facts, targets, commands, and findings. "
      "Be concise and technical.\n\n" + conversation
    )
    return self.chat([{"role": "user", "content": prompt}])

  def status(self) -> Dict[str, Any]:
    available = self.is_available()
    return {
      "available": available,
      "provider": self.provider,
      "model": self.model,
      "max_loops": self.max_loops,
      "error": self._init_error if not available else "",
    }
