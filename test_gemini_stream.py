#!/usr/bin/env python3
"""Smoke-test OpenRouter streaming via NyxStrike ``LLMClient`` (requires API key in env).

Set one of: NYXSTRIKE_LLM_API_KEY, GOOGLE_API_KEY, or OPENROUTER_API_KEY.
"""

import os


def main() -> None:
  if not (
    os.environ.get("NYXSTRIKE_LLM_API_KEY")
    or os.environ.get("GOOGLE_API_KEY")
    or os.environ.get("OPENROUTER_API_KEY")
  ):
    print(
      "Set NYXSTRIKE_LLM_API_KEY, GOOGLE_API_KEY, or OPENROUTER_API_KEY, "
      "then run: python3 test_gemini_stream.py"
    )
    return

  os.environ.setdefault("NYXSTRIKE_LLM_WARMUP", "1")

  from server_core.llm_client import LLMClient

  client = LLMClient()
  messages = [
    {"role": "system", "content": "You are a concise assistant."},
    {"role": "user", "content": 'Reply with exactly: OK'},
  ]
  print("Streaming:")
  for part in client.stream_chat(messages):
    if isinstance(part, dict):
      print(f"[META] {part}")
    else:
      print(part, end="", flush=True)
  print()


if __name__ == "__main__":
  main()
