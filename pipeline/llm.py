"""Thin wrapper around the Claude API for the pipeline's agent steps.

Every call:
- streams (long research turns can run for minutes),
- returns JSON matching a schema (structured outputs),
- can use Anthropic's server-side web search and web fetch tools,
- opts into server-side refusal fallbacks, because security research text can trip
  safety classifiers; a fallback model finishes the turn instead of the run failing.

Needs ANTHROPIC_API_KEY in the environment (a GitHub Actions secret in CI).
"""
from __future__ import annotations

import json
import os

import anthropic

MODEL = os.environ.get("THREATHUNTER_MODEL", "claude-opus-5-5")
MAX_CONTINUATIONS = 5

WEB_TOOLS = [
    {"type": "web_search_20260209", "name": "web_search", "max_uses": 8},
    {"type": "web_fetch_20260209", "name": "web_fetch", "max_uses": 10},
]


class LLMError(RuntimeError):
    pass


def ask_json(system: str, messages: list[dict], schema: dict, *, web: bool = False,
             effort: str = "high", max_tokens: int = 64000) -> tuple[dict, list[dict]]:
    """Run one agent turn and return (parsed JSON, full message history).

    The history is returned so a caller can append a follow-up (for example, validator
    errors) and call again in the same conversation.
    """
    client = anthropic.Anthropic()
    history = list(messages)
    for _ in range(MAX_CONTINUATIONS + 1):
        with client.beta.messages.stream(
            model=MODEL,
            max_tokens=max_tokens,
            system=system,
            messages=history,
            tools=WEB_TOOLS if web else [],
            output_config={
                "effort": effort,
                "format": {"type": "json_schema", "schema": schema},
            },
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        ) as stream:
            response = stream.get_final_message()
        history.append({"role": "assistant", "content": response.content})
        if response.stop_reason == "pause_turn":
            continue  # server-side tool loop hit its limit; resend so it resumes
        break
    else:
        raise LLMError("agent turn did not finish after several continuations")

    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        raise LLMError(f"model declined the request: {details}")
    if response.stop_reason == "max_tokens":
        raise LLMError("response hit max_tokens before finishing")
    texts = [b.text for b in response.content if b.type == "text"]
    if not texts:
        raise LLMError(f"no text in response (stop_reason={response.stop_reason})")
    try:
        return json.loads(texts[-1]), history
    except json.JSONDecodeError as exc:
        raise LLMError(f"response was not valid JSON: {exc}") from exc


def cited_urls(history: list[dict]) -> set[str]:
    """URLs the model actually searched or fetched during the turn(s)."""
    urls: set[str] = set()
    for msg in history:
        if msg["role"] != "assistant" or isinstance(msg["content"], str):
            continue
        for block in msg["content"]:
            btype = getattr(block, "type", None)
            if btype == "web_fetch_tool_result":
                content = getattr(block, "content", None)
                url = getattr(content, "url", None)
                if url:
                    urls.add(url)
            elif btype == "web_search_tool_result":
                content = getattr(block, "content", None)
                if isinstance(content, list):
                    urls.update(r.url for r in content if getattr(r, "url", None))
    return urls
