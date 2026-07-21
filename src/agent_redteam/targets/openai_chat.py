"""OpenAIChatTarget — any OpenAI-compatible /chat/completions endpoint.

Deliberately implemented against the raw HTTP API rather than the `openai` SDK
so it works unchanged against OpenAI, xAI/Grok, vLLM, Ollama, and anything else
that speaks the same wire format — the harness should not care which vendor is
behind the endpoint, only that it answers chat completions.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from agent_redteam.targets.base import Target
from agent_redteam.types import (
    Conversation,
    Response,
    Role,
    TargetInfo,
    TargetKind,
    ToolCall,
    Usage,
)


@dataclass
class OpenAIChatTarget(Target):
    """Chat-completions adapter.

    ``system_prompt`` is prepended to every conversation *unless* the probe
    already supplies a system message — this models the realistic case where an
    operator's agent has a fixed system prompt that the attacker is trying to
    override or leak.
    """

    model: str
    base_url: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"
    system_prompt: str | None = None
    name: str = "openai_chat"
    timeout: float = 30.0
    max_tokens: int = 512
    extra_headers: dict[str, str] = field(default_factory=dict)
    supports_tools: bool = True

    @property
    def info(self) -> TargetInfo:
        return TargetInfo(
            name=self.name,
            kind=TargetKind.OPENAI_CHAT,
            supports_tools=self.supports_tools,
            # authorized/allowlisted are decided by the config gate, not the
            # adapter — the adapter reports capability, config reports permission.
            authorized=True,
            allowlisted=True,
        )

    def endpoint(self) -> str | None:
        return self.base_url

    def _headers(self) -> dict[str, str]:
        key = os.environ.get(self.api_key_env, "")
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def _payload(self, conversation: Conversation) -> dict[str, Any]:
        messages = _to_openai_messages(conversation, self.system_prompt)
        return {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": 0,  # the *target* is exercised deterministically too
        }

    async def send(self, conversation: Conversation) -> Response:
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    url, headers=self._headers(), json=self._payload(conversation)
                )
        except httpx.HTTPError as exc:
            return Response(text="", error=f"transport: {exc}")
        latency = (time.perf_counter() - start) * 1000.0
        if resp.status_code >= 400:
            # Expected failure (rate limit, bad key, refusal-as-error): record it,
            # don't crash — a run against a flaky target should still complete.
            return Response(
                text="", latency_ms=latency,
                error=f"http {resp.status_code}: {resp.text[:300]}",
            )
        return _parse_openai_response(resp.json(), latency)


def _to_openai_messages(
    conversation: Conversation, system_prompt: str | None
) -> list[dict[str, Any]]:
    has_system = any(m.role == Role.SYSTEM for m in conversation)
    out: list[dict[str, Any]] = []
    if system_prompt and not has_system:
        out.append({"role": "system", "content": system_prompt})
    for m in conversation:
        out.append({"role": m.role.value, "content": m.content})
    return out


def _parse_openai_response(data: dict[str, Any], latency_ms: float) -> Response:
    choices = data.get("choices") or [{}]
    message = choices[0].get("message", {}) or {}
    text = message.get("content") or ""
    tool_calls = _parse_tool_calls(message.get("tool_calls") or [])
    usage_raw = data.get("usage") or {}
    usage = Usage(
        prompt_tokens=int(usage_raw.get("prompt_tokens", 0)),
        completion_tokens=int(usage_raw.get("completion_tokens", 0)),
    )
    return Response(
        text=text, tool_calls=tool_calls, usage=usage, latency_ms=latency_ms, raw=data
    )


def _parse_tool_calls(raw_calls: list[dict[str, Any]]) -> tuple[ToolCall, ...]:
    import json

    calls: list[ToolCall] = []
    for c in raw_calls:
        fn = c.get("function", {}) or {}
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"_raw": args}
        calls.append(
            ToolCall(name=fn.get("name", "unknown"), arguments=args, call_id=c.get("id"))
        )
    return tuple(calls)


def target_from_options(name: str, options: dict[str, Any]) -> OpenAIChatTarget:
    """Build an OpenAIChatTarget from a config ``options`` dict."""
    return OpenAIChatTarget(
        model=options.get("model", "gpt-4o-mini"),
        base_url=options.get("base_url", "https://api.openai.com/v1"),
        api_key_env=options.get("api_key_env", "OPENAI_API_KEY"),
        system_prompt=options.get("system_prompt"),
        name=name,
        timeout=float(options.get("timeout", 30.0)),
        max_tokens=int(options.get("max_tokens", 512)),
        extra_headers=options.get("extra_headers", {}),
    )
