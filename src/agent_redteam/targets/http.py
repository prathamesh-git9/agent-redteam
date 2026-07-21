"""HTTPTarget — red-team an arbitrary JSON HTTP agent.

Most real agents are not raw model endpoints; they are your service with a
custom request/response shape. Rather than force every such agent into an
OpenAI-shaped box, this adapter maps a conversation into whatever JSON body the
service expects (via a small template language) and pulls the reply out with a
dotted path. No JSONPath dependency — a dotted path with integer indices covers
essentially every real response shape and keeps the install lean.
"""

from __future__ import annotations

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
    Usage,
)


def _last_user(conversation: Conversation) -> str:
    for m in reversed(conversation):
        if m.role == Role.USER:
            return m.content
    return conversation[-1].content if conversation else ""


def _openai_messages(conversation: Conversation) -> list[dict[str, str]]:
    return [{"role": m.role.value, "content": m.content} for m in conversation]


def _fill(template: Any, conversation: Conversation) -> Any:
    """Recursively substitute placeholder tokens in a request template.

    Supported tokens (as *whole* string values, so we can swap in non-string
    structures like the messages list):
      * ``{{last_user}}``      -> the latest user message text
      * ``{{messages}}``       -> OpenAI-style [{role, content}, ...]
      * ``{{full_prompt}}``    -> all message contents joined by newlines
    Any other string is passed through, so static fields (model name, keys) are
    preserved verbatim.
    """
    if isinstance(template, dict):
        return {k: _fill(v, conversation) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill(v, conversation) for v in template]
    if template == "{{last_user}}":
        return _last_user(conversation)
    if template == "{{messages}}":
        return _openai_messages(conversation)
    if template == "{{full_prompt}}":
        return "\n".join(m.content for m in conversation)
    return template


def _dig(data: Any, path: str) -> str:
    """Follow a dotted path (``choices.0.message.content``) into a JSON object."""
    cur = data
    for part in path.split("."):
        if cur is None:
            return ""
        if part.isdigit() and isinstance(cur, list):
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return ""
    return "" if cur is None else str(cur)


@dataclass
class HTTPTarget(Target):
    url: str
    request_template: dict[str, Any] = field(
        default_factory=lambda: {"input": "{{last_user}}"}
    )
    response_path: str = "output"
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    name: str = "http"
    timeout: float = 30.0
    supports_tools: bool = False

    @property
    def info(self) -> TargetInfo:
        return TargetInfo(
            name=self.name,
            kind=TargetKind.HTTP,
            supports_tools=self.supports_tools,
            authorized=True,
            allowlisted=True,
        )

    def endpoint(self) -> str | None:
        return self.url

    async def send(self, conversation: Conversation) -> Response:
        body = _fill(self.request_template, conversation)
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.request(
                    self.method, self.url, headers=self.headers, json=body
                )
        except httpx.HTTPError as exc:
            return Response(text="", error=f"transport: {exc}")
        latency = (time.perf_counter() - start) * 1000.0
        if resp.status_code >= 400:
            return Response(
                text="", latency_ms=latency,
                error=f"http {resp.status_code}: {resp.text[:300]}",
            )
        try:
            data = resp.json()
        except ValueError:
            # Not JSON — treat the raw body as the reply text.
            return Response(text=resp.text, latency_ms=latency, raw=resp.text)
        return Response(
            text=_dig(data, self.response_path),
            usage=Usage(),  # generic agents rarely report tokens; left zero
            latency_ms=latency,
            raw=data,
        )


def http_from_options(name: str, options: dict[str, Any]) -> HTTPTarget:
    return HTTPTarget(
        url=options["url"],
        request_template=options.get("request_template", {"input": "{{last_user}}"}),
        response_path=options.get("response_path", "output"),
        method=options.get("method", "POST"),
        headers=options.get("headers", {}),
        name=name,
        timeout=float(options.get("timeout", 30.0)),
        supports_tools=bool(options.get("supports_tools", False)),
    )
