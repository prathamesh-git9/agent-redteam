"""CallableTarget — wrap an in-process Python function as a target.

The point of this adapter is to let you red-team the *actual* agent object you
ship, not an HTTP facade of it. If your agent is a coroutine that takes a list
of messages and returns a string (or a richer object), you can point the harness
straight at it — no server, no network, and therefore no allowlist needed.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from agent_redteam.targets.base import Target
from agent_redteam.types import (
    Conversation,
    Response,
    TargetInfo,
    TargetKind,
    ToolCall,
    Usage,
)

# The wrapped function may return either a bare string or a Response. Accepting
# both keeps the common case (return a string) trivial while letting advanced
# users surface tool calls and usage for the tool/DoW oracles.
CallableFn = Callable[[Conversation], "str | Response | Awaitable[str | Response]"]


@dataclass
class CallableTarget(Target):
    fn: CallableFn
    name: str = "callable"
    supports_tools: bool = False

    @property
    def info(self) -> TargetInfo:
        return TargetInfo(
            name=self.name,
            kind=TargetKind.CALLABLE,
            supports_tools=self.supports_tools,
            # In-process: no third party, so authorization is inherent. The
            # runner still checks .endpoint() (None here) and passes.
            authorized=True,
            allowlisted=True,
        )

    def endpoint(self) -> str | None:
        return None

    async def send(self, conversation: Conversation) -> Response:
        start = time.perf_counter()
        try:
            result: Any = self.fn(conversation)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # noqa: BLE001 - surface as target error, don't crash the run
            return Response(text="", error=f"{type(exc).__name__}: {exc}")
        latency = (time.perf_counter() - start) * 1000.0
        return _coerce(result, latency)


def _coerce(result: Any, latency_ms: float) -> Response:
    if isinstance(result, Response):
        # Preserve everything, just stamp latency if the callable didn't.
        if result.latency_ms == 0.0:
            return Response(
                text=result.text,
                tool_calls=result.tool_calls,
                usage=result.usage,
                latency_ms=latency_ms,
                raw=result.raw,
                error=result.error,
            )
        return result
    if isinstance(result, str):
        return Response(text=result, latency_ms=latency_ms)
    if isinstance(result, tuple) and result and isinstance(result[0], str):
        # (text, tool_calls) convenience form.
        text = result[0]
        calls = tuple(result[1]) if len(result) > 1 else ()
        return Response(
            text=text,
            tool_calls=tuple(c for c in calls if isinstance(c, ToolCall)),
            latency_ms=latency_ms,
        )
    return Response(text=str(result), latency_ms=latency_ms, usage=Usage())
