"""Tool-call guardrails for capability policy and SSRF prevention."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from agent_redteam.registry import register_guardrail
from agent_redteam.types import Evidence, GuardAction, GuardDecision, ToolCall

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_DEFAULT_DENY = frozenset({"delete_all", "exec", "shell", "eval"})
_CLOUD_METADATA = ipaddress.ip_address("169.254.169.254")


@register_guardrail("tool_policy")
@dataclass(frozen=True)
class ToolCallPolicy:
    """Enforce tool allow/deny lists and block private-network URL arguments."""

    allow: frozenset[str] = frozenset()
    deny: frozenset[str] = _DEFAULT_DENY
    name: str = "tool_policy"

    def __init__(
        self,
        allow: Iterable[str] = (),
        deny: Iterable[str] = _DEFAULT_DENY,
    ) -> None:
        object.__setattr__(self, "allow", frozenset(allow))
        object.__setattr__(self, "deny", frozenset(deny))
        object.__setattr__(self, "name", "tool_policy")

    def inspect_tool(self, call: ToolCall) -> GuardDecision:
        if call.name in self.deny:
            return GuardDecision(
                GuardAction.BLOCK,
                guardrail=self.name,
                reason=f"tool {call.name!r} is denied",
                evidence=(Evidence("tool_call", f"denied tool: {call.name}"),),
            )
        if self.allow and call.name not in self.allow:
            return GuardDecision(
                GuardAction.BLOCK,
                guardrail=self.name,
                reason=f"tool {call.name!r} is not allowlisted",
                evidence=(Evidence("tool_call", f"not allowlisted: {call.name}"),),
            )
        for path, value in _iter_string_args(call.arguments):
            if _contains_private_url(value):
                return GuardDecision(
                    GuardAction.BLOCK,
                    guardrail=self.name,
                    reason="tool argument contained a private-network URL",
                    evidence=(Evidence("ssrf", f"offending arg: {path}", span=value),),
                )
        return GuardDecision(GuardAction.ALLOW, guardrail=self.name)


def _iter_string_args(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_string_args(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from _iter_string_args(child, f"{path}[{index}]")


def _contains_private_url(text: str) -> bool:
    for match in _URL_RE.finditer(text):
        parsed = urlparse(match.group(0))
        host = parsed.hostname
        if host and _is_private_host(host):
            return True
    return False


def _is_private_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip == _CLOUD_METADATA
        or ip.is_loopback
        or ip in ipaddress.ip_network("10.0.0.0/8")
        or ip in ipaddress.ip_network("192.168.0.0/16")
        or ip in ipaddress.ip_network("172.16.0.0/12")
    )
