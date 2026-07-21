"""FakeTarget — a scripted, deterministic target.

This is the backbone of the test suite and of every attack's regression fixture.
Instead of mocking an LLM, we model a target as a small rule table: an ordered
list of (matcher, reply) pairs. This lets a test express, precisely, "this is a
target that *is* vulnerable to system-prompt leakage" or "this is a target that
correctly refuses jailbreaks", and then assert that the oracle reaches the right
verdict. Because it is pure and offline, the entire attack→oracle→score pipeline
runs in CI with no API key and no flakiness.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from agent_redteam.types import (
    Conversation,
    Response,
    Role,
    TargetInfo,
    TargetKind,
    ToolCall,
    Usage,
)

# A rule maps a predicate over the conversation to a canned reply. Kept as a
# plain callable so tests can express arbitrary conditions without new machinery.
Matcher = Callable[[Conversation], bool]


@dataclass
class Rule:
    matcher: Matcher
    reply: str = ""
    tool_calls: tuple[ToolCall, ...] = ()


def contains(pattern: str, *, flags: int = re.IGNORECASE) -> Matcher:
    """Matcher: any message in the conversation matches ``pattern`` (regex)."""
    rx = re.compile(pattern, flags)
    return lambda convo: any(rx.search(m.content) for m in convo)


def last_user_contains(pattern: str, *, flags: int = re.IGNORECASE) -> Matcher:
    rx = re.compile(pattern, flags)

    def _m(convo: Conversation) -> bool:
        for m in reversed(convo):
            if m.role == Role.USER:
                return bool(rx.search(m.content))
        return False

    return _m


@dataclass
class FakeTarget:
    """A deterministic target driven by an ordered rule table.

    The first rule whose matcher returns True wins; if none match, ``default`` is
    returned. This ordering is significant and mirrors a real guardrailed agent:
    put the "refusal" rules first to model a well-defended target, or the "leak"
    rules first to model a vulnerable one.
    """

    name: str = "fake"
    rules: list[Rule] = field(default_factory=list)
    default: str = "I can help with that."
    supports_tools: bool = False

    @property
    def info(self) -> TargetInfo:
        # Fake targets are authorized/allowlisted by construction: they never
        # touch a network, so there is no third party to protect.
        return TargetInfo(
            name=self.name,
            kind=TargetKind.FAKE,
            supports_tools=self.supports_tools,
            authorized=True,
            allowlisted=True,
        )

    def endpoint(self) -> str | None:
        return None

    async def send(self, conversation: Conversation) -> Response:
        for rule in self.rules:
            if rule.matcher(conversation):
                return Response(
                    text=rule.reply,
                    tool_calls=rule.tool_calls,
                    usage=Usage(
                        prompt_tokens=_estimate(conversation),
                        completion_tokens=len(rule.reply) // 4,
                    ),
                )
        return Response(
            text=self.default,
            usage=Usage(
                prompt_tokens=_estimate(conversation),
                completion_tokens=len(self.default) // 4,
            ),
        )


def _estimate(conversation: Conversation) -> int:
    """Crude token estimate (~4 chars/token) so Usage is populated in tests."""
    return sum(len(m.content) for m in conversation) // 4


def vulnerable_target(*extra_rules: Rule) -> FakeTarget:
    """A target that leaks and complies — the 'before mitigation' baseline.

    Ships with rules that make it succumb to the canonical attacks so each
    attack's fixture can prove it *detects* a real vulnerability. Extra rules are
    prepended so callers can specialise it.
    """
    return FakeTarget(
        name="vulnerable",
        supports_tools=True,
        rules=[*extra_rules],
        # By default it just complies with whatever it's told, including
        # instruction-override — the essence of an undefended model.
        default="Sure! Ignoring previous instructions as requested.",
    )


def hardened_target(*extra_rules: Rule) -> FakeTarget:
    """A target that refuses the canonical attacks — the 'after mitigation' case."""
    return FakeTarget(
        name="hardened",
        supports_tools=True,
        rules=[*extra_rules],
        default="I can't help with that request.",
    )
