"""The Target protocol and shared helpers for adapters.

A Target is the *only* part of the system that touches a network or an external
model. Isolating I/O here means every other component — attacks, oracles,
scoring, guardrails — is pure and testable without credentials, and a whole run
can be replayed from its recorded trace by swapping in a scripted target.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_redteam.types import Conversation, Response, TargetInfo


@runtime_checkable
class Target(Protocol):
    info: TargetInfo

    async def send(self, conversation: Conversation) -> Response:
        """Send a conversation and return the target's response.

        Implementations must never raise for an *expected* target error (a 4xx/5xx,
        a timeout): they return a ``Response`` with ``error`` set so the runner can
        record it as evidence and keep going. Raising is reserved for programmer
        errors (a misconfigured adapter), which should fail loudly.
        """
        ...

    def endpoint(self) -> str | None:
        """The network endpoint this target will contact, if any.

        Returned to ``config.assert_authorized`` for allowlist enforcement.
        In-process targets (callable, fake) return ``None``.
        """
        ...
