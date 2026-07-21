"""Shared oracle contract and evidence construction helpers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_redteam.types import Evidence, OracleVerdict, Probe, Response


@runtime_checkable
class Oracle(Protocol):
    """A pure judge over an already-recorded target response.

    Oracles deliberately do not call targets or mutate traces. That keeps attack
    generation, target execution, and success judgement replayable in isolation.
    """

    async def evaluate(self, probe: Probe, response: Response) -> OracleVerdict: ...


def evidence(kind: str, detail: str, span: str | None = None) -> Evidence:
    return Evidence(kind=kind, detail=detail, span=span)
