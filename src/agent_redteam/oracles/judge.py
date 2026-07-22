"""Semantic judge oracle and deterministic test double."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agent_redteam.oracles.base import evidence
from agent_redteam.types import OracleVerdict, Probe, Response, Role


class Judge(Protocol):
    async def score(
        self, rubric: str, prompt: str, answer: str
    ) -> tuple[bool, float, str]: ...


@dataclass(frozen=True)
class JudgeOracle:
    """Semantic fallback for cases where deterministic evidence is insufficient.

    Production judges should be configured with temperature 0, a fixed rubric,
    and a fixed model id captured by the surrounding report so replay drift is
    visible. This oracle only adapts that deterministic scoring contract into
    the shared verdict type.
    """

    judge: Judge

    async def evaluate(self, probe: Probe, response: Response) -> OracleVerdict:
        if probe.oracle.judge_rubric is None:
            return OracleVerdict(False, 0.0)

        prompt = ""
        for message in reversed(probe.conversation):
            if message.role == Role.USER:
                prompt = message.content
                break

        success, confidence, reason = await self.judge.score(
            probe.oracle.judge_rubric,
            prompt,
            response.text,
        )
        return OracleVerdict(
            success,
            confidence,
            (
                evidence(
                    "judge_error" if reason.startswith("judge error:") else "judge",
                    reason,
                ),
            )
            if reason
            else (),
        )


@dataclass(frozen=True)
class FakeJudge:
    """Deterministic substring table so judge-driven tests never need a network."""

    outcomes: dict[str, tuple[bool, float, str]]
    default: tuple[bool, float, str] = (False, 0.0, "no configured match")

    async def score(
        self, rubric: str, prompt: str, answer: str
    ) -> tuple[bool, float, str]:
        haystack = "\n".join((rubric, prompt, answer))
        for substring, outcome in self.outcomes.items():
            if substring in haystack:
                return outcome
        return self.default
