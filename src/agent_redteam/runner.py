"""The orchestrator: run a suite against a target and produce a Report.

This is where authorization, budget, and concurrency are enforced — the three
things that keep a red-team run safe, bounded, and fast in that order. It is
deliberately provider-agnostic: it speaks only the core protocols (Target,
Attack, and a duck-typed oracle with ``async evaluate``), so nothing here knows
or cares whether the target is OpenAI, a local callable, or a fake.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Protocol

from agent_redteam.attacks.base import AttackContext
from agent_redteam.config import RunConfig, assert_authorized
from agent_redteam.registry import make_attack, select_suite
from agent_redteam.report import Report
from agent_redteam.scoring.model import score
from agent_redteam.targets.base import Target
from agent_redteam.types import AttackResult, OracleVerdict, Probe, Response


class _Oracle(Protocol):
    async def evaluate(self, probe: Probe, response: Response) -> OracleVerdict: ...


class BudgetError(RuntimeError):
    """Raised when a run would exceed its configured call/token/time budget.

    Surfaced as a report note rather than a crash by the runner, because a run
    that hit its budget still produced partial, useful results worth reporting.
    """


@dataclass
class _Budget:
    """A live, shared ledger enforced across all concurrent probes.

    A denial-of-wallet *test* firing many probes concurrently is exactly the
    thing most able to become a real denial-of-wallet event, so the budget is
    checked before every call and decremented after every response.
    """

    max_calls: int
    max_tokens: int
    max_seconds: float
    _started: float
    calls: int = 0
    tokens: int = 0

    def check(self) -> None:
        if self.calls >= self.max_calls:
            raise BudgetError(f"max_calls {self.max_calls} reached")
        if self.tokens >= self.max_tokens:
            raise BudgetError(f"max_tokens {self.max_tokens} reached")
        if time.perf_counter() - self._started >= self.max_seconds:
            raise BudgetError(f"max_seconds {self.max_seconds} reached")

    def record(self, response: Response) -> None:
        self.calls += 1
        self.tokens += response.usage.total_tokens


class Runner:
    def __init__(self, oracle: _Oracle, config: RunConfig) -> None:
        self.oracle = oracle
        self.config = config

    async def run(self, target: Target) -> Report:
        # 1. Authorization is checked exactly once, up front, before a single
        #    probe is built — failing closed is the whole point of the gate.
        assert_authorized(self.config.target, target.endpoint())

        report = Report(
            target=target.info.name,
            suite=self.config.suite,
            fail_threshold=self.config.fail_threshold,
            judge_model=self.config.judge_model,
        )

        # 2. Build every probe offline (no I/O yet) so a bad attack fails before
        #    we spend a single token.
        probes = self._build_probes(target)
        if not probes:
            report.notes.append(f"suite {self.config.suite!r} produced no probes")
            return report

        budget = _Budget(
            max_calls=self.config.max_calls,
            max_tokens=self.config.max_tokens,
            max_seconds=self.config.max_seconds,
            _started=time.perf_counter(),
        )
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def run_one(probe: Probe) -> AttackResult | None:
            async with semaphore:
                try:
                    budget.check()
                except BudgetError as exc:
                    report.notes.append(str(exc))
                    return None
                response = await target.send(probe.conversation)
                budget.record(response)
                verdict = await self.oracle.evaluate(probe, response)
                return AttackResult(
                    probe=probe, response=response, verdict=verdict,
                    score=score(probe, verdict),
                )

        results = await asyncio.gather(*(run_one(p) for p in probes))
        report.results = [r for r in results if r is not None]
        return report

    def _build_probes(self, target: Target) -> list[Probe]:
        ctx = AttackContext(supports_tools=target.info.supports_tools)
        probes: list[Probe] = []
        for spec in select_suite(self.config.suite):
            attack = make_attack(spec.id)
            probes.extend(attack.build_probes(ctx))  # type: ignore[attr-defined]
        return probes
