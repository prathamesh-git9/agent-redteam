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
from typing import Protocol

from agent_redteam.attacks.base import AttackContext
from agent_redteam.budget import BudgetError, BudgetLedger
from agent_redteam.config import RunConfig, assert_authorized
from agent_redteam.registry import make_attack, select_suite
from agent_redteam.report import Report
from agent_redteam.scoring.model import score
from agent_redteam.targets.base import Target
from agent_redteam.types import AttackResult, OracleVerdict, Probe, Response

# Re-exported for backward compatibility: callers historically imported these
# from the runner. The definitions now live in agent_redteam.budget so the
# adaptive engine can meter against the same ledger.
__all__ = ["Runner", "BudgetError", "BudgetLedger"]


class _Oracle(Protocol):
    async def evaluate(self, probe: Probe, response: Response) -> OracleVerdict: ...


class Runner:
    def __init__(
        self, oracle: _Oracle, config: RunConfig, attacker: object | None = None
    ) -> None:
        self.oracle = oracle
        self.config = config
        # The attacker is only consulted in adaptive mode; a static run leaves it
        # None and behaves exactly as before.
        self.attacker = attacker

    async def run(self, target: Target) -> Report:
        # 1. Authorization is checked exactly once, up front, before a single
        #    probe is built — failing closed is the whole point of the gate. It
        #    guards adaptive and static work identically.
        assert_authorized(self.config.target, target.endpoint())

        report = Report(
            target=target.info.name,
            suite=self.config.suite,
            fail_threshold=self.config.fail_threshold,
            judge_model=self.config.judge_model,
        )

        # 2. Collect work offline: static probes fail fast before any I/O, and
        #    adaptive plans (seed + refinement metadata) are gathered separately.
        ctx = AttackContext(supports_tools=target.info.supports_tools)
        static_probes, adaptive_plans = self._collect(ctx)
        if not static_probes and not adaptive_plans:
            report.notes.append(f"suite {self.config.suite!r} produced no probes")
            return report

        # One ledger meters every model call — static probes, adaptive target
        # calls, all of it — so the run as a whole can never outspend the budget.
        budget = BudgetLedger(
            max_calls=self.config.max_calls,
            max_tokens=self.config.max_tokens,
            max_seconds=self.config.max_seconds,
            started=time.perf_counter(),
        )
        results: list[AttackResult] = []
        results.extend(await self._run_static(target, static_probes, budget, report))
        results.extend(await self._run_adaptive(target, adaptive_plans, budget, report))
        report.results = results
        return report

    async def _run_static(
        self,
        target: Target,
        probes: list[Probe],
        budget: BudgetLedger,
        report: Report,
    ) -> list[AttackResult]:
        if not probes:
            return []
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def run_one(probe: Probe) -> AttackResult | None:
            async with semaphore:
                try:
                    budget.check()
                except BudgetError as exc:
                    report.notes.append(str(exc))
                    return None
                response = await target.send(probe.conversation)
                budget.record_response(response)
                verdict = await self.oracle.evaluate(probe, response)
                return AttackResult(
                    probe=probe, response=response, verdict=verdict,
                    score=score(probe, verdict),
                )

        done = await asyncio.gather(*(run_one(p) for p in probes))
        return [r for r in done if r is not None]

    async def _run_adaptive(
        self,
        target: Target,
        plans: list[object],
        budget: BudgetLedger,
        report: Report,
    ) -> list[AttackResult]:
        if not plans:
            return []
        # Imported lazily so a static-only install never pays for the adaptive
        # machinery, and to keep the import graph acyclic.
        from agent_redteam.adaptive.engine import AdaptiveEngine

        engine = AdaptiveEngine(self.attacker, self.oracle)  # type: ignore[arg-type]
        results: list[AttackResult] = []
        for plan in plans:
            if budget.would_exceed(calls=1):
                report.notes.append("budget exhausted before adaptive plan")
                break
            try:
                run_result = await engine.run_plan(target, plan, budget)  # type: ignore[arg-type]
            except BudgetError as exc:
                report.notes.append(str(exc))
                break
            best = run_result.best
            results.append(
                AttackResult(
                    probe=best.probe,
                    response=best.response,
                    verdict=best.verdict,
                    score=best.score,
                    trace=run_result.observations,
                    stop_reason=run_result.stop_reason,
                )
            )
        return results

    def _collect(self, ctx: AttackContext) -> tuple[list[Probe], list[object]]:
        """Split the suite into static probes and adaptive plans.

        An attack runs adaptively only when adaptive mode is on, an attacker is
        wired, and the attack actually implements ``build_adaptive_plans``.
        Otherwise it falls back to its static seed probe — so every adaptive
        attack degrades gracefully to a normal one-shot attack.
        """
        static_probes: list[Probe] = []
        adaptive_plans: list[object] = []
        use_adaptive = self.config.adaptive and self.attacker is not None
        for spec in select_suite(self.config.suite):
            attack = make_attack(spec.id)
            if use_adaptive and hasattr(attack, "build_adaptive_plans"):
                adaptive_plans.extend(attack.build_adaptive_plans(ctx))
            else:
                static_probes.extend(attack.build_probes(ctx))  # type: ignore[attr-defined]
        return static_probes, adaptive_plans
