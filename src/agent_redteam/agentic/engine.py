"""Bounded runner and clean-twin causal attribution for agent episodes."""

from __future__ import annotations

import asyncio
import time

from agent_redteam.agentic.hooks import AllowAllHooks, BoundedRuntimeHooks
from agent_redteam.agentic.oracle import InvariantOracle
from agent_redteam.agentic.protocols import AgentRuntimeHooks, EpisodeTarget
from agent_redteam.agentic.types import (
    AttributionStatus,
    EpisodeRunResult,
    ExecutionControls,
    FailureAttribution,
    ScenarioPlan,
)
from agent_redteam.budget import BudgetError, BudgetLedger


class EpisodeEngine:
    def __init__(self, oracle: InvariantOracle | None = None) -> None:
        self.oracle = oracle or InvariantOracle()

    async def run_plan(
        self,
        target: EpisodeTarget,
        plan: ScenarioPlan,
        budget: BudgetLedger,
        *,
        hooks: AgentRuntimeHooks | None = None,
        seed: int = 0,
        allow_live_side_effects: bool = False,
    ) -> EpisodeRunResult:
        controls = ExecutionControls(
            seed=seed, allow_live_side_effects=allow_live_side_effects
        )
        outcome = await self._execute(
            target, plan, budget, controls, hooks or AllowAllHooks(), "agent_episode"
        )
        verdict, violations = await self.oracle.evaluate(plan, outcome)
        counterfactual = None
        attribution = FailureAttribution(AttributionStatus.NOT_ATTRIBUTED)

        twin = plan.clean_twin()
        if violations and twin is not None:
            first = violations[0]
            try:
                counterfactual = await self._execute(
                    target,
                    twin,
                    budget,
                    controls,
                    hooks or AllowAllHooks(),
                    "agent_counterfactual",
                )
            except BudgetError:
                attribution = FailureAttribution(
                    AttributionStatus.SUSPECTED,
                    source_event_ids=first.source_event_ids,
                    provenance_path=first.provenance_path,
                    explanation="Clean-twin attribution was skipped: budget exhausted.",
                )
            else:
                twin_verdict, _ = await self.oracle.evaluate(twin, counterfactual)
                changed = not twin_verdict.success
                attribution = FailureAttribution(
                    status=(
                        AttributionStatus.CAUSAL
                        if changed
                        else AttributionStatus.SUSPECTED
                    ),
                    source_event_ids=first.source_event_ids,
                    provenance_path=first.provenance_path,
                    counterfactual_changed=changed,
                    explanation=(
                        "Replacing only the untrusted fixture removed the invariant "
                        "violation."
                        if changed
                        else "The clean-twin replay also violated the invariant."
                    ),
                )

        return EpisodeRunResult(
            plan=plan,
            outcome=outcome,
            verdict=verdict,
            violations=violations,
            attribution=attribution,
            counterfactual=counterfactual,
        )

    async def _execute(
        self,
        target: EpisodeTarget,
        plan: ScenarioPlan,
        budget: BudgetLedger,
        controls: ExecutionControls,
        hooks: AgentRuntimeHooks,
        budget_kind: str,
    ):
        reservation = budget.reserve(kind=budget_kind)
        session = None
        try:
            bounded_hooks = BoundedRuntimeHooks(
                hooks,
                max_tool_calls=plan.limits.max_tool_calls,
                deadline=time.perf_counter() + plan.limits.max_seconds,
            )
            async with asyncio.timeout(plan.limits.max_seconds):
                session = await target.begin_episode(plan, controls, bounded_hooks)
                outcome = await session.execute(plan.user_input)
            _validate_trace(plan, outcome)
            budget.commit(reservation, response=outcome.response)
            return outcome
        except BaseException:
            budget.release(reservation)
            raise
        finally:
            if session is not None:
                await session.close()


def _validate_trace(plan: ScenarioPlan, outcome) -> None:  # noqa: ANN001
    trace = outcome.trace
    if trace.scenario_id != plan.id:
        raise ValueError(
            f"trace scenario {trace.scenario_id!r} does not match plan {plan.id!r}"
        )
    expected_sequences = list(range(len(trace.events)))
    if [event.sequence for event in trace.events] != expected_sequences:
        raise ValueError("episode trace sequence numbers must be contiguous")
    ids = [event.id for event in trace.events]
    if len(ids) != len(set(ids)):
        raise ValueError("episode trace event ids must be unique")
    logical_steps = sum(
        event.kind.value
        in {"retrieval_query", "model_output", "tool_request", "memory_write"}
        for event in trace.events
    )
    if logical_steps > plan.limits.max_steps:
        raise ValueError(
            f"episode emitted {logical_steps} logical steps; "
            f"limit is {plan.limits.max_steps}"
        )
