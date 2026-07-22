"""The bounded adaptive loop: send, judge, mutate, retry, stop.

This is the heart of the "smart" upgrade. Everything dangerous about an
adaptive attacker — that it can loop and spend — is contained here by two
independent limiters checked *before every model call*: the plan's own
``AdaptiveLimits`` and the run-wide ``BudgetLedger`` shared with the static
runner. The loop can therefore never outspend the smaller of the two, and an
adaptive run is as budget-safe as a static one.
"""

from __future__ import annotations

import time
from typing import Protocol

from agent_redteam.adaptive.types import (
    AdaptivePlan,
    AdaptiveRunResult,
    Attacker,
    AttackObservation,
    MutationRequest,
)
from agent_redteam.budget import BudgetError, BudgetLedger
from agent_redteam.scoring.model import score as score_probe
from agent_redteam.targets.base import Target
from agent_redteam.types import (
    Conversation,
    Message,
    OracleVerdict,
    Probe,
    Response,
    Role,
)


class _Oracle(Protocol):
    async def evaluate(self, probe: Probe, response: Response) -> OracleVerdict: ...


class AdaptiveEngine:
    """Runs one :class:`AdaptivePlan` against a target until success or a cap.

    Provider-agnostic by construction: it speaks only the ``Attacker``,
    ``Target``, and oracle protocols, so the same engine drives an LLM attacker
    against a real endpoint or a scripted ``FakeAttacker`` against a
    ``FakeTarget`` in CI.
    """

    def __init__(self, attacker: Attacker, oracle: _Oracle) -> None:
        self.attacker = attacker
        self.oracle = oracle

    async def run_plan(
        self, target: Target, plan: AdaptivePlan, budget: BudgetLedger
    ) -> AdaptiveRunResult:
        limits = plan.limits
        deadline = time.perf_counter() + limits.max_seconds
        observations: list[AttackObservation] = []
        target_calls = 0
        attacker_calls = 0

        # Step 0: the seed probe. Its conversation is the loop's starting point.
        seed = plan.seed_probe
        obs0 = await self._observe(
            seed, target, budget, step_id="a0", parent=None, depth=0
        )
        observations.append(obs0)
        if _is_win(obs0.verdict, limits.success_threshold):
            return _result(plan, observations, "success")
        target_calls += 1

        conversation = seed.conversation
        last = obs0

        while True:
            # Stop conditions, checked before spending anything.
            if target_calls >= limits.max_target_calls:
                return _result(plan, observations, "target_budget")
            if attacker_calls >= limits.max_attacker_calls:
                return _result(plan, observations, "attacker_budget")
            if time.perf_counter() >= deadline:
                return _result(plan, observations, "time_budget")
            if budget.would_exceed(calls=1):
                return _result(plan, observations, "target_budget")

            # Ask the attacker for the next payload, reacting to the real answer.
            request = MutationRequest(
                plan=plan,
                conversation=conversation,
                last_response=last.response,
                last_verdict=last.verdict,
                observations=tuple(observations),
                remaining_target_calls=limits.max_target_calls - target_calls,
                remaining_attacker_calls=limits.max_attacker_calls - attacker_calls,
            )
            batch = await self.attacker.mutate(request)
            attacker_calls += 1
            candidate = batch.best
            if candidate is None:
                return _result(plan, observations, "no_candidates")

            # Turn the candidate into the next probe per the strategy.
            next_conversation = _next_conversation(
                plan.strategy, conversation, last.response, candidate.content
            )
            probe = _reseed(seed, next_conversation)
            depth = last.depth + 1
            try:
                obs = await self._observe(
                    probe, target, budget,
                    step_id=f"a{depth}", parent=last.step_id, depth=depth,
                )
            except BudgetError:
                return _result(plan, observations, "target_budget")
            observations.append(obs)
            target_calls += 1
            last = obs
            conversation = next_conversation
            if _is_win(obs.verdict, limits.success_threshold):
                return _result(plan, observations, "success")

    async def _observe(
        self,
        probe: Probe,
        target: Target,
        budget: BudgetLedger,
        *,
        step_id: str,
        parent: str | None,
        depth: int,
    ) -> AttackObservation:
        budget.check(calls=1)
        response = await target.send(probe.conversation)
        budget.record_response(response)
        verdict = await self.oracle.evaluate(probe, response)
        return AttackObservation(
            step_id=step_id,
            parent_id=parent,
            probe=probe,
            response=response,
            verdict=verdict,
            score=score_probe(probe, verdict),
            depth=depth,
        )


def _is_win(verdict: OracleVerdict, threshold: float) -> bool:
    return verdict.success and verdict.confidence >= threshold


def _reseed(seed: Probe, conversation: Conversation) -> Probe:
    """A new probe that reuses the seed's identity/oracle but a fresh payload.

    Keeping the same ``attack_id``/``oracle``/``references`` is deliberate: the
    adaptive result must slot into the same report and baseline machinery as the
    static seed, so a reviewer sees "the exfil attack succeeded", not a new,
    unrecognisable id per refinement step.
    """
    return Probe(
        attack_id=seed.attack_id,
        category=seed.category,
        severity=seed.severity,
        conversation=conversation,
        oracle=seed.oracle,
        label=seed.label,
        references=seed.references,
    )


def _next_conversation(
    strategy: str,
    conversation: Conversation,
    last_response: Response,
    content: str,
) -> Conversation:
    """Build the next turn from a mutation candidate, per strategy.

    ``pair`` is single-turn: replace the last user message so each attempt is a
    fresh standalone prompt sharing the seed's system framing. ``crescendo`` is
    multi-turn: record the target's real answer as an assistant turn, then add
    the new escalating user turn, so the model is nudged step by step.
    """
    if strategy == "crescendo":
        return (
            *conversation,
            Message(Role.ASSISTANT, last_response.text),
            Message(Role.USER, content),
        )
    # default: pair — replace the trailing user turn.
    head = _drop_last_user(conversation)
    return (*head, Message(Role.USER, content))


def _drop_last_user(conversation: Conversation) -> tuple[Message, ...]:
    messages = list(conversation)
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].role == Role.USER:
            del messages[i]
            break
    return tuple(messages)


def _result(
    plan: AdaptivePlan, observations: list[AttackObservation], stop_reason: str
) -> AdaptiveRunResult:
    best = _best_observation(observations)
    return AdaptiveRunResult(
        plan=plan,
        observations=tuple(observations),
        best=best,
        stop_reason=stop_reason,
    )


def _best_observation(observations: list[AttackObservation]) -> AttackObservation:
    """The observation that best represents the run's outcome.

    A successful step always beats an unsuccessful one; among ties, the higher
    score wins. This is what gets promoted into the ``AttackResult``, so the
    report shows the strongest thing the loop actually achieved.
    """
    return max(observations, key=lambda o: (o.verdict.success, o.score.value))
