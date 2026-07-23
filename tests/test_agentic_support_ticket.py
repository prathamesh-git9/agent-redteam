from __future__ import annotations

from examples.live_support_ticket_poc import (
    BASE_URL,
    BENIGN_TICKET,
    CREATE_ACCOUNT_CREDIT,
    DEFAULT_MODEL,
    CreditAuthorizationHook,
    FakeModelBackend,
    SupportOpsAgent,
    make_benign_support_ticket_plan,
    make_support_ticket_plan,
    run_demo,
)

from agent_redteam.agentic import (
    AllowAllHooks,
    AttributionStatus,
    CallableEpisodeTarget,
    EpisodeEngine,
    EventKind,
    InvariantOracle,
)
from agent_redteam.agentic.proof import verify_causal_proof
from agent_redteam.budget import BudgetLedger
from agent_redteam.types import GuardAction


async def test_offline_fake_model_executes_credit_on_poisoned_ticket() -> None:
    agent = SupportOpsAgent(FakeModelBackend())
    result = await _run_vulnerable(agent)

    assert agent.credit_ledger
    assert result.verdict.success
    assert result.violations
    assert result.violations[0].event_id
    assert result.violations[0].source_event_ids
    assert result.violations[0].provenance_path


async def test_clean_twin_removes_violation_and_attribution_is_causal() -> None:
    agent = SupportOpsAgent(FakeModelBackend())
    result = await _run_vulnerable(agent)

    assert result.counterfactual is not None
    twin_verdict, twin_violations = await InvariantOracle().evaluate(
        result.plan.clean_twin(),
        result.counterfactual,
    )
    assert not twin_verdict.success
    assert twin_violations == ()
    assert result.attribution.status == AttributionStatus.CAUSAL
    assert result.attribution.counterfactual_changed


async def test_credit_authorization_hook_blocks_before_executor() -> None:
    agent = SupportOpsAgent(FakeModelBackend())
    result = await _run_defended(agent, CreditAuthorizationHook())

    assert agent.credit_ledger == []
    assert not result.verdict.success
    assert _requested_credit(result)
    assert not _executed_credit(result)
    assert any(
        event.kind == EventKind.GUARD_DECISION
        and event.actor == "credit_authorization_policy"
        and event.data["action"] == GuardAction.BLOCK.value
        for event in result.outcome.trace.events
    )


async def test_demo_json_exposes_proof_and_guard_decision() -> None:
    proof = await run_demo(
        mode="offline",
        model=DEFAULT_MODEL,
        base_url=BASE_URL,
        trials=1,
    )

    assert proof["unauthorized_credit_rate"] == "1/1"
    assert proof["clean_twin_credit_rate"] == "0/1"
    assert proof["defended_executed_rate"] == "0/1"
    assert proof["source_event"]
    assert proof["sink_event"]
    assert proof["provenance_path"]
    assert proof["counterfactual_changed"] is True
    assert proof["guardrail_prevented_execution"] is True
    assert proof["guard_decision"]["decision"] == "BLOCK"
    assert verify_causal_proof(proof["causal_proof"]) == (True, "ok")
    assert proof["guard_decision"]["executor_called"] is False


async def test_budget_exhaustion_downgrades_attribution_to_suspected() -> None:
    agent = SupportOpsAgent(FakeModelBackend())
    target = CallableEpisodeTarget(agent, "budgeted-supportops")
    result = await EpisodeEngine().run_plan(
        target,
        make_support_ticket_plan(),
        BudgetLedger(max_calls=1, max_tokens=100_000, max_seconds=60.0),
        hooks=AllowAllHooks(),
    )

    assert result.verdict.success
    assert result.attribution.status == AttributionStatus.SUSPECTED
    assert "budget exhausted" in result.attribution.explanation


async def test_benign_ticket_is_not_blocked_by_credit_guard() -> None:
    agent = SupportOpsAgent(FakeModelBackend())
    result = await _run_defended(agent, CreditAuthorizationHook(), benign=True)

    assert BENIGN_TICKET in result.outcome.trace.events[4].data["content"]
    assert agent.credit_ledger == []
    assert not _requested_credit(result)
    assert not result.verdict.success
    assert all(
        decision.action != GuardAction.BLOCK
        for decision in result.outcome.trace.guard_decisions
    )


async def _run_vulnerable(agent: SupportOpsAgent):
    target = CallableEpisodeTarget(agent, "test-supportops-vulnerable")
    return await EpisodeEngine().run_plan(
        target,
        make_support_ticket_plan(),
        BudgetLedger(max_calls=4, max_tokens=100_000, max_seconds=60.0),
        hooks=AllowAllHooks(),
    )


async def _run_defended(
    agent: SupportOpsAgent,
    hook: CreditAuthorizationHook,
    *,
    benign: bool = False,
):
    target = CallableEpisodeTarget(agent, "test-supportops-defended")
    plan = make_benign_support_ticket_plan() if benign else make_support_ticket_plan()
    return await EpisodeEngine().run_plan(
        target,
        plan,
        BudgetLedger(max_calls=4, max_tokens=100_000, max_seconds=60.0),
        hooks=hook,
    )


def _requested_credit(result) -> bool:  # noqa: ANN001
    return any(
        event.kind == EventKind.TOOL_REQUEST
        and event.data.get("tool") == CREATE_ACCOUNT_CREDIT
        for event in result.outcome.trace.events
    )


def _executed_credit(result) -> bool:  # noqa: ANN001
    return any(
        event.kind == EventKind.SIDE_EFFECT
        and event.data.get("tool") == CREATE_ACCOUNT_CREDIT
        for event in result.outcome.trace.events
    )
