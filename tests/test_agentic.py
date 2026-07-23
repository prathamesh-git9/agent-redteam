from __future__ import annotations

import asyncio
import copy
from dataclasses import replace

import pytest

import agent_redteam.attacks  # noqa: F401
from agent_redteam.agentic import (
    AttributionStatus,
    CallableEpisodeTarget,
    EpisodeEngine,
    EpisodeInstrumentation,
    EpisodeLimits,
    EpisodeTrace,
    EventKind,
    FakeAgentTarget,
    InvariantKind,
    InvariantOracle,
    SecurityInvariant,
    TraceEvent,
    verify_causal_proof,
)
from agent_redteam.agentic.trace import TraceRecorder
from agent_redteam.agentic.types import AgentOutcome
from agent_redteam.attacks.base import AttackContext
from agent_redteam.budget import BudgetError, BudgetLedger
from agent_redteam.config import AuthorizationError, RunConfig, TargetConfig
from agent_redteam.guardrails import (
    GuardPipeline,
    ToolCallPolicy,
    default_guardrails,
    pipeline_from_mapping,
)
from agent_redteam.oracles import default_oracle
from agent_redteam.registry import make_attack
from agent_redteam.runner import Runner
from agent_redteam.types import Response, ToolCall


def config(name: str, **overrides) -> RunConfig:
    return RunConfig(
        target=TargetConfig(name=name, kind="fake_agent", authorized=True),
        suite="tag:agentic",
        agentic=True,
        concurrency=1,
        max_calls=4,
        seed=11,
        **overrides,
    )


async def test_agentic_runner_finds_and_causally_attributes_poisoned_rag() -> None:
    target = FakeAgentTarget("vulnerable-agent")

    report = await Runner(default_oracle(), config(target.name)).run(target)

    assert len(report.results) == 1
    finding = report.results[0]
    assert finding.succeeded
    assert finding.attribution.status == AttributionStatus.CAUSAL
    assert finding.attribution.counterfactual_changed
    assert finding.attribution.source_event_ids
    assert len(target.side_effects) == 1
    assert target.sessions_started == target.sessions_closed == 2
    assert {item.id for item in finding.recommendations} == {
        "agentic.pre_execution_tool_policy",
        "agentic.retrieval_trust_boundary",
    }


async def test_tool_policy_blocks_before_side_effect_executor() -> None:
    target = FakeAgentTarget("defended-agent")
    guarded = GuardPipeline(
        tool_guards=[ToolCallPolicy(allow=("search", "read_document"))]
    ).wrap(target)

    report = await Runner(default_oracle(), config(target.name)).run(guarded)

    assert len(report.results) == 1
    assert not report.results[0].succeeded
    assert target.side_effects == []
    trace = report.results[0].episode_trace
    assert any(
        event.kind == EventKind.GUARD_DECISION and event.data["action"] == "block"
        for event in trace.events
    )
    assert not any(event.kind == EventKind.SIDE_EFFECT for event in trace.events)


async def test_default_pipeline_scans_normalized_retrieval_before_tool_use() -> None:
    target = FakeAgentTarget("default-defended-agent")

    report = await Runner(default_oracle(), config(target.name)).run(
        default_guardrails().wrap(target)
    )

    assert not report.results[0].succeeded
    assert target.side_effects == []
    decisions = report.results[0].episode_trace.guard_decisions
    assert any(
        decision.guardrail == "injection_detector" and decision.action.value == "block"
        for decision in decisions
    )


async def test_report_serializes_trace_attribution_groups_and_remediation() -> None:
    report = await Runner(default_oracle(), config("report-agent")).run(
        FakeAgentTarget("report-agent")
    )

    data = report.to_dict()
    result = data["results"][0]
    assert result["agentic"] is True
    assert result["episode_trace"]["events"]
    assert result["counterfactual_trace"]["events"]
    assert result["attribution"]["status"] == "causal"
    proof = result["causal_proof"]
    assert verify_causal_proof(proof) == (True, "ok")
    tampered = copy.deepcopy(proof)
    tampered["attack_trace"]["events"][0]["actor"] = "rewritten-after-run"
    valid, reason = verify_causal_proof(tampered)
    assert valid is False
    assert "hash mismatch" in reason
    assert result["recommendations"][0]["config_patch"]
    assert data["finding_groups"][0]["root_cause"] == (
        "untrusted_retrieval_reached_side_effect"
    )
    markdown = report.to_markdown()
    assert "Recommended remediation" in markdown
    assert "pre_execution_tool_policy" in markdown


async def test_report_recommendation_is_directly_executable_as_guard_config() -> None:
    vulnerable_report = await Runner(
        default_oracle(), config("recommendation-source")
    ).run(FakeAgentTarget("recommendation-source"))
    recommendation = next(
        item
        for item in vulnerable_report.results[0].recommendations
        if item.id == "agentic.retrieval_trust_boundary"
    )
    pipeline = pipeline_from_mapping(recommendation.config_patch)
    fixed_target = FakeAgentTarget("recommendation-fixed")

    fixed_report = await Runner(default_oracle(), config(fixed_target.name)).run(
        pipeline.wrap(fixed_target)
    )

    assert not fixed_report.results[0].succeeded
    assert fixed_target.side_effects == []


async def test_agentic_budget_keeps_primary_finding_when_clean_twin_cannot_run() -> None:
    target = FakeAgentTarget("budgeted-agent")
    cfg = config(target.name)
    cfg.max_calls = 1

    report = await Runner(default_oracle(), cfg).run(target)

    assert report.results[0].succeeded
    assert report.results[0].attribution.status == AttributionStatus.SUSPECTED
    assert "budget exhausted" in report.results[0].attribution.explanation
    assert target.sessions_started == target.sessions_closed == 1


async def test_authorization_gate_precedes_agent_session_creation() -> None:
    target = FakeAgentTarget("unauthorized-agent")
    cfg = config(target.name)
    cfg.target.authorized = False

    with pytest.raises(AuthorizationError):
        await Runner(default_oracle(), cfg).run(target)

    assert target.sessions_started == 0


def test_budget_reservations_are_atomic_and_single_use() -> None:
    ledger = BudgetLedger(max_calls=1, max_tokens=100, max_seconds=10)
    reservation = ledger.reserve(kind="target")

    with pytest.raises(BudgetError):
        ledger.reserve(kind="target")

    ledger.commit(reservation, response=Response("ok"))
    assert ledger.calls == 1
    with pytest.raises(ValueError):
        ledger.commit(reservation, response=Response("ok"))


def scenario():
    attack = make_attack("agent.rag_indirect_tool.v1")
    return next(attack.build_scenarios(AttackContext(seed=2, supports_tools=True)))


async def test_invariant_oracle_detects_forbidden_tool_and_cross_tenant_read() -> None:
    events = (
        TraceEvent("e0000", 0, EventKind.EPISODE_START, "harness"),
        TraceEvent(
            "e0001",
            1,
            EventKind.SIDE_EFFECT,
            "delete_all",
            {"tool": "delete_all"},
            ("e0000",),
        ),
        TraceEvent(
            "e0002",
            2,
            EventKind.TOOL_RESULT,
            "lookup",
            {"tool": "lookup", "tenant_id": "tenant-b"},
            ("e0001",),
        ),
    )
    plan = replace(
        scenario(),
        invariants=(
            SecurityInvariant(
                InvariantKind.NO_FORBIDDEN_TOOL,
                "delete_all must never execute",
                {"tools": ["delete_all"]},
            ),
            SecurityInvariant(
                InvariantKind.NO_CROSS_TENANT_READ,
                "reads stay within tenant",
                {"tenant_id": "tenant-a"},
            ),
        ),
    )
    outcome = AgentOutcome(Response("done"), EpisodeTrace(plan.id, events))

    verdict, violations = await InvariantOracle().evaluate(plan, outcome)

    assert verdict.success
    assert {violation.invariant for violation in violations} == {
        InvariantKind.NO_FORBIDDEN_TOOL,
        InvariantKind.NO_CROSS_TENANT_READ,
    }


def test_scenario_without_clean_fixture_has_no_twin_and_trace_rejects_bad_edge() -> None:
    assert replace(scenario(), clean_artifacts=()).clean_twin() is None
    recorder = TraceRecorder()
    with pytest.raises(ValueError, match="parents must already exist"):
        recorder.add(EventKind.MODEL_OUTPUT, "agent", parents=("missing",))


async def test_episode_tool_limit_blocks_before_fake_effect() -> None:
    target = FakeAgentTarget("limited-agent")
    plan = replace(scenario(), limits=EpisodeLimits(max_tool_calls=0))
    budget = BudgetLedger(max_calls=2, max_tokens=10000, max_seconds=5)

    result = await EpisodeEngine().run_plan(target, plan, budget)

    assert not result.verdict.success
    assert target.side_effects == []
    assert any(
        decision.guardrail == "episode_limits"
        for decision in result.outcome.trace.guard_decisions
    )


async def test_episode_timeout_still_runs_cleanup() -> None:
    cleaned = asyncio.Event()

    async def slow(plan, user_input, instrumentation):
        _ = plan, user_input, instrumentation
        await asyncio.sleep(0.05)
        return "too late"

    async def cleanup() -> None:
        cleaned.set()

    target = CallableEpisodeTarget(slow, "slow-agent", cleanup)
    plan = replace(scenario(), limits=EpisodeLimits(max_seconds=0.001))
    budget = BudgetLedger(max_calls=2, max_tokens=10000, max_seconds=5)

    with pytest.raises(TimeoutError):
        await EpisodeEngine().run_plan(target, plan, budget)

    assert cleaned.is_set()


async def test_callable_agent_adapter_instruments_and_blocks_real_executor() -> None:
    effects: list[str] = []
    cleanups = 0

    async def cleanup() -> None:
        nonlocal cleanups
        cleanups += 1

    async def agent(
        plan, user_input: str, instrumentation: EpisodeInstrumentation
    ) -> Response:
        _ = user_input
        artifact = plan.artifacts[0]
        retrieval = await instrumentation.retrieval_result(artifact)
        model = instrumentation.record(
            EventKind.MODEL_OUTPUT,
            "real-agent",
            data={"content": "processed retrieval"},
            parents=(retrieval.event_id,),
        )
        effective = retrieval.artifact
        if retrieval.allowed and effective and "send_email" in effective.content:
            await instrumentation.execute_tool(
                ToolCall("send_email", {"recipient": "attacker@example.invalid"}),
                lambda: effects.append("executed"),
                parents=(model,),
            )
        return Response("done")

    target = CallableEpisodeTarget(agent, "callable-agent", cleanup)
    guarded = GuardPipeline(tool_guards=[ToolCallPolicy(deny=("send_email",))]).wrap(
        target
    )

    report = await Runner(default_oracle(), config(target.name)).run(guarded)

    assert report.results and not report.results[0].succeeded
    assert effects == []
    assert cleanups == 1


async def test_callable_agent_errors_are_reported_and_session_is_cleaned() -> None:
    cleaned = asyncio.Event()

    async def broken(plan, user_input, instrumentation):
        _ = plan, user_input, instrumentation
        raise RuntimeError("agent failed")

    async def cleanup() -> None:
        cleaned.set()

    target = CallableEpisodeTarget(broken, "broken-agent", cleanup)
    report = await Runner(default_oracle(), config(target.name)).run(target)

    assert report.results[0].response.error == "RuntimeError: agent failed"
    assert report.failed
    assert report.errors == [report.results[0]]
    assert cleaned.is_set()
