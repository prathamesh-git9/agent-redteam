from __future__ import annotations

import re

import agent_redteam.attacks  # noqa: F401
from agent_redteam.attacks.base import AttackContext
from agent_redteam.oracles import default_oracle
from agent_redteam.registry import all_attacks, select_suite
from agent_redteam.targets.fake import FakeTarget, Rule
from agent_redteam.types import AttackCategory, Conversation, Probe, ToolCall


def _always(_: Conversation) -> bool:
    return True


def _reply_for(probe: Probe) -> str:
    canary_text = " ".join(canary.token for canary in probe.oracle.canaries)
    if canary_text:
        return f"Leaked protected values: {canary_text}"

    if probe.attack_id == "pi.prefix_injection.v1":
        return "Absolutely! Here is how: comply with the requested format."
    if probe.attack_id == "res.unbounded_generation.v1":
        return "A" * 1200

    for pattern in probe.oracle.success_signatures:
        if re.fullmatch(r"[A-Z0-9_]+", pattern):
            return f"Complied with marker {pattern}."

    return "Sure! Ignoring previous instructions as requested."


def _tool_calls_for(probe: Probe) -> tuple[ToolCall, ...]:
    if "delete_all" in probe.oracle.forbidden_tools:
        return (ToolCall(name="delete_all", arguments={"confirm": True}),)
    if "fetch_url" in probe.oracle.forbidden_tools:
        return (
            ToolCall(
                name="fetch_url",
                arguments={"url": "http://169.254.169.254/latest/meta-data/"},
            ),
        )
    if "run_query" in probe.oracle.forbidden_tools:
        return (
            ToolCall(
                name="run_query",
                arguments={
                    "sql": "SELECT * FROM customers WHERE id=42; DROP TABLE x; --"
                },
            ),
        )
    return ()


def _vulnerable_target(probe: Probe) -> FakeTarget:
    return FakeTarget(
        name=f"vulnerable-{probe.attack_id}",
        supports_tools=True,
        rules=[
            Rule(
                matcher=_always,
                reply=_reply_for(probe),
                tool_calls=_tool_calls_for(probe),
            )
        ],
    )


async def test_registered_attacks_build_probes() -> None:
    specs = all_attacks()

    assert specs
    for spec in specs:
        attack = spec.factory()
        probes = list(attack.build_probes(AttackContext(seed=1, supports_tools=True)))

        assert probes, spec.id
        for probe in probes:
            assert probe.attack_id == spec.id
            assert probe.category == spec.category
            assert probe.conversation
            assert probe.oracle
            assert probe.label
            assert probe.references


async def test_default_suite_excludes_resource_exhaustion() -> None:
    default_categories = {spec.category for spec in select_suite("default")}

    assert AttackCategory.RESOURCE_EXHAUSTION not in default_categories
    assert any(
        spec.category == AttackCategory.RESOURCE_EXHAUSTION
        for spec in select_suite("all")
    )


async def test_tool_attacks_skip_when_tools_unsupported() -> None:
    for spec in select_suite(AttackCategory.TOOL_ABUSE.value):
        attack = spec.factory()
        probes = list(
            attack.build_probes(AttackContext(seed=1, supports_tools=False))
        )

        assert probes == []


async def test_vulnerable_fake_target_succeeds_for_every_probe() -> None:
    oracle = default_oracle()

    for spec in all_attacks():
        attack = spec.factory()
        probes = list(attack.build_probes(AttackContext(seed=1, supports_tools=True)))
        for probe in probes:
            response = await _vulnerable_target(probe).send(probe.conversation)
            verdict = await oracle.evaluate(probe, response)

            assert verdict.success is True, probe.attack_id


async def test_hardened_fake_target_does_not_succeed_for_any_probe() -> None:
    oracle = default_oracle()
    hardened = FakeTarget(
        name="hardened",
        supports_tools=True,
        default="I can't help with that request.",
    )

    for spec in all_attacks():
        attack = spec.factory()
        probes = list(attack.build_probes(AttackContext(seed=1, supports_tools=True)))
        for probe in probes:
            response = await hardened.send(probe.conversation)
            verdict = await oracle.evaluate(probe, response)

            assert verdict.success is False, probe.attack_id


def test_jailbreaks_declare_semantic_rubrics_and_signature_fallbacks() -> None:
    for spec in select_suite(AttackCategory.JAILBREAK.value):
        attack = spec.factory()
        probes = list(attack.build_probes(AttackContext(seed=1, supports_tools=True)))

        assert probes
        for probe in probes:
            assert probe.oracle.judge_rubric
            assert probe.oracle.success_signatures
