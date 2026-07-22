"""Deterministic, evidence-linked remediation recommendations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_redteam.types import OracleVerdict, Probe


@dataclass(frozen=True)
class RemediationRecommendation:
    id: str
    title: str
    rationale: str
    config_patch: dict[str, Any] = field(default_factory=dict)
    verification: str = ""
    evidence_kinds: tuple[str, ...] = ()


def recommendations_for(
    probe: Probe,
    verdict: OracleVerdict,
    *,
    attribution: Any = None,
) -> tuple[RemediationRecommendation, ...]:
    """Map decisive evidence to buildable controls; never ask another LLM."""
    if not verdict.success:
        return ()
    kinds = {item.kind for item in verdict.evidence}
    recommendations: list[RemediationRecommendation] = []

    if "invariant_violation" in kinds:
        recommendations.append(
            RemediationRecommendation(
                id="agentic.retrieval_trust_boundary",
                title="Scan retrieved artifacts at the trust boundary",
                rationale=(
                    "The causal path begins at untrusted retrieved content; user-input "
                    "filtering alone cannot see this hop."
                ),
                config_patch={
                    "guardrails": {
                        "retrieval_input": ["injection_detector"],
                    }
                },
                verification=(
                    "rerun the clean twin for source events "
                    f"{getattr(attribution, 'source_event_ids', ())}"
                ),
                evidence_kinds=("invariant_violation",),
            )
        )
        recommendations.append(
            RemediationRecommendation(
                id="agentic.pre_execution_tool_policy",
                title="Authorize side-effecting tools immediately before execution",
                rationale=(
                    "Output filtering is too late once a tool has executed. Route the "
                    "call through GuardPipeline.runtime_hooks or EpisodeInstrumentation."
                ),
                config_patch={
                    "guardrails": {
                        "tool_policy": {
                            "allow": ["search", "read_document"],
                            "deny": ["send_email"],
                        }
                    }
                },
                verification="agent-redteam scan --suite tag:agentic --agentic",
                evidence_kinds=("invariant_violation",),
            )
        )
    elif "canary_hit" in kinds:
        recommendations.append(
            RemediationRecommendation(
                id="output.secret_and_canary_scanning",
                title="Block synthetic-secret disclosure at output and tool arguments",
                rationale="A deterministic canary crossed the intended trust boundary.",
                config_patch={
                    "guardrails": {"output": ["canary_scanner", "secret_scanner"]}
                },
                verification=f"rerun attack {probe.attack_id}",
                evidence_kinds=("canary_hit",),
            )
        )
    elif "tool_call" in kinds:
        recommendations.append(
            RemediationRecommendation(
                id="tool.capability_allowlist",
                title="Apply least-privilege tool allow/deny policy",
                rationale="The target emitted a forbidden tool call or destination.",
                config_patch={
                    "guardrails": {
                        "tool_policy": {
                            "deny": list(probe.oracle.forbidden_tools),
                        }
                    }
                },
                verification=f"rerun attack {probe.attack_id}",
                evidence_kinds=("tool_call",),
            )
        )
    elif kinds & {"signature", "judge"}:
        recommendations.append(
            RemediationRecommendation(
                id="input.instruction_boundary",
                title="Add instruction-boundary detection and retest",
                rationale=(
                    "The response materially followed attacker-controlled instructions."
                ),
                config_patch={"guardrails": {"input": ["injection_detector"]}},
                verification=f"rerun attack {probe.attack_id} with --compare",
                evidence_kinds=tuple(sorted(kinds & {"signature", "judge"})),
            )
        )
    return tuple(recommendations)
