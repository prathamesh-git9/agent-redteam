"""Root-cause grouping for deduplicated, actionable report output."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from agent_redteam.types import AttackResult


@dataclass(frozen=True)
class FindingGroup:
    id: str
    root_cause: str
    attack_ids: tuple[str, ...]
    max_score: float
    evidence_kinds: tuple[str, ...]
    recommendation_ids: tuple[str, ...]


def cluster_findings(results: list[AttackResult]) -> list[FindingGroup]:
    buckets: dict[str, list[AttackResult]] = {}
    for result in results:
        if not result.succeeded:
            continue
        root_cause = _root_cause(result)
        buckets.setdefault(root_cause, []).append(result)

    groups = []
    for root_cause, members in sorted(buckets.items()):
        digest = hashlib.sha256(root_cause.encode()).hexdigest()[:12]
        groups.append(
            FindingGroup(
                id=f"fg-{digest}",
                root_cause=root_cause,
                attack_ids=tuple(sorted({m.probe.attack_id for m in members})),
                max_score=max(member.score.value for member in members),
                evidence_kinds=tuple(
                    sorted(
                        {
                            evidence.kind
                            for member in members
                            for evidence in member.verdict.evidence
                        }
                    )
                ),
                recommendation_ids=tuple(
                    sorted(
                        {
                            recommendation.id
                            for member in members
                            for recommendation in member.recommendations
                        }
                    )
                ),
            )
        )
    return groups


def _root_cause(result: AttackResult) -> str:
    kinds = {e.kind for e in result.verdict.evidence}
    if result.episode_trace is not None and "invariant_violation" in kinds:
        return "untrusted_retrieval_reached_side_effect"
    if "canary_hit" in kinds:
        return "sensitive_data_crossed_output_boundary"
    if "tool_call" in kinds:
        return "missing_tool_capability_policy"
    if "judge" in kinds or "signature" in kinds:
        return "attacker_instruction_followed"
    return f"{result.probe.category.value}_control_failure"
