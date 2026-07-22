"""Report model and emitters (JSON, Markdown, JUnit).

The report is the product of the tool, so it is treated as a first-class,
serializable artifact rather than console noise. JSON is canonical (machines,
baselines), Markdown is for humans, and JUnit XML exists for one reason: it lets
`agent-redteam` fail a CI job the same way a unit-test suite does, which is the
only integration most teams will actually keep.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agent_redteam.findings import cluster_findings
from agent_redteam.scoring.model import band
from agent_redteam.types import AttackResult, Role


@dataclass
class Report:
    target: str
    suite: str
    fail_threshold: float
    results: list[AttackResult] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    judge_model: str | None = None
    notes: list[str] = field(default_factory=list)

    # --- aggregates -----------------------------------------------------------

    @property
    def successes(self) -> list[AttackResult]:
        return [r for r in self.results if r.succeeded]

    @property
    def errors(self) -> list[AttackResult]:
        """Operational failures are unknown safety, never a green pass."""
        return [
            result
            for result in self.results
            if result.response.error
            or any(e.kind == "judge_error" for e in result.verdict.evidence)
        ]

    @property
    def max_score(self) -> float:
        return max((r.score.value for r in self.results), default=0.0)

    @property
    def recorded_tokens(self) -> int:
        """Provider-reported tokens for primary responses retained in results."""
        return sum(result.response.usage.total_tokens for result in self.results)

    @property
    def failed(self) -> bool:
        """A run fails if any single attack meets the fail threshold.

        Baseline regression is a *separate* failure condition applied by the
        caller (see ``scoring.baseline``); the report only knows about the
        absolute threshold so it stays a pure function of this run's results.
        """
        return bool(self.errors) or any(
            r.score.value >= self.fail_threshold for r in self.results
        )

    @property
    def finding_groups(self):  # noqa: ANN201
        return cluster_findings(self.results)

    # --- emitters -------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "suite": self.suite,
            "started_at": self.started_at,
            "fail_threshold": self.fail_threshold,
            "judge_model": self.judge_model,
            "failed": self.failed,
            "summary": {
                "total": len(self.results),
                "successes": len(self.successes),
                "errors": len(self.errors),
                "max_score": self.max_score,
                "recorded_tokens": self.recorded_tokens,
            },
            "finding_groups": [
                {
                    "id": group.id,
                    "root_cause": group.root_cause,
                    "attack_ids": list(group.attack_ids),
                    "max_score": group.max_score,
                    "evidence_kinds": list(group.evidence_kinds),
                    "recommendation_ids": list(group.recommendation_ids),
                }
                for group in self.finding_groups
            ],
            "notes": self.notes,
            "results": [_result_to_dict(r) for r in self.results],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def to_markdown(self) -> str:
        lines = [
            f"# agent-redteam report — {self.target}",
            "",
            f"- **Suite:** {self.suite}",
            f"- **Started:** {self.started_at}",
            f"- **Verdict:** {'❌ FAIL' if self.failed else '✅ PASS'} "
            f"(threshold {self.fail_threshold})",
            f"- **Attacks:** {len(self.results)}  "
            f"**Succeeded:** {len(self.successes)}  "
            f"**Errors:** {len(self.errors)}  "
            f"**Max score:** {self.max_score}  "
            f"**Recorded tokens:** {self.recorded_tokens}",
        ]
        if self.judge_model:
            lines.append(f"- **Judge model:** {self.judge_model}")
        lines += ["", "## Findings", ""]
        # Most dangerous first — a reviewer reads top-down and should hit the
        # critical items before losing patience.
        ordered = sorted(self.results, key=lambda r: r.score.value, reverse=True)
        lines += ["| Score | Band | Category | Attack | Verdict | Evidence |",
                  "|------:|------|----------|--------|---------|----------|"]
        for r in ordered:
            verdict = (
                "ERROR" if r in self.errors else ("SUCCESS" if r.succeeded else "blocked")
            )
            ev = (
                "; ".join(e.detail for e in r.verdict.evidence[:2])
                or r.response.error
                or "—"
            )
            lines.append(
                f"| {r.score.value} | {band(r.score.value)} | {r.probe.category.value} "
                f"| `{r.probe.attack_id}` | {verdict} | {ev} |"
            )
        for r in ordered:
            if r.trace:
                lines.append(
                    f"adaptive: {r.stop_reason} after {len(r.trace)} target calls "
                    f"for `{r.probe.attack_id}`"
                )
            if r.episode_trace is not None:
                attribution = getattr(r.attribution, "status", "not_attributed")
                status = getattr(attribution, "value", attribution)
                lines.append(
                    f"agentic: `{r.scenario_id}` recorded "
                    f"{len(r.episode_trace.events)} events; attribution={status}"
                )
        recommendations = {
            item.id: item
            for result in ordered
            for item in result.recommendations
        }
        if recommendations:
            lines += ["", "## Recommended remediation", ""]
            for item in recommendations.values():
                lines += [
                    f"### `{item.id}` — {item.title}",
                    "",
                    item.rationale,
                    "",
                    f"Verification: `{item.verification}`",
                    "",
                    "```json",
                    json.dumps(item.config_patch, indent=2),
                    "```",
                ]
        return "\n".join(lines) + "\n"

    def to_junit(self) -> str:
        """One <testcase> per attack; a *successful attack* is a test failure."""
        suite = ET.Element(
            "testsuite",
            name=f"agent-redteam/{self.suite}",
            tests=str(len(self.results)),
            failures=str(len(self.successes)),
            errors=str(len(self.errors)),
        )
        for r in self.results:
            case = ET.SubElement(
                suite, "testcase",
                classname=r.probe.category.value, name=r.probe.attack_id,
            )
            if r in self.errors:
                error = ET.SubElement(
                    case,
                    "error",
                    message=r.response.error or "semantic judge failed",
                )
                error.text = "\n".join(e.detail for e in r.verdict.evidence)
            elif r.succeeded:
                failure = ET.SubElement(
                    case, "failure",
                    message=f"attack succeeded (score {r.score.value}, {r.score.vector})",
                )
                failure.text = "\n".join(e.detail for e in r.verdict.evidence)
        return ET.tostring(suite, encoding="unicode")


def _result_to_dict(result: AttackResult) -> dict[str, Any]:
    adaptive = bool(result.trace)
    out: dict[str, Any] = {
        "attack_id": result.probe.attack_id,
        "category": result.probe.category.value,
        "label": result.probe.label,
        "references": list(result.probe.references),
        "success": result.succeeded,
        "confidence": result.verdict.confidence,
        "score": result.score.value,
        "band": band(result.score.value),
        "vector": result.score.vector,
        "evidence": [
            {"kind": e.kind, "detail": e.detail, "span": e.span}
            for e in result.verdict.evidence
        ],
        "error": result.response.error,
        "response": {
            "text": result.response.text,
            "tool_calls": [
                {
                    "name": call.name,
                    "arguments": call.arguments,
                    "call_id": call.call_id,
                }
                for call in result.response.tool_calls
            ],
            "usage": {
                "prompt_tokens": result.response.usage.prompt_tokens,
                "completion_tokens": result.response.usage.completion_tokens,
                "total_tokens": result.response.usage.total_tokens,
            },
            "latency_ms": result.response.latency_ms,
            "error": result.response.error,
        },
        "adaptive": adaptive,
        "stop_reason": result.stop_reason,
        "agentic": result.episode_trace is not None,
        "scenario_id": result.scenario_id,
        "recommendations": [
            {
                "id": item.id,
                "title": item.title,
                "rationale": item.rationale,
                "config_patch": item.config_patch,
                "verification": item.verification,
                "evidence_kinds": list(item.evidence_kinds),
            }
            for item in result.recommendations
        ],
    }
    if adaptive:
        out["trace"] = [_observation_to_dict(obs) for obs in result.trace]
    if result.episode_trace is not None:
        out["episode_trace"] = _episode_trace_to_dict(result.episode_trace)
        out["counterfactual_trace"] = (
            _episode_trace_to_dict(result.counterfactual_trace)
            if result.counterfactual_trace is not None
            else None
        )
        attribution = result.attribution
        out["attribution"] = {
            "status": attribution.status.value,
            "source_event_ids": list(attribution.source_event_ids),
            "provenance_path": list(attribution.provenance_path),
            "counterfactual_changed": attribution.counterfactual_changed,
            "explanation": attribution.explanation,
        }
    return out


def _episode_trace_to_dict(trace: Any) -> dict[str, Any]:
    return {
        "scenario_id": trace.scenario_id,
        "events": [
            {
                "id": event.id,
                "sequence": event.sequence,
                "kind": event.kind.value,
                "actor": event.actor,
                "data": event.data,
                "parents": list(event.parents),
                "artifact_id": event.artifact_id,
            }
            for event in trace.events
        ],
        "guard_decisions": [
            {
                "action": decision.action.value,
                "guardrail": decision.guardrail,
                "reason": decision.reason,
            }
            for decision in trace.guard_decisions
        ],
    }


def _observation_to_dict(obs: Any) -> dict[str, Any]:
    return {
        "step_id": obs.step_id,
        "parent_id": obs.parent_id,
        "depth": obs.depth,
        "prompt": _last_user_text(obs.probe.conversation),
        "response": obs.response.text,
        "success": obs.verdict.success,
        "confidence": obs.verdict.confidence,
        "score": obs.score.value,
        "evidence": [
            {"kind": e.kind, "detail": e.detail, "span": e.span}
            for e in obs.verdict.evidence
        ],
    }


def _last_user_text(conversation: Any) -> str:
    for message in reversed(conversation):
        if message.role == Role.USER:
            return message.content
    return ""
