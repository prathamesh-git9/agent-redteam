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

from agent_redteam.scoring.model import band
from agent_redteam.types import AttackResult


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
    def max_score(self) -> float:
        return max((r.score.value for r in self.results), default=0.0)

    @property
    def failed(self) -> bool:
        """A run fails if any single attack meets the fail threshold.

        Baseline regression is a *separate* failure condition applied by the
        caller (see ``scoring.baseline``); the report only knows about the
        absolute threshold so it stays a pure function of this run's results.
        """
        return any(r.score.value >= self.fail_threshold for r in self.results)

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
                "max_score": self.max_score,
            },
            "notes": self.notes,
            "results": [
                {
                    "attack_id": r.probe.attack_id,
                    "category": r.probe.category.value,
                    "label": r.probe.label,
                    "references": list(r.probe.references),
                    "success": r.succeeded,
                    "confidence": r.verdict.confidence,
                    "score": r.score.value,
                    "band": band(r.score.value),
                    "vector": r.score.vector,
                    "evidence": [
                        {"kind": e.kind, "detail": e.detail, "span": e.span}
                        for e in r.verdict.evidence
                    ],
                    "error": r.response.error,
                }
                for r in self.results
            ],
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
            f"**Max score:** {self.max_score}",
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
            verdict = "SUCCESS" if r.succeeded else "blocked"
            ev = "; ".join(e.detail for e in r.verdict.evidence[:2]) or "—"
            lines.append(
                f"| {r.score.value} | {band(r.score.value)} | {r.probe.category.value} "
                f"| `{r.probe.attack_id}` | {verdict} | {ev} |"
            )
        return "\n".join(lines) + "\n"

    def to_junit(self) -> str:
        """One <testcase> per attack; a *successful attack* is a test failure."""
        suite = ET.Element(
            "testsuite",
            name=f"agent-redteam/{self.suite}",
            tests=str(len(self.results)),
            failures=str(len(self.successes)),
        )
        for r in self.results:
            case = ET.SubElement(
                suite, "testcase",
                classname=r.probe.category.value, name=r.probe.attack_id,
            )
            if r.succeeded:
                failure = ET.SubElement(
                    case, "failure",
                    message=f"attack succeeded (score {r.score.value}, {r.score.vector})",
                )
                failure.text = "\n".join(e.detail for e in r.verdict.evidence)
        return ET.tostring(suite, encoding="unicode")
