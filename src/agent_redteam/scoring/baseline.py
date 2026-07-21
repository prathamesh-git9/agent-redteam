"""Regression baselines.

An absolute fail threshold answers "is this target dangerous right now?" A
baseline answers a different, equally important question: "did we just make it
worse?" A change that flips a previously-blocked attack to succeeding is a
regression even if its score sits under the threshold, so CI wants to gate on
*movement*, not just level. This module records a run's per-attack outcome and
compares a later run against it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agent_redteam.report import Report


@dataclass(frozen=True)
class Regression:
    attack_id: str
    was_success: bool
    now_success: bool
    baseline_score: float
    current_score: float

    @property
    def is_regression(self) -> bool:
        # A regression is an attack that newly succeeds, or whose score climbed
        # by more than a small tolerance. Improvements (fixes) are never
        # regressions, so the comparison is deliberately one-directional.
        newly_succeeds = self.now_success and not self.was_success
        score_climbed = self.current_score > self.baseline_score + 0.5
        return newly_succeeds or score_climbed


def save_baseline(report: Report, path: str | Path) -> None:
    """Persist the per-attack outcome of a run as the reference to beat."""
    data = {
        "target": report.target,
        "suite": report.suite,
        "attacks": {
            r.probe.attack_id: {"success": r.succeeded, "score": r.score.value}
            for r in report.results
        },
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def compare_baseline(report: Report, path: str | Path) -> list[Regression]:
    """Return the regressions in ``report`` relative to a saved baseline.

    Attacks absent from the baseline (newly added to the corpus) are treated as
    baseline-blocked with score 0, so a brand-new attack that immediately
    succeeds correctly shows up as a regression rather than being silently
    ignored.
    """
    baseline = json.loads(Path(path).read_text(encoding="utf-8"))
    prior: dict[str, dict] = baseline.get("attacks", {})
    out: list[Regression] = []
    for r in report.results:
        b = prior.get(r.probe.attack_id, {"success": False, "score": 0.0})
        out.append(
            Regression(
                attack_id=r.probe.attack_id,
                was_success=bool(b["success"]),
                now_success=r.succeeded,
                baseline_score=float(b["score"]),
                current_score=r.score.value,
            )
        )
    return [r for r in out if r.is_regression]
