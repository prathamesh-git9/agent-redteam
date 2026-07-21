"""Regression-baseline tests: saving a run and detecting movement against it."""

from __future__ import annotations

from pathlib import Path

from agent_redteam.report import Report
from agent_redteam.scoring.baseline import compare_baseline, save_baseline
from agent_redteam.types import (
    AttackCategory,
    AttackResult,
    OracleSpec,
    OracleVerdict,
    Probe,
    Response,
    RiskScore,
    Severity,
    conversation,
    user,
)


def _result(attack_id: str, success: bool, value: float) -> AttackResult:
    probe = Probe(
        attack_id=attack_id,
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        conversation=conversation(user("x")),
        oracle=OracleSpec(),
    )
    verdict = OracleVerdict(success=success, confidence=1.0 if success else 0.0)
    score = RiskScore(value=value, vector="v", base_severity=8.0,
                      success_confidence=verdict.confidence, exploitability=1.0)
    return AttackResult(
        probe=probe, response=Response(text=""), verdict=verdict, score=score
    )


def _report(results) -> Report:
    r = Report(target="t", suite="default", fail_threshold=7.0)
    r.results = results
    return r


def test_no_regression_when_unchanged(tmp_path: Path):
    baseline_file = tmp_path / "b.json"
    report = _report([_result("a", False, 0.0), _result("b", True, 8.0)])
    save_baseline(report, baseline_file)
    assert compare_baseline(report, baseline_file) == []


def test_newly_succeeding_attack_is_a_regression(tmp_path: Path):
    baseline_file = tmp_path / "b.json"
    save_baseline(_report([_result("a", False, 0.0)]), baseline_file)
    # Same attack now succeeds -> regression.
    regressions = compare_baseline(_report([_result("a", True, 8.0)]), baseline_file)
    assert [r.attack_id for r in regressions] == ["a"]


def test_score_climb_is_a_regression(tmp_path: Path):
    baseline_file = tmp_path / "b.json"
    save_baseline(_report([_result("a", True, 4.0)]), baseline_file)
    regressions = compare_baseline(_report([_result("a", True, 6.0)]), baseline_file)
    assert len(regressions) == 1


def test_fix_is_not_a_regression(tmp_path: Path):
    baseline_file = tmp_path / "b.json"
    save_baseline(_report([_result("a", True, 8.0)]), baseline_file)
    # Attack now blocked -> improvement, never flagged.
    assert compare_baseline(_report([_result("a", False, 0.0)]), baseline_file) == []


def test_new_attack_absent_from_baseline_treated_as_blocked(tmp_path: Path):
    baseline_file = tmp_path / "b.json"
    save_baseline(_report([_result("a", False, 0.0)]), baseline_file)
    # 'b' is new and immediately succeeds -> regression (not silently ignored).
    regressions = compare_baseline(
        _report([_result("a", False, 0.0), _result("b", True, 8.0)]), baseline_file
    )
    assert [r.attack_id for r in regressions] == ["b"]
