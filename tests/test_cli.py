from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml
from typer.testing import CliRunner

from agent_redteam.cli import app

runner = CliRunner()


def _write_config(
    tmp_path: Path,
    *,
    name: str = "fake-agent",
    kind: str = "fake",
    authorized: bool = True,
    options: dict[str, object] | None = None,
) -> Path:
    config = {
        "target": {
            "name": name,
            "kind": kind,
            "authorized": authorized,
            "options": options or {},
        },
        "run": {
            "suite": "smoke",
            "concurrency": 1,
        },
    }
    path = tmp_path / f"{name}.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def test_scan_fake_smoke_prints_table_and_exits_zero(tmp_path: Path) -> None:
    config = _write_config(tmp_path)

    result = runner.invoke(app, ["scan", "--config", str(config), "--suite", "smoke"])

    assert result.exit_code == 0
    assert "agent-redteam" in result.stdout
    assert "Score" in result.stdout
    assert "fake-agent" in result.stdout


def test_scan_writes_json_markdown_and_junit_reports(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    junit_path = tmp_path / "report.xml"

    result = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(config),
            "--suite",
            "smoke",
            "--json",
            str(json_path),
            "--report",
            str(markdown_path),
            "--junit",
            str(junit_path),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(json_path.read_text(encoding="utf-8"))["target"] == "fake-agent"
    assert "fake-agent" in markdown_path.read_text(encoding="utf-8")
    assert ET.fromstring(junit_path.read_text(encoding="utf-8")).tag == "testsuite"


def test_scan_guardrails_compare_prints_comparison_table(tmp_path: Path) -> None:
    config = _write_config(tmp_path)

    result = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(config),
            "--suite",
            "smoke",
            "--guardrails",
            "default",
            "--compare",
        ],
    )

    assert result.exit_code == 0
    assert "undefended vs defended" in result.stdout
    assert "undefended" in result.stdout
    assert "defended" in result.stdout


def test_agentic_cli_reproduces_then_blocks_poisoned_rag(tmp_path: Path) -> None:
    config = _write_config(tmp_path, name="agent-poc", kind="fake_agent")
    base = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(config),
            "--suite",
            "tag:agentic",
            "--agentic",
        ],
    )
    defended = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(config),
            "--suite",
            "tag:agentic",
            "--agentic",
            "--guardrails",
            "default",
        ],
    )

    assert base.exit_code == 1
    assert "SUCCESS" in base.stdout
    assert defended.exit_code == 0
    assert "PASS" in defended.stdout
    assert "blocked" in defended.stdout


def test_scan_refuses_unauthorized_remote_target_before_network(tmp_path: Path) -> None:
    config = _write_config(
        tmp_path,
        name="remote-agent",
        kind="openai_chat",
        authorized=False,
        options={
            "base_url": "https://llm.example.test/v1",
            "model": "offline-test",
        },
    )

    result = runner.invoke(app, ["scan", "--config", str(config), "--suite", "smoke"])

    assert result.exit_code == 2
    assert "refused" in result.stdout


def test_list_commands_and_version_print_expected_output() -> None:
    attacks = runner.invoke(app, ["list-attacks"])
    attacks_json = runner.invoke(app, ["list-attacks", "--json"])
    guardrails = runner.invoke(app, ["list-guardrails"])
    version = runner.invoke(app, ["version"])

    assert attacks.exit_code == 0
    assert "attacks" in attacks.stdout
    assert "prompt_injection" in attacks.stdout
    assert attacks_json.exit_code == 0
    assert json.loads(attacks_json.stdout)
    assert guardrails.exit_code == 0
    assert "guardrails" in guardrails.stdout
    assert "suites" in guardrails.stdout
    assert version.exit_code == 0
    assert version.stdout.startswith("agent-redteam ")


def test_baseline_save_then_compare_same_run_has_no_regressions(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    baseline_path = tmp_path / "baseline.json"

    save = runner.invoke(
        app,
        [
            "baseline",
            "--config",
            str(config),
            "--save",
            "--path",
            str(baseline_path),
        ],
    )
    compare = runner.invoke(
        app,
        ["baseline", "--config", str(config), "--path", str(baseline_path)],
    )

    assert save.exit_code == 0
    assert baseline_path.exists()
    assert compare.exit_code == 0
    assert "no regressions" in compare.stdout


def test_report_command_renders_saved_json(tmp_path: Path) -> None:
    # A scan --json artifact should re-render via `report` without a target.
    config = _write_config(tmp_path)
    out = tmp_path / "report.json"
    scan = runner.invoke(app, ["scan", "--config", str(config), "--json", str(out)])
    assert scan.exit_code == 0
    result = runner.invoke(app, ["report", str(out)])
    assert result.exit_code == 0
    assert "fake-agent" in result.stdout
    assert "attacks:" in result.stdout
