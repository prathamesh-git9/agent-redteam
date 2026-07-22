"""Command-line interface.

The CLI is intentionally thin: it parses arguments, assembles the pieces
(target, oracle, runner), and renders results. All real logic lives in the
library so it is testable without spawning a process, and so the FastAPI and MCP
surfaces can reuse exactly the same code paths.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from agent_redteam.adaptive import AdaptiveLimits, OpenAIAttacker
from agent_redteam.config import AuthorizationError, RunConfig, load_run_config
from agent_redteam.oracles import OpenAIJudge, default_oracle
from agent_redteam.registry import all_attacks, all_guardrails, select_suite
from agent_redteam.report import Report
from agent_redteam.runner import Runner
from agent_redteam.scoring.model import band
from agent_redteam.targets.factory import build_target

app = typer.Typer(
    add_completion=False,
    help="Adversarial testing and runtime guardrails for LLM agents. "
    "Only test systems you are authorized to assess.",
)
console = Console()


def _register_attacks() -> None:
    # Imported for its import side effect: every attack module self-registers.
    import agent_redteam.attacks  # noqa: F401


def _verdict_style(result_success: bool, operational_error: bool = False) -> str:
    if operational_error:
        return "[yellow]ERROR[/yellow]"
    return "[red]SUCCESS[/red]" if result_success else "[green]blocked[/green]"


def _render_report(report: Report, title: str) -> None:
    header = (
        f"[bold]{title}[/bold] — target: {report.target}  "
        f"suite: {report.suite}  "
        f"verdict: {'[red]FAIL[/red]' if report.failed else '[green]PASS[/green]'}"
    )
    console.print(header)
    table = Table(show_lines=False)
    table.add_column("Score", justify="right")
    table.add_column("Band")
    table.add_column("Category")
    table.add_column("Attack")
    table.add_column("Verdict")
    table.add_column("Evidence", overflow="fold")
    for r in sorted(report.results, key=lambda r: r.score.value, reverse=True):
        ev = (
            "; ".join(e.detail for e in r.verdict.evidence[:2])
            or r.response.error
            or "—"
        )
        table.add_row(
            str(r.score.value), band(r.score.value), r.probe.category.value,
            r.probe.attack_id, _verdict_style(r.succeeded, r in report.errors), ev,
        )
    console.print(table)
    console.print(
        f"attacks: {len(report.results)}  "
        f"succeeded: [red]{len(report.successes)}[/red]  "
        f"errors: [yellow]{len(report.errors)}[/yellow]  "
        f"max score: {report.max_score}"
    )
    for note in report.notes:
        console.print(f"[yellow]note:[/yellow] {note}")


def _write_reports(
    report: Report, md: Path | None, js: Path | None, junit: Path | None
) -> None:
    if md:
        md.write_text(report.to_markdown(), encoding="utf-8")
        console.print(f"[dim]wrote markdown -> {md}[/dim]")
    if js:
        js.write_text(report.to_json(), encoding="utf-8")
        console.print(f"[dim]wrote json -> {js}[/dim]")
    if junit:
        junit.write_text(report.to_junit(), encoding="utf-8")
        console.print(f"[dim]wrote junit -> {junit}[/dim]")


@app.command()
def scan(
    config: Path = typer.Option(..., "--config", "-c", help="Path to target/run YAML."),
    suite: str | None = typer.Option(None, help="Override the suite in the config."),
    report: Path | None = typer.Option(None, help="Write a Markdown report here."),
    json_out: Path | None = typer.Option(
        None, "--json", help="Write a JSON report here."
    ),
    junit: Path | None = typer.Option(None, help="Write a JUnit XML report here."),
    fail_threshold: float | None = typer.Option(
        None, help="Override the fail threshold."
    ),
    guardrails: str | None = typer.Option(
        None,
        help="Apply a guardrail preset (e.g. 'default') and score the defended target.",
    ),
    guardrail_config: Path | None = typer.Option(
        None,
        "--guardrail-config",
        help="Apply a YAML/JSON GuardPipeline config (including report recommendations).",
    ),
    compare: bool = typer.Option(
        False,
        "--compare",
        help="With --guardrails, print undefended vs defended side by side.",
    ),
    judge_model: str | None = typer.Option(
        None,
        "--judge-model",
        help="OpenAI-compatible model id for semantic judge scoring.",
    ),
    judge_base_url: str = typer.Option(
        "https://api.openai.com/v1",
        "--judge-base-url",
        help="Base URL for the judge chat-completions endpoint.",
    ),
    judge_key_env: str = typer.Option(
        "OPENAI_API_KEY",
        "--judge-key-env",
        help="Environment variable containing the judge API key.",
    ),
    adaptive: bool = typer.Option(
        False,
        "--adaptive",
        help="Run adaptive-capable attacks with a bounded attacker model loop.",
    ),
    agentic: bool = typer.Option(
        False,
        "--agentic",
        help=(
            "Run resettable RAG/tool-agent scenarios (authorized targets only; "
            "side effects default to dry-run)."
        ),
    ),
    attacker_model: str | None = typer.Option(
        None,
        "--attacker-model",
        help="OpenAI-compatible model id for adaptive mutation generation.",
    ),
    attacker_base_url: str = typer.Option(
        "https://api.openai.com/v1",
        "--attacker-base-url",
        help="Base URL for the attacker chat-completions endpoint.",
    ),
    attacker_key_env: str = typer.Option(
        "OPENAI_API_KEY",
        "--attacker-key-env",
        help="Environment variable containing the attacker API key.",
    ),
) -> None:
    """Run an attack suite against the configured target."""
    cfg: RunConfig = load_run_config(config)
    if suite:
        cfg.suite = suite
    if fail_threshold is not None:
        cfg.fail_threshold = fail_threshold
    if judge_model is not None:
        cfg.judge_model = judge_model
    attacker = None
    if adaptive:
        if attacker_model is None:
            console.print("[red]error:[/red] --adaptive requires --attacker-model")
            raise typer.Exit(code=2)
        cfg.adaptive = True
        attacker = OpenAIAttacker(
            model=attacker_model,
            base_url=attacker_base_url,
            api_key_env=attacker_key_env,
        )
    if agentic:
        cfg.agentic = True
    if guardrails and guardrail_config:
        console.print(
            "[red]error:[/red] use either --guardrails or --guardrail-config, not both"
        )
        raise typer.Exit(code=2)
    if guardrails and guardrails != "default":
        console.print(
            "[red]error:[/red] unknown guardrail preset "
            f"{guardrails!r}; expected 'default'"
        )
        raise typer.Exit(code=2)

    _register_attacks()
    target = build_target(cfg.target)
    judge = None
    if judge_model is not None:
        judge = OpenAIJudge(
            model=judge_model,
            base_url=judge_base_url,
            api_key_env=judge_key_env,
        )
    oracle = default_oracle(judge=judge)
    runner = Runner(oracle, cfg, attacker=attacker)

    console.print(
        f"[dim]authorized: {cfg.target.authorized}  "
        f"allowlist: {cfg.target.allowlist or ['(loopback only)']}[/dim]"
    )
    if adaptive and attacker_model is not None:
        limits = AdaptiveLimits()
        console.print(
            "[yellow]responsible use:[/yellow] adaptive testing is bounded to "
            "authorized synthetic-canary objectives only; "
            f"attacker_model={attacker_model} caps="
            f"target_calls={limits.max_target_calls}, "
            f"attacker_calls={limits.max_attacker_calls}, "
            f"tokens={limits.max_total_tokens}, seconds={limits.max_seconds}"
        )
    if cfg.agentic:
        console.print(
            "[yellow]responsible use:[/yellow] agentic testing remains behind the "
            "authorization gate and uses sandbox/dry-run side effects by default"
        )

    try:
        base_report = asyncio.run(runner.run(target))
    except AuthorizationError as exc:
        console.print(f"[red]refused:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    pipeline = None
    defense_label = None
    if guardrail_config is not None:
        from agent_redteam.guardrails import (
            GuardrailConfigError,
            load_guardrail_config,
        )

        try:
            pipeline = load_guardrail_config(guardrail_config)
        except (GuardrailConfigError, OSError) as exc:
            console.print(f"[red]error:[/red] invalid guardrail config: {exc}")
            raise typer.Exit(code=2) from exc
        defense_label = str(guardrail_config)
    elif guardrails:
        from agent_redteam.guardrails import default_guardrails

        pipeline = default_guardrails()
        defense_label = guardrails

    if pipeline is not None:
        defended = pipeline.wrap(target)
        defended_report = asyncio.run(runner.run(defended))
        if compare:
            _render_compare(base_report, defended_report)
        else:
            _render_report(
                defended_report,
                f"agent-redteam (guardrails={defense_label})",
            )
        _write_reports(defended_report, report, json_out, junit)
        raise typer.Exit(code=1 if defended_report.failed else 0)

    _render_report(base_report, "agent-redteam")
    _write_reports(base_report, report, json_out, junit)
    raise typer.Exit(code=1 if base_report.failed else 0)


def _render_compare(base: Report, defended: Report) -> None:
    table = Table(title="undefended vs defended")
    table.add_column("metric")
    table.add_column("undefended", justify="right")
    table.add_column("defended", justify="right")
    table.add_row("successes", str(len(base.successes)), str(len(defended.successes)))
    table.add_row("max score", str(base.max_score), str(defended.max_score))
    table.add_row("verdict",
                  "FAIL" if base.failed else "PASS",
                  "FAIL" if defended.failed else "PASS")
    console.print(table)


@app.command("list-attacks")
def list_attacks(as_json: bool = typer.Option(False, "--json")) -> None:
    """List every registered attack with its id, category and references."""
    _register_attacks()
    specs = all_attacks()
    if as_json:
        import json

        console.print_json(
            json.dumps([
                {
                    "id": s.id,
                    "category": s.category.value,
                    "tags": sorted(s.tags),
                    "requirements": sorted(s.requirements),
                    "summary": s.summary,
                }
                for s in specs
            ])
        )
        return
    table = Table(title=f"{len(specs)} attacks")
    table.add_column("id")
    table.add_column("category")
    table.add_column("tags")
    table.add_column("summary", overflow="fold")
    for s in specs:
        table.add_row(s.id, s.category.value, ",".join(sorted(s.tags)), s.summary)
    console.print(table)


@app.command("list-guardrails")
def list_guardrails() -> None:
    """List available guardrails and built-in suites."""
    _register_attacks()
    console.print("[bold]guardrails[/bold]")
    for name in all_guardrails():
        console.print(f"  - {name}")
    console.print("\n[bold]suites[/bold]: all, default, smoke, <category>, tag:<t>")
    for cat in {s.category.value for s in all_attacks()}:
        console.print(f"  - {cat} ({len(select_suite(cat))} attacks)")


@app.command()
def baseline(
    config: Path = typer.Option(..., "--config", "-c", help="Path to target/run YAML."),
    path: Path = typer.Option(Path("baseline.json"), help="Baseline file to read/write."),
    save: bool = typer.Option(False, "--save", help="Save this run as the new baseline."),
    suite: str | None = typer.Option(None, help="Override the suite in the config."),
) -> None:
    """Save a run as a baseline, or compare the current run against a saved one.

    Without --save, exits non-zero if any attack regressed (newly succeeds or
    climbed in score) versus the saved baseline — the CI gate for "did we make
    the target worse?".
    """
    from agent_redteam.scoring.baseline import compare_baseline, save_baseline

    cfg = load_run_config(config)
    if suite:
        cfg.suite = suite
    _register_attacks()
    target = build_target(cfg.target)
    runner = Runner(default_oracle(), cfg)
    try:
        report = asyncio.run(runner.run(target))
    except AuthorizationError as exc:
        console.print(f"[red]refused:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if save:
        save_baseline(report, path)
        console.print(
            f"[green]saved baseline[/green] -> {path} ({len(report.results)} attacks)"
        )
        raise typer.Exit(code=0)

    regressions = compare_baseline(report, path)
    if not regressions:
        console.print("[green]no regressions[/green] versus baseline")
        raise typer.Exit(code=0)
    table = Table(title=f"{len(regressions)} regressions")
    table.add_column("attack")
    table.add_column("baseline", justify="right")
    table.add_column("current", justify="right")
    for r in regressions:
        table.add_row(r.attack_id, str(r.baseline_score), str(r.current_score))
    console.print(table)
    raise typer.Exit(code=1)


@app.command("report")
def show_report(
    path: Path = typer.Argument(
        ..., help="A JSON report previously written by scan --json."
    ),
) -> None:
    """Re-render a saved JSON report as a table.

    Lets a CI job or a reviewer inspect a stored scan artifact without re-running
    the suite. Renders straight from the JSON so it never needs the target or an
    API key.
    """
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    verdict = "[red]FAIL[/red]" if data.get("failed") else "[green]PASS[/green]"
    console.print(
        f"[bold]{data.get('target', '?')}[/bold]  suite: {data.get('suite', '?')}  "
        f"verdict: {verdict}"
    )
    table = Table()
    columns = ("Score", "Band", "Category", "Attack", "Verdict", "Evidence")
    for col in columns:
        table.add_column(
            col,
            justify="right" if col == "Score" else "left",
            overflow="fold" if col == "Evidence" else None,
        )
    results = sorted(
        data.get("results", []), key=lambda r: r.get("score", 0), reverse=True
    )
    for r in results:
        ev = "; ".join(e.get("detail", "") for e in r.get("evidence", [])[:2]) or "—"
        succeeded = r.get("success")
        operational_error = bool(r.get("error")) or any(
            item.get("kind") == "judge_error" for item in r.get("evidence", [])
        )
        verdict_cell = _verdict_style(bool(succeeded), operational_error)
        table.add_row(
            str(r.get("score", 0)), r.get("band", "?"), r.get("category", "?"),
            r.get("attack_id", "?"), verdict_cell, ev,
        )
    console.print(table)
    summary = data.get("summary", {})
    console.print(
        f"attacks: {summary.get('total', 0)}  "
        f"succeeded: [red]{summary.get('successes', 0)}[/red]  "
        f"errors: [yellow]{summary.get('errors', 0)}[/yellow]  "
        f"max score: {summary.get('max_score', 0)}"
    )


@app.command()
def version() -> None:
    from agent_redteam import __version__

    console.print(f"agent-redteam {__version__}")


def main() -> None:  # pragma: no cover - console entrypoint
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
