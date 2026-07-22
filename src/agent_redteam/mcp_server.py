"""Expose the harness through MCP so an agent platform can self-test.

The two tools mirror the two halves of the project: ``run_attack_suite`` runs
the red-team suite against a target the caller describes, and ``check_guardrail``
lets a platform ask "would my output filters have caught this string?" without
running a full scan. MCP is imported lazily because most installs only need the
CLI; install the ``mcp`` extra to use this surface.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agent_redteam.config import AuthorizationError, parse_run_config
from agent_redteam.guardrails import default_guardrails
from agent_redteam.oracles import default_oracle
from agent_redteam.registry import all_attacks
from agent_redteam.runner import Runner
from agent_redteam.targets.factory import build_target
from agent_redteam.types import GuardAction


def create_mcp_server() -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "agent_redteam.mcp_server requires the official mcp package; install "
            "the mcp extra (pip install 'agent-redteam[mcp]') to use MCP integration."
        ) from exc

    import agent_redteam.attacks  # noqa: F401  (register the corpus)

    server = FastMCP("agent-redteam")

    @server.tool()
    def list_attacks() -> list[dict[str, Any]]:
        """List every registered attack with id, category and references."""
        return [
            {
                "id": s.id,
                "category": s.category.value,
                "requirements": sorted(s.requirements),
                "summary": s.summary,
            }
            for s in all_attacks()
        ]

    @server.tool()
    def run_attack_suite(
        target: dict[str, Any], suite: str = "default", agentic: bool = False
    ) -> dict[str, Any]:
        """Run an attack suite against a target you are authorized to test.

        ``target`` is the same mapping the CLI config uses (name, kind,
        authorized, allowlist, options). The authorization gate still applies:
        an unauthorized or off-allowlist target is refused, not scanned.
        """
        cfg = parse_run_config(
            {"target": target, "run": {"suite": suite, "agentic": agentic}}
        )
        built = build_target(cfg.target)
        try:
            report = asyncio.run(Runner(default_oracle(), cfg).run(built))
        except AuthorizationError as exc:
            return {"error": "unauthorized", "detail": str(exc)}
        return report.to_dict()

    @server.tool()
    def check_guardrail(text: str) -> dict[str, Any]:
        """Report which output guardrails would fire on a candidate string.

        Lets a platform pre-flight a model output through the default output
        filters and see what would be blocked or rewritten, without a scan.
        """
        pipeline = default_guardrails()
        rewritten, decisions, blocked = pipeline.apply_output(text)
        return {
            "blocked": blocked,
            "rewritten": rewritten if rewritten != text else None,
            "fired": [
                {"guardrail": d.guardrail, "action": d.action.value, "reason": d.reason}
                for d in decisions
                if d.action != GuardAction.ALLOW
            ],
        }

    return server


def main() -> None:  # pragma: no cover - stdio entrypoint
    create_mcp_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
