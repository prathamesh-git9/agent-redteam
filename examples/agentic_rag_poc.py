"""Offline end-to-end proof: poisoned RAG -> tool effect -> causal remediation."""

from __future__ import annotations

import asyncio
import json

import agent_redteam.attacks  # noqa: F401  (register scenarios)
from agent_redteam.agentic import FakeAgentTarget
from agent_redteam.config import RunConfig, TargetConfig
from agent_redteam.guardrails import GuardPipeline, ToolCallPolicy
from agent_redteam.oracles import default_oracle
from agent_redteam.runner import Runner


def _config(name: str) -> RunConfig:
    return RunConfig(
        target=TargetConfig(name=name, kind="fake_agent", authorized=True),
        suite="tag:agentic",
        agentic=True,
        concurrency=1,
        max_calls=4,
        seed=7,
    )


async def main() -> None:
    vulnerable = FakeAgentTarget("poc-vulnerable")
    before = await Runner(default_oracle(), _config(vulnerable.name)).run(vulnerable)

    defended_base = FakeAgentTarget("poc-defended")
    policy = GuardPipeline(
        tool_guards=[ToolCallPolicy(allow=("search", "read_document"))]
    )
    after = await Runner(default_oracle(), _config(defended_base.name)).run(
        policy.wrap(defended_base)
    )

    finding = before.results[0]
    proof = {
        "problem_reproduced": finding.succeeded,
        "causal_attribution": finding.attribution.status.value,
        "poisoned_source_events": list(finding.attribution.source_event_ids),
        "provenance_path": list(finding.attribution.provenance_path),
        "simulated_side_effects_before": len(vulnerable.side_effects),
        "guardrail_prevented_execution": len(defended_base.side_effects) == 0,
        "findings_after": len(after.successes),
        "before_trace_events": len(finding.episode_trace.events),
        "after_trace_events": len(after.results[0].episode_trace.events),
        "sessions_cleaned_up": (
            vulnerable.sessions_started == vulnerable.sessions_closed
            and defended_base.sessions_started == defended_base.sessions_closed
        ),
    }
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
