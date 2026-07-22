"""Runtime hooks that enforce guardrails before retrieval/tool effects."""

from __future__ import annotations

import time
from dataclasses import dataclass

from agent_redteam.agentic.protocols import AgentRuntimeHooks
from agent_redteam.agentic.types import Artifact
from agent_redteam.guardrails.base import GuardPipeline
from agent_redteam.types import GuardAction, GuardDecision, ToolCall


@dataclass(frozen=True)
class AllowAllHooks:
    async def before_retrieval_use(self, artifact: Artifact) -> GuardDecision:
        _ = artifact
        return GuardDecision(GuardAction.ALLOW, "agentic_allow_all")

    async def before_tool_execute(self, call: ToolCall) -> GuardDecision:
        _ = call
        return GuardDecision(GuardAction.ALLOW, "agentic_allow_all")


@dataclass
class PipelineRuntimeHooks:
    pipeline: GuardPipeline
    downstream: AgentRuntimeHooks | None = None

    async def before_retrieval_use(self, artifact: Artifact) -> GuardDecision:
        # Retrieved content is attacker-controlled input even when the original
        # user request was benign. Reuse the existing input guards at this trust
        # boundary instead of only scanning the first chat turn.
        rewritten, decisions = self.pipeline.apply_retrieval(artifact.content)
        blocked = next(
            (
                decision
                for decision in decisions
                if decision.action == GuardAction.BLOCK
            ),
            None,
        )
        if blocked is not None:
            return blocked
        if self.downstream is not None:
            downstream = await self.downstream.before_retrieval_use(artifact)
            if downstream.action != GuardAction.ALLOW:
                return downstream
        if rewritten != artifact.content:
            return GuardDecision(
                GuardAction.REWRITE,
                "guard_pipeline",
                "retrieved artifact was normalized before use",
                content=rewritten,
                evidence=tuple(
                    evidence
                    for decision in decisions
                    for evidence in decision.evidence
                ),
            )
        return GuardDecision(GuardAction.ALLOW, "guard_pipeline")

    async def before_tool_execute(self, call: ToolCall) -> GuardDecision:
        for guard in self.pipeline.tool_guards:
            decision = guard.inspect_tool(call)
            if decision.action != GuardAction.ALLOW:
                return decision
        if self.downstream is not None:
            return await self.downstream.before_tool_execute(call)
        return GuardDecision(GuardAction.ALLOW, "guard_pipeline")


@dataclass
class BoundedRuntimeHooks:
    """Fail closed at runtime when an episode exceeds tool/time limits."""

    downstream: AgentRuntimeHooks
    max_tool_calls: int
    deadline: float
    tool_calls: int = 0

    def _time_decision(self) -> GuardDecision | None:
        if time.perf_counter() >= self.deadline:
            return GuardDecision(
                GuardAction.BLOCK,
                "episode_limits",
                "episode wall-clock limit reached",
            )
        return None

    async def before_retrieval_use(self, artifact: Artifact) -> GuardDecision:
        limited = self._time_decision()
        if limited is not None:
            return limited
        return await self.downstream.before_retrieval_use(artifact)

    async def before_tool_execute(self, call: ToolCall) -> GuardDecision:
        limited = self._time_decision()
        if limited is not None:
            return limited
        if self.tool_calls >= self.max_tool_calls:
            return GuardDecision(
                GuardAction.BLOCK,
                "episode_limits",
                f"max_tool_calls {self.max_tool_calls} reached",
            )
        self.tool_calls += 1
        return await self.downstream.before_tool_execute(call)
