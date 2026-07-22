"""Protocols for resettable, instrumented agent episodes."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_redteam.agentic.types import (
    AgentOutcome,
    Artifact,
    ExecutionControls,
    ScenarioPlan,
)
from agent_redteam.types import GuardDecision, TargetInfo, ToolCall


@runtime_checkable
class AgentRuntimeHooks(Protocol):
    async def before_retrieval_use(self, artifact: Artifact) -> GuardDecision: ...

    async def before_tool_execute(self, call: ToolCall) -> GuardDecision: ...


@runtime_checkable
class EpisodeSession(Protocol):
    async def execute(self, user_input: str) -> AgentOutcome: ...

    async def close(self) -> None: ...


@runtime_checkable
class EpisodeTarget(Protocol):
    info: TargetInfo

    def endpoint(self) -> str | None: ...

    async def begin_episode(
        self,
        plan: ScenarioPlan,
        controls: ExecutionControls,
        hooks: AgentRuntimeHooks,
    ) -> EpisodeSession: ...
