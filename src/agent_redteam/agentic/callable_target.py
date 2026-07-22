"""Production adapter and instrumentation helpers for in-process agents."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Any

from agent_redteam.agentic.protocols import AgentRuntimeHooks
from agent_redteam.agentic.trace import TraceRecorder
from agent_redteam.agentic.types import (
    AgentOutcome,
    Artifact,
    EpisodeTrace,
    EventKind,
    ExecutionControls,
    ScenarioPlan,
)
from agent_redteam.types import (
    Conversation,
    GuardAction,
    GuardDecision,
    Response,
    TargetInfo,
    TargetKind,
    ToolCall,
)

AgentFn = Callable[
    [ScenarioPlan, str, "EpisodeInstrumentation"],
    "str | Response | Awaitable[str | Response]",
]
CleanupFn = Callable[[], "None | Awaitable[None]"]
ToolExecutor = Callable[[], "Any | Awaitable[Any]"]


@dataclass(frozen=True)
class ToolExecution:
    allowed: bool
    decision: GuardDecision
    event_id: str
    result: Any = None


@dataclass(frozen=True)
class ArtifactUse:
    """The policy-approved artifact a real agent must consume."""

    allowed: bool
    decision: GuardDecision
    event_id: str
    artifact: Artifact | None = None


@dataclass
class EpisodeInstrumentation:
    """Event recorder that puts guard decisions before the supplied executor.

    A real agent adapter calls ``retrieval_result`` whenever it consumes a RAG
    artifact and routes every side-effecting tool through ``execute_tool``. The
    latter invokes policy before ``executor``; a block therefore means the
    application's side-effect function was provably never called.
    """

    plan: ScenarioPlan
    controls: ExecutionControls
    hooks: AgentRuntimeHooks
    recorder: TraceRecorder = field(default_factory=TraceRecorder)
    decisions: list[GuardDecision] = field(default_factory=list)
    _tool_calls: int = 0
    _last_event: str | None = None

    def start(self, user_input: str) -> str:
        start = self.recorder.add(EventKind.EPISODE_START, "harness")
        self._last_event = self.recorder.add(
            EventKind.USER_INPUT,
            "user",
            data={"content": user_input},
            parents=(start,),
        )
        return self._last_event

    def record(
        self,
        kind: EventKind,
        actor: str,
        *,
        data: dict[str, Any] | None = None,
        parents: tuple[str, ...] | None = None,
        artifact_id: str | None = None,
    ) -> str:
        actual_parents = parents
        if actual_parents is None:
            actual_parents = (self._last_event,) if self._last_event else ()
        self._last_event = self.recorder.add(
            kind,
            actor,
            data=data,
            parents=actual_parents,
            artifact_id=artifact_id,
        )
        return self._last_event

    async def retrieval_result(
        self, artifact: Artifact, *, parents: tuple[str, ...] | None = None
    ) -> ArtifactUse:
        decision = await self.hooks.before_retrieval_use(artifact)
        self.decisions.append(decision)
        guard_event = self.record(
            EventKind.GUARD_DECISION,
            decision.guardrail,
            data={"action": decision.action.value, "reason": decision.reason},
            parents=parents,
            artifact_id=artifact.id,
        )
        if decision.action == GuardAction.BLOCK:
            return ArtifactUse(False, decision, guard_event)
        effective = (
            replace(artifact, content=decision.content)
            if decision.action == GuardAction.REWRITE and decision.content is not None
            else artifact
        )
        event_id = self.record(
            EventKind.RETRIEVAL_RESULT,
            effective.source,
            data={"content": effective.content, "trust": effective.trust.value},
            parents=(guard_event,),
            artifact_id=effective.id,
        )
        return ArtifactUse(True, decision, event_id, effective)

    async def execute_tool(
        self,
        call: ToolCall,
        executor: ToolExecutor,
        *,
        parents: tuple[str, ...] | None = None,
        side_effect: bool = True,
        live: bool = False,
    ) -> ToolExecution:
        request_event = self.record(
            EventKind.TOOL_REQUEST,
            "agent",
            data={"tool": call.name, "arguments": call.arguments},
            parents=parents,
        )
        self._tool_calls += 1
        if self._tool_calls > self.plan.limits.max_tool_calls:
            decision = GuardDecision(
                GuardAction.BLOCK,
                "episode_limits",
                f"max_tool_calls {self.plan.limits.max_tool_calls} reached",
            )
        elif live and not self.controls.allow_live_side_effects:
            decision = GuardDecision(
                GuardAction.BLOCK,
                "dry_run_policy",
                "live side effects are disabled for this red-team run",
            )
        else:
            decision = await self.hooks.before_tool_execute(call)
        self.decisions.append(decision)
        guard_event = self.record(
            EventKind.GUARD_DECISION,
            decision.guardrail,
            data={"action": decision.action.value, "reason": decision.reason},
            parents=(request_event,),
        )
        if decision.action == GuardAction.BLOCK:
            return ToolExecution(False, decision, guard_event)

        result = executor()
        if inspect.isawaitable(result):
            result = await result
        event_kind = EventKind.SIDE_EFFECT if side_effect else EventKind.TOOL_RESULT
        result_event = self.record(
            event_kind,
            call.name,
            data={"tool": call.name, "arguments": call.arguments, "result": result},
            parents=(guard_event,),
        )
        return ToolExecution(True, decision, result_event, result)

    def finish(self, response: Response) -> AgentOutcome:
        self.record(
            EventKind.EPISODE_END,
            "harness",
            data={"response": response.text, "error": response.error},
        )
        return AgentOutcome(
            response,
            EpisodeTrace(self.plan.id, self.recorder.events, tuple(self.decisions)),
        )


@dataclass
class CallableEpisodeTarget:
    """Wrap an instrumented in-process agent without adding an HTTP facade."""

    fn: AgentFn
    name: str = "callable-agent"
    cleanup: CleanupFn | None = None

    @property
    def info(self) -> TargetInfo:
        return TargetInfo(
            self.name,
            TargetKind.AGENT,
            supports_tools=True,
            authorized=True,
            allowlisted=True,
        )

    def endpoint(self) -> str | None:
        return None

    async def send(self, conversation: Conversation) -> Response:
        _ = conversation
        return Response(
            text="",
            error="CallableEpisodeTarget only supports agentic scenario runs",
        )

    async def begin_episode(
        self,
        plan: ScenarioPlan,
        controls: ExecutionControls,
        hooks: AgentRuntimeHooks,
    ) -> _CallableSession:
        return _CallableSession(
            self.fn,
            plan,
            EpisodeInstrumentation(plan, controls, hooks),
            self.cleanup,
        )


@dataclass
class _CallableSession:
    fn: AgentFn
    plan: ScenarioPlan
    instrumentation: EpisodeInstrumentation
    cleanup: CleanupFn | None
    closed: bool = False

    async def execute(self, user_input: str) -> AgentOutcome:
        self.instrumentation.start(user_input)
        try:
            result = self.fn(self.plan, user_input, self.instrumentation)
            if inspect.isawaitable(result):
                result = await result
            response = (
                result if isinstance(result, Response) else Response(text=str(result))
            )
        except Exception as exc:  # noqa: BLE001 - target failures belong in reports
            response = Response(text="", error=f"{type(exc).__name__}: {exc}")
        return self.instrumentation.finish(response)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.cleanup is not None:
            result = self.cleanup()
            if inspect.isawaitable(result):
                await result
