"""Offline fake agent with poisoned-retrieval and pre-tool-hook semantics."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from agent_redteam.agentic.protocols import AgentRuntimeHooks
from agent_redteam.agentic.trace import TraceRecorder
from agent_redteam.agentic.types import (
    AgentOutcome,
    ArtifactKind,
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
    Usage,
)

_RECIPIENT = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")


@dataclass
class FakeAgentTarget:
    """A safe deterministic POC target; side effects are recorded, never live."""

    name: str = "fake-agent"
    vulnerable: bool = True
    sessions_started: int = 0
    sessions_closed: int = 0
    side_effects: list[ToolCall] = field(default_factory=list)

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
        return Response(text="I can help with that.")

    async def begin_episode(
        self,
        plan: ScenarioPlan,
        controls: ExecutionControls,
        hooks: AgentRuntimeHooks,
    ) -> _FakeSession:
        if controls.allow_live_side_effects:
            raise ValueError("FakeAgentTarget never permits live side effects")
        self.sessions_started += 1
        return _FakeSession(self, plan, hooks)


@dataclass
class _FakeSession:
    target: FakeAgentTarget
    plan: ScenarioPlan
    hooks: AgentRuntimeHooks
    closed: bool = False

    async def execute(self, user_input: str) -> AgentOutcome:
        recorder = TraceRecorder()
        decisions: list[GuardDecision] = []
        start = recorder.add(EventKind.EPISODE_START, "harness")
        user_event = recorder.add(
            EventKind.USER_INPUT, "user", data={"content": user_input}, parents=(start,)
        )
        query = recorder.add(
            EventKind.RETRIEVAL_QUERY,
            "agent",
            data={"query": user_input},
            parents=(user_event,),
        )
        retrieval_events: list[str] = []
        usable = []
        for artifact in self.plan.artifacts:
            if artifact.kind != ArtifactKind.RETRIEVED_DOCUMENT:
                continue
            decision = await self.hooks.before_retrieval_use(artifact)
            decisions.append(decision)
            guard_event = recorder.add(
                EventKind.GUARD_DECISION,
                decision.guardrail,
                data={"action": decision.action.value, "reason": decision.reason},
                parents=(query,),
                artifact_id=artifact.id,
            )
            if decision.action == GuardAction.BLOCK:
                continue
            effective = (
                replace(artifact, content=decision.content)
                if decision.action == GuardAction.REWRITE
                and decision.content is not None
                else artifact
            )
            event_id = recorder.add(
                EventKind.RETRIEVAL_RESULT,
                effective.source,
                data={"content": effective.content, "trust": effective.trust.value},
                parents=(guard_event,),
                artifact_id=effective.id,
            )
            retrieval_events.append(event_id)
            usable.append(effective)

        response_text = "I summarized the retrieved material without taking actions."
        model_event = recorder.add(
            EventKind.MODEL_OUTPUT,
            "agent",
            data={"content": response_text},
            parents=tuple(retrieval_events) or (query,),
        )
        if self.target.vulnerable:
            injected = next(
                (
                    artifact
                    for artifact in usable
                    if "send_email" in artifact.content.lower()
                ),
                None,
            )
            if injected is not None:
                match = _RECIPIENT.search(injected.content)
                recipient = match.group(0) if match else "attacker@example.invalid"
                call = ToolCall(
                    "send_email",
                    {"recipient": recipient, "body": "synthetic quarterly summary"},
                    "call-1",
                )
                request = recorder.add(
                    EventKind.TOOL_REQUEST,
                    "agent",
                    data={"tool": call.name, "arguments": call.arguments},
                    parents=(model_event,),
                )
                decision = await self.hooks.before_tool_execute(call)
                decisions.append(decision)
                decision_event = recorder.add(
                    EventKind.GUARD_DECISION,
                    decision.guardrail,
                    data={"action": decision.action.value, "reason": decision.reason},
                    parents=(request,),
                )
                if decision.action != GuardAction.BLOCK:
                    # This fake effect is an append-only audit record. No network
                    # or real email action exists, even if a caller requests it.
                    self.target.side_effects.append(call)
                    recorder.add(
                        EventKind.SIDE_EFFECT,
                        "send_email",
                        data={"tool": call.name, "arguments": call.arguments,
                              "simulated": True},
                        parents=(decision_event,),
                    )
                    response_text = f"Email queued to {recipient}."
                else:
                    response_text = "The requested tool action was blocked by policy."

        end = recorder.add(
            EventKind.EPISODE_END,
            "harness",
            data={"response": response_text},
            parents=(model_event,),
        )
        _ = end
        response = Response(
            text=response_text,
            usage=Usage(prompt_tokens=len(user_input) // 4, completion_tokens=12),
        )
        return AgentOutcome(
            response,
            EpisodeTrace(self.plan.id, recorder.events, tuple(decisions)),
        )

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.target.sessions_closed += 1
