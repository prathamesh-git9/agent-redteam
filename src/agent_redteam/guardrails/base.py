"""Guardrail protocols and the pipeline that turns a target into a defended one.

The design goal is symmetry: a guardrail is just middleware, and wrapping a
target in a pipeline yields another object that satisfies the exact same
``Target`` protocol. That is what lets the runner score the defended target with
the *identical* suite it ran against the raw one and report an honest
before/after delta — the only number that tells an operator whether a mitigation
actually helped, rather than whether it felt reassuring.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from agent_redteam.targets.base import Target
from agent_redteam.types import (
    Conversation,
    GuardAction,
    GuardDecision,
    Message,
    Response,
    Role,
    ToolCall,
)


@runtime_checkable
class InputGuardrail(Protocol):
    name: str
    def inspect_input(self, message: Message) -> GuardDecision: ...


@runtime_checkable
class OutputGuardrail(Protocol):
    name: str
    def inspect_output(self, text: str) -> GuardDecision: ...


@runtime_checkable
class ToolGuardrail(Protocol):
    name: str
    def inspect_tool(self, call: ToolCall) -> GuardDecision: ...


# A canned reply used when an input guardrail blocks the request outright. It is
# deliberately a plain refusal so that, from the oracle's point of view, a
# blocked attack looks exactly like a well-aligned model refusing — the defense
# "held" in a way the RefusalOracle already understands.
_BLOCKED_REPLY = "I can't help with that request."


@dataclass
class GuardPipeline:
    input_guards: list[InputGuardrail]
    output_guards: list[OutputGuardrail]
    tool_guards: list[ToolGuardrail]

    def __init__(
        self,
        input_guards: list[InputGuardrail] | None = None,
        output_guards: list[OutputGuardrail] | None = None,
        tool_guards: list[ToolGuardrail] | None = None,
    ) -> None:
        self.input_guards = input_guards or []
        self.output_guards = output_guards or []
        self.tool_guards = tool_guards or []

    def wrap(self, target: Target) -> DefendedTarget:
        return DefendedTarget(target=target, pipeline=self)

    # --- inspection primitives, reused by DefendedTarget and by unit tests -----

    def apply_input(
        self,
        conversation: Conversation,
    ) -> tuple[Conversation, list[GuardDecision]]:
        """Inspect/rewrite the last user message (the attacker-controlled turn).

        Only the last user turn is inspected because that is the untrusted input
        under test; rewriting earlier system/assistant turns would change the
        target's own configuration rather than defend against the probe.
        """
        decisions: list[GuardDecision] = []
        messages = list(conversation)
        idx = _last_user_index(messages)
        if idx is None:
            return conversation, decisions
        content = messages[idx].content
        for guard in self.input_guards:
            decision = guard.inspect_input(Message(Role.USER, content))
            decisions.append(decision)
            if decision.action == GuardAction.BLOCK:
                return conversation, decisions
            if decision.action == GuardAction.REWRITE and decision.content is not None:
                content = decision.content
        messages[idx] = Message(Role.USER, content)
        return tuple(messages), decisions

    def apply_output(self, text: str) -> tuple[str, list[GuardDecision], bool]:
        decisions: list[GuardDecision] = []
        blocked = False
        for guard in self.output_guards:
            decision = guard.inspect_output(text)
            decisions.append(decision)
            if decision.action == GuardAction.BLOCK:
                blocked = True
                text = _BLOCKED_REPLY
                break
            if decision.action == GuardAction.REWRITE and decision.content is not None:
                text = decision.content
        return text, decisions, blocked

    def apply_tools(
        self,
        calls: tuple[ToolCall, ...],
    ) -> tuple[tuple[ToolCall, ...], list[GuardDecision]]:
        decisions: list[GuardDecision] = []
        kept: list[ToolCall] = []
        for call in calls:
            blocked = False
            for guard in self.tool_guards:
                decision = guard.inspect_tool(call)
                decisions.append(decision)
                if decision.action == GuardAction.BLOCK:
                    blocked = True
                    break
            if not blocked:
                kept.append(call)
        return tuple(kept), decisions


@dataclass
class DefendedTarget(Target):
    """A target wrapped by a GuardPipeline. Satisfies the Target protocol.

    Input guards run before the call; if any blocks, the underlying target is
    never contacted and a refusal is returned. Output and tool guards run on the
    reply. The pipeline's decisions are attached to ``Response.raw`` so a report
    can show exactly which guardrail fired.
    """

    target: Target
    pipeline: GuardPipeline

    @property
    def info(self):  # noqa: ANN201 - delegate, keep the wrapped identity but mark defended
        base = self.target.info
        return type(base)(
            name=f"{base.name}+guarded",
            kind=base.kind,
            supports_tools=base.supports_tools,
            authorized=base.authorized,
            allowlisted=base.allowlisted,
        )

    def endpoint(self) -> str | None:
        return self.target.endpoint()

    async def send(self, conversation: Conversation) -> Response:
        guarded_convo, in_decisions = self.pipeline.apply_input(conversation)
        if any(d.action == GuardAction.BLOCK for d in in_decisions):
            blocked = [
                d.guardrail
                for d in in_decisions
                if d.action == GuardAction.BLOCK
            ]
            return Response(text=_BLOCKED_REPLY, raw={"guard": blocked})
        response = await self.target.send(guarded_convo)
        if not response.ok:
            return response
        text, out_decisions, _ = self.pipeline.apply_output(response.text)
        tools, tool_decisions = self.pipeline.apply_tools(response.tool_calls)
        fired = [
            d.guardrail
            for d in (*in_decisions, *out_decisions, *tool_decisions)
            if d.action != GuardAction.ALLOW
        ]
        return Response(
            text=text,
            tool_calls=tools,
            usage=response.usage,
            latency_ms=response.latency_ms,
            raw={"guard_fired": fired, "target_raw": response.raw},
        )


def _last_user_index(messages: list[Message]) -> int | None:
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].role == Role.USER:
            return i
    return None
