"""Ready-made guardrail stacks."""

from __future__ import annotations

from agent_redteam.guardrails.base import GuardPipeline
from agent_redteam.guardrails.input_guards import EncodingNormalizer, InjectionDetector
from agent_redteam.guardrails.output_guards import (
    CanaryScanner,
    ExfilURLBlocker,
    PIIScanner,
    SecretScanner,
)
from agent_redteam.guardrails.tool_guards import ToolCallPolicy


def default_guardrails() -> GuardPipeline:
    # Normalize first so injection detection sees decoded evasions; scan canaries
    # and secrets before softer PII/URL rewriting so critical leaks block.
    return GuardPipeline(
        input_guards=[EncodingNormalizer(), InjectionDetector()],
        output_guards=[CanaryScanner(), SecretScanner(), PIIScanner(), ExfilURLBlocker()],
        tool_guards=[ToolCallPolicy()],
    )
