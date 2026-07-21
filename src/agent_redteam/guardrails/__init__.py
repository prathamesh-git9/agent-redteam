"""Composable guardrail middleware and the pipeline that applies it.

Individual guardrails (secret/PII/canary scanners, injection detector, encoding
normalizer, tool policy) live in sibling modules and are aggregated by
``default_guardrails``; the pipeline machinery lives in ``base``.
"""

from __future__ import annotations

from agent_redteam.guardrails.base import (
    DefendedTarget,
    GuardPipeline,
    InputGuardrail,
    OutputGuardrail,
    ToolGuardrail,
)
from agent_redteam.guardrails.input_guards import (
    AllowlistGuard,
    EncodingNormalizer,
    InjectionDetector,
)
from agent_redteam.guardrails.output_guards import (
    CanaryScanner,
    ExfilURLBlocker,
    PIIScanner,
    SecretScanner,
)
from agent_redteam.guardrails.tool_guards import ToolCallPolicy

__all__ = [
    "AllowlistGuard",
    "CanaryScanner",
    "DefendedTarget",
    "EncodingNormalizer",
    "ExfilURLBlocker",
    "GuardPipeline",
    "InjectionDetector",
    "InputGuardrail",
    "OutputGuardrail",
    "PIIScanner",
    "SecretScanner",
    "ToolCallPolicy",
    "ToolGuardrail",
    "default_guardrails",
]


def default_guardrails() -> GuardPipeline:
    """The recommended defense stack.

    Imported lazily so the individual guardrail modules (which self-register)
    are only required when defenses are actually requested, keeping the core
    import light. Populated by ``agent_redteam.guardrails.presets``.
    """
    from agent_redteam.guardrails.presets import default_guardrails as _default

    return _default()
