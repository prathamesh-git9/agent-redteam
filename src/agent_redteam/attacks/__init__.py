"""Import attack modules so their registry decorators run."""

from __future__ import annotations

from agent_redteam.attacks import (
    adaptive,
    exfiltration,
    jailbreak,
    multi_turn,
    obfuscation,
    prompt_injection,
    resource_exhaustion,
    tool_abuse,
)

__all__ = [
    "adaptive",
    "exfiltration",
    "jailbreak",
    "multi_turn",
    "obfuscation",
    "prompt_injection",
    "resource_exhaustion",
    "tool_abuse",
]
