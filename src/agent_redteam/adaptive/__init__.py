"""Bounded adaptive attacks: observe the target, mutate, retry, stop.

The static corpus asks "does this fixed prompt work?"; the adaptive engine asks
"what prompt works *after* watching how this target fails?" — a closed
feedback loop (PAIR / Crescendo style) that reuses the same Target, Oracle, and
budget contracts as the static runner, and stays opt-in behind the same
authorization gate.
"""

from __future__ import annotations

from agent_redteam.adaptive.attackers import (
    FakeAttacker,
    OpenAIAttacker,
    build_attacker_messages,
    parse_candidates,
)
from agent_redteam.adaptive.types import (
    AdaptiveLimits,
    AdaptivePlan,
    AdaptiveRunResult,
    Attacker,
    AttackObservation,
    MutationBatch,
    MutationCandidate,
    MutationRequest,
)

__all__ = [
    "AdaptiveLimits",
    "AdaptivePlan",
    "AdaptiveRunResult",
    "Attacker",
    "AttackObservation",
    "FakeAttacker",
    "MutationBatch",
    "MutationCandidate",
    "MutationRequest",
    "OpenAIAttacker",
    "build_attacker_messages",
    "parse_candidates",
]
