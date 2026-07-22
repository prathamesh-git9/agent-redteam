"""Typed contracts for multi-step agent and RAG security episodes."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any

from agent_redteam.types import AttackCategory, GuardDecision, Response, Severity


class ArtifactKind(StrEnum):
    RETRIEVED_DOCUMENT = "retrieved_document"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"


class TrustLabel(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class EventKind(StrEnum):
    EPISODE_START = "episode_start"
    USER_INPUT = "user_input"
    RETRIEVAL_QUERY = "retrieval_query"
    RETRIEVAL_RESULT = "retrieval_result"
    MODEL_OUTPUT = "model_output"
    TOOL_REQUEST = "tool_request"
    GUARD_DECISION = "guard_decision"
    TOOL_RESULT = "tool_result"
    SIDE_EFFECT = "side_effect"
    MEMORY_WRITE = "memory_write"
    EPISODE_END = "episode_end"


class InvariantKind(StrEnum):
    NO_UNTRUSTED_SIDE_EFFECT = "no_untrusted_side_effect"
    NO_UNAUTHORIZED_ACCOUNT_CREDIT = "no_unauthorized_account_credit"
    NO_FORBIDDEN_TOOL = "no_forbidden_tool"
    NO_CROSS_TENANT_READ = "no_cross_tenant_read"


class AttributionStatus(StrEnum):
    CAUSAL = "causal"
    SUSPECTED = "suspected"
    NOT_ATTRIBUTED = "not_attributed"


@dataclass(frozen=True)
class Artifact:
    id: str
    kind: ArtifactKind
    content: str
    trust: TrustLabel
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityInvariant:
    kind: InvariantKind
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EpisodeLimits:
    max_steps: int = 12
    max_tool_calls: int = 4
    max_seconds: float = 30.0


@dataclass(frozen=True)
class ExecutionControls:
    seed: int = 0
    allow_live_side_effects: bool = False


@dataclass(frozen=True)
class ScenarioPlan:
    id: str
    attack_id: str
    category: AttackCategory
    severity: Severity
    label: str
    user_input: str
    artifacts: tuple[Artifact, ...]
    invariants: tuple[SecurityInvariant, ...]
    clean_artifacts: tuple[Artifact, ...] = ()
    references: tuple[str, ...] = ()
    limits: EpisodeLimits = field(default_factory=EpisodeLimits)

    def clean_twin(self) -> ScenarioPlan | None:
        if not self.clean_artifacts:
            return None
        return replace(self, id=f"{self.id}.clean", artifacts=self.clean_artifacts,
                       clean_artifacts=())


@dataclass(frozen=True)
class TraceEvent:
    id: str
    sequence: int
    kind: EventKind
    actor: str
    data: dict[str, Any] = field(default_factory=dict)
    parents: tuple[str, ...] = ()
    artifact_id: str | None = None


@dataclass(frozen=True)
class EpisodeTrace:
    scenario_id: str
    events: tuple[TraceEvent, ...]
    guard_decisions: tuple[GuardDecision, ...] = ()


@dataclass(frozen=True)
class AgentOutcome:
    response: Response
    trace: EpisodeTrace


@dataclass(frozen=True)
class InvariantViolation:
    invariant: InvariantKind
    event_id: str
    source_event_ids: tuple[str, ...]
    provenance_path: tuple[str, ...]
    detail: str


@dataclass(frozen=True)
class FailureAttribution:
    status: AttributionStatus
    source_event_ids: tuple[str, ...] = ()
    provenance_path: tuple[str, ...] = ()
    counterfactual_changed: bool = False
    explanation: str = ""


@dataclass(frozen=True)
class EpisodeRunResult:
    plan: ScenarioPlan
    outcome: AgentOutcome
    verdict: Any
    violations: tuple[InvariantViolation, ...]
    attribution: FailureAttribution
    counterfactual: AgentOutcome | None = None
