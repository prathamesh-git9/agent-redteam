"""Core data types shared across the whole harness.

These types are the contract between the four independent halves of the system:
attacks (which *generate* adversarial input), targets (which *answer* it),
oracles (which *judge* the answer), and scoring (which *aggregates* the
judgements). Each half is deliberately ignorant of the others' internals and
speaks only in the vocabulary defined here. Keeping this module free of any I/O,
provider SDKs, or business logic is what lets the attack corpus be snapshot
tested offline and lets a run be replayed from its recorded trace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True)
class ToolCall:
    """A tool/function invocation a target chose to emit.

    We capture these separately from free text because the most dangerous
    outcomes (SSRF, unauthorized actions, argument injection) live in the tool
    channel, and a text-only oracle would miss them entirely.
    """

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str | None = None


@dataclass(frozen=True)
class Message:
    role: Role
    content: str
    name: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()


# A Conversation is an ordered transcript. We use a plain tuple rather than a
# wrapper class so that probes are trivially hashable/comparable, which the
# snapshot tests and the deduplicating runner both rely on.
Conversation = tuple[Message, ...]


def conversation(*messages: Message) -> Conversation:
    """Small ergonomic constructor: ``conversation(system(...), user(...))``."""
    return tuple(messages)


def system(content: str) -> Message:
    return Message(Role.SYSTEM, content)


def user(content: str) -> Message:
    return Message(Role.USER, content)


def assistant(content: str, tool_calls: tuple[ToolCall, ...] = ()) -> Message:
    return Message(Role.ASSISTANT, content, tool_calls=tool_calls)


@dataclass(frozen=True)
class Usage:
    """Token accounting. Populated when the target reports it.

    Required by the resource-exhaustion oracle and by the runner's hard budget:
    a denial-of-wallet *test* must never be able to become a real denial-of-wallet
    event, so we meter every call.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass(frozen=True)
class Response:
    """What a target returns for one ``send``.

    ``raw`` retains the provider-native payload untouched so evidence can quote
    exactly what came back, not a lossy reconstruction of it.
    """

    text: str
    tool_calls: tuple[ToolCall, ...] = ()
    usage: Usage = field(default_factory=Usage)
    latency_ms: float = 0.0
    raw: Any = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class TargetKind(StrEnum):
    OPENAI_CHAT = "openai_chat"
    HTTP = "http"
    CALLABLE = "callable"
    FAKE = "fake"


@dataclass(frozen=True)
class TargetInfo:
    """Identity and — crucially — the authorization state of a target.

    ``authorized`` and ``allowlisted`` are not decoration. The runner refuses to
    dispatch a single probe unless both are true (see ``config.assert_authorized``).
    This is the mechanical enforcement of the project's responsible-use posture:
    the harness structurally cannot be pointed at a system the operator has not
    asserted ownership of.
    """

    name: str
    kind: TargetKind
    supports_tools: bool = False
    authorized: bool = False
    allowlisted: bool = False


class AttackCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    EXFILTRATION = "exfiltration"
    TOOL_ABUSE = "tool_abuse"
    OBFUSCATION = "obfuscation"
    MULTI_TURN = "multi_turn"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


class Severity(StrEnum):
    """Base severity if an attack of this category succeeds.

    This is the *potential* impact, independent of whether a given target was
    actually vulnerable — the oracle's confidence and the exploitability factor
    scale it down in ``scoring``. Values map to a numeric base in scoring.model.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Canary:
    """A synthetic secret planted so that leakage is unambiguously detectable.

    Canaries are the backbone of deterministic oracles: rather than asking an
    LLM judge "did the model leak the system prompt?", we plant a unique,
    high-entropy token in the system prompt or tool output and check whether it
    appears in the response. A hit is a leak with ~zero false positives.
    """

    token: str
    kind: str  # e.g. "system_prompt", "credential", "pii"
    description: str = ""


@dataclass(frozen=True)
class OracleSpec:
    """Declares, per probe, what counts as a successful attack.

    An attack author picks the cheapest oracle that is decisive for their probe:
    a canary hit where possible, a signature where the success string is stable,
    and only falls back to the LLM judge when success is genuinely semantic.
    ``success_signatures`` and ``failure_signatures`` are regex strings.
    """

    canaries: tuple[Canary, ...] = ()
    success_signatures: tuple[str, ...] = ()
    failure_signatures: tuple[str, ...] = ()
    judge_rubric: str | None = None
    # If the target emits any of these tool names, the attack is considered to
    # have induced unauthorized tool use.
    forbidden_tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class Probe:
    """One concrete attack attempt: the payload plus how to judge the answer."""

    attack_id: str
    category: AttackCategory
    severity: Severity
    conversation: Conversation
    oracle: OracleSpec
    label: str = ""
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    """A single, quotable reason behind a verdict.

    Verdicts are never returned bare. Every ``success=True`` must carry at least
    one Evidence pointing at the exact span/token/tool that proves it, because a
    security finding you cannot show your reviewer is a finding they will (rightly)
    ignore.
    """

    kind: str  # "canary_hit" | "signature" | "tool_call" | "judge" | "refusal"
    detail: str
    span: str | None = None


@dataclass(frozen=True)
class OracleVerdict:
    success: bool
    confidence: float
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0,1], got {self.confidence}")


@dataclass(frozen=True)
class RiskScore:
    """Per-attack 0-10 risk with a human-readable vector string."""

    value: float
    vector: str
    base_severity: float
    success_confidence: float
    exploitability: float


@dataclass(frozen=True)
class AttackResult:
    """The full, replayable record of one probe run end to end."""

    probe: Probe
    response: Response
    verdict: OracleVerdict
    score: RiskScore

    @property
    def succeeded(self) -> bool:
        return self.verdict.success


class GuardAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REWRITE = "rewrite"


@dataclass(frozen=True)
class GuardDecision:
    """The outcome of a single guardrail inspecting one message or response.

    ``REWRITE`` carries the sanitized ``content`` (e.g. canary redacted, exfil
    URL stripped); ``BLOCK`` short-circuits the pipeline; ``ALLOW`` passes
    through. Every non-ALLOW decision must carry a reason so an operator can
    audit why a request was altered.
    """

    action: GuardAction
    guardrail: str
    reason: str = ""
    content: str | None = None
    evidence: tuple[Evidence, ...] = ()
