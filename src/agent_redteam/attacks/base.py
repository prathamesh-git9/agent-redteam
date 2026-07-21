"""The Attack contract and the context passed to attacks at build time.

Attacks are pure payload generators: given an ``AttackContext`` they yield one or
more ``Probe`` objects and never perform I/O. That purity is what lets the whole
corpus be snapshot-tested and lets a single canary be threaded consistently from
the payload that plants it to the oracle that detects its leak.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from agent_redteam.types import (
    AttackCategory,
    Canary,
    Probe,
    Severity,
)


@dataclass
class AttackContext:
    """Everything an attack needs to build probes, and nothing it doesn't.

    A ``seed`` makes canary generation reproducible when set (used by snapshot
    tests); left ``None`` it draws fresh high-entropy tokens per run so a target
    cannot learn to recognise and echo a fixed canary. ``supports_tools`` lets
    tool-abuse attacks skip targets that expose no tools rather than emit probes
    that can never succeed.
    """

    supports_tools: bool = False
    seed: int | None = None
    _counter: int = field(default=0, repr=False)

    def mint_canary(self, kind: str, description: str = "") -> Canary:
        """Create a unique, high-entropy synthetic secret to plant.

        Deterministic when ``seed`` is set (``seed`` + a per-context counter),
        random otherwise. The ``ART-`` prefix makes an accidental canary in real
        logs trivially greppable and unmistakably synthetic.
        """
        self._counter += 1
        if self.seed is not None:
            token = f"ART-{kind}-{self.seed:x}-{self._counter:04x}"
        else:
            token = f"ART-{kind}-{secrets.token_hex(8)}"
        return Canary(token=token, kind=kind, description=description)


@runtime_checkable
class Attack(Protocol):
    id: str
    category: AttackCategory
    severity: Severity
    references: tuple[str, ...]

    def build_probes(self, ctx: AttackContext) -> Iterable[Probe]: ...


@dataclass
class BaseAttack:
    """Convenience base carrying the metadata fields, so concrete attacks only
    implement ``build_probes``. Not required by the protocol — a plain object
    with the right attributes is equally valid — but it removes boilerplate from
    the ~30 attacks in the corpus.
    """

    id: str
    category: AttackCategory
    severity: Severity
    references: tuple[str, ...] = ()

    def build_probes(self, ctx: AttackContext) -> Iterable[Probe]:  # pragma: no cover
        raise NotImplementedError
