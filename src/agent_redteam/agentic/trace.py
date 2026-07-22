"""Deterministic trace recorder with validated provenance edges."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_redteam.agentic.types import EventKind, TraceEvent


@dataclass
class TraceRecorder:
    _events: list[TraceEvent] = field(default_factory=list)

    def add(
        self,
        kind: EventKind,
        actor: str,
        *,
        data: dict[str, Any] | None = None,
        parents: tuple[str, ...] = (),
        artifact_id: str | None = None,
    ) -> str:
        known = {event.id for event in self._events}
        missing = set(parents) - known
        if missing:
            raise ValueError(f"trace parents must already exist: {sorted(missing)}")
        event_id = f"e{len(self._events):04d}"
        self._events.append(
            TraceEvent(
                id=event_id,
                sequence=len(self._events),
                kind=kind,
                actor=actor,
                data=data or {},
                parents=parents,
                artifact_id=artifact_id,
            )
        )
        return event_id

    @property
    def events(self) -> tuple[TraceEvent, ...]:
        return tuple(self._events)
