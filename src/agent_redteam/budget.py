"""A shared, live budget ledger enforced across every model call.

Extracted so both the static runner and the adaptive engine meter against the
*same* ledger. A red-team run — especially an adaptive one that loops, mutating
and retrying — is the single thing most able to turn a denial-of-wallet *test*
into a real denial-of-wallet event, so nothing calls a model without first
asking the ledger for permission and then recording what it spent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock
from uuid import uuid4

from agent_redteam.types import Response


class BudgetError(RuntimeError):
    """Raised when an action would exceed the configured call/token/time budget.

    Deliberately not a subclass of a broad, easily-swallowed exception: a run
    that hit its budget still produced partial, useful results, so callers are
    expected to catch this explicitly and record it, not ignore it.
    """


@dataclass(frozen=True)
class BudgetReservation:
    """An atomic claim on shared call/token capacity.

    Reservations close the check-then-send race that otherwise lets concurrent
    probes all observe the same remaining call.  ``token_ceiling`` is optional
    because some legacy targets cannot declare their response cap up front.
    """

    id: str
    kind: str
    calls: int
    token_ceiling: int


@dataclass
class BudgetLedger:
    max_calls: int
    max_tokens: int
    max_seconds: float
    started: float = field(default_factory=time.perf_counter)
    calls: int = 0
    tokens: int = 0
    _reserved_calls: int = field(default=0, init=False, repr=False)
    _reserved_tokens: int = field(default=0, init=False, repr=False)
    _reservations: dict[str, BudgetReservation] = field(
        default_factory=dict, init=False, repr=False
    )
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def check(self, *, calls: int = 1, tokens: int = 0) -> None:
        """Raise if performing an action of the given size would exceed a cap.

        ``calls``/``tokens`` describe the action about to happen so a caller can
        test-ahead (the adaptive engine asks "do I have budget for one more
        target call?" before spending it). The time cap is checked on every call
        because wall-clock is the one budget that ticks without any action.
        """
        with self._lock:
            self._check_locked(calls=calls, tokens=tokens)

    def _check_locked(self, *, calls: int, tokens: int) -> None:
        if self.calls + self._reserved_calls + calls > self.max_calls:
            raise BudgetError(f"max_calls {self.max_calls} reached")
        if self.tokens + self._reserved_tokens + tokens > self.max_tokens:
            raise BudgetError(f"max_tokens {self.max_tokens} reached")
        if time.perf_counter() - self.started >= self.max_seconds:
            raise BudgetError(f"max_seconds {self.max_seconds} reached")

    def reserve(
        self,
        *,
        kind: str = "target",
        calls: int = 1,
        token_ceiling: int = 0,
    ) -> BudgetReservation:
        """Atomically reserve capacity before any external/model action."""
        if calls < 0 or token_ceiling < 0:
            raise ValueError("reservation sizes must be non-negative")
        with self._lock:
            self._check_locked(calls=calls, tokens=token_ceiling)
            reservation = BudgetReservation(
                id=uuid4().hex,
                kind=kind,
                calls=calls,
                token_ceiling=token_ceiling,
            )
            self._reservations[reservation.id] = reservation
            self._reserved_calls += calls
            self._reserved_tokens += token_ceiling
            return reservation

    def commit(
        self,
        reservation: BudgetReservation,
        *,
        response: Response | None = None,
        tokens: int | None = None,
    ) -> None:
        """Record actual spend and release a reservation exactly once."""
        actual_tokens = (
            response.usage.total_tokens
            if response is not None
            else (tokens if tokens is not None else 0)
        )
        with self._lock:
            current = self._reservations.pop(reservation.id, None)
            if current is None:
                raise ValueError("unknown or already completed budget reservation")
            self._reserved_calls -= current.calls
            self._reserved_tokens -= current.token_ceiling
            self.calls += current.calls
            self.tokens += actual_tokens

    def release(self, reservation: BudgetReservation) -> None:
        """Release capacity after an action fails before incurring spend."""
        with self._lock:
            current = self._reservations.pop(reservation.id, None)
            if current is None:
                return
            self._reserved_calls -= current.calls
            self._reserved_tokens -= current.token_ceiling

    def would_exceed(self, *, calls: int = 1, tokens: int = 0) -> bool:
        """Non-raising variant for loop conditions."""
        try:
            self.check(calls=calls, tokens=tokens)
            return False
        except BudgetError:
            return True

    def record_response(self, response: Response) -> None:
        # Backward-compatible non-reservation path for external integrations.
        with self._lock:
            self.calls += 1
            self.tokens += response.usage.total_tokens
