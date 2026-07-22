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

from agent_redteam.types import Response


class BudgetError(RuntimeError):
    """Raised when an action would exceed the configured call/token/time budget.

    Deliberately not a subclass of a broad, easily-swallowed exception: a run
    that hit its budget still produced partial, useful results, so callers are
    expected to catch this explicitly and record it, not ignore it.
    """


@dataclass
class BudgetLedger:
    max_calls: int
    max_tokens: int
    max_seconds: float
    started: float = field(default_factory=time.perf_counter)
    calls: int = 0
    tokens: int = 0

    def check(self, *, calls: int = 1, tokens: int = 0) -> None:
        """Raise if performing an action of the given size would exceed a cap.

        ``calls``/``tokens`` describe the action about to happen so a caller can
        test-ahead (the adaptive engine asks "do I have budget for one more
        target call?" before spending it). The time cap is checked on every call
        because wall-clock is the one budget that ticks without any action.
        """
        if self.calls + calls > self.max_calls:
            raise BudgetError(f"max_calls {self.max_calls} reached")
        if self.tokens + tokens > self.max_tokens:
            raise BudgetError(f"max_tokens {self.max_tokens} reached")
        if time.perf_counter() - self.started >= self.max_seconds:
            raise BudgetError(f"max_seconds {self.max_seconds} reached")

    def would_exceed(self, *, calls: int = 1, tokens: int = 0) -> bool:
        """Non-raising variant for loop conditions."""
        try:
            self.check(calls=calls, tokens=tokens)
            return False
        except BudgetError:
            return True

    def record_response(self, response: Response) -> None:
        self.calls += 1
        self.tokens += response.usage.total_tokens
