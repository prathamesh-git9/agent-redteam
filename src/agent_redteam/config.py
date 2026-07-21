"""Configuration loading and — the part that matters most — authorization.

The single most important line of code in this project is the one that refuses
to run against a target the operator has not asserted they own. A red-team tool
that will happily fire prompt-injection payloads at an arbitrary URL is an abuse
tool. The gate here is what keeps this a defensive instrument: nothing in the
runner dispatches a probe until ``assert_authorized`` has passed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class AuthorizationError(RuntimeError):
    """Raised when a run is attempted against an unauthorized target.

    This is intentionally not a subclass of a broad, easily-caught exception:
    swallowing it silently would defeat its entire purpose, so callers must
    handle it explicitly or crash.
    """


@dataclass
class TargetConfig:
    name: str
    kind: str
    # Free-form adapter options (base_url, model, headers, request template...).
    options: dict[str, Any] = field(default_factory=dict)
    # Responsible-use gate. Both must be satisfied before any probe is sent.
    authorized: bool = False
    allowlist: list[str] = field(default_factory=list)


@dataclass
class RunConfig:
    target: TargetConfig
    suite: str = "default"
    concurrency: int = 4
    max_calls: int = 500
    max_tokens: int = 500_000
    max_seconds: float = 600.0
    fail_threshold: float = 7.0
    judge_model: str | None = None
    baseline_path: str | None = None


def _host_of(target: str) -> str:
    """Extract a comparable host from a URL or bare host string.

    Accepts both ``https://api.example.com/v1`` and ``api.example.com`` so a
    config author can allowlist either form without surprises.
    """
    parsed = urlparse(target if "//" in target else f"//{target}")
    return (parsed.hostname or target).lower()


def _is_loopback(host: str) -> bool:
    if host in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_authorized(cfg: TargetConfig, endpoint: str | None) -> None:
    """Fail closed unless the operator has authorized *this* endpoint.

    Rules, in order:

    1. ``authorized`` must be explicitly true. The default is false, so a config
       that simply forgets the flag is refused rather than silently permitted.
    2. If the target has a network endpoint, its host must appear on the
       allowlist. Loopback hosts are allowed implicitly because testing an agent
       you are running locally is the common, safe case and forcing operators to
       allowlist ``127.0.0.1`` every time trains them to rubber-stamp the gate.
    3. An empty allowlist for a *remote* endpoint is refused: "authorized but
       against nothing in particular" is exactly the blank cheque we must not
       sign.
    """
    if not cfg.authorized:
        raise AuthorizationError(
            f"Target {cfg.name!r} is not authorized. Set authorized: true in the "
            "target config to confirm you own or have written permission to test it."
        )
    if endpoint is None:
        return  # in-process callable / fake target: no network, nothing to allowlist
    host = _host_of(endpoint)
    if _is_loopback(host):
        return
    allow = {_host_of(a) for a in cfg.allowlist}
    if not allow:
        raise AuthorizationError(
            f"Target {cfg.name!r} points at remote host {host!r} but the allowlist "
            "is empty. Add the host to 'allowlist' to confirm scope of testing."
        )
    if host not in allow:
        raise AuthorizationError(
            f"Host {host!r} is not on the allowlist for target {cfg.name!r}: "
            f"{sorted(allow)}. Refusing to send probes off-scope."
        )


def load_run_config(path: str | Path) -> RunConfig:
    """Load a run config from a YAML file, applying defaults and validation."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return parse_run_config(data)


def parse_run_config(data: dict[str, Any]) -> RunConfig:
    """Build a RunConfig from an already-parsed mapping.

    Shared by the YAML loader and the HTTP server so a config posted as JSON is
    validated by exactly the same code path as one read from disk.
    """
    raw_target = data.get("target") or {}
    target = TargetConfig(
        name=raw_target.get("name", "unnamed"),
        kind=raw_target.get("kind", "openai_chat"),
        options=raw_target.get("options", {}),
        authorized=bool(raw_target.get("authorized", False)),
        allowlist=list(raw_target.get("allowlist", [])),
    )
    run = data.get("run", {})
    return RunConfig(
        target=target,
        suite=run.get("suite", "default"),
        concurrency=int(run.get("concurrency", 4)),
        max_calls=int(run.get("max_calls", 500)),
        max_tokens=int(run.get("max_tokens", 500_000)),
        max_seconds=float(run.get("max_seconds", 600.0)),
        fail_threshold=float(run.get("fail_threshold", 7.0)),
        judge_model=run.get("judge_model"),
        baseline_path=run.get("baseline_path"),
    )
