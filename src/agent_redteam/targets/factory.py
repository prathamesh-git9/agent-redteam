"""Build a concrete Target from a parsed TargetConfig.

Kept separate from the CLI so a programmatic caller can construct a target from
config without importing typer, and so adding a new adapter is a one-line change
here rather than a scattered edit.
"""

from __future__ import annotations

from agent_redteam.config import TargetConfig
from agent_redteam.targets.base import Target
from agent_redteam.targets.fake import FakeTarget
from agent_redteam.targets.http import http_from_options
from agent_redteam.targets.openai_chat import target_from_options


def build_target(cfg: TargetConfig) -> Target:
    if cfg.kind == "openai_chat":
        return target_from_options(cfg.name, cfg.options)
    if cfg.kind == "http":
        return http_from_options(cfg.name, cfg.options)
    if cfg.kind == "fake":
        # A fake target is only useful for self-tests/demos; it ignores options.
        return FakeTarget(name=cfg.name)
    raise ValueError(
        f"unknown target kind {cfg.kind!r} (expected openai_chat, http, callable, fake)"
    )
