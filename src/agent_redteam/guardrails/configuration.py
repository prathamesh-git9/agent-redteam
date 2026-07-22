"""Load a concrete GuardPipeline from report-recommended YAML/JSON config."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agent_redteam.guardrails.base import GuardPipeline, InputGuardrail, OutputGuardrail
from agent_redteam.guardrails.input_guards import (
    AllowlistGuard,
    EncodingNormalizer,
    InjectionDetector,
)
from agent_redteam.guardrails.output_guards import (
    CanaryScanner,
    ExfilURLBlocker,
    PIIScanner,
    SecretScanner,
)
from agent_redteam.guardrails.tool_guards import ToolCallPolicy


class GuardrailConfigError(ValueError):
    pass


def load_guardrail_config(path: str | Path) -> GuardPipeline:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise GuardrailConfigError("guardrail config must be a mapping")
    return pipeline_from_mapping(data)


def pipeline_from_mapping(data: dict[str, Any]) -> GuardPipeline:
    """Build the exact schema emitted in report recommendation config patches."""
    raw = data.get("guardrails", data)
    if not isinstance(raw, dict):
        raise GuardrailConfigError("'guardrails' must be a mapping")
    input_guards = _input_guards(raw.get("input", ()))
    retrieval_raw = raw.get("retrieval_input")
    retrieval_guards = (
        _input_guards(retrieval_raw) if retrieval_raw is not None else None
    )
    output_guards = _output_guards(raw.get("output", ()))
    tool_guards = []
    if "tool_policy" in raw:
        options = raw["tool_policy"]
        if options is None:
            options = {}
        if not isinstance(options, dict):
            raise GuardrailConfigError("tool_policy must be a mapping")
        allow = options.get("allow", ())
        if "deny" in options:
            tool_guards.append(ToolCallPolicy(allow=allow, deny=options["deny"]))
        else:
            tool_guards.append(ToolCallPolicy(allow=allow))
    known = {"input", "retrieval_input", "output", "tool_policy"}
    unknown = set(raw) - known
    if unknown:
        raise GuardrailConfigError(f"unknown guardrail config keys: {sorted(unknown)}")
    return GuardPipeline(
        input_guards=input_guards,
        retrieval_guards=retrieval_guards,
        output_guards=output_guards,
        tool_guards=tool_guards,
    )


def _names(raw: Any, field: str) -> list[str]:
    if not isinstance(raw, (list, tuple)):
        raise GuardrailConfigError(f"{field} must be a list of guardrail names")
    if not all(isinstance(item, str) for item in raw):
        raise GuardrailConfigError(f"{field} entries must be strings")
    return list(raw)


def _input_guards(raw: Any) -> list[InputGuardrail]:
    factories = {
        "encoding_normalizer": EncodingNormalizer,
        "injection_detector": InjectionDetector,
        "allowlist": AllowlistGuard,
    }
    return _build(_names(raw, "input/retrieval_input"), factories, "input")


def _output_guards(raw: Any) -> list[OutputGuardrail]:
    factories = {
        "canary_scanner": CanaryScanner,
        "secret_scanner": SecretScanner,
        "pii_scanner": PIIScanner,
        "exfil_url_blocker": ExfilURLBlocker,
    }
    return _build(_names(raw, "output"), factories, "output")


def _build(names: list[str], factories: dict, field: str) -> list:
    unknown = set(names) - set(factories)
    if unknown:
        raise GuardrailConfigError(
            f"unknown {field} guardrails: {sorted(unknown)}"
        )
    return [factories[name]() for name in names]
