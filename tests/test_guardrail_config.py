from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agent_redteam.guardrails import (
    GuardrailConfigError,
    load_guardrail_config,
    pipeline_from_mapping,
)


def test_load_complete_guardrail_config(tmp_path: Path) -> None:
    path = tmp_path / "guards.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "guardrails": {
                    "input": ["encoding_normalizer"],
                    "retrieval_input": ["injection_detector"],
                    "output": [
                        "canary_scanner",
                        "secret_scanner",
                        "pii_scanner",
                        "exfil_url_blocker",
                    ],
                    "tool_policy": {"allow": ["search"], "deny": ["send_email"]},
                }
            }
        ),
        encoding="utf-8",
    )

    pipeline = load_guardrail_config(path)

    assert [guard.name for guard in pipeline.input_guards] == ["encoding_normalizer"]
    assert [guard.name for guard in pipeline.retrieval_guards] == [
        "injection_detector"
    ]
    assert len(pipeline.output_guards) == 4
    assert pipeline.tool_guards[0].allow == frozenset({"search"})
    assert pipeline.tool_guards[0].deny == frozenset({"send_email"})


@pytest.mark.parametrize(
    "mapping",
    [
        {"guardrails": []},
        {"guardrails": {"unknown": []}},
        {"guardrails": {"input": "injection_detector"}},
        {"guardrails": {"input": [123]}},
        {"guardrails": {"input": ["does_not_exist"]}},
        {"guardrails": {"output": ["does_not_exist"]}},
        {"guardrails": {"tool_policy": []}},
    ],
)
def test_invalid_guardrail_config_fails_closed(mapping) -> None:
    with pytest.raises(GuardrailConfigError):
        pipeline_from_mapping(mapping)


def test_tool_policy_uses_default_deny_when_omitted() -> None:
    pipeline = pipeline_from_mapping({"guardrails": {"tool_policy": {}}})

    assert "exec" in pipeline.tool_guards[0].deny
