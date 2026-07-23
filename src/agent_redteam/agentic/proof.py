"""Portable, tamper-evident proof bundles for causal agent findings.

The bundle does not make a trace true. It makes later mutation detectable and
binds the poisoned episode, clean counterfactual, and attribution claim into one
content-addressed artifact that CI or an auditor can verify without rerunning a
probabilistic model.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from typing import Any

SCHEMA_VERSION = "agent-redteam.causal-proof.v1"
_GENESIS = "0" * 64


def build_causal_proof(
    scenario_id: str,
    episode_trace: Any,
    counterfactual_trace: Any,
    attribution: Any,
) -> dict[str, Any]:
    """Bind both traces and the causal claim into a verifiable JSON object."""
    attack = _trace_payload(episode_trace)
    counterfactual = (
        _trace_payload(counterfactual_trace) if counterfactual_trace is not None else None
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "attack_trace": attack,
        "counterfactual_trace": counterfactual,
        "attribution": _attribution_payload(attribution),
    }
    return {**payload, "proof_sha256": _digest(payload)}


def verify_causal_proof(bundle: dict[str, Any]) -> tuple[bool, str]:
    """Verify every event chain and the top-level content address."""
    if bundle.get("schema_version") != SCHEMA_VERSION:
        return False, "unsupported schema_version"
    supplied = bundle.get("proof_sha256")
    if not isinstance(supplied, str):
        return False, "proof_sha256 is missing"

    for field in ("attack_trace", "counterfactual_trace"):
        trace = bundle.get(field)
        if trace is None and field == "counterfactual_trace":
            continue
        if not isinstance(trace, dict):
            return False, f"{field} is not an object"
        valid, reason = _verify_trace(trace)
        if not valid:
            return False, f"{field}: {reason}"

    unsigned = copy.deepcopy(bundle)
    unsigned.pop("proof_sha256", None)
    expected = _digest(unsigned)
    if not hmac.compare_digest(supplied, expected):
        return False, "top-level proof hash mismatch"
    return True, "ok"


def _trace_payload(trace: Any) -> dict[str, Any]:
    previous = _GENESIS
    events: list[dict[str, Any]] = []
    for event in trace.events:
        body = {
            "id": event.id,
            "sequence": event.sequence,
            "kind": event.kind.value,
            "actor": event.actor,
            "data": _jsonable(event.data),
            "parents": list(event.parents),
            "artifact_id": event.artifact_id,
        }
        event_hash = _digest({"previous_event_sha256": previous, "event": body})
        events.append(
            {
                **body,
                "previous_event_sha256": previous,
                "event_sha256": event_hash,
            }
        )
        previous = event_hash
    return {
        "scenario_id": trace.scenario_id,
        "events": events,
        "trace_sha256": previous,
    }


def _verify_trace(trace: dict[str, Any]) -> tuple[bool, str]:
    previous = _GENESIS
    events = trace.get("events")
    if not isinstance(events, list):
        return False, "events is not a list"
    for index, item in enumerate(events):
        if not isinstance(item, dict):
            return False, f"event {index} is not an object"
        if item.get("previous_event_sha256") != previous:
            return False, f"event {index} previous hash mismatch"
        body = {
            key: value
            for key, value in item.items()
            if key not in {"previous_event_sha256", "event_sha256"}
        }
        expected = _digest({"previous_event_sha256": previous, "event": body})
        supplied = item.get("event_sha256")
        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
            return False, f"event {index} hash mismatch"
        previous = expected
    if not hmac.compare_digest(str(trace.get("trace_sha256")), previous):
        return False, "trace root mismatch"
    return True, "ok"


def _attribution_payload(attribution: Any) -> dict[str, Any]:
    if attribution is None:
        return {
            "status": "not_attributed",
            "source_event_ids": [],
            "provenance_path": [],
            "counterfactual_changed": False,
            "explanation": "",
        }
    status = getattr(attribution, "status", "not_attributed")
    return {
        "status": getattr(status, "value", status),
        "source_event_ids": list(getattr(attribution, "source_event_ids", ())),
        "provenance_path": list(getattr(attribution, "provenance_path", ())),
        "counterfactual_changed": bool(
            getattr(attribution, "counterfactual_changed", False)
        ),
        "explanation": str(getattr(attribution, "explanation", "")),
    }


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
