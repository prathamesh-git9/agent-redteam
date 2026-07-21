# Contributing

Thanks for your interest in improving `agent-redteam`.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,llm,server,mcp]"
pytest              # entire suite runs offline (FakeTarget/FakeJudge), no API key
ruff check .
```

## Adding an attack

Attacks live under `src/agent_redteam/attacks/`, one module per category. An
attack is a pure payload generator — it must not perform I/O.

1. Give it a **stable, dotted id** (e.g. `pi.new_trick.v1`). Ids appear in
   reports and regression baselines, so never reuse or repurpose one.
2. Register it with `@register_attack(id, category, tags=[...], summary=...)`.
   Tag one fast, deterministic variant per category `smoke`.
3. Build probes that plant a canary (`ctx.mint_canary(...)`) wherever the attack
   tries to make the target leak something, and set the `OracleSpec` so the
   **cheapest decisive oracle** fires — prefer a canary hit, then a signature,
   and reach for the LLM judge only when success is genuinely semantic.
4. Add a fixture in `tests/test_attacks.py` proving the attack succeeds against a
   deliberately-vulnerable `FakeTarget` and is blocked by a hardened one.

## Adding a guardrail

Guardrails live under `src/agent_redteam/guardrails/`. Implement the relevant
protocol (`InputGuardrail` / `OutputGuardrail` / `ToolGuardrail`), register it,
and add a test with **both** a true-catch case and a false-positive-safety case
— a guardrail that blocks benign traffic is worse than no guardrail.

## Style

- `from __future__ import annotations` at the top of every module.
- Docstrings explain **why**, not what. Comment only where a reader would
  otherwise be puzzled.
- Line length ≤ 90. Run `ruff check .` before pushing.
- Keep the three core protocols small: attacks don't do I/O, targets don't
  judge, oracles don't generate payloads.

## Responsible use

New attacks must be adversarial *inputs* that reveal a weakness via a synthetic
canary or a stable signature. Do not contribute payloads whose only purpose is
to attack systems the operator does not own. See [SECURITY.md](SECURITY.md).
