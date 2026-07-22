# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to adhere
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Agent/RAG episode harness** - opt-in `EpisodeTarget` scenarios exercise
  poisoned retrieved documents and tool execution as a resettable multi-step
  system, not a chat transcript. Findings contain typed provenance events,
  deterministic security-invariant evidence, and clean-twin causal attribution.
- **Pre-execution agent guard hooks** - existing input/tool guardrails now run
  at retrieval consumption and immediately before a tool executor. A blocked
  call cannot produce a side effect. `CallableEpisodeTarget` and
  `EpisodeInstrumentation` provide the production integration seam; the safe
  `FakeAgentTarget` and `examples/agentic_rag_poc.py` provide an offline proof.
- **Actionable findings** - successful attacks receive evidence-linked,
  machine-readable guardrail configuration recommendations; related probes are
  deduplicated into deterministic root-cause groups in JSON reports.
- **Agentic CLI/config support** - `run.agentic`, `run.seed`, `--agentic`, the
  `tag:agentic` scenario suite, and `fake_agent` target. Agentic execution stays
  behind the existing authorization gate, shared call/token/time budget, and
  dry-run side-effect default.
- **Atomic budget reservations** close the concurrent check/send race. The
  refusal-gated oracle also avoids semantic judges when deterministic evidence
  decides and treats canary/tool facts as stronger than refusal wording.

- **Bounded adaptive attack engine** — attacks can now run as a closed
  refinement loop: an attacker LLM reads the target's real response and mutates
  the next payload toward the oracle's success criterion (PAIR / Crescendo
  strategies), instead of firing a fixed payload once. Opt-in via
  `scan --adaptive --attacker-model <id>`; still gated by the same authorization
  check and metered by a shared budget ledger so it can never runaway-spend.
  Adaptive findings carry a full step-by-step `trace` in the report, so they are
  as auditable as static ones. Verified live: it found a jailbreak bypass on a
  real model that the static suite did not.
- `OpenAIJudge` — a production LLM-as-judge for semantic success oracles, wired
  into the CLI via `scan --judge-model` (with `--judge-base-url` /
  `--judge-key-env`). Temperature-0, strict-JSON rubric, and fail-safe: any
  transport or parse error scores the attack as not successful.
- Offline unit tests for the target adapters, the CLI, and the judge, raising
  coverage to 90%.
- A PEP 561 `py.typed` marker so downstream users get the shipped type hints.

## [0.1.0]

Initial release.

### Added

- **Core engine** — provider-agnostic `Target` / `Attack` / `Oracle` protocols,
  a deterministic risk-scoring model with a recomputable vector string, and an
  async `Runner` with bounded concurrency, a rate limiter, and a hard
  call/token/time budget.
- **Authorization gate** — runs are refused unless the target asserts
  `authorized: true` and its host is allowlisted (loopback exempt).
- **Attack corpus** — prompt injection, jailbreak, exfiltration, tool abuse,
  obfuscation, multi-turn crescendo, and (opt-in) resource exhaustion, each
  carrying OWASP-LLM / MITRE ATLAS references and a vulnerable/hardened fixture.
- **Layered oracles** — canary, signature, refusal (inverse signal), tool-abuse
  (with SSRF evidence), and an LLM judge, combined under a refusal-gated policy.
- **Guardrails** — encoding normalizer, injection detector, secret/PII/canary
  scanners, exfil-URL blocker, and tool-call policy, composable into a pipeline
  that wraps any target so defended and undefended runs can be compared.
- **Interfaces** — `typer` CLI (`scan`, `list-attacks`, `list-guardrails`,
  `baseline`, `version`), an optional FastAPI server, and an MCP server.
- **Reporting** — JSON (canonical), Markdown, and JUnit XML, plus regression
  baselines that fail CI when a previously-blocked attack starts succeeding.
- Docker image, GitHub Actions CI (Python 3.11–3.13), and worked examples.

[Unreleased]: https://github.com/prathamesh-git9/agent-redteam/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/prathamesh-git9/agent-redteam/releases/tag/v0.1.0
