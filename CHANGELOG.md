# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to adhere
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
