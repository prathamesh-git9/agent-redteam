# Security & Responsible Use

`agent-redteam` is a **defensive** tool for assessing and hardening LLM agents
you own or are explicitly authorized to test. Please use it accordingly.

## Scope of use

- **Only test systems you own or have written permission to assess.** The tool
  enforces this mechanically: a run is refused unless the target config asserts
  `authorized: true` and the target host is on the operator's `allowlist`
  (loopback is permitted implicitly for local testing). See
  `src/agent_redteam/config.py::assert_authorized`.
- The attack corpus contains adversarial **inputs**, not weaponized exploits.
  Canaries are synthetic, high-entropy tokens (prefixed `ART-`); no real
  secrets, credentials, or third-party systems are ever used or contacted.
- The "exfiltration" attacks demonstrate that a data channel *exists* by leaking
  a planted canary back to the operator. They do not send data anywhere.

## What this tool is not

It is not a service for attacking arbitrary endpoints, and it deliberately ships
no capability to do so. If you are looking to test a system you do not control,
you are outside the intended and supported use of this project.

## Reporting a vulnerability

If you find a security issue **in agent-redteam itself** (for example, a way the
authorization gate could be bypassed, or a guardrail that fails open):

1. Do **not** open a public issue.
2. Email the maintainer or open a private security advisory on GitHub.
3. Include a minimal reproduction and the version/commit.

We aim to acknowledge reports within a few days.

## Coordinated disclosure for findings against your own systems

Findings this tool produces against *your* agent are yours. If your agent
integrates a third-party model or service and you believe a finding reflects a
weakness in that upstream provider, please report it to that provider through
their disclosure process.
