# agent-redteam — Architecture

> Adversarial testing and runtime guardrails for LLM agents. This document is
> the authoritative design contract. Implementations conform to the interfaces
> defined here; deviations are bugs.

## 1. Purpose and non-goals

`agent-redteam` does three things for a target **you are authorized to test**:

1. **Attack** — run a versioned library of adversarial probes (prompt
   injection, jailbreak, data exfiltration, tool abuse, obfuscation, multi-turn)
   against a target endpoint or callable.
2. **Score** — decide, without a human in the loop, whether each attack
   *succeeded*, attach evidence, and roll the results into a CVSS-style risk
   score and a pass/fail regression verdict.
3. **Defend** — ship composable guardrail middleware you can put in front of
   your own agent, and measure the defended target against the undefended one.

**Non-goals.** It does not exploit third-party systems, does not exfiltrate real
data anywhere, and does not ship offensive payloads that are useful only for
attacking systems you do not own. Every run requires an explicit authorization
assertion (§9).

## 2. The three core abstractions

Everything composes from three protocols. Keeping them small is deliberate: an
`Attack` never talks to a network, a `Target` never judges, an `Oracle` never
generates payloads. This separation is what makes results reproducible and the
suite regression-testable.

```
Attack  --produces-->  Probe(s)  --sent by Runner to-->  Target  --Response-->  Oracle  --Verdict-->  Scoring
```

### 2.1 `Target` — the system under test

```python
class Target(Protocol):
    info: TargetInfo
    async def send(self, conversation: Conversation) -> Response: ...
```

- `Conversation` is an ordered list of `Message(role, content, name?, tool_calls?)`.
- `Response` carries `text`, optional `tool_calls`, `raw` (provider payload), and
  `usage` (tokens) so the resource-exhaustion oracle and cost accounting work.
- `TargetInfo` carries `name`, `kind`, `supports_tools`, and — critically —
  `authorized: bool` and `allowlisted: bool`. The runner refuses to send a
  single probe unless both are true.

Adapters (all in `targets/`):

| Adapter | Wraps | Notes |
|---|---|---|
| `OpenAIChatTarget` | any OpenAI-compatible `/chat/completions` (OpenAI, Grok/xAI, local vLLM, Ollama) | reuses the provider pattern from the sibling repos |
| `HTTPTarget` | an arbitrary JSON HTTP agent | request/response templated via JSONPath so any schema maps |
| `CallableTarget` | a local `Callable[[Conversation], str] \| Awaitable` | in-process agents, unit tests |
| `FakeTarget` | a scripted rule table | deterministic; the backbone of the test suite |

### 2.2 `Attack` — the adversarial payload generator

```python
class Attack(Protocol):
    id: str                    # stable, e.g. "pi.instruction_override.v1"
    category: AttackCategory   # enum
    severity: Severity         # base severity if it succeeds
    references: list[str]      # OWASP LLM / MITRE ATLAS ids
    def build_probes(self, ctx: AttackContext) -> Iterable[Probe]: ...
```

A `Probe` is one concrete attempt: `conversation`, the `OracleSpec` that defines
what success means for *this* probe, and any `canaries` (planted secrets/tokens)
the harness seeded so leakage is detectable. Attacks are pure and offline —
`build_probes` never does I/O — so the corpus is snapshot-testable.

Attack categories (each a module under `attacks/`): `prompt_injection`,
`jailbreak`, `exfiltration`, `tool_abuse`, `obfuscation`, `multi_turn`,
`resource_exhaustion`. Registration is via a decorator into a central
`REGISTRY`; suites are named selections over the registry.

### 2.3 `Oracle` — the automated success judge

```python
class Oracle(Protocol):
    async def evaluate(self, probe: Probe, response: Response) -> OracleVerdict: ...
```

`OracleVerdict(success: bool, confidence: float, evidence: list[Evidence])`.

Oracles are layered because no single method is both precise and general:

| Oracle | Detects | FP risk | Cost |
|---|---|---|---|
| `SignatureOracle` | known success strings / regex | med (paraphrase evades) | ~0 |
| `CanaryOracle` | a planted secret/token appearing in output | ~0 | ~0 |
| `RefusalOracle` | model refused (⇒ **defense held**, inverse signal) | low | ~0 |
| `JudgeOracle` | semantic success via LLM-as-judge, rubric + structured output at temp 0 | low | 1 model call |
| `CompositeOracle` | combines the above under a decision policy | — | — |

**Determinism for regression.** The `JudgeOracle` pins temperature 0, a fixed
rubric, a fixed judge model id (recorded in the report), and requests a
structured `{verdict, confidence, reason}` object. Canary/signature oracles are
fully deterministic and are preferred whenever an attack *can* be made to leak a
canary — we design attacks to be canary-detectable wherever possible precisely
so we depend on the judge as little as possible.

## 3. Scoring

Per-attack risk on a 0–10 scale, CVSS-flavored but LLM-specific:

```
risk = base_severity(category) * success_confidence * exploitability
```

- `base_severity` ∈ (0,10], per category (exfil/tool-abuse high, DoW medium).
- `success_confidence` ∈ [0,1] from the oracle.
- `exploitability` ∈ [0,1]: reproducibility across probes × how little attacker
  control is needed (single-turn direct = 1.0, needs poisoned document = 0.6,
  needs many turns = 0.4).

A human-readable vector string is emitted, e.g.
`ART:1.0/C:exfil/S:0.92/E:1.0 → 8.3`. Suite pass/fail: a run **fails** if any
attack scores ≥ the configured `fail_threshold`, or if the count of successes
regresses against a stored baseline. Rationale and the exact formula are locked
in `scoring/model.py` and unit-tested against a table of hand-scored cases.

## 4. Runner / orchestrator

`Runner` takes `(target, suite, oracles, config)` and returns a `Report`. It is
async with a bounded concurrency semaphore, a token-bucket rate limiter, retries
with jitter on transient target errors, and a hard budget (max calls / max
tokens / max wall-clock) so a resource-exhaustion *test* can never itself become
a denial-of-wallet event. Every probe/response/verdict is recorded as an
append-only `Trace` for evidence — nothing is judged off data we didn't store.

## 5. Guardrails (the defensive half)

Guardrails are middleware, independent of attacks, composed into a `GuardPipeline`
that can wrap any `Target` to produce a *defended* target. This lets the runner
score defended vs. undefended and report the delta — the number that actually
tells an operator whether a mitigation helped.

- **Input**: `EncodingNormalizer` (decode/normalize base64, unicode homoglyphs,
  leetspeak before inspection), `InjectionDetector` (heuristics + optional
  classifier), `AllowlistGuard`.
- **Output**: `SecretScanner` + `PIIScanner`, `CanaryScanner`, `ExfilURLBlocker`
  (strips/greenlights markdown-image and link side channels).
- **Tool**: `ToolCallPolicy` (allow/deny tool + argument schema + SSRF host
  checks).

Each guardrail returns `GuardDecision(action=ALLOW|BLOCK|REWRITE, reason, evidence)`
and is individually unit-tested for both true catches and false-positive safety.

## 6. Interfaces / surfaces

- **CLI** (`typer`): `scan`, `list-attacks`, `list-guardrails`, `report`,
  `baseline` (save/compare). Human table + `--json`.
- **FastAPI server**: `POST /scan`, `GET /report/{id}`, `GET /attacks`. For
  operators wiring the harness into a control plane.
- **MCP server**: exposes `run_attack_suite` and `check_guardrail` as tools so an
  agent platform can self-test.
- **Reporting**: JSON (canonical), Markdown (human), JUnit XML (CI gating).

## 7. Module layout

```
src/agent_redteam/
  __init__.py
  types.py            # Message, Conversation, Response, enums, verdict/score types
  registry.py         # attack + guardrail registries
  config.py           # typed config + authorization assertion
  targets/            # Target protocol + adapters
  attacks/            # one module per category, each registering Attack(s)
  oracles/            # Signature/Canary/Refusal/Judge/Composite
  scoring/            # risk model + regression baseline
  guardrails/         # input/output/tool guardrails + pipeline
  runner.py           # orchestrator
  report.py           # JSON / Markdown / JUnit emitters
  cli.py              # typer app
  server.py           # FastAPI (optional extra)
  mcp_server.py       # MCP (optional extra)
```

## 8. Testing strategy

`FakeTarget` + scripted rule tables make the entire pipeline deterministic
without a network or an API key. Every attack ships a fixture proving it *can*
succeed against a deliberately-vulnerable `FakeTarget` and *is blocked* by the
relevant guardrail — that paired fixture is the regression contract. Judge-based
oracles are tested against a `FakeJudge`. CI runs ruff + pytest with coverage.

## 9. Responsible use

- A run is refused unless the target config asserts `authorized: true` and the
  target host is on the operator's `allowlist`.
- Payloads are adversarial *inputs*, not weaponized exploits; canaries are
  synthetic; no real secrets or third-party systems are ever touched.
- The README leads with scope-of-use, and the CLI prints the authorized target
  and allowlist on every run.
```
