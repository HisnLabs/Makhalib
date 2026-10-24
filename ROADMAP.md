# Makhalib (مخالب — "claws")

A Rust LLM red-teaming framework: the scanner engine of **augustus/garak** (probes → buffs →
target → detectors → report) fused with the multi-turn orchestration of **PyRIT**
(attacker / target / judge), driven by a **natural-language planner** so an operator describes
intent instead of writing code.

> For **authorized** LLM security testing only. Every run carries an explicit authorization gate.

---

## The problem we are correcting

garak, augustus and PyRIT are powerful but share the same tax: **to do anything custom you must
write and ship code.**

| Pain in garak / augustus / PyRIT | Makhalib correction |
|---|---|
| **New probe = code.** garak: Python `Probe` subclass. augustus: Go struct + `init()` + `registry.RegisterProbe()`, then recompile. PyRIT: Python wiring. | **Probes are data.** A probe is a declarative spec (YAML/JSON). Add one by dropping a file — or by describing it in natural language and letting the planner synthesize the spec. No recompile, no subclass. |
| **New detector = code.** Hard-coded keyword lists / judge wiring. | **Detectors are data.** keyword/regex/refusal/LLM-judge detectors are configured declaratively; a judge rubric is plain prose. |
| **New target/provider = code.** Write a generator class per API. | **Targets are data.** A generic REST target is configured with request/response templates; built-ins (Ollama, OpenAI-compat, Anthropic) are presets. Any HTTP LLM works with zero code. |
| **New multi-turn strategy = code.** PyRIT orchestrators are Python classes. | **Strategies are data.** Multi-turn harness (attacker/target/judge, escalation) is parameterized by a declarative spec. |
| **Steep learning curve** — learn the plugin API, flags, YAML schema before first run. | **Natural language front-end.** "Test my local Ollama llama3 for jailbreaks and prompt injection, thorough" compiles to a plan. |
| **Non-reproducible / opaque runs** — flags scattered across shell history. | **The plan is the artifact.** Every NL request compiles to a saved, versioned, human-readable `ScanPlan` (YAML). Re-running the plan is deterministic; the LLM only authors the plan, which the user reviews and can hand-edit. |
| **Python footprint** — heavy deps, slow start, env hell. | **Single static Rust binary.** Fast start, no runtime. |
| **Footguns** — point it anywhere, no guardrails. | **Authorization gate + target allowlist** are first-class and required to execute. |

### Four principles that make "no code" real

1. **Everything is data.** Target, probe, detector, buff, harness/strategy are all declarative
   specs loaded at runtime from a catalog. Built-ins are just bundled data. Custom = one more file,
   or one NL description the brain turns into a file.
2. **The plan is the artifact.** NL → (LLM planner) → `ScanPlan` (reviewable, editable YAML) →
   deterministic engine. This gives both zero-code ergonomics *and* testability/reproducibility:
   the engine is tested against plans; the planner is tested against its output schema with a
   mocked LLM; non-determinism is confined to plan authoring, which a human approves.
3. **The LLM is the DNA.** The model is not just a one-shot planner — it is the adaptive brain of
   the tool. It *understands the kind of attack needed* from the operator's intent and the target's
   behavior, *selects or synthesizes* the right probe class, and *steers each subsequent turn*. The
   same brain serves three roles PyRIT splits across code: **attacker** (crafts the next move),
   **planner** (compiles intent → plan), and can back the **judge** (scores responses). Targets,
   probes and detectors are the inert body; the LLM is the DNA that decides what the body does.
4. **Semantic memory closes the loop.** Every attempt — prompt, target response, judge verdict,
   what worked and what was refused — is embedded and written to a **semantic memory** store. Before
   each turn the orchestrator retrieves the semantically relevant history and feeds it to the brain,
   so multi-turn is *consequent*: coherent, adaptive escalation informed by feedback, not a fixed
   script. This is the engine behind PyRIT-style Crescendo/GOAT done right — the conversation
   *remembers and reacts*. Memory is persisted per engagement so a campaign resumes with its
   learned context intact.

---

## The churn-drivers — full scorecard

The reasons people adopt these tools and then leave, and where Makhalib stands on each.
✅ = addressed by the design · ➕ = explicit roadmap item below.

| # | Why people leave | Makhalib |
|---|---|---|
| 1 | **Static, stale attack corpora.** Fixed DAN/jailbreak lists get patched within weeks; the tool stops finding anything and users wrongly conclude "my model is safe." | ✅/➕ **LLM-as-DNA** generates/mutates attacks adaptively; we make **generative/mutational probes a first-class probe type** (P5). |
| 2 | **Weak adaptivity / no memory across turns.** Single-shot or scripted multi-turn that can't carry context or escalate. | ✅ **Semantic memory + consequent multi-turn** (P6). |
| 3 | **False positives/negatives from crude detectors.** String-match scoring floods operators with noise. | ➕ **Confidence scores + multi-detector voting + LLM-judge rubric + automatic dedup/triage** (P5). |
| 4 | **Can't test real systems** — RAG apps, tool-using agents, MCP servers, authenticated endpoints, multimodal. | ➕ **Data-driven REST/agent/MCP/multimodal target specs**, zero code (P4). |
| 5 | **Cost / token blowups.** Runs silently rack up spend; a surprise bill kills adoption. | ➕ **Per-run token/cost budget + pre-run estimate + hard stop** in the plan (P8). |
| 6 | **Reproducibility & CI.** Notebook-driven, nondeterministic, can't gate a pipeline. | ✅/➕ **Plan-as-artifact** (reproducible) + **CI mode**: exit codes, JUnit output, pass/fail thresholds, regression baselines (P7). |
| 7 | **Reporting isn't actionable.** Raw hit dumps, no severity, no remediation, no framework mapping. | ➕ **Severity/CVSS + remediation + OWASP LLM Top 10 & MITRE ATLAS mapping + coverage model** (P7). |
| 8 | **Install / ops friction.** Python env hell, heavy ML deps, slow start. | ✅ **Single static Rust binary.** |
| 9 | **Governance / safety.** No scope enforcement, no audit trail — risky for orgs to authorize. | ✅/➕ **Authorization gate** (done) + **tamper-evident audit log + target allowlist** (P8). |
| 10 | **No resumability.** Long runs die partway; primitive rate-limit handling. | ➕ **Persisted memory per engagement = resumable campaigns** + rate-limit/retry decorators (P6). |
| 11 | **Sharing customizations = sharing code.** A new probe is a code PR. | ✅ **Shareable YAML spec** anyone can drop in. |
| 12 | **Model-only scope.** garak/augustus/PyRIT test the model; the guardrails and the model artifact go untested. | ➕ **Whole-stack red-teaming**: model, **guardrails** (bypass/over-block metrics), full pipeline, and **model-artifact** scanning (P4, P7, P9). |

---

## Architecture (mirrors augustus, idiomatic async Rust)

| Layer | augustus analog | Makhalib module | Customize by |
|---|---|---|---|
| Domain types | `pkg/attempt`, `pkg/types` | `core` | — |
| Plugin traits (async) | `Prober`/`Generator`/`Detector`/`Transformer`/`Harness` | `traits` | — |
| Typed registries | `pkg/registry` | `registry` | — |
| **Declarative plan** | (augustus YAML templates, partial) | `plan` | **NL or YAML** |
| Targets | `generators/` | `generators` (mock, rest, ollama, openai, anthropic) | **YAML preset/template** |
| Probes | `probes/` | `probes` (+ `catalog/`) | **YAML spec / NL** |
| Detectors | `detectors/` | `detectors` | **YAML spec / NL rubric** |
| Buffs | `buffs/` | `buffs` | **YAML** |
| Harnesses / multiturn | `harnesses/`, `multiturn/` | `harnesses` | **YAML spec** |
| **Engine (concurrent)** | `pkg/scanner` | `scanner` — bounded worker pool, streaming results, backpressure; **memory-efficient, multithreaded** (no whole-run buffering) | flags/plan |
| Output | `pkg/output` | `report` | — |
| **Brain (LLM-as-DNA)** | — (PyRIT splits across code) | `brain` — one model backing attacker / planner / judge | — |
| **Semantic memory** | PyRIT `memory` (relational) | `memory` — embeddings store; feedback recall steers each turn | — |
| **NL planner** | — | `planner` (LLM-backed, Ollama/Anthropic) | — |
| CLI | `cmd/augustus` | `cli` (`scan`, `plan`, `list`, `version`) | — |

### Concurrency & memory model (the "simple, memory-efficient, multithreaded" engine)

- Probes/prompts are consumed as a **stream of attempts**, run through a **bounded worker pool**
  (`tokio` tasks with a semaphore, size = plan concurrency), results flushed to the reporter as
  they complete — the full result set is never held in memory at once.
- Shared state is `Arc<dyn Trait + Send + Sync>`; attempts move by value through channels, so there
  is no cross-thread cloning of large buffers and no lock on the hot path.
- Rate-limit + retry are decorators around the target, independent of the pool.

---

## Integrations catalog

The open-source tools, datasets and techniques we pull from — attack generation, evasion transforms,
benchmarks, guardrails, secrets/PII/supply-chain, and metrics/methods — are catalogued, mapped to
plug-points and phases, in [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md). It aligns with the
HisnLabs "AI Security Testing Framework" (COV-01/02/03 coverage, OWASP/ATLAS/NIST crosswalk, agentic
controls APE/BLR/SKL, OPA/OpenAPPA policy) and the Augustus probe/metrics deck (confusion matrix,
F-beta, ROC, judge reliability).

## Phases (each ships green tests before the next)

- **P0 — Foundation.** cargo project; `core` domain types (`Attempt`, `Conversation`, `Message`,
  `Score`, `Verdict`); typed `registry`. *Pure, offline, fully unit-tested.*
- **P1 — The plan keystone.** `ScanPlan` schema with authorization gate, declarative target/probe/
  detector/harness specs; YAML round-trip; validation. This is the contract every other layer
  speaks. *Pure, offline.*
- **P2 — NL planner (LLM-backed).** NL → `ScanPlan` via an LLM (Ollama local first) emitting
  strict JSON; schema-validated; `plan` subcommand shows the compiled plan for review. Tested with
  a **mock LLM client** returning canned JSON + deterministic schema validation.
- **P3 — Engine (concurrent, memory-efficient).** `traits`, mock generator, deterministic detector,
  probewise harness, `scanner` with a bounded worker pool + streaming results → end-to-end scan on
  the mock target, offline-tested. *(fanned out to Sonnet agents against the P0/P1 contract)*
- **P4 — Real targets (zero code).** Ollama first, then OpenAI-compat, Anthropic, generic REST,
  **tool-using agents, MCP servers, authenticated endpoints, multimodal** — all data-configured.
  Plus **guardrail targets** (moderation / jailbreak classifiers / prompt firewalls like Guardrino,
  Llama Guard) and **pipeline targets** (guardrail + model composed) — a target may return a
  `GuardrailVerdict {allow|block|flag, labels, score, latency}` instead of a completion, and the
  scanner scores the verdict. HTTP mocked in tests. *(churn-drivers #4, #12)*
- **P5 — Data catalog + smarter attacks & scoring.** Probe/detector/buff specs loaded from YAML;
  starter catalog ported from augustus's **published** set as data (not hand-authored novel attacks);
  **generative/mutational probes as a first-class type** (#1); **LLM-judge detector + confidence
  scores + multi-detector voting + automatic finding dedup/triage** (#3); brain can synthesize + save
  a spec from NL. Adds InferGuard-style layers as data: **encoding-evasion buffs** (Unicode / Morse /
  emoji / base64 obfuscation) and **output detectors** for secret/API-key leaks, PII and toxicity.
  *(Shipped: `secrets.Secrets` gitleaks-style ruleset, `secrets.Gitleaks` external-CLI detector, and
  `pii.PII` with Luhn-checked cards.)*
- **P6 — Brain + semantic memory + resumable multiturn.** `brain` (LLM-as-DNA) backing
  attacker/planner/judge; `memory` embeddings store; attacker/target/judge orchestrator whose each
  turn is steered by semantic recall of prior feedback (#2); memory **persisted per engagement so a
  campaign resumes**, with rate-limit/retry decorators (#10).
- **P7 — Actionable reporting + CI.** table/json/jsonl/html reports with **severity/CVSS,
  remediation, OWASP LLM Top 10 + MITRE ATLAS mapping, and a coverage model** (#7); a **guardrail
  efficacy scorecard** (bypass / detection / over-block rate, driven by a benign false-positive
  corpus); **CI mode** — exit codes, JUnit output, pass/fail thresholds, regression baselines (#6).
- **P8 — Governance & budget.** Per-run **token/cost budget + estimate + hard stop** (#5);
  **tamper-evident audit log + target allowlist** on top of the authorization gate (#9); CLI polish.
- **P9 — Supply-chain / model-artifact scanning.** Scan model files before trusting them
  (InferGuard-style): malicious **pickle** detection, MIME sniffing, safetensors checks, and
  **weight-poisoning / backdoor** signals — a static axis distinct from inference-time probing.
  Activation-tracing / interpretability-based backdoor detection is a research stretch (likely a
  Python sidecar, since it needs a model runtime).

**TDD discipline:** red (failing test) → green (minimal impl) → refactor, every module.
Honesty gate: reported results reflect the real `cargo test` output.

## Status
- [x] P0 Foundation — domain types, typed registry *(tested)*
- [x] P1 Plan keystone — `ScanPlan` + authorization gate *(tested)*
- [x] P3 Engine — `Probewise` concurrent harness *(tested)*
- [x] Probe / detector / generator layers (data-driven) *(tested; 57 tests green)*
- [ ] P2 NL planner (LLM-backed, Ollama first)
- [ ] P4 Real targets — LLMs, **guardrails & pipelines**, agents/MCP, multimodal
- [ ] P5 Data catalog + generative probes + LLM-judge + encoding-evasion buffs + secret/PII/toxicity detectors
- [ ] P6 Brain + semantic memory + resumable multiturn
- [ ] P7 Actionable reporting (OWASP/ATLAS, coverage) + **guardrail efficacy scorecard** + CI mode
- [ ] P8 Governance & budget (audit log, allowlist, cost caps)
- [ ] P9 Supply-chain / model-artifact scanning (pickle, weight-poisoning)
