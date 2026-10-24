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
- **P4 — Real targets.** Ollama first, then OpenAI-compat, Anthropic, generic REST (data-configured).
  HTTP mocked in tests.
- **P5 — Data catalog.** Probe/detector/buff specs loaded from YAML; starter catalog ported from
  augustus's **published** set as data (not hand-authored novel attacks); LLM-judge detector;
  brain can synthesize + save a new spec from NL.
- **P6 — Brain + semantic memory + multiturn (PyRIT-style).** `brain` (LLM-as-DNA) backing
  attacker/planner/judge; `memory` embeddings store; attacker/target/judge orchestrator whose each
  turn is steered by semantic recall of prior feedback (consequent, adaptive escalation); memory
  persisted per engagement so a campaign resumes.
- **P7 — Report + polish.** table/json/jsonl/html reports, CLI UX, authorization allowlist, docs.

**TDD discipline:** red (failing test) → green (minimal impl) → refactor, every module.
Honesty gate: reported results reflect the real `cargo test` output.

## Status
- [ ] P0 Foundation
- [ ] P1 Plan keystone
- [ ] P2 NL planner
- [ ] P3 Engine
- [ ] P4 Real targets
- [ ] P5 Data catalog
- [ ] P6 Multiturn
- [ ] P7 Report + polish
