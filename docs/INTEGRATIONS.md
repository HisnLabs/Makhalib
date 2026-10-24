# Makhalib — Integrations Catalog

Proven open-source tools, datasets and techniques to pull into Makhalib for testing **LLM and
guardrail readiness**, organized by the role each plays in our architecture. This complements
[`../ROADMAP.md`](../ROADMAP.md).

> ⚠️ **Authorized use only.** Attack-generation items are integrated as **data or algorithms**
> (loaded/credited), never shipped as novel working exploits. Before bundling any third-party tool,
> **check its license** — prefer *loading rules as data* or *shelling out* over vendoring code,
> especially for copyleft (AGPL/GPL) tools. Model-license tools (e.g. Llama Guard) follow their own
> terms.

**Plug-points:** `Probe` (attack) · `Buff` (transform) · `Detector`/`Judge` (scoring) ·
`Target` (system under test) · `Corpus` (benchmark data) · `Policy` (access/guardrail rule) ·
`Artifact-scan` (model file). Phases refer to the ROADMAP (P4–P9).

---

## A. Attack generation → `Probe`

| Source | Technique | Plug-in | Phase | Notes |
|---|---|---|---|---|
| **garak** (NVIDIA) | 100s of published probes (DAN, encoding, XSS, malwaregen, leakage) | port as YAML probe specs | P5 | Apache-2.0; port as **data** |
| **PyRIT** (Microsoft) | orchestrators, converters, attacker/judge | multi-turn harness + brain | P6 | MIT |
| **PAIR / TAP** | attacker-LLM iteratively refines a jailbreak | algorithmic probe (uses the brain) | P5–P6 | research technique |
| **GPTFuzz / AutoDAN** | template fuzzing / genetic mutation of seeds | **generative/mutational probe** type | P5 | technique, not payloads |
| **PromptInject / ArtPrompt** | structured + ASCII-art injection | probe + buff | P5 | |
| **"In-the-Wild" jailbreak set** | real-world jailbreak corpus | probe corpus (data) | P5 | dataset |
| **Many-shot / Crescendo / GOAT** | long-context & multi-turn escalation | harness strategies | P6 | |

## B. Evasion transforms → `Buff`

| Technique | Why it matters |
|---|---|
| base64 · hex · ROT13 · leetspeak | filters tuned to plain English miss encoded payloads |
| **Morse / Unicode homoglyphs / zero-width / emoji smuggling** | bypass classifier tokenization |
| **low-resource-language translation** | safety training is weakest off-English |
| payload splitting / interleaving | defeats substring matching |

> Shipped seed: `secrets`/`pii` detectors already exist; encoding-evasion buffs are **P5**.

## C. Benchmarks & corpora → `Corpus` (coverage + false-positive testing)

| Dataset | Use | Plug-in |
|---|---|---|
| **HarmBench · AdvBench · JailbreakBench** | standardized attack-success-rate (ASR) | probe corpus + metric |
| **StrongREJECT** | low-false-positive refusal/compliance scoring | LLM-judge rubric |
| **XSTest · OR-Bench** | **over-refusal / over-block** — essential guardrail FPR | benign corpus |
| **PINT (Lakera)** | prompt-injection benchmark | probe corpus |
| **InjecAgent · AgentDojo** | tool/agent injection | agent-target probes |
| **Do-Not-Answer · ToxicChat · WildGuardMix** | moderation ground truth | detector eval |

## D. Guardrails → `Target` (red-team it) **and** `Detector`/`Judge` (reuse it)

| Tool | As target | As detector/judge | Notes |
|---|---|---|---|
| **Llama Guard 3 / Prompt Guard** (Meta) | ✅ bypass/FPR | ✅ safety/injection judge | Llama license |
| **NeMo Guardrails** (NVIDIA) | ✅ | rails inline | Apache-2.0 |
| **Guardrails AI / LLM Guard / Rebuff / Vigil** | ✅ efficacy scorecard | some inline | OSS |
| **Lakera Guard / your Guardrino** | ✅ | — | commercial / HisnLabs |
| **OpenAI Moderation / Azure AI Content Safety** | ✅ | ✅ toxicity/category | API |
| **Presidio** (Microsoft) | — | ✅ PII (beyond our regexes) | MIT |
| **Detoxify / Perspective API** | — | ✅ toxicity | Apache-2.0 / API |

## E. Secrets · PII · supply-chain → `Detector` + `Artifact-scan`

| Tool | Role | Phase | Notes |
|---|---|---|---|
| **gitleaks** | secret-leak detector on output | ✅ shipped (`secrets.Gitleaks` + embedded ruleset) | MIT |
| **TruffleHog** | secret detection w/ verification | P5 | **AGPL — shell out, don't vendor** |
| **detect-secrets** (Yelp) | entropy + rules | P5 | Apache-2.0 |
| **Presidio / MS PII** | richer PII than regex | P5 | MIT |
| **ModelScan** (Protect AI) | malicious pickle / model-file scan | P9 | Apache-2.0 |
| **picklescan** | pickle opcode scan | P9 | MIT |
| **Fickling** (Trail of Bits) | pickle decompile/inject detection | P9 | check license |
| **YARA / ClamAV** | malware scan of artifacts | P9 | |

> Shipped: `secrets.Secrets` (embedded gitleaks-style ruleset), `secrets.Gitleaks` (CLI), `pii.PII`.

## F. Metrics & methods → report + engine

| Method | What it adds | Phase |
|---|---|---|
| **Differential testing** | same attack *with* vs *without* the guardrail — the delta is the guardrail's value | P7 |
| **Canary-token leak test** | plant a secret in the system prompt; any exfiltration is an unambiguous hit | P5 |
| **ASR + over-refusal + transferability** | first-class report metrics | P7 |
| **Confusion matrix · F-beta · ROC · base-rate · confidence** | detector/judge quality (per your Augustus deck) | P7 |
| **LLM-as-judge (StrongREJECT rubric)** | cuts false positives | P5 |
| **OPA / OpenAPPA policy** | enforce access policy & blast-radius limits on agentic targets (your framework's APE/BLR) | P8 |

---

## Alignment with the HisnLabs framework

These map onto the "AI Security Testing Framework" domains: coverage **COV-01/02/03** (C + A),
**metrics** (F), **agentic controls** — access policy enforcement (APE), blast radius (BLR),
component supply chain (SKL) — (D + E + F/OPA), and the **OWASP LLM Top 10 / MITRE ATLAS / NIST**
crosswalk in reporting (P7).

## Recommended build order (highest value, lowest risk)

1. **XSTest/OR-Bench over-block corpus + FPR metric** (C, F) — honest guardrail testing.
2. **Encoding-evasion buffs** (B) — cheap, brutal on filters.
3. **Canary-token system-prompt-leak probe** (F) — pairs with the shipped secrets detector.
4. **StrongREJECT LLM-judge detector** (F) — kills false positives.
5. **Llama Guard / Presidio / Detoxify** reusable detectors (D).
6. **ModelScan / picklescan** artifact scanning (E, P9).

---

## Augustus ports (Apache-2.0, praetorian-inc/augustus)

Scoring logic only. Payload text is never copied into this repository; probe prompts are read from
an operator-supplied augustus checkout at run time.

| Augustus component | Makhalib module | Status |
|---|---|---|
| `base.StringDetector` (str / word / startswith) | `detect_base` | ✅ ported, tested |
| `patterns.Patterns` (any / all / weighted) | `detect_patterns` | ✅ ported, tested |
| YAML probe templates | `catalog`, `catalog-convert` | ✅ loader and conversion |
| Multi-turn strategies (Crescendo, GOAT, Hydra) | `multiturn` (replay only) | ⬜ escalation logic not built by design |
| Go-coded probes | — | ⬜ not ported (payloads stay in the augustus checkout) |
| `toxiccomment` | `detect_toxic` | ✅ ported (substring scoring; slur entries left for the caller to add) |
| `unsafecontent` | `detect_unsafe` | ✅ ported (word, substring and startswith; lexicons supplied by the caller) |
| `shields` (Up / Down) | `detect_shields` | ✅ ported (startswith scoring) |
| `judge` (Judge / Refusal) | `detect_judge` | ✅ ported (LLM rubric written in our own words; registered with a caller-supplied client) |

