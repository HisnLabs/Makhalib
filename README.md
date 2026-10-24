<p align="center">
  <img src="assets/logo.jpg" alt="Makhalib — falcon claw logo" width="170">
</p>
<p align="center">
  <b>Natural-language LLM &amp; guardrail red-teaming, in Rust.</b><br>
  <i>Describe the attack. Don't code it.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-107%20passing-brightgreen.svg" alt="Tests">
  <img src="https://img.shields.io/badge/status-early%20development-yellow.svg" alt="Status"> <img src="https://img.shields.io/badge/v0.0.1-runs%20live-success.svg" alt="v0.0.1">
  <img src="https://img.shields.io/badge/engine-Rust-orange.svg" alt="Built in Rust">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs welcome">
  <a href="https://github.com/HisnLabs/Makhalib"><img src="https://img.shields.io/github/stars/HisnLabs/Makhalib?style=social" alt="Stars"></a>
</p>

<p align="center">
  <b>Targets</b> &nbsp;·&nbsp; LLMs &nbsp;·&nbsp; guardrails &amp; moderation &nbsp;·&nbsp; full pipelines
</p>
<p align="center">
  <b>Works with</b> &nbsp;·&nbsp; Ollama &nbsp;·&nbsp; OpenAI-compatible &nbsp;·&nbsp; Anthropic &nbsp;·&nbsp; any REST endpoint &nbsp;·&nbsp; <i>Guardrino · Llama Guard · moderation APIs · MCP (coming soon)</i>
</p>

---

# Makhalib — 🦅 مخالب _describe the attack, don't code it_

**Makhalib** (مخالب, _"claws"_) is a natural-language-driven red-teaming framework for the whole AI
safety stack — **the model, the guardrails around it, or the full pipeline.** It brings together the
scanner engine of [augustus](https://github.com/praetorian-inc/augustus) / [garak](https://github.com/NVIDIA/garak)
and the adaptive multi-turn orchestration of [PyRIT](https://github.com/Azure/PyRIT) — then removes
the thing that makes all three painful: **you never write code to customize it.** You describe what
you want in plain language, and an LLM brain compiles it into a reviewable, reproducible scan plan.

Unlike model-only scanners, Makhalib also red-teams **guardrails** — moderation APIs, jailbreak
classifiers, prompt firewalls and PII filters (like [HisnLabs' own **Guardrino**](https://github.com/HisnLabs/Guardrino)) —
measuring how often attacks **bypass** them, how much benign traffic they **over-block**, and the
overhead they add.

> **This repository is the open-source framework.** It ships the engine, the plugin contract, a
> data-driven probe/detector/target catalog, and the plan compiler. It is **not** a hosted service
> and it does **not** bundle a library of working exploits — attack content is loaded as data you
> control. **Authorized security testing only:** use it exclusively against systems you own or have
> explicit written permission to test. Every plan carries a mandatory authorization gate.

<p align="center"><b>✅ V0.0.1 is live</b> — adaptive guardrail-bypass (COV-13) against any HTTP <code>/classify</code> endpoint, with exportable findings.</p>

```console
$ makhalib redteam --endpoint http://localhost:8810/classify \
      --scope "my own guardrail (authorized)" --max-depth 3 --beam 4

makhalib redteam · 12 seeds · adaptive(depth=3, beam=4) · authorized ✓
─ searching ─────────────────────────────────────────────────────────
=== result ===
attempts: 23 · bypasses: 11 · bypass rate: 47.8%

By mutation (obfuscation)       By category
  reverse      100%   (3/3)       prompt_extraction  50%
  leetspeak    100%   (1/1)       direct_injection   50%
  rot13         86%   (6/7)       indirect_injection 40%
  base64         0%   (0/2)  ← caught

  wrote out/.../summary.md  findings.csv  results.json  results.jsonl
```

> The adaptive search mutates known-blocked attacks and **hill-climbs on the guardrail's own
> score** until one slips through — the class of attack most likely to break a filter. Findings
> export straight into your report & review list. *(Example output; run your own — see
> [`ROADMAP.md`](./ROADMAP.md) for what else is in flight.)*

---

## 🧰 What Makhalib offers

| | Capability | How |
|---|---|---|
| 🗣️ | **Natural-language scans** | Describe intent; the LLM brain compiles it into a `ScanPlan` you review before anything runs. |
| 🧬 | **Adaptive attacks (LLM-as-DNA)** | One model plays attacker, planner and judge — it *generates and mutates* attacks instead of replaying a stale list. |
| 🧠 | **Semantic memory** | Each turn's feedback is embedded and recalled to drive coherent, escalating multi-turn — and to resume campaigns. |
| 📄 | **Zero-code customization** | Targets, probes, detectors and strategies are declarative YAML. Share a customization by sharing a file. |
| 📐 | **Reproducible by design** | The compiled plan is the artifact — deterministic to re-run, diff-able, CI-friendly. |
| 🛡️ | **Guardrail red-teaming** | Measure **bypass rate**, **over-block (false-positive) rate** and overhead of moderation / classifiers / firewalls — not just the model. |
| ⚡ | **Single Rust binary** | Concurrent, memory-efficient, no Python env, fast start. |
| 🔒 | **Safe & accountable** | Mandatory authorization gate, target allowlist, audit log. |

---

## 🛡️ Red-team the whole AI stack

Model-only scanners test one layer. In production, attacks cross a whole stack — and so does Makhalib.
Point a plan at any layer, or the full pipeline end-to-end:

| Layer | What Makhalib does | Key metrics |
|---|---|---|
| 📦 **Model artifact** | Scan weights before you trust them — malicious pickle, MIME sniffing, weight-poisoning / backdoor signals. | malicious-artifact findings |
| 🚧 **Input guardrail** | Throw adversarial prompts (incl. encoding-evasion: Unicode / Morse / emoji / base64) at moderation, jailbreak classifiers, prompt firewalls. | **bypass rate**, **over-block rate**, latency |
| 🎯 **Model** | Jailbreaks, prompt injection, data/secret extraction, unsafe tool use. | vulnerable / passed, severity |
| 🧹 **Output guardrail** | Check leak filters catch secrets / PII / toxicity — and don't mangle benign output. | leak-catch rate, over-redaction |
| 🔗 **Full pipeline** | End-to-end: did the attack clear the input filter *and* move the model *and* pass the output filter? | end-to-end bypass |

This is what makes guardrail products — including HisnLabs' own [Guardrino](https://github.com/HisnLabs/Guardrino) —
testable: you get an **efficacy scorecard** (caught vs. bypassed vs. over-blocked), not just a pile of hits.

---

## ✅ What's shipped today

Honest status — what runs now versus what's still on the [roadmap](./ROADMAP.md).

| Area | Feature | Status |
|---|---|:--:|
| **Engine** | Concurrent, bounded-pool scanner; typed plugin registry; async trait contract | ✅ |
| **Safety** | Mandatory authorization gate (`--scope`), `ScanPlan` validation | ✅ |
| **Targets** | Mock · Ollama · guardrail `/classify` · gateway `/v1/inspect` (L1+L2) | ✅ |
| **Attacks** | Adaptive beam/hill-climb search over 10 transform buffs (base64, rot13, leetspeak, homoglyph, zero-width, reverse, case, spaced, payload-split, wrap) | ✅ |
| **Detectors** | keyword · regex · refusal · secrets (gitleaks-style + CLI) · PII (Luhn-checked) · guardrail-bypass · inspect-bypass | ✅ |
| **Cost control** | Per-attempt token counts, `--token-limit` hard cap, pre-run estimate | ✅ |
| **Efficacy** | Bypass rate **and** over-block rate on benign traffic, `scorecard.md`, CI gates (`--max-bypass`, `--max-false-block`) | ✅ |
| **Reporting** | `summary.md`, `findings.csv`, `results.json`, `results.jsonl`, severity matrix | ✅ |
| **Defender** | `harden` — projects normalize-then-classify and re-verifies the fix on the live guard | ✅ |
| **Brain plumbing** | Provider-agnostic `LlmClient`: Ollama · OpenAI · Anthropic · Gemini · OpenAI-compatible, `ask` command | ✅ |
| **NL planner** | Natural language → reviewable `ScanPlan` | 🟡 in progress |
| **Targets (more)** | OpenAI/Anthropic as *targets*, generic REST, agents/MCP, multimodal | ⬜ |
| **Catalog** | Generative probes, LLM-judge, YAML catalog loader, threat-intel feed | ⬜ |
| **Memory** | Semantic memory, resumable multi-turn, Redis vector store | ⬜ |
| **Defender (more)** | MCP server + defender agent (find → fix → verify loop in CI) | ⬜ |
| **Multimodal** | PDF / image-steganography / hidden-text attack surfaces | ⬜ |

---

## 🛠️ How it works

```mermaid
flowchart LR
    NL["🗣️ natural language<br/>request"] --> BRAIN["🧬 LLM brain<br/>(planner)"]
    BRAIN --> PLAN["📄 ScanPlan<br/>(reviewable YAML)"]
    PLAN --> SCAN{{"⚙️ scanner<br/>bounded · concurrent"}}
    subgraph loop ["per attempt"]
      PROBE["probe"] --> BUFF["buff"] --> TARGET["🎯 target<br/>(generator)"] --> DET["detector"] --> SCORE["attempt + score"]
    end
    SCAN --> loop
    MEM[("🧠 semantic<br/>memory")] -. feedback .-> BRAIN
    SCORE -. remember .-> MEM
    SCORE --> REPORT["📊 report<br/>table · json · html · OWASP/ATLAS"]
```

1. You describe intent in natural language.
2. The **brain** compiles it into a `ScanPlan` — the authorization gate, the target, the selected
   probes/detectors, and the strategy — as reviewable YAML.
3. The **scanner** runs each probe against the target under a bounded, concurrent worker pool, scores
   every response with the detectors, and records a verdict per attempt.
4. **Semantic memory** feeds results back to the brain so multi-turn attacks escalate coherently.
5. Findings are reported with severity and mapped to OWASP LLM Top 10 / MITRE ATLAS.

---

## 🔁 Why teams switch from garak / augustus / PyRIT

| What drives people away | What Makhalib does instead |
|---|---|
| **Customizing means writing code** — a Python subclass, a Go `init()` + recompile, or a PyRIT orchestrator notebook. | **Everything is data.** A probe/detector/target/strategy is a YAML spec — or a sentence the brain turns into one. |
| **Static corpora go stale** — vendors patch known jailbreaks and the tool stops finding anything. | **Generative, adaptive attacks** driven by the LLM brain, not a frozen prompt list. |
| **No real memory** — single-shot or scripted multi-turn. | **Semantic memory** for consequent, escalating, resumable conversations. |
| **Crude detectors → false-positive noise.** | Confidence-scored detectors, voting, and an LLM judge with a plain-language rubric. |
| **Hard to target real systems** — RAG, agents, MCP, auth'd endpoints. | Data-configured targets: REST / OpenAI / Anthropic / Ollama / MCP, zero code. |
| **Surprise API bills.** | Per-run token/cost **budget with a hard stop**. |
| **Not reproducible / CI-hostile.** | **The plan is the artifact** — deterministic, with a CI mode and regression baselines. |
| **Reports aren't actionable.** | Severity, remediation, OWASP LLM Top 10 + MITRE ATLAS mapping, coverage. |
| **Long runs die with no resume.** | **Persisted memory per engagement** = resumable campaigns, with rate-limit/retry. |
| **No guardrails / audit trail.** | Mandatory **authorization gate**, target allowlist, tamper-evident audit log. |
| **Sharing a tweak means sharing code.** | Share a **YAML file** — the whole catalog is data. |
| **Python env hell, slow start.** | **Single static Rust binary.** |

---

## 🚀 Quick start & tutorial

> Prerequisites: a recent stable **Rust** toolchain. No Python, no system ML libraries.
> **Authorized testing only** — every run needs `--scope`, your attestation of what you may test.

### 1. Build & test

```sh
git clone https://github.com/HisnLabs/Makhalib.git
cd Makhalib
cargo build --release          # single static binary at target/release/makhalib
cargo test                     # 107 tests, fully offline & deterministic
```

### 2. Red-team a guardrail classifier

Point it at any HTTP endpoint that scores text — contract
`POST {"text":"..."}` → `{"score", "attack", "threshold", "categories"}`:

```sh
makhalib redteam \
  --endpoint http://localhost:8810/classify \
  --scope "my own guardrail (authorized)" \
  --max-depth 3 --beam 4 \
  --out out/run-1
```

Makhalib sends canonical attack seeds, then **adaptively mutates** the blocked ones (rot13, reverse,
leetspeak, base64, homoglyph, zero-width…), hill-climbing on the guardrail's own score until one slips
through. Everything lands in `out/run-1/`.

### 3. Red-team the full product (two layers)

If your guardrail is a gateway that combines a rule layer + a model layer and returns a decision
(`{action, forward, layers:[...]}`), use `--format inspect` to score the **product**, not the bare model:

```sh
makhalib redteam \
  --endpoint http://localhost:8787/v1/inspect --format inspect \
  --scope "my gateway L1+L2 (authorized)" \
  --out out/gateway
```

### 4. Cap the cost

A hard token budget stops the run gracefully — never burn more than you allow:

```sh
makhalib redteam --endpoint … --scope "…" --token-limit 50000
# tokens used (est): 49987 / 50000 (budget reached — run stopped early)
```

### 5. Measure efficacy & gate a release (CI)

A bypass rate alone is misleading — a guardrail that blocks *everything* looks perfect. Every run also
measures the **over-block rate** on benign traffic, and can **fail CI** on thresholds:

```sh
makhalib redteam --endpoint http://localhost:8787/v1/inspect --format inspect --scope "…" \
  --max-bypass 5 --max-false-block 3      # percent; non-zero exit if exceeded
# => scorecard.md + "GATE: PASS" (exit 0) or "GATE: FAIL" (exit 1)
```

Supply your own normal-traffic sample with `--benign traffic.txt` (one message per line).

### 6. Read the results

| File | What |
|---|---|
| `summary.md` | human-readable: bypass rate, per-category & per-obfuscation breakdown, findings |
| `findings.csv` | confirmed bypasses for the review list (id, category, severity, mutations, text) |
| `scorecard.md` | bypass vs over-block, with PASS/FAIL against your thresholds |
| `results.json` / `.jsonl` | full machine-readable run (every attempt, scores, tokens) |

### 7. Bring your own attacks (no code)

Seeds are data — pass `--seeds seeds.yaml`:

```yaml
seeds:
  - { category: direct_injection,  text: "…" }
  - { category: prompt_extraction, text: "…" }
```

### 8. Verify a fix (`harden`)

After a run, project what **normalize-then-classify** hardening would close — Makhalib re-queries your
live guard with normalized views of each confirmed bypass and reports how many it would catch:

```sh
makhalib harden \
  --endpoint http://localhost:8787/v1/inspect --format inspect \
  --run out/gateway --scope "my gateway (authorized)"
# -> out/gateway/harden.md   (caught-by-normalization table + residual)
```

### 9. Talk to any LLM provider (`ask`)

The brain's provider-agnostic client — smoke-test any backend before wiring it in:

```sh
makhalib ask --provider ollama    --model qwen2.5:14b   "Say pong"
makhalib ask --provider anthropic --model <claude-model> "…"    # needs ANTHROPIC_API_KEY
makhalib ask --provider gemini    --model <gemini-model> "…"    # needs GEMINI_API_KEY
makhalib ask --provider openai    --model <gpt-model>    "…"    # needs OPENAI_API_KEY
```

Any OpenAI-compatible server (OpenRouter, vLLM, LM Studio) works with `--provider openai-compatible --base-url …`.

### CLI reference

| Flag | Default | Meaning |
|---|---|---|
| `--endpoint <url>` | `…:8810/classify` | target endpoint |
| `--format <classify\|inspect>` | `classify` | bare model vs gateway L1+L2 |
| `--scope "<text>"` | **required** | authorization attestation |
| `--max-depth` / `--beam <n>` | 3 / 4 | adaptive search depth & width |
| `--runs <n>` | 1 | repetitions per candidate (exploitability) |
| `--concurrency <n>` | 8 | max concurrent target calls |
| `--token-limit <n>` | 0 (∞) | hard token budget |
| `--benign <file>` | built-in | normal-traffic corpus for over-block |
| `--max-bypass` / `--max-false-block <pct>` | off | CI gate thresholds |
| `--out <dir>` | `out/guardrail-run` | export directory |

---

<div dir="rtl" align="right">

## 🦅 مخالب — صِف الهجوم، ولا تكتب الكود

**مخالب** إطار عمل مكتوب بلغة Rust لاختبار أمان نماذج الذكاء الاصطناعي اللغوية (LLM) عبر محاكاة
هجمات الفريق الأحمر. يجمع بين محرك الفحص الموجود في أدوات مثل augustus وgarak، وتنسيق الحوار متعدد
الأدوار التكيّفي الموجود في PyRIT — مع إزالة أكبر عائق في تلك الأدوات: **لا حاجة لكتابة أي كود
للتخصيص.** تصف ما تريده بلغة طبيعية، فيقوم «العقل» المعتمد على نموذج لغوي بتحويله إلى خطة فحص قابلة
للمراجعة والتكرار.

- 🧬 **النموذج هو الحمض النووي:** يختار نوع الهجوم المناسب ويولّده ويتكيّف بدل إعادة تشغيل قائمة ثابتة.
- 🧠 **ذاكرة دلالية:** تتذكر نتيجة كل دور لتقود حوارًا متعدد الأدوار متصاعدًا ومترابطًا.
- 📄 **كل شيء بيانات:** الأهداف والمجسّات والكواشف تُعرَّف بملفات YAML، لا بالكود.
- 🔒 **للاستخدام المصرّح به فقط:** كل خطة تتضمن بوابة تفويض إلزامية.

> ⚠️ استخدم الأداة فقط على الأنظمة التي تملكها أو لديك إذن خطي صريح باختبارها.

</div>

---

## 🤝 Contributing

**Makhalib is open for contribution** — and because the catalog is *data, not code*, you don't need
Rust to extend it:

- 📄 **Add an attack, detector, or target** as a declarative **YAML spec** — no Rust required. Start
  from the [New spec issue form](https://github.com/HisnLabs/Makhalib/issues/new/choose).
- 🦀 **Work on the engine** — the NL planner, real targets (REST/agent/MCP), generative probes, the
  LLM-judge detector, semantic memory, reporting. Test-first; we keep the suite green and
  warning-free.
- 📚 **Docs, examples, triage.**

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) · [`SECURITY.md`](./SECURITY.md) ·
[`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md). Look for issues labeled **`good first issue`** and
**`help wanted`**. By using or contributing you agree to use Makhalib for **authorized testing only**.

## 🙏 Prior art & inspiration

Makhalib stands on the shoulders of excellent open-source work and brings these ideas under one
natural-language, no-code roof: [augustus](https://github.com/praetorian-inc/augustus) &
[garak](https://github.com/NVIDIA/garak) (scanner engine, probes/detectors), [PyRIT](https://github.com/Azure/PyRIT)
(adaptive multi-turn, attacker/judge, memory), and [InferGuard](https://github.com/InferGuard/InferGuard)
(output scanning for secrets/PII/toxicity, encoding-evasion, and model-artifact / weight-poisoning
scanning). Guardrail efficacy testing ties it to [Guardrino](https://github.com/HisnLabs/Guardrino).

## 💬 Get in touch

Have a use case, a target type you want supported, or want to contribute a probe spec?
Open an [issue](https://github.com/HisnLabs/Makhalib/issues) or a [discussion](https://github.com/HisnLabs/Makhalib/discussions).

## 🔗 Links

- **Source:** https://github.com/HisnLabs/Makhalib
- **Roadmap & design rationale:** [`ROADMAP.md`](./ROADMAP.md)
- **HisnLabs (حصن):** https://github.com/HisnLabs

## 📜 License

Licensed under the **Apache License, Version 2.0** — see [`LICENSE`](./LICENSE).
The framework is open source; attack content you load remains yours and your responsibility.

---

<p align="center">
  <b>⭐ If Makhalib is useful to your red-teaming, star the repo.</b><br>
  <sub>Built by <a href="https://github.com/HisnLabs">HisnLabs</a> · حصن — fortify your AI.</sub>
</p>
