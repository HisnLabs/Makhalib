# Contributing to Makhalib

Thanks for your interest in making LLM red-teaming better! Makhalib is built on one idea:
**you shouldn't have to write code to extend it.** That shapes how you can contribute.

> ⚠️ **Authorized security testing only.** Makhalib is an offensive-security tool. Contributions
> must support *defensive* and *authorized* testing. We do not accept working exploit payloads,
> contributions aimed at evading a specific production safety system, or anything designed to harm
> systems you don't own. See [`SECURITY.md`](./SECURITY.md).

## Three ways to contribute

### 1. 📄 Contribute an attack, detector, or target — **no Rust required**
This is the point of the project. Probes, detectors and targets are **declarative YAML specs**, not
code. If you can write a YAML file, you can extend Makhalib.

- Open a **[New probe/detector/target spec](../../issues/new/choose)** issue, or
- Add your spec under the appropriate catalog directory and open a PR.

A probe spec looks like this (benign example):

```yaml
name: test.Hello
description: Sends a harmless greeting to verify connectivity.
goal: Smoke-test that the target responds.
prompts:
  - "Hello, who are you?"
detector: refusal.Refusal
```

Keep examples benign and educational. Catalog entries that map to a real vulnerability class should
cite the public technique/reference, not ship a novel working exploit.

### 2. 🦀 Contribute to the engine (Rust)
New generators, harness strategies, the NL planner, semantic memory, reporting, etc.

- **Test-first (TDD).** Every change lands with tests; we keep the suite green and warning-free.
- Match the existing module style and the trait contract in [`src/traits.rs`](./src/traits.rs).
- Run before pushing:
  ```sh
  cargo test
  cargo fmt --all
  cargo clippy --all-targets -- -D warnings
  ```
- Keep capabilities `Send + Sync`; the scanner shares them across threads.

### 3. 📚 Docs, examples, triage
Improve the README/ROADMAP, add example plans, file good bug reports, help triage issues.

## Development setup

```sh
git clone https://github.com/HisnLabs/Makhalib.git
cd Makhalib
cargo build
cargo test        # offline, deterministic
```

Requirements: a recent stable Rust toolchain. No Python, no system ML libraries.

## Pull request checklist

- [ ] Tests added/updated and `cargo test` is green
- [ ] `cargo fmt` and `cargo clippy -D warnings` are clean
- [ ] Docs/README/ROADMAP updated if behavior changed
- [ ] Change supports authorized/defensive use (no novel exploit payloads)
- [ ] Commits are signed off (`git commit -s`) — we use the [DCO](https://developercertificate.org/)

## Where to start

Look for issues labeled **`good first issue`** and **`help wanted`**. The roadmap's open phases
(see [`ROADMAP.md`](./ROADMAP.md)) are the big-ticket areas: the NL planner, real targets
(REST/agent/MCP), generative probes, the LLM-judge detector, and actionable reporting.

## Code of conduct

By participating you agree to the [Code of Conduct](./CODE_OF_CONDUCT.md).

## License

Contributions are licensed under **Apache-2.0**, the same as the project.
