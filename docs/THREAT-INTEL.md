# Makhalib — Threat Intelligence Feed (2025–2026)

Latest published LLM/guardrail attack techniques and real-world disclosures, each mapped to a
Makhalib plug-point so our customers are tested against **fresh** techniques, not a stale list.
Seeds P12/P13. Sourced from arXiv + vendor research; details are from abstracts/secondary sources —
verify primary papers before citing figures.

> ⚠️ Defensive coverage map. We integrate these as *test techniques and detectors*, never as
> weaponized payloads.

## Character & encoding injection — **confirmed against Guardrino**

Guardrails that score the *surface string* are near-completely evaded by character-level
obfuscation. Our live run reproduced this: `rot13` (6/7), `reverse` (3/3), `leetspeak` (1/1) beat
Guardrino; `base64` was caught.

| Technique | Makhalib plug-in | Status |
|---|---|---|
| Zero-width / invisible chars | `zero_width` buff | ✅ |
| Homoglyphs (confusables) | `homoglyph` buff | ✅ |
| rot13 / reverse / leetspeak | `rot13`/`reverse`/`leetspeak` buffs | ✅ |
| **Emoji smuggling** (variation selectors) | `emoji_smuggle` buff | ⬜ P12 |
| **Bidirectional (bidi) text** overrides | `bidi` buff | ⬜ P12 |
| **Unicode tag** chars (invisible ASCII) | `unicode_tags` buff | ⬜ P12 |

Sources: [Bypassing LLM Guardrails (Hackett et al., 2504.11168)](https://arxiv.org/abs/2504.11168) ·
[Mindgard: invisible characters](https://mindgard.ai/blog/outsmarting-ai-guardrails-with-invisible-characters-and-adversarial-prompts).
**Defense to recommend:** [Broken-Token (2510.26847)](https://arxiv.org/pdf/2510.26847) — filter by
chars-per-token; and **decode-normalize** before classifying (see `docs/DEFENDER.md`).

## Semantic / multi-turn decomposition

| Technique | Idea | Makhalib plug-in |
|---|---|---|
| **Harmless prompt weaving / CKA-Agent** | chain individually-benign sub-queries + adaptive tree search | multi-turn decomposition probe (P6) |
| **Implication chaining / lexical misdirection** | prompt-level taxonomy, "Anyone Can Jailbreak" | probe family (P5) |
| **TopicAttack** | indirect injection via gradual topic transition | indirect-injection probe (COV-02) |
| **H-CoT** | hijack chain-of-thought so the model believes safety already passed | reasoning-model probe |
| **Ninja / Jailbreaking in the Haystack** | long-context benign padding; position matters | long-context probe |

Sources: [Trojan Knowledge / CKA-Agent (ICML 2026)](https://research.ibm.com/publications/the-trojan-knowledge-bypassing-commercial-llm-guardrails-via-harmless-prompt-weaving-and-adaptive-tree-search) ·
[Anyone Can Jailbreak (2507.21820)](https://arxiv.org/html/2507.21820v1) ·
[TopicAttack (2507.13686)](https://arxiv.org/pdf/2507.13686) · H-CoT (2502.12893) ·
[Jailbreaking in the Haystack (2511.04707)](https://arxiv.org/html/2511.04707v2).

## Multimodal & document attacks → P12

| Technique | Idea | Makhalib plug-in |
|---|---|---|
| **Image steganography** (LSB/spatial) | hidden instructions in images for VLMs | `image_stego` probe (COV-12) |
| **Odysseus dual-steganography** | jailbreak commercial multimodal systems | multimodal probe |
| Typographic / adversarial-pixel / physical | CSA's 4 embedding families | image probe set |
| **PDF-borne injection** | hidden text + PDF-embedded images bypass text extraction | `pdf_inject` probe (COV-02/12) |

Sources: [Odysseus (2512.20168, NDSS 2026)](https://arxiv.org/abs/2512.20168v1) ·
[CSA: image prompt injection](https://labs.cloudsecurityalliance.org/research/csa-research-note-image-prompt-injection-multimodal-llm-2026/) ·
[Multimodal prompt injection (Schneider)](https://christian-schneider.net/blog/multimodal-prompt-injection/).

## Agent / MCP attacks → P4 + COV-02/17/18

| Technique | Idea | Makhalib plug-in |
|---|---|---|
| **Tool poisoning** (Invariant Labs, Apr 2025) | hidden instructions in a tool's description/schema/output | MCP target + COV-18 probe |
| **Cross-server tool shadowing** | one server's tool overrides another's | MCP multi-server probe |
| **Mid-session tool injection (WebMCP)** | 3rd-party scripts add malicious tools mid-session | MCP session probe |
| **Adaptive IPI (AdapTools)** | predict next tool, steer to high-authority tool | adaptive agent probe (COV-05/17) |

Sources: [Netskope: tools turn hostile](https://www.netskope.com/blog/securing-llm-superpowers-when-tools-turn-hostile-in-mcp) ·
[Snyk: prompt injection + MCP](https://labs.snyk.io/resources/prompt-injection-mcp/) ·
[WebMCP (2606.06387)](https://www.emergentmind.com/papers/2606.06387) ·
[Promptfoo LM-security DB](https://www.promptfoo.dev/lm-security-db/).

## Zero-day / CVE watchlist → P13

| ID | What | Relevance |
|---|---|---|
| **CVE-2025-32711 "EchoLeak"** | first real-world **zero-click** indirect prompt injection → data exfil in M365 Copilot (single crafted email) | indirect-injection + canary-exfil test (COV-02/03) |
| **MCP server CVEs** | 30+ reported early 2026 (unverified count) against MCP servers/agent tooling | MCP target hardening (COV-18) |
| GitHub MCP case (Invariant, May 2025) | malicious public issue → agent reads private repos, leaks | agent authorization test (COV-17) |

Sources: [EchoLeak (2509.10540)](https://arxiv.org/html/2509.10540v1) ·
[Invariant Labs](https://invariantlabs.ai/) · [Akto: MCP security risks](https://www.akto.io/learn/mcp-security-risks).

## Intake process (P13, automated)

1. Scheduled pull of new arXiv `cs.CR` LLM-attack papers + vendor disclosures + CVE feeds.
2. LLM brain summarizes each into a **declarative probe/buff spec** (data, reviewed before merge).
3. New specs land in the catalog with their source + date; the regression set keeps old bypasses.
4. Customers are re-tested nightly against the refreshed catalog — a living attack database.
