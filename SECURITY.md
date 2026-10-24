# Security & Responsible Use Policy

Makhalib is an **offensive-security tool for authorized LLM red-teaming**. This policy covers both
how to report vulnerabilities *in Makhalib* and the rules for *using* it responsibly.

## Responsible use

- Use Makhalib **only** against LLM systems you **own** or have **explicit written authorization**
  to test. Unauthorized testing of third-party systems may be illegal.
- Every scan plan carries a mandatory **authorization gate** (`authorization.authorized`). Do not
  patch it out, and do not route around the audit log.
- The project ships a *framework* and benign built-ins. It does **not** distribute a library of
  working exploits. Attack content you load is **your responsibility**.
- Respect the acceptable-use policies and rate limits of any model provider you target.

## Reporting a vulnerability in Makhalib

If you find a security issue in Makhalib itself (e.g. the engine, the authorization gate, or
anything that could enable misuse):

- **Do not** open a public issue.
- Use **[GitHub Private Vulnerability Reporting](../../security/advisories/new)** on this repo, or
  contact the HisnLabs maintainers privately.
- Please include a description, affected version/commit, and reproduction steps.

We aim to acknowledge reports promptly and will coordinate disclosure with you.

## Scope for contributions

We welcome contributions that strengthen **defensive and authorized** testing. We will **decline**:

- Novel, working exploit payloads optimized to defeat a specific production safety system.
- Features whose primary purpose is evading detection or attribution for malicious use.
- Anything targeting systems the contributor is not authorized to test.

Catalog entries that correspond to a known vulnerability class should reference the public technique
rather than ship a weaponized payload. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).
