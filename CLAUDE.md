# CLAUDE.md — Post-Quantum Crypto Discovery Platform

> **Working name:** TBD (placeholder: `CryptoBOM` / `PQScan`)
> **Status:** Phase 1 — pre-MVP, scoping and architecture
> **Last updated:** 2026-05-24

---

## 1. Mission

Build the **developer-first cryptographic discovery and migration platform** that organizations need to prepare for the post-quantum transition. Help engineering and security teams find every cryptographic asset they own (in code, on the network, in the cloud), understand which ones are quantum-vulnerable or otherwise weak, and plan migration to NIST-standardized post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA, FN-DSA).

Positioning: **"Snyk for cryptography."** Bottom-up adoption by developers and security engineers, expand to enterprise.

---

## 2. Target User

**Primary (MVP):** Application security engineers and senior developers at mid-to-large engineering orgs who:
- Care about supply chain and cryptographic hygiene.
- Already use tools like Snyk, Semgrep, Trivy, Wiz.
- Have started getting questions from compliance/CISO about PQC readiness but don't have tooling.

**Secondary (Phase 2+):** Security architects, platform teams, CISOs at regulated industries (finance, healthcare, government, critical infrastructure).

**Buyer evolution:** individual dev → team lead → security org → enterprise procurement.

---

## 3. Why Now (Market Context)

- **NIST PQC standards finalized** (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA; FN-DSA pending). Migration is no longer theoretical.
- **NSA CNSA 2.0** mandates PQC for national security systems by 2030–2035.
- **White House NSM-10 / OMB M-23-02** require federal agencies to inventory cryptography.
- **EU DORA, NIS2** are pushing cryptographic inventory requirements onto financial services and critical infrastructure.
- **"Harvest now, decrypt later"** attacks are an active threat — long-lived data needs protection today.
- Buyers don't need to be convinced *why* — only *which tool*.

---

## 4. Competitive Landscape (Know What We're Not)

Existing players (mostly top-down enterprise sales, $200k+ ACVs):
- IBM Quantum Safe Explorer (+ CBOM work)
- SandboxAQ
- PQShield
- InfoSec Global (AgileSec)
- QuSecure, Crypto4A
- PKI/CLM incumbents moving in: Keyfactor, DigiCert, AppViewX

**Our wedge:** developer-first PLG, open-source CLI, CycloneDX **CBOM** standard output. None of the above own the developer workflow.

---

## 5. Product Scope

### 5.1 Phase 1 MVP (Months 0–3) — BUILD THIS FIRST

A free, open-source **CLI + GitHub Action** that scans source code for cryptographic usage and emits a CycloneDX **CBOM**.

**In scope:**
- Languages: **Java, Python, Go** (in that priority order).
- Detection of:
  - Cryptographic library calls (e.g., `javax.crypto`, `cryptography`, `crypto/tls`, `crypto/rsa`, etc.).
  - Algorithm + key size + mode of operation + library + file/line.
  - Quantum-vulnerable algorithms (RSA, ECDSA, ECDH, DH, classic Diffie-Hellman).
  - Deprecated/weak algorithms (MD5, SHA-1, DES, 3DES, RC4).
  - Common misuse (ECB mode, static IVs, hardcoded keys, weak PRNGs, broken comparisons).
- Output formats:
  - **Primary:** CycloneDX CBOM (JSON) — must conform to the OWASP CBOM spec.
  - Human-readable terminal report.
  - SARIF for IDE/CI integration.
- Distribution:
  - `npm`/`pip`/`brew` installable CLI.
  - GitHub Action in Marketplace.
  - Hosted free-tier dashboard that ingests CBOMs for visualization and history.

**Explicitly OUT of scope for Phase 1:**
- Network scanning. Cloud KMS inventory. Binary/container scanning. Auto-remediation. Anything with an agent.
- Languages beyond Java/Python/Go.
- Paid features (those come in Phase 2).

### 5.2 Phase 2 (Months 4–8) — Adjacent surfaces + first paid tier

- SBOM ingestion (parse Syft/Trivy/CycloneDX SBOMs, enrich with crypto findings).
- Container/image crypto scanning.
- Dependency-graph inference (what algorithms does this version of BoringSSL/OpenSSL/Bouncy Castle actually expose).
- **Team tier:** $20–40/dev/month. Private repos, org dashboard, drift over time, Slack/Jira integrations, policy rules ("fail PR if new RSA-2048 introduced").
- More languages: Node.js/TypeScript, C/C++, Rust, C#.

### 5.3 Phase 3 (Months 9–18) — Network, cloud, enterprise

- Internal/external TLS scanning (active probe).
- Cloud KMS/cert inventory: **AWS first**, then Azure, then GCP.
- SSH key inventory.
- PGP/code-signing key inventory.
- **Enterprise tier:** SSO, RBAC, on-prem deployment, custom rules, migration playbooks, all channels unified. $50k–200k ACVs.

---

## 6. Differentiation (Pick One to Lead With)

Three viable wedges. **We are leading with developer experience, with remediation guidance as the second-order moat.**

1. **Best developer experience.** Sub-second scans, near-zero false positives, beautiful PR comments, works offline. ← Our primary wedge.
2. **Best remediation guidance.** AI-assisted migration plans, automatic PRs to upgrade crypto, hybrid scheme generation. ← Layered in starting Phase 2.
3. **Best compliance artifact.** CBOM that auditors accept. ← Natural byproduct of doing #1 right.

**Hard rule:** if a feature would compromise developer experience (noise, latency, complexity), it doesn't ship until we can do it without that tradeoff.

---

## 7. Engineering Principles

These apply to every line of code written for this project:

- **Zero false positives over completeness.** Developers abandon noisy security tools instantly. When in doubt, don't flag.
- **Fast feedback.** CLI scan of a medium repo (<50k LOC) must complete in under 5 seconds. CI scans in under 30s.
- **Offline-first.** The CLI must work without network access. No phone-home telemetry by default.
- **Standard outputs.** CBOM (CycloneDX) and SARIF only. Don't invent proprietary formats.
- **Composable.** The CLI is a unix-style tool. It should pipe well with other tools.
- **Open source where it builds trust.** Detection rules, CLI, and CBOM emitter are OSS (Apache 2.0 or MIT). Dashboard, multi-repo aggregation, and enterprise features are closed.
- **Test the detector with real-world repos.** Maintain a corpus of real OSS projects with known crypto usage and regression-test against them.

---

## 8. Tech Stack (Initial Bets — Revisit)

| Layer | Choice | Why |
|---|---|---|
| CLI core | **Go** | Single static binary, easy distribution, fast startup, good AST tooling. |
| Language analyzers | Per-language (tree-sitter where possible) | Tree-sitter gives consistent AST traversal across languages with one infra. |
| Python parser | `tree-sitter-python` + Python `ast` for validation | |
| Java parser | `tree-sitter-java` + JavaParser if needed for deeper resolution | |
| Go parser | `go/ast` (native) | |
| CBOM emitter | CycloneDX Go library | Don't roll your own. |
| Dashboard backend | TBD (likely Go or TypeScript/Node) | Decide once we have a designer. |
| Dashboard frontend | TBD (likely Next.js + Tailwind + shadcn/ui) | |
| Database | Postgres | |
| Hosting | TBD (Fly.io / Render / AWS) | |

**All of the above is a starting bet, not a commitment.** Revisit before Phase 2.

---

## 9. Suggested Repo Structure

```
/
├── CLAUDE.md                  # This file
├── README.md                  # Public-facing
├── LICENSE                    # Apache 2.0
├── cmd/
│   └── cryptobom/             # CLI entrypoint (Go)
├── internal/
│   ├── analyzers/             # Per-language detectors
│   │   ├── python/
│   │   ├── java/
│   │   └── golang/
│   ├── rules/                 # Detection rules (data, not code where possible)
│   ├── cbom/                  # CycloneDX CBOM emission
│   ├── sarif/                 # SARIF emission
│   └── report/                # Terminal/human-readable output
├── pkg/                       # Public Go packages, if any
├── testdata/                  # Real-world repos for regression testing
├── docs/                      # Longer-form docs (move strategy content here over time)
├── .github/
│   └── workflows/             # Our own CI + the GitHub Action we publish
└── dashboard/                 # Web app (separate module)
```

---

## 10. What NOT to Do

- **Don't build a kitchen sink.** Single-language MVP > three-language MVP that's all mediocre. Ship Python first if forced to choose.
- **Don't chase enterprise features before product-market fit.** No SSO, RBAC, audit logs, or compliance certs until we have ~20 teams paying.
- **Don't invent crypto detection heuristics from scratch** when there's prior art (Cryptosense, IBM CBOM detectors, academic work). Read first, build second.
- **Don't ship a network scanner in Phase 1.** Even if it would impress someone in a demo. Stay focused.
- **Don't add LLM-based detection to the core scanner.** It's slow, costly, and non-deterministic. LLMs are fine for remediation suggestions in Phase 2+, not for primary detection.
- **Don't fight the CBOM standard** — extend it where needed, contribute upstream, don't fork.
- **Don't sell to enterprises before we have community signal.** PLG comes first; sales motion comes later.

---

## 11. Business Model

- **Free / OSS:** CLI, GitHub Action, public-repo scans, CBOM emission, terminal/SARIF output.
- **Team ($20–40/dev/month):** Private repos, hosted dashboard, history & drift, Slack/Jira, policy rules.
- **Enterprise (custom, $50k–$200k+ ACV):** SSO/SCIM, on-prem, all discovery channels (network/cloud/code), migration planning, support SLAs, custom rules.

---

## 12. Key Open Decisions

Things we need to resolve as we build — track here, move to GitHub issues once concrete:

- [ ] Final product name and domain.
- [ ] Open-source license: Apache 2.0 vs. MIT vs. dual-license / BSL?
- [ ] First language: Java, Python, or Go? (Tentative: Python — largest dev community, easiest distribution.)
- [ ] Cloud provider for hosted dashboard.
- [ ] Who is the technical co-founder / first senior engineer? (Critical gap — see §13.)
- [ ] Which CycloneDX CBOM working group / OWASP venue do we engage with first?

---

## 13. Known Gaps & Risks

- **Founder gap:** Current founding profile is product/business. **A technical co-founder with static-analysis or developer-security experience is the #1 hire.** Outsourcing detector quality to contractors will produce a noisy, untrusted tool — fatal for a dev-focused product.
- **Cryptography expertise:** Need an advisor (academic or industry cryptographer) on retainer ~4 hrs/month to vet rules and migration recommendations.
- **PLG-to-enterprise gap:** Bottom-up motion is slow to monetize. Plan to be unprofitable for 18–24 months.
- **Standard risk:** CBOM spec is still evolving. Stay close to OWASP working group.

---

## 14. References

- CycloneDX CBOM spec — https://cyclonedx.org/capabilities/cbom/
- NIST PQC project — https://csrc.nist.gov/projects/post-quantum-cryptography
- NSA CNSA 2.0 — https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
- OMB M-23-02 (federal PQC inventory mandate)
- OWASP Cryptographic Storage Cheat Sheet

---

## 15. Note on This File

This file is intentionally comprehensive for project bootstrapping. Once the project is in active development:

- Move §3 (market context), §4 (competitive landscape), §5.2–5.3 (later phases), and §11 (business model) into `docs/PRODUCT_STRATEGY.md`.
- Keep CLAUDE.md focused on §6 (differentiation rules), §7 (engineering principles), §9 (repo structure), §10 (anti-patterns), and current-phase scope.
- Target: **under 150 lines** once development is underway. Lean CLAUDE.md = better Claude Code performance.
