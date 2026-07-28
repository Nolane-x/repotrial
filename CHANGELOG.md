# Changelog

All notable changes are documented here.

## 0.4.2 — 2026-07-28

- Correct the release proof workflow to use the actual key pair filenames emitted by `repotrial keygen`.

## 0.4.1 — 2026-07-28

- Fix Windows fixture paths with `fileURLToPath`.
- Mark POSIX-only fake-Cosign tests as skipped on Windows while retaining their Linux coverage.

## 0.4.0 — 2026-07-27

- Added opt-in Linux runtime detonation in a disposable copied rootfs with user, mount, UTS, IPC, network, PID, and cgroup namespaces, chroot, private propagation, secret-free environment, bounded execution, network traps, Node instrumentation, and filesystem diffs.
- Added bounded full JSON/YAML/TOML parsing with anchors, aliases, merge keys, block scalars, custom tags, inline collections, dotted tables, arrays of tables, multiline strings, duplicate-key checks, and depth/node limits.
- Added multi-ecosystem lockfile inventory, CycloneDX 1.6 SBOM, license summary, bounded OSV querybatch/CVSS analysis, Dockerfile image inventory, and optional Trivy/Grype/SARIF container normalization.
- Added report-to-report and Git-ref differential analysis, stable finding identities, SARIF baselineState, `--fail-on-new`, and GitHub Action baseline controls.
- Added artifact proofs, deterministic report invariants, in-toto/SLSA provenance v1, Ed25519 DSSE keygen/sign/verify, and optional Cosign/Sigstore bundle generation and verification.
- Added provider/JWT/private-key/contextual encoded-secret redaction, deep-data hardening, 1,000-case deterministic fuzz coverage, and preservation of boolean security metadata.
- Added report/runtime/supply/differential/proof/provenance schemas, Node 22/24 CI, Docker E2E CI, release signing workflow, and expanded English/Vietnamese documentation.
- Removed Node.js 20 support and set the production floor to Node.js 22.14.
- Added JSONC comments/trailing-comma parsing without altering string literals, stable finding fingerprints resilient to line/hash movement, and cross-platform atomic artifact replacement.
- Added runtime source-copy budgets and generated-output exclusion across static, runtime, and supply-chain providers.
- Bound provenance subjects to artifact proofs and DSSE payloads to the exact present provenance statement; credentials are stripped from provenance URLs and metadata.
- Expanded CLI help to document every production scan, sandbox, provider, signing, differential, and ForgeOS control.
- Added `--exclude` and GitHub Action `exclude-paths` so adversarial fixtures, generated corpora, or intentionally out-of-scope subtrees can be excluded consistently from static, runtime, and supply-chain providers without falsifying coverage.
- Fixed report redaction treating harmless shared object references as cycles, which could corrupt runtime candidates and multi-charge evidence as `[CIRCULAR]`.
- Added credible Makefile verification discovery, including `uv run pytest`, while rejecting no-op targets.
- Added bounded in-root file-symlink alias analysis so agent-facing aliases such as `CLAUDE.md -> AGENTS.md` are inspected without permitting root escape, ignored-target bypass, or budget amplification.

## 0.3.0 — 2026-07-27

- Added one shared classifier for AGENTS, Claude, Gemini, GitHub Copilot, Cursor, Cline, Windsurf, and Continue repository instruction surfaces.
- Added conservative JSON/YAML/TOML capability extraction for local rules and the native ForgeOS agent-surface manifest.
- Rejected no-op verification scripts, detected nested package verification, shell-only capability, multiline shell arrays, and broader wildcard forms.
- Restricted capability and destructive-operation rules to recognized agent/configuration/operational surfaces so ordinary README examples do not create self-scan false positives.
- Added bounded evidence matching with precomputed line offsets.
- Excluded generated output subtrees, rejected output-at-root, recorded invalid UTF-8 and filesystem omissions, and removed absolute target paths by default.
- Fixed report-server symlink escape through real-path containment.
- Added shared secret redaction across local evidence, safeguards, ForgeOS findings/enrichment, JSON, HTML, evidence ledgers, and SARIF.
- Hardened HTTP bridge URL policy, protocol/mode/enrichment validation, deep-payload normalization, HTTPS requirements, and response bounds.
- Protected sidecar readiness, added bounded body duration, and returned structured 408/413 errors.
- Added deterministic SARIF 2.1.0 output and GitHub Action `sarif-path` support.
- Validated GitHub Action enum inputs and escaped workflow outputs.
- Preserved zero runtime dependencies and ForgeOS v0.6.1 acceptance coverage.

## 0.2.0 — 2026-07-27

- Replaced the provisional bridge manifest with the native ForgeOS v0.6 agent-surface contract.
- Fixed valid ForgeOS `blocked` scans being lost when the CLI returned exit code `2`.
- Added `--forgeos-root` for connecting a sibling ForgeOS source checkout.
- Added `--forgeos-depth security|full`.
- Added full-mode ForgeOS runtime inventory, adversarial-corpus evidence, security receipt, and remediation RoutePlan.
- Added `repotrial forgeos-doctor` and a real ForgeOS v0.6.1 compatibility acceptance script.
- Added sidecar `GET /ready`, full-depth forwarding, source-checkout support, and blocked-report HTTP success semantics.
- Re-anchored ForgeOS package, MCP, environment, hook, and direct-path locations to repository files when resolvable.
- Added a dedicated ForgeOS Powered section to the offline report and new GitHub Action inputs/outputs.
- Fixed negated approval instructions such as `do not ask for human approval` being misclassified as safeguards.

## 0.1.0 — 2026-07-27

- Added bounded, non-executing repository discovery.
- Added ten deterministic agent-surface rule families.
- Added hash-and-line evidence anchors and deterministic verdicts.
- Added portable HTML, JSON, evidence, badge, and ForgeOS manifest artifacts.
- Added fail-open ForgeOS CLI and versioned HTTP sidecar integration.
- Added CLI, static report server, Dockerfile, GitHub Action, schemas, CI, and threat-model documentation.
