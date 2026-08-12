# Changelog

All notable changes are documented here.

## 0.6.0 — 2026-08-12

- Added the Adaptive Adversarial Experiment Engine: initial evidence reasoning now identifies runtime-addressable `PARTIAL` / `UNKNOWN` attack paths and can deterministically plan targeted verification experiments.
- Added three bounded internal experiment templates: synthetic credential egress canaries, sandbox-local filesystem sentinels, and synthetic CI-context triggers.
- Added `off | plan | sandbox` experiment modes. `off` preserves RepoTrial 0.5 report/receipt behavior, `plan` performs no repository execution, and `sandbox` reuses the existing copied-rootfs + namespace + chroot containment boundary.
- Added an internal synthetic-canary generator. Real host credentials are never injected; raw canary values exist only during in-memory classification and are replaced by SHA-256 fingerprints/redacted markers before public artifacts are created.
- Added observation states `OBSERVED`, `TRIGGERED`, `NOT_OBSERVED`, and `INCONCLUSIVE`, with a hard epistemic rule that `NOT_OBSERVED` never becomes global negative evidence or proof of absence.
- Added positive experiment evidence rules for synthetic secret egress, conditionally triggered network behavior, sandbox sentinel destruction, and contextual CI-triggered behavior. Only strong rules map into dangerous reasoning capabilities.
- Added `repotrial.epistemic-delta.v1` to record hypothesis transitions, attack-path transitions, newly satisfied stages, new capabilities, and unresolved targets after experiment evidence is assimilated.
- Added `experiments.json`, `repotrial.experiments.v1`, optional report-v2 schema integration, artifact-proof/provenance binding, and an Adaptive Experiments panel in the portable HTML case file.
- Added CLI controls `--experiments`, `--experiment-max-runs`, `--experiment-max-per-candidate`, and `--experiment-timeout`, plus equivalent GitHub Action inputs and experiment/epistemic outputs.
- Added a deterministic experiment planner with global/per-candidate budgets and hard caps, while retaining zero npm runtime dependencies and Node.js 22.14+ support.

## 0.5.0 — 2026-08-11

- Added a pure deterministic Evidence Reasoning Engine that converts canonical charges and safeguards into a typed evidence graph, normalized capabilities, threat hypotheses, and ordered attack paths.
- Added explicit epistemic states (`PROVEN`, `SUPPORTED`, `CONTRADICTED`, `REFUTED`, `UNKNOWN`, `UNTESTED`) so missing or unavailable evidence is never silently interpreted as proof of safety.
- Added built-in threat hypotheses for credential exfiltration, arbitrary code execution, unapproved destructive action, prompt-to-tool escalation, and high-impact supply-chain compromise.
- Added stable SHA-256-derived graph and attack-path identities and charge-order invariance tests.
- Added counterfactual remediation ranking that recomputes the evidence model after removing each proven charge and measures attack-path elimination and high-impact hypothesis downgrade.
- Embedded reasoning into `verdict.json`, the receipt-bound portable HTML report, and the package public API while preserving v0.4 deterministic verdict thresholds for compatibility.
- Added `repotrial.reasoning.v1`, `repotrial.evidence-graph.v1`, and `repotrial.counterfactual-remediation.v1` contracts plus a published JSON Schema.
- Corrected npm repository/homepage/issue metadata to `Nolane-x/repotrial` and removed the independent hard-coded SARIF package version source.
- Retained zero npm runtime dependencies and Node.js 22.14+ support.

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