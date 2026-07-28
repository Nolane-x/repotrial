# RepoTrial v0.4 Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Deliver RepoTrial v0.4 with dynamic sandbox evidence, full bounded structured-config parsing, supply-chain evidence, differential PR gating, cryptographic provenance, and verified release portability.

**Architecture:** Add isolated provider modules around the deterministic core. Refactor scanning into analysis and artifact-writing phases so baseline analysis and verification can reuse behavior without recursive artifact output. Every provider returns a bounded status object and never silently upgrades trust.

**Tech Stack:** Node.js ESM 22/24, built-in `node:test`, Linux `unshare`, CycloneDX JSON 1.6, OSV REST API, Ed25519/DSSE/in-toto provenance, optional Cosign, GitHub Actions.

## Global Constraints

- Dynamic execution is opt-in and never runs in the source directory.
- No host shell invocation.
- Network providers are opt-in and bounded.
- All persisted repository-controlled values pass redaction.
- ForgeOS v0.6.1 compatibility remains mandatory.
- Supported Node versions are 22 and 24; Node 20 is rejected as EOL.
- All new behavior begins with a failing test.

---

### Task 1: Structured configuration parser
- [x] Add failing JSON/YAML/TOML parser tests including anchors, aliases, merge keys, block scalars, multiline TOML, arrays of tables, duplicate keys, alias cycles, and depth/node limits.
- [x] Implement `src/core/structured.mjs` and replace regex-only config ingestion where a parsed structure is available.
- [x] Verify parser tests and existing surface/ForgeOS tests.

### Task 2: Runtime sandbox provider
- [x] Add failing candidate discovery and sandbox behavior tests.
- [x] Implement disposable workspace, namespace probe, resource-limited runner, network traps, Node preload events, filesystem diff, and bounded results.
- [x] Add runtime charges and `runtime.json`; integrate CLI options.
- [x] Verify escape, timeout, output-cap, network-attempt, and source-immutability tests.

### Task 3: Supply-chain evidence
- [x] Add failing dependency inventory/SBOM/license/OSV tests.
- [x] Implement npm, PyPI, Cargo, and Go inventory; CycloneDX 1.6; license summaries; bounded OSV querybatch/detail client.
- [x] Implement optional normalized container scanner adapters.
- [x] Add artifacts and charges, preserving offline operation.

### Task 4: Differential PR mode
- [x] Add failing finding identity and baseline comparison tests.
- [x] Implement report-to-report diff and Git-ref baseline extraction.
- [x] Add CLI `diff`, scan baseline flags, `--fail-on-new`, report/SARIF differential metadata, and Action inputs/outputs.

### Task 5: Provenance, signatures, and proof verification
- [x] Add failing keygen/sign/verify/tamper tests.
- [x] Implement artifact manifest, SLSA-style in-toto provenance, DSSE Ed25519 signatures, optional Cosign bundle, and deterministic proof invariants.
- [x] Add `keygen` and `verify` commands and report artifacts.

### Task 6: Redaction and adversarial hardening
- [x] Add failing tests for known token prefixes, JWTs, high-entropy encoded secrets, private keys, nested provider data, and over-redaction controls.
- [x] Improve common-prefix, contextual entropy, and decoded-secret detection with strict bounds.
- [x] Run fuzz/property corpus over parser, redaction, bridge, report, and sandbox event normalization.

### Task 7: Release integration and documentation
- [x] Update package/version/exports, schemas, README EN/VI, architecture, security model, changelog, Action, and workflows.
- [x] Add Node 22/24 matrix, OSV mocked acceptance, SARIF upload example, SLSA release workflow, and Docker runtime test.
- [x] Update project manifest with every changed file.

### Task 8: Final verification and packaging
- [x] Run tests, coverage, syntax, audit, self-scan, cautious/reckless fixtures, runtime sandbox fixture, supply-chain fixture, diff fixture, signature verification, ForgeOS CLI/HTTP acceptance, clean npm install, Node 22/24, and Docker build/run.
- [x] Commit a clean branch.
- [x] Package source ZIP, changes ZIP, npm tarball, demo report, verification JSON, checksums, and expose all changed artifacts.
