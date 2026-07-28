# RepoTrial Production v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone production-ready RepoTrial CLI, report renderer, GitHub Action, and versioned ForgeOS bridge.

**Architecture:** A zero-runtime-dependency Node.js core performs bounded file discovery, deterministic rules, verdict calculation, and portable artifact generation. ForgeOS is integrated through a fail-open CLI/HTTP sidecar adapter that returns canonical bridge findings without coupling RepoTrial to internal ForgeOS modules.

**Tech Stack:** Node.js 20.12+ ESM, built-in `node:test`, Node HTTP server, GitHub composite Action, Docker.

## Global Constraints

- Never execute code from the scanned repository.
- Use no runtime npm dependencies.
- Use `spawn` with `shell: false` for ForgeOS CLI integration.
- ForgeOS failures must not fail the local scan.
- Escape all target-controlled content in HTML.
- Keep all filesystem access inside the resolved scan/report roots.

---

### Task 1: Evidence discovery core

**Files:** `src/core/discover.mjs`, `src/core/evidence.mjs`, `src/core/hash.mjs`, `tests/discover.test.mjs`

**Interfaces:** Produce `discoverRepository(root, options)` and `anchorMatches(file, regex, metadata)`.

- [ ] Write failing tests for bounded discovery, binary skipping, symlink skipping, hashing, and line anchors.
- [ ] Run tests and confirm missing-module failure.
- [ ] Implement minimal discovery and evidence helpers.
- [ ] Run tests and confirm pass.

### Task 2: Deterministic rules and verdict

**Files:** `src/core/rules.mjs`, `src/core/verdict.mjs`, `tests/rules.test.mjs`, fixture repositories.

**Interfaces:** Produce `evaluateRules(snapshot)` and `calculateVerdict(charges, coverage)`.

- [ ] Write failing fixture tests for lifecycle scripts, pipe-to-shell, MCP wildcard, prompt override, verification safeguards, and verdict thresholds.
- [ ] Run tests and confirm failure.
- [ ] Implement ten bounded rules and deterministic scoring.
- [ ] Run tests and confirm pass.

### Task 3: ForgeOS bridge contract

**Files:** `src/bridge/manifest.mjs`, `src/bridge/forgeos.mjs`, `integrations/forgeos/bridge-server.mjs`, `tests/bridge.test.mjs`.

**Interfaces:** Produce `buildForgeOsManifest(snapshot)`, `runForgeOsBridge(manifest, options)`, and bridge `POST /v1/scan`.

- [ ] Write failing tests for redaction, unavailable CLI, canonical finding normalization, and HTTP token handling.
- [ ] Run tests and confirm failure.
- [ ] Implement client and sidecar with strict limits and `shell: false`.
- [ ] Run tests and confirm pass.

### Task 4: Scan orchestration and artifacts

**Files:** `src/core/analyze.mjs`, `src/core/report.mjs`, `src/core/badge.mjs`, `src/index.mjs`, `tests/analyze.test.mjs`.

**Interfaces:** Produce `scanRepository(options)` returning the report and artifact paths.

- [ ] Write failing end-to-end tests for artifact set, deterministic receipts, and escaped HTML.
- [ ] Run tests and confirm failure.
- [ ] Implement orchestration and atomic writes.
- [ ] Run tests and confirm pass.

### Task 5: CLI and static server

**Files:** `src/cli.mjs`, `src/server.mjs`, `bin/repotrial.mjs`, `tests/cli.test.mjs`, `tests/server.test.mjs`.

**Interfaces:** Commands `scan`, `serve`, `bridge-manifest`, `version`, `help`.

- [ ] Write failing tests for argument parsing, threshold exits, server content types, and traversal rejection.
- [ ] Run tests and confirm failure.
- [ ] Implement CLI and server.
- [ ] Run tests and confirm pass.

### Task 6: Production packaging and documentation

**Files:** `README.md`, `SECURITY.md`, `LICENSE`, `Dockerfile`, `.dockerignore`, `action.yml`, `scripts/github-action.mjs`, `.github/workflows/ci.yml`, `docs/architecture.md`, `docs/forgeos-bridge.md`, `project-manifest.json`.

- [ ] Add install, CLI, GitHub Action, Docker, threat model, bridge, and limitations documentation.
- [ ] Add CI and packaging metadata.
- [ ] Run full tests, coverage, syntax checks, self-scan, and package dry-run.
- [ ] Build release archive and update manifest statuses from created to verified.
