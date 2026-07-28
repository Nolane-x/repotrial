# RepoTrial v0.3.0 Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans and superpowers:test-driven-development. Every behavioral task follows red-green-refactor.

**Goal:** Harden RepoTrial against filesystem/bridge bypasses, expand deterministic coverage across popular coding agents, and add GitHub-native SARIF output.

**Architecture:** Shared surface classification feeds both local rules and ForgeOS manifest generation. Discovery becomes omission-tolerant and output-aware, the report server resolves real paths, bridge inputs are policy-checked and protocol-validated, and a new deterministic SARIF renderer consumes canonical charges.

**Tech Stack:** Node.js 20.12+ ESM, built-in `node:test`, Node HTTP/filesystem/child-process APIs, SARIF 2.1.0, zero runtime npm dependencies.

## Global Constraints

- Never execute target repository code.
- Never follow repository symlinks.
- Never include absolute target paths or secret values in portable output by default.
- ForgeOS remains optional and fail-open for the independent scan.
- No production implementation without a failing regression test first.

---

### Task 1: Shared agent-surface classification

**Files:** Create `src/core/surfaces.mjs`; modify `src/core/rules.mjs`, `src/bridge/manifest.mjs`; test `tests/surfaces.test.mjs`, `tests/rules.test.mjs`, `tests/forgeos-native.test.mjs`.

- [x] Add failing tests for Copilot, Cursor, Cline, Windsurf, Continue, Claude, Gemini, and AGENTS instruction paths.
- [x] Implement one shared `classifyRepositoryFile(relativePath)` interface.
- [x] Reuse it in local rules and ForgeOS manifest generation.

### Task 2: Rule accuracy hardening

**Files:** Modify `src/core/rules.mjs`, `src/core/evidence.mjs`; test `tests/rules.test.mjs`, `tests/evidence.test.mjs`.

- [x] Add failing tests for no-op verification, nested package verification, shell-only capability, wildcard variants, and bounded evidence.
- [x] Implement credible verification classification and broader agent-config scanning.
- [x] Replace repeated prefix line scans with precomputed line offsets and match caps.

### Task 3: Discovery and output isolation

**Files:** Modify `src/core/discover.mjs`, `src/core/analyze.mjs`, `src/cli.mjs`; test `tests/discover.test.mjs`, `tests/analyze.test.mjs`, `tests/cli.test.mjs`.

- [x] Add failing tests for exact ignored paths, invalid UTF-8, changed/unreadable entries, output-root rejection, output-subtree exclusion, and portable target paths.
- [x] Implement omission-tolerant discovery and target privacy option.

### Task 4: Report server containment

**Files:** Modify `src/server.mjs`; test `tests/server.test.mjs`.

- [x] Add a failing symlink escape test.
- [x] Resolve report root/candidates with realpath and reject escaped or symbolic resources.

### Task 5: Bridge protocol and transport policy

**Files:** Modify `src/bridge/forgeos.mjs`, `src/cli.mjs`; test `tests/bridge.test.mjs`, `tests/cli.test.mjs`.

- [x] Add failing tests for non-loopback plaintext URL rejection, invalid schema/status/mode, and deeply nested payloads.
- [x] Implement URL policy, explicit insecure opt-in, strict response normalization, and iterative traversal.

### Task 6: Sidecar request hardening

**Files:** Modify `integrations/forgeos/bridge-server.mjs`; test `tests/bridge.test.mjs`.

- [x] Add failing tests for authenticated readiness, oversized body response, and body timeout.
- [x] Implement reliable bounded-body handling and server timeout configuration.

### Task 7: SARIF output

**Files:** Create `src/core/sarif.mjs`, `schemas/repotrial-sarif-notes.md`; modify `src/core/analyze.mjs`, `src/cli.mjs`, `scripts/github-action.mjs`, `action.yml`; test `tests/sarif.test.mjs`, `tests/analyze.test.mjs`, `tests/action.test.mjs`.

- [x] Add failing tests for SARIF structure, relative locations, rule metadata, and action output.
- [x] Generate SARIF 2.1.0 as a sixth portable artifact.

### Task 8: Release hardening

**Files:** Modify package/docs/workflows/security/changelog/manifest.

- [x] Validate GitHub Action threshold and output escaping.
- [x] Update version to 0.3.0 and document limitations/security changes.
- [x] Run all release gates and ForgeOS v0.6.1 acceptance.
- [x] Build verified source, npm, changeset, and demo packages with SHA-256 checksums.
