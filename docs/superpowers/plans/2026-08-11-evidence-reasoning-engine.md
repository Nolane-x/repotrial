# Evidence Reasoning Engine v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic evidence reasoning layer that converts canonical RepoTrial charges and safeguards into an evidence graph, threat hypotheses, attack paths, confidence states, and counterfactual remediation ranking.

**Architecture:** Keep all existing evidence providers unchanged. Add a pure `src/reasoning` subsystem that consumes canonical post-provider charges, then attach its result to `report.reasoning` before report hashing/provenance. Preserve current verdict behavior for compatibility.

**Tech Stack:** Node.js ESM >=22.14, built-in `node:test`, existing `src/core/hash.mjs`; zero new runtime dependencies.

## Global Constraints

- Node.js >=22.14.
- Zero npm runtime dependencies.
- Existing verdict semantics and provider contracts remain backward compatible.
- Same semantic inputs must produce byte-stable reasoning output regardless of charge ordering.
- Missing evidence must never be interpreted as proof of absence.

---

### Task 1: Reasoning core contract and deterministic graph

**Files:**
- Create: `src/reasoning/engine.mjs`
- Create: `test/reasoning-engine.test.mjs`

**Interfaces:**
- Consumes: `reasonAboutEvidence({ charges, safeguards, coverage, providers })`.
- Produces: `repotrial.reasoning.v1` object containing `graph`, `hypotheses`, `attackPaths`, `remediation`, and `summary`.

- [ ] **Step 1: Write failing tests** for stable output, unknown-rule preservation without capability invention, and charge-order invariance.
- [ ] **Step 2: Run `node --test test/reasoning-engine.test.mjs`** and verify failure is caused by the missing module/export.
- [ ] **Step 3: Implement normalized evidence nodes, capability extraction, stable SHA-256 IDs, deterministic sorting, and schema contract.**
- [ ] **Step 4: Re-run the focused test** and verify green.
- [ ] **Step 5: Commit** `feat(reasoning): add deterministic evidence graph core`.

### Task 2: Threat hypotheses and epistemic states

**Files:**
- Modify: `src/reasoning/engine.mjs`
- Modify: `test/reasoning-engine.test.mjs`

**Interfaces:**
- Produces built-in hypotheses: `credential-exfiltration`, `arbitrary-code-execution`, `unapproved-destructive-action`, `prompt-to-tool-escalation`, `supply-chain-compromise`.

- [ ] **Step 1: Add failing tests** proving complete credential exfiltration becomes `PROVEN`, incomplete evidence does not, and human approval contradicts destructive-action escalation.
- [ ] **Step 2: Run focused tests** and observe expected assertion failures.
- [ ] **Step 3: Implement deterministic hypothesis evaluation** with required capabilities, support evidence, missing capabilities, contradictions, severity, and numeric confidence `[0,1]`.
- [ ] **Step 4: Run focused tests** and verify green.
- [ ] **Step 5: Commit** `feat(reasoning): evaluate threat hypotheses`.

### Task 3: Attack paths and counterfactual remediation

**Files:**
- Modify: `src/reasoning/engine.mjs`
- Modify: `test/reasoning-engine.test.mjs`

**Interfaces:**
- Produces ordered `attackPaths[]` with `VIABLE|PARTIAL|BLOCKED` viability.
- Produces `remediation.candidates[]` ranked by paths eliminated, hypothesis downgrades, severity, then stable rule ID.

- [ ] **Step 1: Add failing tests** for multi-stage attack paths and a counterfactual where removing network-egress evidence eliminates more paths than removing an unrelated finding.
- [ ] **Step 2: Run focused tests** and verify red.
- [ ] **Step 3: Implement path construction and no-recursion counterfactual simulation.**
- [ ] **Step 4: Run focused tests** and verify green.
- [ ] **Step 5: Commit** `feat(reasoning): add attack paths and causal remediation ranking`.

### Task 4: Integrate reasoning into scan reports and public API

**Files:**
- Modify: `src/core/analyze.mjs`
- Modify: `src/index.mjs`
- Create: `test/reasoning-integration.test.mjs`

**Interfaces:**
- `scanRepository()` attaches `reasoning` before redaction/receipt hashing.
- Package root exports `reasonAboutEvidence`.

- [ ] **Step 1: Add failing integration/API tests** proving `reasoning` is present and existing verdict calculation remains unchanged for equivalent charges.
- [ ] **Step 2: Run focused tests** and verify red.
- [ ] **Step 3: Wire the pure engine after canonical charge assembly and export it.**
- [ ] **Step 4: Run focused tests and full `npm test`.**
- [ ] **Step 5: Commit** `feat: integrate evidence reasoning into RepoTrial reports`.

### Task 5: Schema/docs/version hygiene

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `package.json`

**Interfaces:**
- Document `report.reasoning` and its epistemic-state semantics.
- Correct repository metadata to `Nolane-x/repotrial`.
- Move package version to `0.5.0`; production code must not introduce a second independent version constant for reasoning.

- [ ] **Step 1: Update architecture and README** with the new reasoning pipeline and explicit non-certification language.
- [ ] **Step 2: Correct package repository/homepage/bugs metadata and bump version to `0.5.0`.**
- [ ] **Step 3: Run `npm run check`, `npm test`, `npm run test:coverage`, and `npm pack --dry-run`.**
- [ ] **Step 4: Commit** `docs: document RepoTrial 0.5 evidence reasoning`.

### Task 6: GitHub verification and review gate

**Files:** none unless CI exposes a defect.

- [ ] **Step 1: Open a PR from `feat/evidence-reasoning-engine-v1` to `main`.**
- [ ] **Step 2: Inspect the PR diff for unintended provider/verdict changes.**
- [ ] **Step 3: Inspect available GitHub Actions checks/logs.**
- [ ] **Step 4: Fix any concrete failures with test-first patches.**
- [ ] **Step 5: Leave the PR unmerged unless verification is green and the diff matches this design.**

## Self-review

- Spec coverage: graph, hypotheses, attack paths, epistemic states, counterfactual remediation, integration, compatibility, docs, and verification all have explicit tasks.
- Placeholder scan: no deferred implementation requirements are required for v1.
- Type consistency: a single public function `reasonAboutEvidence(input)` is used across unit tests, integration, and package export.