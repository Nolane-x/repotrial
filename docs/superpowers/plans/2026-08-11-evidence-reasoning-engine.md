# Evidence Reasoning Engine v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic evidence reasoning layer that converts canonical RepoTrial charges and safeguards into an evidence graph, threat hypotheses, attack paths, confidence states, counterfactual remediation ranking, and security invariant proof.

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
- Create: `tests/reasoning-engine.test.mjs`

**Interfaces:**
- Consumes: `reasonAboutEvidence({ charges, safeguards, coverage, providers })`.
- Produces: `repotrial.reasoning.v1` object containing `graph`, `hypotheses`, `attackPaths`, `remediation`, and `summary`.

- [x] **Step 1: Write failing tests** for stable output, unknown-rule preservation without capability invention, and charge-order invariance.
- [x] **Step 2: Verify the tests fail for the missing module/export.**
- [x] **Step 3: Implement normalized evidence nodes, capability extraction, stable SHA-256 IDs, deterministic sorting, and schema contract.**
- [x] **Step 4: Re-run focused and CI tests** and verify green.

### Task 2: Threat hypotheses and epistemic states

**Files:**
- Modify: `src/reasoning/engine.mjs`
- Modify: `tests/reasoning-engine.test.mjs`

- [x] Implement built-in hypotheses for credential exfiltration, arbitrary code execution, destructive action, prompt-to-tool escalation, and supply-chain compromise.
- [x] Preserve `UNKNOWN` instead of inventing absence.
- [x] Model safeguard contradictions explicitly.

### Task 3: Attack paths and counterfactual remediation

**Files:**
- Modify: `src/reasoning/engine.mjs`
- Modify: `tests/reasoning-engine.test.mjs`

- [x] Build deterministic `VIABLE|PARTIAL|BLOCKED` attack paths.
- [x] Rank counterfactual remediation by paths eliminated and high-impact hypotheses downgraded.
- [x] Verify charge-order determinism.

### Task 4: Integrate reasoning into scan reports and public API

**Files:**
- Modify: `src/core/analyze.mjs`
- Modify: `src/index.mjs`
- Create: `tests/reasoning-integration.test.mjs`

- [x] Attach reasoning before report receipt hashing.
- [x] Export `reasonAboutEvidence` from package root.
- [x] Render an offline Evidence Reasoning panel.
- [x] Preserve legacy verdict semantics.

### Task 5: Schema/docs/version hygiene

**Files:**
- Modify: `docs/architecture.md`
- Create: `docs/evidence-reasoning.md`
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `schemas/reasoning.schema.json`

- [x] Publish the reasoning schema and documentation.
- [x] Correct package metadata to `Nolane-x/repotrial` and move to `0.5.0`.
- [x] Remove the independent hard-coded package version from scan/SARIF generation.
- [x] Preserve `repotrial.report.v2` compatibility by keeping the additive `reasoning` property optional in the v2 schema.
- [x] Stabilize evidence identity across presentation/severity changes when the stable evidence anchor is unchanged.

### Task 6: GitHub verification and review gate

- [x] Open draft PR `#1` from `feat/evidence-reasoning-engine-v1` to `main`.
- [x] Inspect the complete PR diff for provider/verdict regressions.
- [x] Use GitHub Actions Node 22, Node 24, package, coverage, fixture scan, and Docker gates.
- [x] Fix concrete review findings with test-first patches.
- [ ] Run the final verification gate after invariant proof lands.

### Task 7: Security invariant proof engine

**Files:**
- Create: `src/reasoning/invariants.mjs`
- Create: `tests/reasoning-invariants.test.mjs`
- Modify: `src/reasoning/engine.mjs`
- Modify: `src/index.mjs`
- Modify: `schemas/reasoning.schema.json`

**Interfaces:**
- Built-in and caller-supplied declarative invariants.
- States: `VIOLATED`, `SATISFIED`, `UNKNOWN`, `NOT_APPLICABLE`.
- Forbidden conjunctions may only become `SATISFIED` when explicit negative evidence refutes a missing capability; simple non-observation remains `UNKNOWN`.
- Implication invariants may become `SATISFIED` when their antecedent is observed and the required safeguard is explicitly present.

- [ ] **Step 1: Write failing tests** for destructive-action approval, secret+network forbidden composition, non-observation staying UNKNOWN, and explicit negative evidence producing SATISFIED.
- [ ] **Step 2: Implement pure declarative invariant evaluation.**
- [ ] **Step 3: Integrate invariant results into reasoning and public API.**
- [ ] **Step 4: Verify deterministic behavior and schema contract.**

### Task 8: Explicit negative evidence model

**Files:**
- Create: `src/reasoning/negative-evidence.mjs`
- Modify: `src/reasoning/engine.mjs`
- Modify: `schemas/reasoning.schema.json`
- Modify: `docs/evidence-reasoning.md`

**Interfaces:**
- Accept explicit bounded negative-evidence claims from trusted/acquisition providers; never infer them from an absent finding.
- Negative evidence identifies a capability, source, method, scope, confidence, and stable ID.
- Hypotheses become `REFUTED` only when every alternative capability for a missing required stage is explicitly absent.
- Evidence graph represents negative evidence and refutation without deleting positive evidence.

- [ ] **Step 1: Write failing tests** for explicit capability absence and hypothesis refutation.
- [ ] **Step 2: Normalize negative evidence deterministically and bind it into graph identity.**
- [ ] **Step 3: Feed negative evidence into hypothesis and invariant evaluation.**
- [ ] **Step 4: Verify no provider absence is converted into negative evidence.**

## Self-review

- Spec coverage includes graph, hypotheses, attack paths, epistemic states, counterfactual remediation, explicit negative evidence, invariant proof, integration, compatibility, docs, and verification.
- No LLM/cloud dependency is introduced.
- Reasoning remains pure and zero-dependency.
- Type consistency: `reasonAboutEvidence(input)` remains the primary public composition API; lower-level invariant and negative-evidence helpers are independently testable.