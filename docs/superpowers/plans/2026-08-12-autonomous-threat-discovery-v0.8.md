# RepoTrial 0.8 Autonomous Threat Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add deterministic autonomous threat-hypothesis discovery and evidence-realm isolation, then dogfood RepoTrial on itself.

**Architecture:** Preserve 0.5 evidence reasoning and 0.7 registry-backed causal synthesis. Add pure realm classification, pure hypothesis discovery, and a fail-closed promotion gate, then integrate additively into causal orchestration, artifacts, CLI/Action/report, benchmarks, and release contracts.

**Tech Stack:** Node.js ESM, zero runtime dependencies, `node:test`, existing causal graph/runtime/proof/provenance infrastructure.

## Global Constraints
- Node.js `>=22.14`.
- Zero npm runtime dependencies.
- `NOT_OBSERVED` never becomes global proof of absence.
- No real host secrets in experiments.
- Discovery never mutates the built-in threat registry.
- `all` remains compatibility realm scope.
- Legacy verdict semantics remain unchanged by default.

### Task 1 — Evidence realms
Create `src/reasoning/evidence-realms.mjs` and `tests/evidence-realms.test.mjs`. RED tests cover production/test/benchmark/fixture/docs/generated/vendor/unknown, multi-anchor evidence, mixed-realm chains, and deterministic identity. Implement `classifyEvidencePath`, `buildEvidenceRealmIndex`, and `assessChainRealm`. Run focused tests then full suite.

### Task 2 — Capability semantics + hypothesis discovery
Create `src/reasoning/capability-semantics.mjs`, `src/reasoning/hypothesis-discovery.mjs`, and tests. RED tests require no invented capabilities, generic bounded composition grammar, same-realm composition, mixed-realm rejection, novelty scoring, top-K bounds, dominance pruning, severity bounds, and input-order determinism. Implement candidate states `STRUCTURAL`, `CORROBORATED`, `PROMOTABLE`, `DISMISSED`.

### Task 3 — Promotion gate
Create `src/reasoning/hypothesis-promotion.mjs` and tests. Only production-relevant, corroborated, novel candidates can convert into transient `repotrial.threat-registry.v1` compatible definitions. Promotion must never mutate the built-in registry.

### Task 4 — Causal integration
Modify `src/reasoning/causal-engine.mjs`, `src/reasoning/causal-gates.mjs`, `src/index.mjs`, and integration tests. Add `discover` mode and `realmScope: all|production`. Annotate existing chains with realm assessments. Discovery runs only for `discover|active`; analyze remains compatible.

### Task 5 — Artifacts/report/schemas
Modify scan orchestration and HTML. Add `schemas/hypotheses.schema.json`; write proof/provenance-bound `hypotheses.json` only when discovery runs. Preserve off-mode report shape. Render realm counts and discovered candidates with explicit candidate-not-proven language.

### Task 6 — CLI + GitHub Action
Add `--causal discover`, `--causal-realm-scope all|production`, Action inputs/outputs, help validation, production-active count, candidate count and promotable count. Keep existing exit semantics.

### Task 7 — Discovery benchmark + self-dogfood
Add repository-native discovery corpus and metrics: candidate recall >= .95, promotable precision >= .95, benign production FPR <= .05, realm isolation = 1, replay = 1. Add CI benchmark. Dogfood RepoTrial on RepoTrial: 0.7 fixture/corpus chains remain visible in all-scope but production-active count becomes zero.

### Task 8 — Release 0.8.0
Bump package/lock/manifest/changelog/docs, keep zero dependencies, add release contracts. Run full tests/check/coverage/adversarial benchmark/discovery benchmark/audit/pack/syntax/self-scan/sandbox tests. Push, PR, CI Node 22/24 + Docker, squash merge main, post-merge CI, exact-main ZIP, checksum, Library backup.
