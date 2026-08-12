# RepoTrial 0.7 Causal Adversarial Reasoning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build RepoTrial 0.7.0 as a deterministic causal adversarial investigation engine with declarative threat knowledge, multi-chain synthesis, active experiment selection, bounded stateful episodes, and a repository-native benchmark corpus.

**Architecture:** Keep the existing canonical evidence/reasoning pipeline as the compatibility core. Add focused pure modules under `src/causal/`, extend experiments through an episode layer rather than rewriting the sandbox, and integrate causal artifacts/gates/reporting additively so `--causal off` preserves 0.6 behavior.

**Tech Stack:** Node.js ESM, built-in Node APIs only, `node:test`, JSON Schema, GitHub Actions. Zero npm runtime dependencies.

## Global Constraints

- Version target is `0.7.0`.
- Node.js floor remains 22.14+ with Node 22/24 CI.
- Zero npm runtime dependencies.
- Causal mode defaults to `off` and preserves RepoTrial 0.6 report/verdict behavior.
- No real host secret enters an episode environment.
- Synthetic canaries never persist verbatim.
- Episodes cannot weaken namespace/chroot/copied-rootfs/network/resource containment.
- `NOT_OBSERVED` never becomes global negative evidence.
- Registry, graph, chain synthesis, and active-policy outputs are deterministic for identical normalized inputs.
- Every causal hop must retain evidence ancestry and scope.

---

## File Structure

**Create**
- `src/causal/registry.mjs` — declarative threat registry and validation.
- `src/causal/graph.mjs` — causal capability graph construction.
- `src/causal/chains.mjs` — bounded deterministic attack-chain synthesis.
- `src/causal/policy.mjs` — uncertainty frontier and active probe utility ranking.
- `src/causal/engine.mjs` — pure causal orchestration.
- `src/experiments/episodes.mjs` — bounded stateful episode planner/executor.
- `schemas/causal.schema.json` — `repotrial.causal.v1`.
- `schemas/benchmark.schema.json` — `repotrial.benchmark.v1`.
- `benchmarks/adversarial-corpus/manifest.json` plus fixture repositories.
- `scripts/run-adversarial-benchmark.mjs` — corpus metrics runner.
- focused tests: `tests/causal-registry.test.mjs`, `tests/causal-graph.test.mjs`, `tests/causal-chains.test.mjs`, `tests/causal-policy.test.mjs`, `tests/episodes.test.mjs`, `tests/causal-integration.test.mjs`, `tests/benchmark.test.mjs`.

**Modify**
- `src/reasoning/engine.mjs` — consume registry-backed threat definitions while preserving existing `repotrial.reasoning.v1` shape.
- `src/experiments/planner.mjs` / `run.mjs` — expose inputs needed by active causal policy without changing 0.6 defaults.
- `src/runtime/sandbox.mjs` — no containment change; only reusable validated episode phase execution if required.
- `src/core/analyze.mjs` — optional causal orchestration/artifact binding.
- `src/core/report.mjs` — causal attack-chain/uncertainty panel.
- `src/core/diff.mjs` — additive causal regression diff.
- `src/index.mjs`, `src/cli.mjs`, `scripts/github-action.mjs`, `action.yml` — product surface.
- `schemas/report.schema.json`, integrity/provenance paths, package/version/docs/release contract.

---

### Task 1: Declarative Threat Registry

**Interfaces:**
- Produces `getThreatRegistry()`, `validateThreatRegistry(registry)`, `threatById(id)`.
- Registry definitions include `id`, `title`, `severity`, `stages`, `mitigatedBy`, `runtimeAddressableStages`.

- [ ] Write failing tests asserting 10 seeded threat families, stable ordering, duplicate/stage validation, and immutability.
- [ ] Run `node --test tests/causal-registry.test.mjs` and verify module-not-found/contract failures.
- [ ] Implement `src/causal/registry.mjs` with frozen normalized definitions and fail-closed validation.
- [ ] Replace hard-coded `HYPOTHESES` in reasoning with registry-derived compatibility definitions for the original five threats; preserve existing IDs/states.
- [ ] Run registry + reasoning tests; commit `feat: add declarative causal threat registry`.

### Task 2: Causal Capability Graph

**Interfaces:**
- `buildCausalGraph({ charges, safeguards, negativeEvidence, reasoning }) -> repotrial.causal-graph.v1`.
- Node identity must depend on semantic anchors, not title/severity wording.

- [ ] Write RED tests for node/edge classes, evidence ancestry, stable IDs under wording change, reordering determinism, and unknown-rule non-invention.
- [ ] Implement graph construction with typed nodes/relations and stable SHA-256 IDs.
- [ ] Add bounded metadata normalization/redaction-compatible values.
- [ ] Run tests + fuzz malformed inputs; commit `feat: build causal capability graph`.

### Task 3: Multi-chain Synthesizer

**Interfaces:**
- `synthesizeAttackChains({ graph, registry, maxDepth=8, topKPerThreat=8 })`.
- Output `repotrial.attack-chains.v1` with states `PROVEN|SUPPORTED|PARTIAL|CONTRADICTED|REFUTED|UNTESTED` and exact hop evidence IDs.

- [ ] Write RED tests for two causally distinct chains for one threat, cycles, depth caps, top-K, dominance pruning, mitigation contradiction, explicit absence refutation, and deterministic replay.
- [ ] Implement bounded graph search and chain scoring.
- [ ] Ensure chains with same sink but distinct prerequisite routes remain distinct unless dominated.
- [ ] Run targeted + reasoning regression tests; commit `feat: synthesize bounded causal attack chains`.

### Task 4: Active Uncertainty / Probe Policy

**Interfaces:**
- `rankCausalProbes({ chains, candidates, templates, maxExperiments })`.
- Every result exposes auditable factors: `impact`, `epistemicGain`, `centrality`, `discrimination`, `executionCost`, `redundancyPenalty`, `riskPenalty`, `utility`.

- [ ] Write RED tests proving a probe that discriminates multiple critical chains outranks a redundant single-chain probe, plus tie determinism/budget caps.
- [ ] Implement uncertainty frontier extraction and utility decomposition with fixed bounded arithmetic.
- [ ] Add adapter from ranked causal probe to existing validated 0.6 experiment scenarios.
- [ ] Run planner 0.6 regression tests + new policy tests; commit `feat: add active causal experiment policy`.

### Task 5: Stateful Adversarial Episodes

**Interfaces:**
- `planAdversarialEpisode(probe)` and `runAdversarialEpisode({ root, candidate, episode, timeoutMs, seed })`.
- Phase states: `PREPARE|PRIME|TRIGGER|OBSERVE|FOLLOW_UP|VERIFY`.

- [ ] Write RED tests for memory persistence, identity context, tool-marker propagation, traversal/arbitrary-env rejection, raw canary non-persistence, and sandbox unavailable → `INCONCLUSIVE`.
- [ ] Implement `episodes.mjs` using internal templates and repeated validated `runRuntimeScenario()` phases.
- [ ] Preserve copied-rootfs and containment invariants; never accept arbitrary secret values.
- [ ] Run targeted sandbox-capable tests where available; commit `feat: add bounded stateful adversarial episodes`.

### Task 6: Causal Engine + Scan/Product Integration

**Interfaces:**
- `analyzeCausalEvidence(input)` returns `repotrial.causal.v1` with graph, chains, frontier, episode summary, and causal summary.
- CLI `--causal off|analyze|active`; defaults off.

- [ ] Write RED integration tests: causal off report/receipt compatibility, analyze no execution, active bounded execution, causal artifact proof binding, schemas and public exports.
- [ ] Implement pure causal engine and optional `scanRepository()` path.
- [ ] Add `causal.json`, report panel, causal diff fields, provenance/artifact proof subjects.
- [ ] Add opt-in `--fail-on-causal` exit 6 and `--fail-on-new-causal` exit 7 via shared gate module; preserve 0–5 semantics.
- [ ] Add GitHub Action inputs/outputs and runner integration.
- [ ] Run full tests/check/coverage/fixture/package/Docker CI; commit `feat: integrate RepoTrial causal analysis`.

### Task 7: Adversarial Corpus + Metrics

**Interfaces:**
- `node scripts/run-adversarial-benchmark.mjs [--json path]`.
- Manifest cases declare expected threat IDs, minimum chain state, expected benign flag, and optional expected stage IDs.

- [ ] Add RED benchmark tests for metric math and manifest validation.
- [ ] Create at least 12 compact corpus cases spanning positive, benign near-miss, multi-file, lifecycle, secret-egress, instruction-tool, memory, identity/CI, destructive approval, incomplete/decoy cases.
- [ ] Implement benchmark runner with threat recall, chain precision, benign FPR, stage recall, deterministic replay equality.
- [ ] Add CI benchmark gate with explicit minimum thresholds derived from the committed corpus and no hidden network dependency.
- [ ] Commit `test: add adversarial causal benchmark corpus`.

### Task 8: 0.7 Release Contract and Hardening

- [ ] Add RED release-contract tests for version `0.7.0`, schemas/docs/action inputs, zero runtime dependencies, and no hard-coded secondary version source.
- [ ] Update package/lock, README/README-VN, CHANGELOG, architecture/evidence/adaptive docs, and add `docs/causal-adversarial-reasoning.md`.
- [ ] Run `node --check` over production `.mjs`, `npm audit --omit=dev --audit-level=high`, `git diff --check`, full Node 22/24 CI, benchmark, npm pack, Docker E2E.
- [ ] Self-scan RepoTrial 0.7 with causal analyze mode and inspect raw-canary leakage/artifact proof.
- [ ] Open PR, review full patch, merge only if all gates are green, then verify `main` post-merge.
- [ ] Export complete source from final main SHA, rerun sandbox-capable tests from exported tree, create `RepoTrial-0.7.0-COMPLETE-DELIVERY-<sha>.zip`, SHA-256 ledger/checksum, and persist ZIP/checksum to ChatGPT Library.
