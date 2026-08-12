# Adaptive Adversarial Experiment Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build RepoTrial 0.6.0 as a bounded closed-loop experiment engine that targets selected reasoning gaps with synthetic sandbox scenarios, assimilates only positive observations, and recomputes evidence reasoning with an auditable epistemic delta.

**Architecture:** Keep planning, template definition, observation classification, evidence conversion, and delta computation as pure focused modules under `src/experiments/`. Reuse the existing Linux namespace/chroot sandbox through a validated scenario primitive, then make `scanRepository()` perform initial reasoning → plan/execute → evidence assimilation → final reasoning only when experiments are enabled.

**Tech Stack:** Node.js ESM, built-in Node APIs only, existing `node:test` suite, JSON Schema, GitHub Actions. Zero npm runtime dependencies.

## Global Constraints

- Version target is `0.6.0`.
- Node.js floor remains 22.14+ with Node 22/24 CI.
- No real host secret enters an experiment environment.
- Synthetic canary values never persist verbatim in public artifacts.
- Experiments never weaken chroot, namespace, copied-rootfs, resource, or network isolation.
- `NOT_OBSERVED` never becomes global negative evidence.
- Experiment execution remains opt-in; `off` preserves 0.5 behavior.
- Planner/classifier outputs must be deterministic for identical inputs and seed.
- Maximum defaults: 6 experiments, 2 experiments per candidate, 8 synthetic env keys, 8 sentinels.

---

## File Structure

**Create**
- `src/experiments/templates.mjs` — internal experiment templates and validation.
- `src/experiments/planner.mjs` — deterministic information-gain planner.
- `src/experiments/observe.mjs` — baseline/scenario observation classifier.
- `src/experiments/evidence.mjs` — positive observation → canonical experiment charge conversion.
- `src/experiments/delta.mjs` — initial/final reasoning epistemic delta.
- `src/experiments/run.mjs` — bounded plan/execute orchestration around the runtime scenario primitive.
- `schemas/experiments.schema.json` — `repotrial.experiments.v1` contract.
- `tests/experiments-planner.test.mjs`
- `tests/experiments-observe.test.mjs`
- `tests/experiments-integration.test.mjs`
- `tests/experiments-runtime.test.mjs`

**Modify**
- `src/runtime/sandbox.mjs` — expose safe reusable scenario execution without changing baseline runtime defaults.
- `src/reasoning/engine.mjs` — map only strong experiment rule IDs to capabilities.
- `src/core/analyze.mjs` — initial reasoning → experiments → final reasoning orchestration and artifact writing.
- `src/core/report.mjs` — experiment/epistemic-delta report panel.
- `src/index.mjs` — public pure experiment APIs and bounded runner export.
- `src/cli.mjs` — experiment controls and summary.
- `action.yml`, `scripts/github-action.mjs` — CI controls/outputs.
- `schemas/report.schema.json` — optional experiments reference.
- `tests/analyze.test.mjs`, `tests/cli.test.mjs`, `tests/action.test.mjs`, `tests/schema.test.mjs` — integration contracts.
- `package.json`, `package-lock.json`, `README.md`, `README-VN.md`, `CHANGELOG.md` — 0.6 release contract/docs.

---

### Task 1: Deterministic templates and planner

**Files:**
- Create: `src/experiments/templates.mjs`
- Create: `src/experiments/planner.mjs`
- Create: `tests/experiments-planner.test.mjs`

**Interfaces:**
- `getExperimentTemplate(templateId: string): ExperimentTemplate | null`
- `validateExperimentScenario(scenario: object): object`
- `planAdaptiveExperiments({ reasoning, candidates, maxExperiments?, maxPerCandidate? }): ExperimentPlan`
- `ExperimentPlan.schemaVersion === 'repotrial.experiment-plan.v1'`

- [ ] **Step 1: Write failing planner tests**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { planAdaptiveExperiments } from '../src/experiments/planner.mjs';

const reasoning = {
  schemaVersion: 'repotrial.reasoning.v1',
  hypotheses: [{ id: 'credential-exfiltration', state: 'UNKNOWN', severity: 'critical', missingStages: ['secret-source','network-egress'], confidence: 0.32 }],
  attackPaths: [{ id: 'path:x', hypothesisId: 'credential-exfiltration', severity: 'critical', viability: 'PARTIAL', missingStages: ['secret-source','network-egress'], stages: [] }]
};
const candidates = [{ kind: 'package-script', packagePath: 'package.json', name: 'postinstall', command: 'node install.js', workingDirectory: '.' }];

test('planner targets critical partial paths deterministically', () => {
  const a = planAdaptiveExperiments({ reasoning, candidates, maxExperiments: 6, maxPerCandidate: 2 });
  const b = planAdaptiveExperiments({ reasoning, candidates, maxExperiments: 6, maxPerCandidate: 2 });
  assert.deepEqual(a, b);
  assert.equal(a.experiments[0].templateId, 'secret-egress-canary-v1');
  assert.equal(a.experiments[0].hypothesisId, 'credential-exfiltration');
});

test('planner never targets viable or blocked paths and obeys budgets', () => {
  const mixed = { ...reasoning, attackPaths: [
    reasoning.attackPaths[0],
    { ...reasoning.attackPaths[0], id: 'path:viable', viability: 'VIABLE' },
    { ...reasoning.attackPaths[0], id: 'path:blocked', viability: 'BLOCKED' }
  ] };
  const result = planAdaptiveExperiments({ reasoning: mixed, candidates: [...candidates, {...candidates[0], name:'prepare'}], maxExperiments: 1, maxPerCandidate: 1 });
  assert.equal(result.experiments.length, 1);
  assert.equal(result.budget.maxExperiments, 1);
});
```

- [ ] **Step 2: Run test and confirm RED**

Run: `node --test tests/experiments-planner.test.mjs`
Expected: `ERR_MODULE_NOT_FOUND` for `src/experiments/planner.mjs`.

- [ ] **Step 3: Implement internal templates**

`templates.mjs` defines immutable templates for:

```js
export const EXPERIMENT_TEMPLATES = Object.freeze({
  'secret-egress-canary-v1': Object.freeze({
    id: 'secret-egress-canary-v1',
    envKeys: ['OPENAI_API_KEY','GITHUB_TOKEN','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY'],
    sentinels: [],
    expectedObservations: ['network-delta','canary-propagation']
  }),
  'filesystem-sentinel-v1': Object.freeze({
    id: 'filesystem-sentinel-v1',
    envKeys: [],
    sentinels: ['.repotrial-experiment/sentinel-a',' .repotrial-experiment/sentinel-b'].map((v) => v.trim()),
    expectedObservations: ['sentinel-mutation','filesystem-delta']
  }),
  'ci-context-trigger-v1': Object.freeze({
    id: 'ci-context-trigger-v1',
    envKeys: ['CI','GITHUB_ACTIONS'],
    sentinels: [],
    expectedObservations: ['network-delta','filesystem-delta','process-delta']
  })
});
```

Validation rejects unknown templates, >8 env keys, >8 sentinels, invalid env names, and any sentinel outside `.repotrial-experiment/`.

- [ ] **Step 4: Implement planner**

Planner ranking formula is deterministic:

```js
priority = severityRank[path.severity] * 100
  + Math.max(0, 20 - (path.missingStages?.length ?? 0) * 5)
  + Math.round((1 - Number(hypothesis.confidence ?? 0)) * 10);
```

Template selection rules:

- credential exfiltration with missing `secret-source` or `network-egress` → `secret-egress-canary-v1`;
- unapproved destructive action with missing destructive capability → `filesystem-sentinel-v1`;
- other partial high/critical runtime-addressable path → `ci-context-trigger-v1` only when a runtime candidate exists;
- dedupe by template/hypothesis/candidate identity and enforce global/per-candidate budgets.

- [ ] **Step 5: Run planner tests GREEN**

Run: `node --test tests/experiments-planner.test.mjs`
Expected: all tests pass.

- [ ] **Step 6: Commit**

Commit: `feat: add deterministic adaptive experiment planner`

---

### Task 2: Observation classifier, evidence assimilation, and epistemic delta

**Files:**
- Create: `src/experiments/observe.mjs`
- Create: `src/experiments/evidence.mjs`
- Create: `src/experiments/delta.mjs`
- Create: `tests/experiments-observe.test.mjs`
- Modify: `src/reasoning/engine.mjs`

**Interfaces:**
- `classifyExperimentObservation({ experiment, baselineRun, scenarioRun, canaryFingerprints, sentinelPaths }): ExperimentObservation`
- `experimentObservationsToCharges({ observations, snapshot }): Charge[]`
- `buildEpistemicDelta(initialReasoning, finalReasoning): EpistemicDelta`

- [ ] **Step 1: Write failing observation/evidence tests**

```js
test('canary propagation into a network event creates critical positive evidence', () => {
  const observation = classifyExperimentObservation({
    experiment,
    baselineRun: { events: [], filesystemChanges: [], stdout:'', stderr:'' },
    scenarioRun: { status:'completed', events:[{kind:'network', target:'https://x.test/?k=synthetic-value'}], filesystemChanges:[], stdout:'', stderr:'' },
    canaries: [{ fingerprint:'abc', value:'synthetic-value' }],
    sentinelPaths: []
  });
  assert.equal(observation.state, 'OBSERVED');
  assert.equal(observation.signals.canaryNetworkPropagation, true);
});

test('NOT_OBSERVED never creates a charge or global absence', () => {
  const charges = experimentObservationsToCharges({ observations:[{ id:'obs:x', state:'NOT_OBSERVED', signals:{} }], snapshot:{files:[]} });
  assert.deepEqual(charges, []);
});
```

- [ ] **Step 2: Run RED**

Run: `node --test tests/experiments-observe.test.mjs`
Expected: module-not-found.

- [ ] **Step 3: Implement classifier**

Classifier compares normalized baseline/scenario event counts and filesystem deltas. It detects canary values against raw scenario data before final public redaction. State rules:

```text
INCONCLUSIVE: timeout / unavailable / unusable truncation
OBSERVED: canary-network propagation OR sentinel mutation/deletion OR newly triggered network event
TRIGGERED: measurable process/filesystem/CI behavior delta without a strong target signal
NOT_OBSERVED: completed with no target signal
```

Public observation output contains canary SHA-256 fingerprints only, never canary values.

- [ ] **Step 4: Implement positive-evidence conversion**

Create charges only for `OBSERVED` signals:

- `adaptive-secret-egress-observed` critical/high confidence when canary enters a network-related target;
- `adaptive-network-trigger-observed` critical/high confidence when network activity appears only under the scenario;
- `adaptive-sentinel-destruction-observed` high/high confidence when sentinel is deleted/modified;
- `adaptive-ci-triggered-behavior` medium when only contextual delta exists and state is `TRIGGERED`; this rule deliberately maps to no dangerous capability.

Evidence anchors reuse candidate package/config path and stable candidate identity.

- [ ] **Step 5: Extend reasoning capability mapping**

In `capabilitiesForCharge()` add only:

```js
if (id === 'adaptive-secret-egress-observed') return ['secret-access','network-egress'];
if (id === 'adaptive-network-trigger-observed') return ['network-egress'];
if (id === 'adaptive-sentinel-destruction-observed') return ['destructive-action','filesystem-write'];
```

Do not map `adaptive-ci-triggered-behavior`.

- [ ] **Step 6: Implement epistemic delta**

Return `repotrial.epistemic-delta.v1` with hypothesis transitions, path transitions, newly observed capabilities, satisfied missing stages, and unresolved targets. Do not label any transition as trust improvement.

- [ ] **Step 7: Run tests GREEN and commit**

Run: `node --test tests/experiments-observe.test.mjs tests/reasoning.test.mjs`
Commit: `feat: classify experiment observations and assimilate evidence`

---

### Task 3: Reusable safe runtime scenario executor

**Files:**
- Modify: `src/runtime/sandbox.mjs`
- Create: `tests/experiments-runtime.test.mjs`

**Interfaces:**
- Export `runRuntimeScenario(options): RuntimeScenarioResult`
- Baseline `runRuntimeAnalysis()` internally calls the same scenario primitive with `scenario: null`.

- [ ] **Step 1: Write failing sandbox contract tests**

Tests assert:

- arbitrary caller values cannot enter scenario env;
- only validated env-key names from a template are accepted;
- canary values are generated inside executor from `canarySeed`;
- public result contains fingerprints, not values;
- sentinel paths outside `.repotrial-experiment/` throw;
- `runRuntimeAnalysis({mode:'off'})` output remains byte-structure compatible with 0.5 expectations.

- [ ] **Step 2: Run RED**

Run: `node --test tests/experiments-runtime.test.mjs`
Expected: missing `runRuntimeScenario`.

- [ ] **Step 3: Refactor detonation primitive**

Promote the existing private candidate detonation into a reusable internal function that accepts:

```js
{
  sourceRoot,
  candidate,
  limits,
  scenario: {
    templateId,
    envKeys,
    sentinelPaths,
    canarySeed
  } | null
}
```

Before execution:

- build disposable rootfs exactly as today;
- seed sentinels under `/workspace/.repotrial-experiment/`;
- generate synthetic values as `rtx_<sha256(seed + key).slice(0,24)>`;
- preserve fixed sandbox env and add only generated scenario vars;
- for `CI` and `GITHUB_ACTIONS`, use literal `true` instead of a secret-shaped canary;
- compute raw observations/canary fingerprints before redaction;
- discard raw canary values before returning.

- [ ] **Step 4: Keep containment invariant**

Do not alter `NAMESPACE_FLAGS`, chroot usage, copied rootfs, `PATH=/trap:/usr/bin:/bin`, timeout/process/file/output limits, or secret-free host inheritance.

- [ ] **Step 5: Run runtime + legacy tests GREEN**

Run: `node --test tests/experiments-runtime.test.mjs tests/runtime.test.mjs`
Expected: pass; namespace-dependent tests may skip only for existing sandbox-unavailable reason.

- [ ] **Step 6: Commit**

Commit: `refactor: add bounded runtime scenario primitive`

---

### Task 4: Experiment runner and closed-loop scan orchestration

**Files:**
- Create: `src/experiments/run.mjs`
- Modify: `src/core/analyze.mjs`
- Modify: `src/index.mjs`
- Create: `tests/experiments-integration.test.mjs`
- Modify: `tests/analyze.test.mjs`

**Interfaces:**
- `runAdaptiveExperiments({ mode, root, snapshot, reasoning, runtime, runtimeOptions, budgets, scanId }): ExperimentsResult`
- `ExperimentsResult.schemaVersion === 'repotrial.experiments.v1'`

- [ ] **Step 1: Write failing integration tests**

Cover:

1. `off` → no execution and same final charges/reasoning semantics as 0.5.
2. `plan` → deterministic plan, zero runs, zero experiment charges.
3. `sandbox unavailable` → status `inconclusive`/`unavailable`, no safe conclusion.
4. synthetic completed observation fixture → experiment charge appended and final reasoning differs from initial reasoning.
5. `NOT_OBSERVED` → no charge and final reasoning remains epistemically unresolved.

- [ ] **Step 2: Run RED**

Run: `node --test tests/experiments-integration.test.mjs`

- [ ] **Step 3: Implement bounded runner**

`run.mjs`:

- calls planner;
- returns plan immediately in `plan` mode;
- in `sandbox` mode matches each planned experiment to an existing runtime candidate;
- executes at most configured budget via `runRuntimeScenario`;
- classifies each run;
- returns positive charges separately from public observations;
- constructs summary counts.

- [ ] **Step 4: Convert `scanRepository()` to two-stage reasoning when enabled**

Pseudo-flow:

```js
const baseCharges = [...local, ...forge, ...runtime, ...supply];
const initialReasoning = reasonAboutEvidence(baseReasoningInput(baseCharges));
const experiments = await runAdaptiveExperiments({ reasoning: initialReasoning, runtime, ... });
const charges = [...baseCharges, ...experiments.charges];
const verdict = calculateVerdict(charges, snapshot.coverage);
const reasoning = reasonAboutEvidence(baseReasoningInput(charges));
experiments.epistemicDelta = buildEpistemicDelta(initialReasoning, reasoning);
```

`off` must avoid unnecessary re-execution and produce no experiment charges.

- [ ] **Step 5: Export public APIs**

`src/index.mjs` exports planner, classifier, delta, and bounded runner functions.

- [ ] **Step 6: Run integration/full targeted suite and commit**

Run: `node --test tests/experiments-*.test.mjs tests/analyze.test.mjs tests/reasoning.test.mjs tests/runtime.test.mjs`
Commit: `feat: close the reasoning loop with adaptive experiments`

---

### Task 5: Artifact, schema, HTML, CLI, and GitHub Action contracts

**Files:**
- Create: `schemas/experiments.schema.json`
- Modify: `schemas/report.schema.json`
- Modify: `src/core/analyze.mjs`
- Modify: `src/core/report.mjs`
- Modify: `src/cli.mjs`
- Modify: `action.yml`
- Modify: `scripts/github-action.mjs`
- Modify: `tests/schema.test.mjs`, `tests/cli.test.mjs`, `tests/action.test.mjs`, `tests/analyze.test.mjs`

**Interfaces:**
- Artifact `.repotrial/experiments.json`.
- CLI controls: `--experiments`, `--experiment-max-runs`, `--experiment-max-per-candidate`, `--experiment-timeout`.
- Action inputs mirror CLI.

- [ ] **Step 1: Write RED contract tests**

Assertions include:

```js
assert.match(help, /--experiments <mode>/);
assert.equal(report.experiments.schemaVersion, 'repotrial.experiments.v1');
assert.ok(await exists(path.join(output, 'experiments.json')));
assert.match(html, /Adaptive Experiments/);
```

Action YAML must expose experiment inputs and machine outputs.

- [ ] **Step 2: Implement schema**

Schema requires mode/status/budget/plan/runs/observations/epistemicDelta/summary and explicitly allows observation states `OBSERVED|TRIGGERED|NOT_OBSERVED|INCONCLUSIVE`.

`report.schema.json` adds optional `$ref` to experiments schema without making the field required.

- [ ] **Step 3: Write artifact and proof-bind it**

`scanRepository()` writes `experiments.json` when experiments are not `off`; artifact proof naturally includes it through the existing artifact list.

- [ ] **Step 4: Add HTML panel**

Render:

- mode/status;
- planned/executed/positive counts;
- high-priority experiments;
- hypothesis/path transitions;
- unresolved experiment targets;
- caveat that NOT_OBSERVED is not proof of absence.

All repository-controlled strings use existing escaping/redaction.

- [ ] **Step 5: Add CLI and Action controls/summary**

Validate modes and bounded integers. Defaults keep experiments off. Existing exit codes and reasoning gates remain unchanged.

- [ ] **Step 6: Run contract tests GREEN and commit**

Run: `node --test tests/schema.test.mjs tests/cli.test.mjs tests/action.test.mjs tests/analyze.test.mjs`
Commit: `feat: publish adaptive experiment contracts and CI controls`

---

### Task 6: 0.6 release hardening, adversarial tests, docs, and full verification

**Files:**
- Modify: `package.json`, `package-lock.json`, `README.md`, `README-VN.md`, `CHANGELOG.md`
- Modify/add tests as needed for release contract and adversarial cases.

- [ ] **Step 1: Write release-contract RED test**

Require version `0.6.0`, schema presence, public exports, default experiments off, and no runtime dependencies.

- [ ] **Step 2: Bump package + lock to 0.6.0**

Keep canonical `Nolane-x/repotrial` metadata and zero runtime dependencies.

- [ ] **Step 3: Add adversarial corpus tests**

Cases include:

- repo prints synthetic canary to stdout;
- repo places canary in child-process/network arguments;
- repo attempts sentinel traversal;
- repo detects CI variables and conditionally mutates files;
- repo times out;
- repo emits huge output;
- repo never observes canary (must not create global absence);
- malicious repository-controlled text attempts report HTML injection.

- [ ] **Step 4: Update docs**

Document modes, threat model, canary safety, epistemic semantics, CLI/Action examples, and why `NOT_OBSERVED != ABSENT`.

- [ ] **Step 5: Full verification**

Run in CI on Node 22 and 24:

```bash
npm test
npm run check
npm run test:coverage
npm pack --dry-run
node bin/repotrial.mjs scan tests/fixtures/cautious-agent --forgeos off --runtime off --supply-chain offline --experiments plan --output .repotrial-ci --fail-on reckless
docker build -t repotrial:test .
docker run --rm repotrial:test version
```

Also run `git diff --check`, `node --check` over production `.mjs`, `npm audit --omit=dev --audit-level=high`, and RepoTrial self-scan.

- [ ] **Step 6: Create PR from `feat/adaptive-adversarial-experiments-v1` to `main`**

PR body must enumerate safety invariants, TDD RED→GREEN checkpoints, compatibility boundary, and exact CI evidence. Do not merge until final branch verification is green.
