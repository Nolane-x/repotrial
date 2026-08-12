# RepoTrial 0.6 Adaptive Adversarial Experiment Engine — Design

Date: 2026-08-12
Status: Approved direction, implementation specification
Base: RepoTrial 0.5.0 (`4540cc46813140c120b4003c0c93c4283fd63aab`)

## Goal

Evolve RepoTrial from evidence reasoning over already-collected observations into a bounded closed-loop verifier that can turn selected `UNKNOWN` / `PARTIAL` reasoning gaps into targeted sandbox experiments.

The engine must answer a stronger question than “what evidence exists?”:

> Which missing capability in a high-impact attack path can be safely tested next, what synthetic scenario should be used, what was actually observed, and did that observation materially change the epistemic state of the security claim?

## Non-goals

- No LLM or probabilistic agent is required to create experiments.
- No real credential, token, API key, SSH key, cloud credential, or user secret is ever injected.
- No experiment may disable the existing network namespace, chroot, user namespace, source-copy isolation, resource budgets, or output redaction.
- A single negative experiment result must never become global negative evidence.
- The engine does not certify safety and does not silently change legacy verdict semantics.
- RepoTrial 0.6 does not attempt full interactive GUI-agent or browser-agent execution.

## Architecture

```text
repository
  -> bounded discovery / static / ForgeOS / supply chain / baseline runtime
  -> canonical charges
  -> Initial Evidence Reasoning
  -> Experiment Planner
       -> target PARTIAL / UNKNOWN high-impact paths
       -> select deterministic internal templates
       -> rank by expected information gain
       -> enforce global budget
  -> Scenario Executor (existing Linux sandbox boundary)
       -> synthetic canary environment only
       -> sandbox-local sentinel files only
       -> no host secrets / no network escape
  -> Observation Classifier
       -> baseline-vs-scenario behavior delta
       -> network attempts
       -> canary propagation
       -> sentinel mutation
       -> timeout / unavailable / inconclusive
  -> Evidence Assimilation
       -> positive experiment evidence only
       -> no global negative evidence from NOT_OBSERVED
  -> Final Evidence Reasoning
  -> Epistemic Delta
       -> hypothesis transitions
       -> attack path transitions
       -> newly satisfied stages
       -> evidence gained
  -> report / experiments.json / CI outputs
```

## Modes

`experiments.mode` has three values:

- `off` — default; preserves RepoTrial 0.5 behavior.
- `plan` — creates the deterministic experiment plan but executes nothing.
- `sandbox` — plans and executes experiments using the existing Linux sandbox boundary.

The CLI exposes the same modes as `--experiments off|plan|sandbox`.

## Core Components

### 1. Experiment Planner

New module: `src/experiments/planner.mjs`.

Inputs:

- initial `repotrial.reasoning.v1` output;
- runtime candidates;
- provider states;
- configured experiment budgets.

The planner considers only attack paths whose viability is `PARTIAL` and hypotheses whose state is `UNKNOWN` or `UNTESTED`. It prioritizes high/critical hypotheses and paths with the smallest number of missing stages.

Planner output is deterministic for the same reasoning/candidate input.

Each experiment contains:

- stable experiment ID;
- template ID;
- hypothesis ID and attack-path ID;
- targeted stage IDs / capabilities;
- runtime candidate identity;
- priority score and rationale;
- declared synthetic environment-key names;
- declared sandbox-local sentinels;
- expected observation classes.

The plan contains no canary value.

### 2. Experiment Templates

New module: `src/experiments/templates.mjs`.

Initial templates:

#### `secret-egress-canary-v1`

Purpose: test whether an existing runtime candidate changes behavior when realistic synthetic credential variables are present.

Synthetic names are bounded and internal, initially including common AI/CI/cloud credential surfaces such as `OPENAI_API_KEY`, `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY`.

Values are generated per scan from an internal canary seed. The values are not persisted in reports; only SHA-256 fingerprints may be persisted.

Positive observations:

- scenario introduces a network/DNS/network-tool attempt absent from the matching baseline run;
- a canary value is propagated into an instrumented network/process target, stdout, or stderr.

A canary-propagation observation is stronger than simple secret presence and may support both `secret-access` and `network-egress` when propagation occurs through a network-related event.

#### `filesystem-sentinel-v1`

Purpose: detect broad/destructive file behavior under a scenario without risking host data.

The executor creates bounded sentinel files only inside a dedicated sandbox-local path under the copied workspace. Mutation/deletion of those sentinels is positive evidence of broad/destructive filesystem behavior.

No absence conclusion is produced if sentinels remain untouched.

#### `ci-context-trigger-v1`

Purpose: detect code paths conditionally activated in CI contexts.

Injects synthetic context booleans/identifiers such as `CI=true` and `GITHUB_ACTIONS=true`, plus non-secret synthetic metadata. It compares network/filesystem/process behavior against the matching baseline run.

Behavior delta is recorded as experiment evidence, but it does not automatically map to a critical capability unless a stronger observation (network/canary/sentinel destruction) is present.

### 3. Scenario Executor

Refactor `src/runtime/sandbox.mjs` to expose a reusable internal scenario execution primitive while keeping `runRuntimeAnalysis()` backward compatible.

Scenario constraints:

- caller supplies template/scenario metadata, not arbitrary secret values;
- environment keys and values are bounded;
- synthetic values are generated by RepoTrial;
- sentinel paths are normalized under a fixed sandbox-local root;
- source root is still copied into a disposable rootfs;
- namespace/chroot/network isolation is unchanged;
- process, output, file, and wall-clock limits remain enforced;
- raw synthetic values are classified before redaction, then discarded.

### 4. Observation Classifier

New module: `src/experiments/observe.mjs`.

Observation states:

- `OBSERVED` — direct positive signal exists.
- `TRIGGERED` — scenario caused a measurable behavior delta, but not enough to assert a target capability.
- `NOT_OBSERVED` — experiment completed without the target signal; local result only.
- `INCONCLUSIVE` — timeout, candidate failure before meaningful execution, truncation affecting the probe, or sandbox/provider limitation.

`NOT_OBSERVED` is explicitly prohibited from becoming global `ABSENT` negative evidence.

### 5. Evidence Assimilation

New module: `src/experiments/evidence.mjs`.

Positive observations become canonical charges from source `repotrial-experiment` with stable evidence anchors back to the original candidate configuration.

Initial rules:

- `adaptive-secret-egress-observed` — critical; maps to `secret-access` + `network-egress` only when canary propagation reaches a network-related observation.
- `adaptive-network-trigger-observed` — high/critical depending on context; maps to `network-egress`.
- `adaptive-sentinel-destruction-observed` — high; maps to `destructive-action` + `filesystem-write`.
- `adaptive-ci-triggered-behavior` — informational/medium contextual evidence; does not independently invent a dangerous capability.

`src/reasoning/engine.mjs` adds mappings only for experiment rules with semantics strong enough to justify them.

### 6. Closed-loop Scan Orchestration

`scanRepository()` becomes a two-stage reasoning pipeline when experiments are enabled:

1. collect normal providers + baseline runtime;
2. build initial charges and initial reasoning;
3. plan experiments;
4. optionally execute them;
5. convert positive observations to experiment charges;
6. append experiment charges;
7. recompute the legacy verdict from the complete charge set only if experiment charges are canonical risk findings;
8. recompute final reasoning;
9. compute an epistemic delta from initial to final reasoning.

When experiments are `off`, the code path and report semantics remain equivalent to 0.5.

When experiments are `plan`, no experiment charge is produced and final reasoning equals initial reasoning.

### 7. Epistemic Delta

New module: `src/experiments/delta.mjs`.

Records:

- hypothesis state transitions;
- attack-path viability transitions;
- missing stages that became satisfied;
- newly observed capabilities;
- number of experiments that produced positive evidence;
- unresolved targets.

This is explicitly “knowledge gained”, not “trust gained”. A transition from `UNKNOWN` to `PROVEN` may make the repository look more dangerous.

## Data Contract

New artifact: `.repotrial/experiments.json`.

Schema version: `repotrial.experiments.v1`.

Top-level fields:

- `schemaVersion`
- `mode`
- `status`
- `budget`
- `plan`
- `runs`
- `observations`
- `evidence`
- `epistemicDelta`
- `summary`

`verdict.json` receives an additive optional `experiments` summary/full object while `repotrial.report.v2` remains backward compatible.

## Budgets

Defaults:

- max experiments: 6
- max experiments per candidate: 2
- max planning rounds: 2 (v1 executor performs one execution batch; the contract reserves bounded rounds for future iterative re-planning)
- runtime timeout: reuse configured runtime timeout unless a stricter experiment timeout is provided
- maximum synthetic environment keys: 8 per experiment
- maximum sentinel files: 8 per experiment

Hard caps prevent configuration from turning RepoTrial into an unbounded executor.

## CLI / GitHub Action

CLI additions:

- `--experiments off|plan|sandbox`
- `--experiment-max-runs <n>`
- `--experiment-max-per-candidate <n>`
- `--experiment-timeout <ms>`

GitHub Action additions mirror these controls.

Machine-readable summary adds:

- experiments status;
- experiments planned/executed;
- positive experiment count;
- hypothesis transitions;
- newly viable attack paths.

No new failure gate is enabled by default in this wave. Existing reasoning gates naturally see assimilated positive evidence after experiments execute.

## Security Invariants of the Experiment Engine

1. No real host secret enters experiment environment.
2. Synthetic canary values never persist verbatim in public artifacts.
3. Experiment mode cannot weaken sandbox isolation.
4. Sentinels cannot escape the copied workspace.
5. Arbitrary caller-provided environment values are rejected/not exposed as a public API.
6. `NOT_OBSERVED` never becomes global negative evidence.
7. Unavailable sandbox means `INCONCLUSIVE`, never “safe”.
8. All experiment execution is opt-in.
9. Planner and classifier are deterministic for the same inputs and seed.
10. Existing `runtime` and `reasoning` contracts remain readable by 0.5 consumers.

## Testing Strategy

TDD is required.

Pure unit tests:

- planner determinism and budget enforcement;
- high-impact/small-gap prioritization;
- no experiment for already `VIABLE` or `BLOCKED` paths;
- template validation and synthetic-only contract;
- classifier baseline-vs-scenario behavior;
- canary fingerprinting without value persistence;
- `NOT_OBSERVED` cannot create negative evidence;
- epistemic delta transitions.

Sandbox tests (skip only when unprivileged namespaces are unavailable):

- conditional network attempt activates only when synthetic key exists;
- canary propagation is detected before redaction while value is absent from output artifact;
- sentinel deletion produces destructive evidence;
- host filesystem remains unchanged;
- network namespace remains isolated;
- timeout remains bounded.

Integration tests:

- `off` preserves 0.5 behavior;
- `plan` writes deterministic plan and executes nothing;
- `sandbox` adds experiment evidence and recomputes reasoning;
- report/HTML/schema/artifact proof include experiments;
- baseline differential remains compatible;
- CLI and GitHub Action expose controls without changing defaults.

## Release Boundary

This wave is RepoTrial `0.6.0` because it adds a new execution/evidence subsystem and public report contract while preserving backward compatibility.

A future 0.7 wave may add multi-round adaptive replanning and provider-specific experiment plugins, but 0.6 must first establish a deterministic, auditable, bounded experiment kernel.