# Adaptive Adversarial Experiments

RepoTrial 0.6 adds a bounded closed-loop verification layer between evidence reasoning and the existing Linux runtime sandbox.

## Why it exists

A static or provider-backed scan can identify an attack path whose prerequisites are only partly observed. A traditional scanner usually stops at `UNKNOWN`. Adaptive experiments let RepoTrial ask a narrower question: **which missing runtime-observable stage should be tested next, and did a synthetic sandbox scenario produce direct evidence?**

The pipeline is deterministic:

```text
canonical charges
  -> initial evidence reasoning
  -> deterministic experiment planner
  -> optional sandbox scenario
  -> observation classifier
  -> positive evidence assimilation
  -> final evidence reasoning
  -> epistemic delta
```

The result is knowledge gain, not a safety score. An experiment can make a repository look more dangerous by turning an `UNKNOWN` hypothesis into `PROVEN`.

## Modes

- `off` — default. No experiment field is added to the report, preserving RepoTrial 0.5 report/receipt behavior.
- `plan` — produces a deterministic plan but executes no repository code.
- `sandbox` — executes selected scenarios through the same copied-rootfs, user/mount/UTS/IPC/network/PID/cgroup namespace and chroot boundary used by runtime detonation.

Example:

```bash
repotrial scan . \
  --experiments plan \
  --experiment-max-runs 6 \
  --experiment-max-per-candidate 2
```

On a supported Linux host:

```bash
repotrial scan . \
  --runtime sandbox \
  --experiments sandbox \
  --experiment-timeout 8000
```

## Experiment templates

### `secret-egress-canary-v1`

Tests whether a runtime candidate changes behavior when common credential *names* exist. RepoTrial generates synthetic values internally for names such as `OPENAI_API_KEY`, `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY`.

No host credential is copied. Raw synthetic values are used only in memory while classifying observations. Public artifacts retain SHA-256 fingerprints and redacted markers, never the canary value.

A canary reaching a network-related observation is strong evidence because it demonstrates both synthetic secret access and an egress path under the scenario.

### `filesystem-sentinel-v1`

Seeds fixed files only below `.repotrial-experiment/` inside the disposable copied workspace. Mutation or deletion is evidence of broad/destructive filesystem behavior. Sentinel paths cannot traverse outside the fixed root.

### `ci-context-trigger-v1`

Adds synthetic CI context such as `CI=true` and `GITHUB_ACTIONS=true` to test conditional behavior. Context-only process/filesystem changes are recorded as contextual evidence and do not independently invent a dangerous capability.

## Observation states

Each experiment ends in exactly one epistemic state:

- `OBSERVED` — direct positive target signal exists.
- `TRIGGERED` — scenario caused a measurable delta but not enough to assert the target capability.
- `NOT_OBSERVED` — completed without the target signal.
- `INCONCLUSIVE` — timeout, unavailable sandbox, early failure, or truncation prevented a meaningful conclusion.

### Critical rule: `NOT_OBSERVED != ABSENT`

A single experiment only tests one candidate, template, environment, and bounded time window. Therefore `NOT_OBSERVED` never becomes global negative evidence and never satisfies a security invariant by proving a capability absent.

Explicit negative evidence remains a separate RepoTrial reasoning contract and requires a provider/method that can actually justify an absence claim.

## Planning and budgets

The planner considers `PARTIAL` attack paths attached to `UNKNOWN` or `UNTESTED` hypotheses. It ranks high-impact paths deterministically, preferring severe paths with fewer missing stages and lower current confidence.

Defaults:

- 6 experiments maximum per scan;
- 2 experiments maximum per runtime candidate;
- 8 synthetic environment keys per template;
- 8 sandbox-local sentinels per template.

Hard caps prevent the experiment subsystem from becoming an unbounded executor.

## Evidence assimilation

Only sufficiently strong observations become canonical charges:

- `adaptive-secret-egress-observed`
- `adaptive-network-trigger-observed`
- `adaptive-sentinel-destruction-observed`
- `adaptive-ci-triggered-behavior` for contextual `TRIGGERED` behavior

The first three have explicit capability mappings in the evidence-reasoning engine. Context-only CI behavior deliberately has no dangerous capability mapping.

After positive evidence is appended, RepoTrial recomputes the deterministic verdict and evidence reasoning. If no experiment charge is produced, the original reasoning remains unchanged.

## Epistemic delta

`experiments.json` records `repotrial.epistemic-delta.v1`, including:

- hypothesis state transitions;
- attack-path viability transitions;
- newly satisfied stages;
- newly observed capabilities;
- unresolved targets.

The contract uses the interpretation `knowledge-change-not-trust-change` to prevent consumers from treating more information as automatically safer.

## Artifacts and integrity

When experiments are `plan` or `sandbox`, RepoTrial writes:

```text
.repotrial/experiments.json
```

It is included in `artifact-proof.json`, provenance subjects, and the overall report receipt path. The portable HTML case file renders experiment status, planned/executed counts, positive observations, epistemic transitions, and unresolved targets.

## Security invariants

The experiment subsystem is designed around these non-negotiable rules:

1. No real host secret enters a scenario environment.
2. Synthetic canary values are generated internally and never persisted verbatim.
3. Experiment mode cannot weaken namespace/chroot/network containment.
4. Sentinels remain inside the copied workspace.
5. Public APIs do not accept arbitrary secret environment values.
6. `NOT_OBSERVED` never becomes global negative evidence.
7. Sandbox unavailability is `INCONCLUSIVE`, never safe.
8. Execution is opt-in; the default is `off`.
9. Planner/classifier behavior is deterministic for identical inputs and seed.
10. RepoTrial 0.5 report consumers remain compatible because the experiment field is additive and optional.
