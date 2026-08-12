# RepoTrial 0.7 — Causal Adversarial Reasoning Engine Design

## Goal

Evolve RepoTrial from a deterministic evidence/reasoning scanner with bounded single-scenario adaptive experiments into a deterministic causal security investigation engine that can synthesize multi-step attack chains, rank uncertainty by expected information gain, execute bounded stateful adversarial episodes, and measure itself against a repository-native adversarial benchmark corpus.

## Non-negotiable constraints

- Version target: `0.7.0`.
- Node.js floor remains 22.14+; CI stays on Node 22 and 24.
- Zero npm runtime dependencies.
- Existing `off`, `plan`, and `sandbox` experiment modes remain backward compatible.
- Legacy verdict thresholds remain unchanged unless an explicitly opt-in causal gate is enabled.
- No real host secrets enter runtime scenarios.
- Synthetic canaries never persist verbatim in artifacts.
- No experiment may weaken namespace/chroot/copied-rootfs/network/resource containment.
- Missing or non-observed evidence never becomes global proof of absence.
- All reasoning and planning outputs are deterministic for identical normalized inputs.
- All persisted causal conclusions must retain evidence ancestry and scope.

## Architecture

```text
Repository/providers
    ↓
Canonical charges + safeguards + coverage
    ↓
Capability normalization
    ↓
Threat Knowledge Registry v2
    ↓
Causal Capability Graph
    ↓
Bounded Attack-Chain Synthesizer
    ↓
Uncertainty Frontier
    ↓
Active Experiment Policy
    ↓
Optional Stateful Sandbox Episode
    ↓
Causal Observation Trace
    ↓
Positive Evidence Assimilation
    ↓
Re-synthesis + Epistemic Delta
    ↓
Causal gates / reports / benchmark metrics / provenance
```

The existing `reasonAboutEvidence()` public contract remains supported. A new causal subsystem consumes the same normalized charges and adds richer graph and chain artifacts without making filesystem, process, network, clock, random, or model calls.

## Threat Knowledge Registry v2

Move hard-coded threat definitions out of `src/reasoning/engine.mjs` into a declarative registry. Each threat family contains:

- stable threat ID and severity;
- source/source-capability alternatives;
- ordered or partially ordered prerequisite stages;
- sink capabilities;
- optional trust-boundary requirements;
- mitigating safeguard IDs;
- runtime-addressable stage metadata;
- experiment template hints.

Seed registry families:

1. credential exfiltration;
2. arbitrary/attacker-influenced code execution;
3. unapproved destructive action;
4. prompt/instruction-to-tool escalation;
5. supply-chain-to-execution compromise;
6. persistent memory/context poisoning;
7. identity/privilege abuse;
8. tool-confused-deputy misuse;
9. CI/CD identity takeover;
10. cross-boundary data exfiltration.

Unknown charge rule IDs remain evidence only and cannot silently invent capabilities.

## Causal Capability Graph

Extend the v0.5 evidence graph with causal node classes:

- `IDENTITY`
- `SECRET`
- `MEMORY`
- `TOOL`
- `EXECUTION_SURFACE`
- `DATA_SOURCE`
- `STATE`
- `SINK`
- `TRUST_DOMAIN`

and edge relations:

- `READS_FROM`
- `WRITES_TO`
- `CONTROLS`
- `TRIGGERS`
- `PERSISTS_IN`
- `AUTHORIZES`
- `EXECUTES`
- `PROPAGATES_TO`
- `CROSSES_TRUST_BOUNDARY`
- plus existing `SUPPORTS`, `ENABLES`, `MITIGATES`, `REQUIRES`, `REFUTES`.

Causal nodes are derived only from canonical evidence and explicit registry semantics. IDs are SHA-256-derived from stable semantic identity rather than titles or severity wording.

## Attack-Chain Synthesizer

Generate multiple candidate chains per threat family using bounded deterministic graph search.

Hard bounds:

- default max depth: 8 causal hops;
- hard max depth: 16;
- default top-K chains per threat: 8;
- hard top-K: 32;
- cycle detection by semantic node identity;
- dominance pruning removes a chain when another chain satisfies the same sink with equal/better evidence strength and fewer/equal prerequisites;
- mitigation-aware pruning marks rather than deletes contradicted paths;
- deterministic ordering by severity, viability, confidence, hop count, threat ID, chain ID.

Chain states:

- `PROVEN` — all required causal steps have direct high-confidence evidence;
- `SUPPORTED` — complete chain with at least one indirect/non-high proof;
- `PARTIAL` — one or more addressable causal links unresolved;
- `CONTRADICTED` — complete/partial positive chain conflicts with explicit negative evidence or safeguard proof;
- `REFUTED` — at least one mandatory link has explicit scoped absence proof;
- `UNTESTED` — no meaningful positive or negative evidence exists.

Every chain stores the exact evidence IDs that justify each hop.

## Uncertainty Frontier and Active Experiment Policy

Replace the v0.6 severity-only priority heuristic with deterministic expected-value ranking. For each unresolved runtime-addressable causal link compute:

```text
utility = impact × epistemicGain × centrality × discrimination
          ---------------------------------------------------
          executionCost × redundancyPenalty × riskPenalty
```

All factors are deterministic normalized values in `[0,1]` or bounded integer ranks; no probabilistic model/LLM is required.

The policy should prefer an experiment that can discriminate among several high-impact chains over an experiment that only confirms one low-centrality stage. The planner outputs the factor decomposition so reviewers can audit why a probe was selected.

## Stateful Adversarial Episodes

Introduce an episode primitive above `runRuntimeScenario()`:

`PREPARE → PRIME → TRIGGER → OBSERVE → FOLLOW_UP → VERIFY`.

Episode templates remain internal and validated. 0.7 initially adds:

- `memory-poison-persistence-v1`: synthetic untrusted state is written to a sandbox-local memory fixture, followed by a fresh invocation to test whether it influences later behavior;
- `identity-context-escalation-v1`: synthetic low/high privilege CI identity contexts test conditional behavior without real credentials;
- `tool-chain-propagation-v1`: synthetic marker propagation across bounded subprocess/tool stages;
- reuse of 0.6 secret-egress, filesystem-sentinel, and CI-context probes as single-phase episodes.

Raw canary values and raw internal run objects remain non-enumerable/non-persisted. Public traces contain redacted markers and SHA-256 fingerprints.

## Causal Observation Trace

Each executed episode emits a trace with stable events:

- episode/phase ID;
- candidate identity;
- causal relation being tested;
- sanitized observed event IDs;
- marker fingerprints;
- before/after state fingerprints;
- result state: `OBSERVED`, `TRIGGERED`, `NOT_OBSERVED`, `INCONCLUSIVE`;
- evidence conversion decision and reason.

Only sufficiently strong positive observations become canonical charges. `NOT_OBSERVED` remains scoped metadata and never global negative evidence.

## Adversarial Corpus v1

Create repository-native synthetic fixtures under `benchmarks/adversarial-corpus/` with manifest-driven expected threat chains. Corpus classes:

- vulnerable positives;
- benign near-misses;
- cross-file indirection;
- lifecycle/supply-chain execution;
- secret → subprocess → egress;
- prompt/instruction → tool escalation;
- memory persistence/context poisoning;
- CI identity/privilege conditional behavior;
- destructive action with and without effective approval;
- incomplete/decoy chains designed to test false positives.

A pure benchmark runner reports:

- threat-family recall;
- chain precision;
- benign false-positive rate;
- chain-stage recall;
- deterministic replay equality;
- corpus coverage counts.

Benchmark metrics are evidence about RepoTrial quality, not claims of universal detection.

## Product integration

Add optional report sections/artifacts:

- `causal.json` (`repotrial.causal.v1`);
- `benchmark.json` (`repotrial.benchmark.v1`, only when benchmark command is run);
- HTML causal attack-chain panel;
- CLI `--causal off|analyze|active` with `off` default for backward compatibility;
- CLI bounded controls for chain depth/top-K/episode budget;
- opt-in `--fail-on-causal <severity>` and `--fail-on-new-causal <severity>` gates using new exit codes after existing 0–5 range;
- equivalent GitHub Action inputs/outputs;
- schema/provenance/artifact-proof binding.

## Error handling and epistemic rules

Provider/runtime failures are first-class states. Sandbox unavailable, timeouts, truncation, unsupported episode templates, or invalid fixtures produce `INCONCLUSIVE`/diagnostics and cannot reduce risk. Invalid registry definitions fail closed during startup/tests rather than silently skipping threat semantics.

## Testing strategy

TDD for every subsystem. Required release gates:

- registry validation and deterministic ordering;
- graph identity stability under wording/severity changes;
- causal search cycle/dominance/depth/top-K tests;
- input-reordering determinism;
- active-policy ranking/factor auditability tests;
- stateful episode validation and synthetic-secret leakage tests;
- sandbox-capable targeted runtime tests where environment permits;
- backward compatibility with 0.6 when causal mode is off;
- report/schema/provenance/action/CLI release-contract tests;
- adversarial corpus precision/recall and benign false-positive gates;
- fuzz/mutation tests for malformed registries and causal graphs;
- Node 22/24 full CI, coverage, fixture scan, npm pack, Docker build/version E2E.

## Success criteria

RepoTrial 0.7 is complete only when it can deterministically synthesize more than one causally distinct attack chain from the same repository evidence, explain every hop with evidence ancestry, select the next bounded probe using an auditable information-gain policy, execute at least one multi-phase sandbox episode safely, and pass a manifest-driven adversarial corpus without regressing 0.6 behavior when causal mode is disabled.
