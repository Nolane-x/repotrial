# Evidence Reasoning Engine v1 Design

## Goal

Evolve RepoTrial from a finding-oriented AI-agent repository scanner into a deterministic evidence reasoning engine that can explain *why* a repository is risky, which multi-step attack paths are viable, how certain each claim is, what was not proven, and which remediation removes the most risk.

## Non-goals

- No LLM or cloud dependency.
- No replacement of existing static, runtime, supply-chain, ForgeOS, differential, provenance, or signing providers.
- No binary safe/unsafe certification.
- No adaptive runtime experiment generation in this wave; the v1 data model must make that a compatible future provider.

## Compatibility constraints

- Node.js >=22.14.
- Zero npm runtime dependencies remains mandatory.
- Existing report fields, CLI behavior, verdict labels, SARIF/SBOM/provenance generation, and provider contracts remain backward compatible.
- Reasoning output is deterministic for the same canonical charges, safeguards, provider states, and coverage.
- Unknown/unavailable evidence must never be silently converted into absence or trust.

## Architecture

The current scan pipeline remains the evidence acquisition layer. A new pure reasoning layer executes after canonical charges have been assembled and before the report receipt is computed.

```text
static/runtime/supply/ForgeOS providers
              |
              v
       canonical charges
              |
              v
     Evidence Reasoning Engine
       |        |         |
       |        |         +--> counterfactual remediation
       |        +------------> attack paths
       +---------------------> evidence graph + hypotheses
              |
              v
      report.reasoning.v1
```

The engine is intentionally pure: it performs no filesystem, process, network, clock, random, or model calls. This gives RepoTrial deterministic, independently testable reasoning.

## Canonical epistemic states

Every hypothesis uses one of:

- `PROVEN`: direct canonical evidence proves every required capability/condition.
- `SUPPORTED`: evidence supports the claim but at least one required condition is inferred or externally anchored rather than directly proven.
- `CONTRADICTED`: evidence exists for the claim but a relevant safeguard materially weakens it.
- `REFUTED`: explicit negative evidence refutes a required condition. Reserved for future negative-evidence providers; v1 does not manufacture refutation from missing findings.
- `UNKNOWN`: required evidence is unavailable or incomplete.
- `UNTESTED`: no applicable evidence provider attempted the claim.

Confidence is a numeric value in `[0,1]` derived deterministically from evidence strength, provider provenance, coverage, and safeguard contradiction. Confidence is not probability of exploitation.

## Evidence graph

`report.reasoning.graph` is a compact typed graph:

- evidence nodes: canonical charges and safeguards;
- capability nodes: normalized powers such as `shell-exec`, `network-egress`, `secret-access`, `destructive-action`, `instruction-control`, `dependency-execution`, `filesystem-write`;
- claim nodes: hypotheses about exploitability;
- directed edges: `SUPPORTS`, `ENABLES`, `MITIGATES`, `REQUIRES`.

Node and edge IDs are stable SHA-256-derived identifiers so the same semantic evidence preserves identity across scans.

## Capability normalization

Known rule families map to normalized capabilities. Unknown rules still appear as evidence nodes but do not create invented capabilities.

Examples:

- `unrestricted-shell-capability`, `pipe-to-shell`, `dangerous-lifecycle-script`, runtime execution evidence -> `shell-exec` or `dependency-execution`;
- `secret-to-egress-path` -> `secret-access` and `network-egress`;
- runtime network attempts -> `network-egress`;
- runtime filesystem mutation -> `filesystem-write`;
- `destructive-without-approval` -> `destructive-action`;
- `prompt-boundary-override` -> `instruction-control`;
- vulnerable dependency/container findings -> `supply-chain-exposure`.

## Hypotheses

V1 ships a deterministic built-in threat model:

1. `credential-exfiltration`: secret access + network egress + an execution/control primitive.
2. `arbitrary-code-execution`: shell execution or dangerous dependency lifecycle execution.
3. `unapproved-destructive-action`: destructive capability + execution capability without effective human-approval safeguard.
4. `prompt-to-tool-escalation`: instruction-control + broad/unrestricted tool capability.
5. `supply-chain-compromise`: supply-chain exposure + execution surface.

A hypothesis records required capabilities, supporting evidence IDs, missing capabilities, contradicting safeguard IDs, epistemic state, confidence, and severity.

## Attack paths

An attack path is emitted only when a hypothesis has at least two required stages or represents a direct high-impact execution route. Paths are ordered sequences of normalized stages, not arbitrary graph walks. Each path records:

- stable ID;
- hypothesis ID;
- stage list;
- supporting evidence;
- missing stages;
- viability: `VIABLE`, `PARTIAL`, or `BLOCKED`;
- confidence.

Missing evidence produces `PARTIAL`, never a fabricated clean path.

## Counterfactual remediation

For every proven charge, the engine simulates removal of that charge and recomputes viable/supported hypotheses. It ranks remediation candidates by:

1. number of viable attack paths eliminated;
2. number of high/critical hypotheses downgraded;
3. severity of the removed charge;
4. stable rule ID tie-breaker.

The output explicitly says this is a *counterfactual model over current evidence*, not proof that applying a recommendation makes the repository safe.

## Reasoning summary

`report.reasoning.summary` includes:

- evidence node count;
- capability count;
- hypothesis counts by epistemic state;
- viable/partial/blocked attack-path counts;
- maximum reasoning severity;
- reasoning confidence floor;
- top remediation IDs.

The existing `verdict` remains authoritative in v1. Reasoning enriches and explains it; a later version may make verdict policy consume verified hypotheses after compatibility data is accumulated.

## Failure handling

Reasoning failures are analysis failures because corrupt reasoning must not be emitted as trusted evidence. Inputs are bounded by the already-bounded canonical charge set. Unknown rule IDs are preserved as evidence only.

## Testing strategy

Unit tests must prove:

- stable deterministic graph identities;
- no capability invention for unknown rules;
- credential-exfiltration attack-chain construction;
- incomplete evidence yields `UNKNOWN`/`PARTIAL`, not `PROVEN`;
- approval safeguards contradict destructive hypotheses;
- counterfactual ranking prefers a charge that breaks multiple paths;
- output is invariant to input charge ordering;
- integration attaches `reasoning` to scan reports without changing existing verdict semantics.

## Future-compatible extensions

The v1 schema deliberately supports later providers for explicit negative evidence, adaptive runtime experiments, policy/invariant proof, eBPF observations, CodeQL/Semgrep, external enterprise evidence, and ForgeOS causal remediation without changing canonical hypothesis identities.