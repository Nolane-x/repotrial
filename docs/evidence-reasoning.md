# Evidence Reasoning

RepoTrial 0.5 adds a deterministic reasoning layer above canonical security evidence. The goal is not to make a model guess whether a repository is safe. The goal is to transform bounded evidence into explicit claims whose support, missing prerequisites, contradictions, refutations, invariant violations, and remediation leverage can be inspected and reproduced.

## Contract

```js
import {
  reasonAboutEvidence,
  evaluateSecurityInvariants,
  normalizeNegativeEvidence
} from 'repotrial';

const reasoning = reasonAboutEvidence({
  charges,
  safeguards,
  coverage,
  providers,
  negativeEvidence,
  invariants
});
```

The result uses schema version `repotrial.reasoning.v1` and contains:

- `graph`: typed evidence/capability/safeguard/claim nodes and relationships;
- `negativeEvidence`: explicit bounded claims that a capability was tested and absent;
- `hypotheses`: threat claims with epistemic state and confidence;
- `attackPaths`: ordered capability chains with viability state;
- `invariants`: deterministic security-policy proofs;
- `remediation`: counterfactual charge-removal ranking;
- `summary`: bounded machine-readable roll-up.

The engine is pure. It performs no repository reads, network access, process spawning, time access, random generation, or model calls. Acquisition remains the responsibility of static, runtime, supply-chain, ForgeOS, or another explicit evidence provider.

## Epistemic states

Threat hypotheses use `PROVEN`, `SUPPORTED`, `CONTRADICTED`, `REFUTED`, `UNKNOWN`, and `UNTESTED`.

`PROVEN` means all required stages have direct high-confidence canonical evidence. `SUPPORTED` means the chain is complete but at least one stage uses lower-strength or externally anchored evidence. `CONTRADICTED` means positive evidence is materially opposed by a recognized safeguard or explicit contradictory evidence. `REFUTED` requires explicit negative evidence that eliminates every alternative capability for at least one required stage. `UNKNOWN` means required evidence remains unresolved. `UNTESTED` means no applicable evidence was available.

A missing finding never becomes `REFUTED`. A disabled runtime provider never becomes evidence that runtime behavior is safe. Confidence is an evidence-strength score under this model, not an exploitation probability.

## Built-in threat hypotheses

### Credential exfiltration

Requires a secret source, an execution/tool-control primitive, and network egress. Secret access or egress alone is not treated as a proven exfiltration path.

### Arbitrary code execution

Requires a shell or dangerous dependency-lifecycle execution surface. Critical direct execution routes remain visible even when they are single-stage paths.

### Unapproved destructive action

Requires destructive capability plus an execution/tool primitive. Explicit human approval contradicts the claim rather than deleting the underlying evidence.

### Prompt-to-tool escalation

Requires instruction-control evidence and broad tool power. Least-privilege safeguards are represented as contradictions so reviewers see both the dangerous primitive and compensating control.

### Supply-chain compromise

Requires high/critical supply-chain exposure plus an execution surface. Lower-severity dependency findings remain evidence but do not automatically create a high-impact capability.

## Evidence graph

Graph relationships are explicit:

```text
POSITIVE EVIDENCE ──SUPPORTS──> CAPABILITY ──ENABLES──> CLAIM
SAFEGUARD ───────────MITIGATES────────────────────────> CLAIM
NEGATIVE EVIDENCE ───REFUTES──> CAPABILITY
```

Unknown rule IDs remain `EVIDENCE` nodes but receive no capability edge unless RepoTrial has an explicit normalization rule. This prevents semantic invention for third-party findings.

Stable evidence IDs are derived from rule/source plus stable evidence anchors rather than presentation text or severity. Rewording a title, changing remediation prose, or moving a finding whose stable fingerprint is unchanged does not break its reasoning identity.

## Explicit negative evidence

Negative evidence is never inferred from silence. A provider must explicitly state that a capability was tested and absent, including:

- capability;
- source/provider;
- method;
- scope;
- confidence;
- stable deterministic identity.

Example:

```js
normalizeNegativeEvidence([{
  capability: 'network-egress',
  state: 'absent',
  source: 'runtime-sandbox',
  method: 'network-namespace-and-syscall-observation',
  scope: 'bounded-runtime-experiments',
  confidence: 'high'
}]);
```

A hypothesis becomes `REFUTED` only when every alternative capability for a required stage is explicitly absent at sufficient confidence. If positive and negative evidence conflict, RepoTrial preserves both rather than silently choosing the desired conclusion.

## Security invariant proof

RepoTrial 0.5 evaluates declarative invariants with states `VIOLATED`, `SATISFIED`, `UNKNOWN`, and `NOT_APPLICABLE`.

Built-in invariants include:

- secret access and network egress must not compose;
- destructive capability requires explicit human approval;
- instruction-control capability requires least-privilege safeguards;
- dependency execution and network egress must not compose.

Two invariant forms are supported:

```js
{
  id: 'custom-no-shell-network',
  kind: 'forbid-all',
  capabilities: ['shell-exec', 'network-egress'],
  severity: 'critical'
}
```

and:

```js
{
  id: 'destructive-requires-approval',
  kind: 'require-safeguard',
  whenAll: ['destructive-action'],
  safeguards: ['human-approval'],
  severity: 'critical'
}
```

For a forbidden composition, merely failing to observe one capability produces `UNKNOWN`, not `SATISFIED`. It becomes `SATISFIED` only when explicit negative evidence proves a required member absent. For a safeguard implication, an observed antecedent plus the explicit safeguard can prove `SATISFIED`; an observed antecedent without the safeguard is `VIOLATED`.

## Attack paths

Attack paths are threat-model stage sequences, not unrestricted graph walks. A path is:

- `VIABLE` when its hypothesis is `PROVEN` or `SUPPORTED`;
- `BLOCKED` when its hypothesis is `CONTRADICTED` or `REFUTED`;
- `PARTIAL` when prerequisites remain unknown or untested.

Every path carries supporting evidence IDs, refuting evidence IDs, missing/refuted stages, contradictions, severity, and confidence. This preserves the difference between “not observed” and “proven absent”.

## Counterfactual remediation

For each proven charge, RepoTrial removes that evidence from a simulated copy of the current case and recomputes the pure reasoning core. Ranking measures:

1. viable attack paths eliminated;
2. invariant violations eliminated;
3. high/critical hypotheses downgraded;
4. severity of the removed charge.

The ranking answers a narrow question: **which currently observed evidence item has the most leverage over the modeled attack surface and policy violations?** It does not certify that applying the recommendation makes the repository safe.

## Relationship to verdicts

RepoTrial 0.5 intentionally keeps the established deterministic verdict engine authoritative. Reasoning is receipt-bound, rendered in the offline HTML case file, schema-versioned, and exported through the public API, but it does not silently change existing CI thresholds.

This compatibility boundary allows the project to accumulate adversarial and regression evidence about the new reasoning model before a later policy version decides whether verified hypotheses or invariants should participate directly in gating.

## Security properties

The reasoning layer preserves these invariants:

- deterministic output for semantically identical inputs regardless of charge ordering;
- no capability invention for unknown rules;
- no conversion of missing evidence into proof of absence;
- explicit positive/negative conflicts remain visible;
- no execution or network side effects;
- no mutation of provider evidence;
- stable schema-versioned output;
- stable evidence identity across presentation/severity changes when the anchor is stable;
- bounded computation over the already bounded canonical charge set.

## Next extensions

The v1 contracts are designed for behavior-differential reasoning, adaptive runtime experiment planning, eBPF/Falco observations, CodeQL/Semgrep providers, enterprise evidence sources, richer invariant languages, and ForgeOS causal remediation. Those extensions should add evidence or definitions without weakening the epistemic rules above.
