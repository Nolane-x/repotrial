# Evidence Reasoning

RepoTrial 0.5 adds a deterministic reasoning layer above canonical security evidence. The goal is not to make a language model guess whether a repository is safe. The goal is to transform bounded evidence into explicit claims whose support, missing prerequisites, contradictions, and remediation leverage can be inspected and reproduced.

## Contract

The public API is:

```js
import { reasonAboutEvidence } from 'repotrial';

const reasoning = reasonAboutEvidence({
  charges,
  safeguards,
  coverage,
  providers
});
```

The result uses schema version `repotrial.reasoning.v1` and contains:

- `graph`: typed evidence/capability/safeguard/claim nodes and relationships;
- `hypotheses`: threat claims with epistemic state and confidence;
- `attackPaths`: ordered capability chains with viability state;
- `remediation`: counterfactual charge-removal ranking;
- `summary`: bounded machine-readable roll-up.

The engine is pure. It performs no repository reads, network access, process spawning, time access, random generation, or model calls. Acquisition remains the responsibility of static, runtime, supply-chain, and ForgeOS providers.

## Epistemic states

`PROVEN` means all required stages have direct high-confidence canonical evidence. `SUPPORTED` means the chain is complete but at least one stage is supported by lower-strength or externally anchored evidence. `CONTRADICTED` means a complete chain is materially opposed by a recognized safeguard. `UNKNOWN` means one or more required stages are missing from the observed evidence. `UNTESTED` means no applicable evidence was available. `REFUTED` is reserved for future explicit negative-evidence providers.

A missing finding never becomes `REFUTED`. A disabled runtime provider never becomes evidence that runtime behavior is safe. A high confidence number is an evidence-strength score under this model, not an exploitation probability.

## Built-in threat hypotheses

### Credential exfiltration

Requires a secret source, an execution/tool-control primitive, and network egress. This models composition: secret access or egress alone is not treated as a proven exfiltration path.

### Arbitrary code execution

Requires a shell or dangerous dependency lifecycle execution surface. Critical direct execution routes remain visible even when they are single-stage attack paths.

### Unapproved destructive action

Requires destructive capability plus an execution/tool primitive. An explicit human-approval safeguard contradicts the claim rather than silently deleting the underlying evidence.

### Prompt-to-tool escalation

Requires instruction-control evidence and broad tool power. Least-privilege safeguards are represented as contradictions so reviewers can see both the dangerous primitive and the compensating control.

### Supply-chain compromise

Requires high/critical supply-chain exposure plus an execution surface. Low and medium vulnerability findings remain evidence but do not automatically create a high-impact supply-chain capability.

## Evidence graph

Graph node classes are:

```text
EVIDENCE ──SUPPORTS──> CAPABILITY ──ENABLES──> CLAIM
SAFEGUARD ──MITIGATES────────────────────────> CLAIM
```

Unknown rule IDs are retained as `EVIDENCE` nodes but have no capability edge unless RepoTrial has an explicit normalization rule. This prevents the reasoning layer from inventing semantics for third-party findings it does not understand.

Stable IDs are SHA-256-derived from canonical semantic input. Charge ordering therefore does not change the reasoning output.

## Attack paths

Attack paths are threat-model stage sequences, not unrestricted graph walks. A path is:

- `VIABLE` when its hypothesis is `PROVEN` or `SUPPORTED`;
- `BLOCKED` when its hypothesis is `CONTRADICTED` or `REFUTED`;
- `PARTIAL` when prerequisites remain unknown or untested.

Every path carries supporting evidence IDs, missing stages, contradictions, severity, and confidence. This preserves the difference between “no observed path” and “path proven impossible”.

## Counterfactual remediation

For each proven charge, RepoTrial removes that evidence from a simulated copy of the current case, recomputes the reasoning core, and measures:

1. viable attack paths eliminated;
2. high/critical hypotheses downgraded;
3. severity of the removed charge.

The resulting ranking answers a narrow question: **which currently observed evidence item has the most leverage over the modeled attack surface?**

It does not claim that applying the associated recommendation makes a repository safe. New evidence, alternative paths, implementation mistakes, or provider blind spots can change the result.

## Relationship to verdicts

RepoTrial 0.5 intentionally keeps the established deterministic verdict engine authoritative. Evidence reasoning is attached to the report and receipt, rendered in the offline HTML case file, and available through the public API, but it does not silently change existing CI thresholds.

This compatibility boundary is deliberate. A later policy version can consume reasoning states for gating after the hypotheses and normalization rules have accumulated enough adversarial and regression evidence.

## Security properties

The reasoning layer must preserve these invariants:

- deterministic output for semantically identical inputs regardless of charge ordering;
- no capability invention for unknown rules;
- no conversion of missing evidence into proof of absence;
- no execution or network side effects;
- no mutation of provider evidence;
- stable schema-versioned output;
- bounded computation over the already bounded canonical charge set.

## Next extensions

The v1 contract is designed for explicit negative evidence, policy/invariant proof, behavior-differential reasoning, adaptive runtime experiment plans, eBPF/Falco observations, CodeQL/Semgrep providers, enterprise evidence sources, and ForgeOS causal remediation. Those extensions should add evidence or hypothesis definitions without weakening the epistemic rules above.
