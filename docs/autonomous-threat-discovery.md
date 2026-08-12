# Autonomous Threat Discovery and Evidence Realms

RepoTrial 0.8 adds deterministic autonomous threat-hypothesis discovery without making a model, network service, or mutable learned registry part of the trust boundary.

## Why Evidence Realms exist

A repository can intentionally contain dangerous-looking material that is not part of its production execution surface: exploit fixtures, adversarial benchmark cases, parser fuzz inputs, documentation examples, generated reports, and vendored test data. RepoTrial 0.7 kept that evidence transparent but could compose it into the same causal world as production evidence.

RepoTrial 0.8 assigns every evidence anchor to an **Evidence Realm**:

- `production`
- `test`
- `benchmark`
- `fixture`
- `docs`
- `generated`
- `vendor`
- `unknown`

All-repository analysis remains visible. Realm metadata changes interpretation, not history. A `PROVEN` chain supported only by benchmark evidence is still shown as `PROVEN`, but its realm assessment is `NON_PRODUCTION_ONLY`; it cannot silently satisfy a production-only causal gate. A chain that needs unrelated evidence from isolated realms becomes `CROSS_REALM_UNPROVEN` unless an explicit trust/reachability crossing is proven.

`--causal-realm-scope all` preserves the broad compatibility view. `--causal-realm-scope production` gates only chains whose evidence is production relevant.

## Autonomous hypotheses

The built-in threat registry remains the authoritative catalog of named threat families. Discovery is a separate layer that asks whether observed capabilities form an impact-bearing composition not already well represented by that registry.

The engine uses a bounded capability-role grammar over observed capabilities only. Roles include `SOURCE`, `CONTROL`, `EXECUTION`, `PERSISTENCE`, `AUTHORITY`, `TOOL`, and `SINK`. It never invents a missing capability to make a candidate complete.

Candidates are compared against every concrete registered threat variant. The result records the nearest threat, known-threat similarity, and novelty score. Duplicate and dominated candidates are pruned deterministically, with bounded candidate and depth budgets.

Candidate states are:

- `STRUCTURAL`: a plausible same-realm composition exists but corroboration is weak.
- `CORROBORATED`: shared evidence, same-file evidence, or an explicit causal/trust relationship links stages.
- `PROMOTABLE`: corroborated, sufficiently novel, production relevant, and suitable for transient verification promotion.
- `DISMISSED`: registry-covered, realm-incoherent, dominated, or non-impactful.

**Candidate, not proven:** a discovered hypothesis is not a vulnerability finding and `PROMOTABLE` is not evidence that exploitation occurred. Promotion only creates a transient validated threat definition for further bounded analysis. It never edits the built-in registry or source tree.

## Discovery modes

```bash
# Registry-backed causal analysis with realm annotations only
repotrial scan . --causal analyze --causal-realm-scope production

# Add deterministic autonomous hypothesis discovery; no repository code executes
repotrial scan . --causal discover --causal-realm-scope production

# Discovery plus supported bounded active verification in the existing Linux sandbox
repotrial scan . --causal active --causal-realm-scope production
```

Discovery controls:

```text
--causal-max-discovered <n>   Maximum retained candidates; default 32, hard maximum 128
--causal-min-novelty <0..1>   Minimum novelty versus registered threats; default 0.35
```

When discovery runs, `hypotheses.json` is emitted and included in artifact proof and provenance subjects. The HTML report shows all-repository chains, production-relevant counts, realm assessments, and the autonomous candidate list separately.

## Self-dogfood result that motivated 0.8

RepoTrial 0.7 scanning RepoTrial itself produced two active critical `arbitrary-code-execution` chains. Their evidence came from the repository's malicious adversarial corpus and test fixtures. RepoTrial 0.8 keeps those chains visible but classifies them as non-production or unproven cross-realm compositions. In the release regression, their production-active count is zero.

This distinction is intentionally epistemic: RepoTrial does not erase evidence to make itself look safe; it states which world the evidence belongs to and what crossing would need to be proven before that evidence can support a production threat.

## Security boundaries

Autonomous discovery remains pure and deterministic. It performs no model calls, filesystem reads, process execution, network calls, random generation, or clock access. Active execution remains a separate opt-in provider and preserves the existing copied-rootfs, namespace, chroot, network-isolation, synthetic-canary, and resource-limit boundaries.

Missing evidence remains unknown. `NOT_OBSERVED` never becomes global proof of absence, and realm isolation never means code is safe; it means RepoTrial lacks evidence that the non-production surface reaches production.
