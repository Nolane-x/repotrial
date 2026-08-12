# Causal Adversarial Reasoning

RepoTrial 0.7 adds a deterministic causal investigation layer above the 0.5 evidence-reasoning model and the 0.6 adaptive experiment system. The goal is not to assign a smarter-looking score. The goal is to preserve *why* a security capability exists, synthesize bounded multi-stage attack chains, identify which missing observation would change the most high-impact conclusions, and—only when explicitly requested—run a bounded synthetic episode to collect that observation.

## Modes

- `off` — default. No `causal` field and no `causal.json` artifact are emitted; the 0.6 acquisition/reasoning path remains compatible.
- `analyze` — non-executing causal graph and attack-chain synthesis over canonical evidence already collected by RepoTrial.
- `active` — performs `analyze`, selects bounded high-information probes, then executes supported synthetic episodes through the existing copied-rootfs / namespace / chroot sandbox boundary. Positive observations may be assimilated and the chains are synthesized again.

```bash
repotrial scan . --causal analyze --fail-on-causal critical
repotrial scan . --runtime sandbox --causal active --causal-max-runs 4
```

## Declarative threat registry

Threat families are data rather than hard-coded branches in the reasoning engine. `repotrial.threat-registry.v1` preserves the original five threats and adds agentic families for persistent goal hijacking, memory/context poisoning, identity/privilege abuse, unauthorized tool use, CI lifecycle credential abuse, cross-agent delegation escalation, and verification-bypass unsafe actions.

Definitions contain ordered stages, capability alternatives, mitigations, and optional experiment hints. Validation is fail-closed, canonicalized, deterministic, and receipt-bound.

## Causal graph and multi-chain synthesis

The causal layer projects canonical evidence into capability roles and explicit trust-domain relationships. Synthesis is bounded by depth and retained-chain budgets, uses deterministic ordering and dominance pruning, and never invents a satisfied stage without evidence ancestry.

Causal chain states are:

- `PROVEN` — every required stage has direct strong evidence;
- `SUPPORTED` — every required stage is satisfied, but at least one stage is indirect/lower-confidence;
- `CONTRADICTED` — active evidence is opposed by an explicit safeguard/negative-evidence relationship;
- `BLOCKED` — an explicit refutation blocks a required stage;
- `PARTIAL` — at least one required stage remains unresolved.

A `PARTIAL` chain is uncertainty, not safety.

## Active verification policy

The active planner ranks probes by expected epistemic value rather than severity alone. Its auditable score combines threat impact, uncertainty, severity-weighted chain centrality, discrimination power, expected evidence strength, a soft execution-cost penalty, and redundancy penalty. A single probe can cover several chains; the same template/candidate pair is not scheduled twice merely because it explains multiple threats.

The planner is deterministic for identical normalized evidence and budgets.

## Stateful adversarial episodes

An episode is a bounded sequence of sandbox phases such as baseline, prime, trigger, observe, follow-up, and verify. Supported episodes reuse the existing runtime primitive. Synthetic environment canaries are generated internally and raw values are available only transiently to the in-memory observation classifier.

Memory-persistence testing is intentionally fail-closed: if the runtime cannot provide a safe shared-workspace/state primitive for the required phases, the episode is `INCONCLUSIVE` rather than pretending that persistence is absent.

## Epistemic safety rules

These rules are non-negotiable:

1. No real host secret is copied into a causal episode.
2. Raw synthetic canary values are never persisted verbatim.
3. Causal execution cannot weaken namespace, network, chroot, copied-rootfs, timeout, or resource containment.
4. `NOT_OBSERVED` is **not** `ABSENT`. An episode-scoped non-observation never becomes global negative evidence.
5. Sandbox unavailability and truncated execution remain `INCONCLUSIVE`.
6. Only canonical positive observations can add capability evidence.
7. Every satisfied causal stage retains evidence ancestry.
8. Active investigation can make a repository look more dangerous; more knowledge is not automatically more trust.

## Differential and gates

When both baseline and current reports contain causal analysis, RepoTrial emits `repotrial.causal-differential.v1`. It compares exact active chains and also aggregates threat state so a regression such as `PARTIAL -> PROVEN` is caught even when the detailed chain identity changes after a missing stage becomes observed.

- `--fail-on-causal <severity>` exits `6` for active `PROVEN`/`SUPPORTED` chains at or above the threshold.
- `--fail-on-new-causal <severity>` exits `7` for newly active or regressed causal threats at or above the threshold.

The GitHub Action exposes the same modes, budgets, outputs and shared gate implementation.

## Repository-native adversarial benchmark

RepoTrial ships a compact deterministic corpus containing benign near-misses and malicious multi-file compositions. `npm run benchmark:adversarial` scans the corpus with runtime/network providers disabled and measures:

- expected threat recall;
- active-threat precision against reviewed allowed labels;
- expected observed-stage recall;
- benign false-positive rate;
- deterministic causal receipt replay.

The benchmark is a required CI gate on Node 22 and 24. It complements unit tests by checking whole-repository composition behavior.
