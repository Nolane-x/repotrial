# RepoTrial architecture

RepoTrial v0.7 is a provider-oriented evidence pipeline with deterministic trust calculation, pure evidence reasoning, and an optional deterministic causal attack-synthesis and active-verification layer.

```text
Repository
  ├─ bounded discovery + structured config parser
  ├─ deterministic local rules
  ├─ optional Linux runtime sandbox
  ├─ optional supply-chain providers
  ├─ optional ForgeOS bridge
  └─ optional baseline report / isolated Git worktree
          ↓
   canonical charges + safeguards + coverage
          ├──────────────────────────────┐
          ↓                              ↓
   deterministic verdict          Evidence Reasoning Engine
   + differential identities        ├─ typed evidence graph
                                     ├─ normalized capabilities
                                     ├─ threat hypotheses
                                     ├─ legacy attack paths
                                     ├─ security invariants
                                     └─ counterfactual remediation
                                             ↓
                                  Causal Reasoning Engine (opt-in)
                                     ├─ declarative threat registry
                                     ├─ causal capability graph
                                     ├─ bounded multi-chain synthesis
                                     ├─ epistemic state + ancestry
                                     └─ active probe policy
                                             ↓
                               optional bounded sandbox episodes
                                             ↓
                                  causal trace + positive evidence
                                             ↓
                                      re-synthesis / delta
          └──────────────────────┬───────────────────────────┘
                                 ↓
                  portable HTML / JSON / SARIF / SBOM
                                 ↓
                  artifact proof + in-toto/SLSA provenance
                                 ↓
                  optional DSSE and/or Sigstore signature
```

## Boundaries

- `src/core`: discovery, parser, rules, verdict, differential analysis, redaction, reporting, SARIF, and orchestration.
- `src/reasoning`: pure deterministic evidence reasoning, threat registry, causal graph, bounded attack-chain synthesis, epistemic state, gates, and counterfactual remediation. It performs no filesystem, process, network, clock, random, or model calls.
- `src/experiments`: deterministic adaptive/active planning, bounded episode descriptions, observation classification, causal traces, and positive-evidence assimilation. Execution is delegated to the runtime provider rather than implemented here.
- `src/benchmark`: repository-native adversarial corpus metrics and deterministic replay gate.
- `src/runtime`: disposable Linux sandbox provider; never invoked implicitly outside configured runtime/experiment/active-causal execution modes.
- `src/supply`: lockfile inventory, CycloneDX, OSV, and container normalization.
- `src/bridge`: native surface construction and versioned ForgeOS client.
- `integrations/forgeos`: authenticated loopback sidecar.
- `src/integrity`: artifact proof, provenance, DSSE, and Cosign/Sigstore integration.
- `src/server.mjs`: local script-free report server with real-path containment.

## Evidence reasoning boundary

Evidence reasoning consumes canonical post-provider charges, safeguards, coverage, explicit negative evidence, and bounded provider-state metadata. It never executes repository content. Unknown rule IDs remain evidence nodes but cannot silently invent a normalized capability.

The evidence graph has `EVIDENCE`, `SAFEGUARD`, `CAPABILITY`, and `CLAIM` nodes. Stable SHA-256-derived identities make semantic elements comparable across scans. Threat hypotheses preserve explicit epistemic states: `PROVEN`, `SUPPORTED`, `CONTRADICTED`, `REFUTED`, `UNKNOWN`, and `UNTESTED`. Missing evidence is not evidence of absence; `REFUTED` requires explicit negative evidence rather than a clean scan.

Legacy attack paths are ordered threat-model stages marked `VIABLE`, `PARTIAL`, or `BLOCKED`. Counterfactual remediation re-runs the pure reasoning core after removing one proven charge at a time and ranks evidence by modeled attack-path, hypothesis, and invariant impact. It is causal prioritization over the current evidence model, not a safety certification.

## Causal reasoning boundary

Causal mode is `off` by default. With `--causal analyze`, RepoTrial constructs a receipt-bound threat registry, projects canonical evidence into a causal capability graph, and synthesizes bounded multi-stage chains without executing repository code. With `--causal active`, the active planner may request bounded synthetic episodes through the existing runtime sandbox.

Causal chains are `PROVEN`, `SUPPORTED`, `CONTRADICTED`, `BLOCKED`, or `PARTIAL`. Every satisfied stage retains evidence ancestry. Search is bounded by depth and retained-chain budgets, uses deterministic ordering and dominance pruning, and cannot manufacture a satisfied stage from a registry definition alone.

Active planning optimizes expected epistemic value using threat impact, uncertainty, severity-weighted chain centrality, discrimination power, expected evidence strength, soft execution cost, and redundancy. A probe can inform several chains. Only positive canonical observations can add capability evidence; `NOT_OBSERVED` remains episode-scoped and never becomes global proof of absence.

Stateful episode support is deliberately fail-closed. If the sandbox cannot safely provide a persistence/shared-workspace primitive required by a threat probe, the result is `INCONCLUSIVE`, not `ABSENT` or safe.

## Compatibility and authority

The deterministic legacy verdict remains authoritative for the established verdict thresholds. Evidence reasoning and causal reasoning add opt-in explanatory and CI-gating layers without silently changing legacy `0–5` exit semantics. Causal current-risk and regression gates use exits `6` and `7` respectively.

When causal mode is `off`, RepoTrial preserves the 0.6 report/receipt compatibility boundary: no `causal` field or `causal.json` artifact is created. When causal analysis is enabled, `causal.json` becomes a proof/provenance subject just like other persisted analysis artifacts.

## Trust invariants

Provider failures are data. They return disabled/skipped/unavailable/error states and diagnostics; they do not convert unknown evidence into a clean verdict. Coverage omissions prevent `TRUSTED`.

All persisted untrusted values pass the iterative redaction/bounding path. Child processes use argument arrays and `shell: false`. Contract shapes have explicit schema versions. Reasoning is deterministic under canonical input reordering, acquisition providers are not mutated, real host secrets never enter adaptive/causal scenarios, raw synthetic canaries are not persisted verbatim, and active causal execution cannot weaken the namespace/chroot/copied-rootfs/network/resource containment boundary.
