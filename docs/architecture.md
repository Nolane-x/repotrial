# RepoTrial architecture

RepoTrial v0.5 is a provider-oriented evidence pipeline with deterministic trust calculation and a pure evidence-reasoning layer.

```text
Repository
  ├─ bounded discovery + full structured config parser
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
                                     ├─ attack paths
                                     └─ counterfactual remediation
          └──────────────┬───────────────┘
                         ↓
              portable HTML / JSON / SARIF / SBOM
                         ↓
              artifact proof + in-toto/SLSA provenance
                         ↓
              optional DSSE and/or Sigstore signature
```

## Boundaries

- `src/core`: discovery, parser, rules, verdict, differential, redaction, report, SARIF, and orchestration.
- `src/reasoning`: pure deterministic evidence graph, capability normalization, hypothesis evaluation, attack paths, epistemic state, confidence, and counterfactual remediation. It performs no filesystem, process, network, clock, random, or model calls.
- `src/runtime`: disposable sandbox provider; never invoked implicitly outside configured runtime mode.
- `src/supply`: lockfile inventory, CycloneDX, OSV, container normalization.
- `src/bridge`: native surface construction and versioned ForgeOS client.
- `integrations/forgeos`: authenticated loopback sidecar.
- `src/integrity`: artifact proof, deterministic invariants, provenance, DSSE, Cosign.
- `src/server.mjs`: local script-free report server with real-path containment.

## Evidence reasoning boundary

Reasoning consumes only canonical post-provider charges, safeguards, coverage, and bounded provider-state metadata. It never executes repository content. Unknown rule IDs remain evidence nodes but cannot silently invent a normalized capability.

The reasoning graph has four node classes: `EVIDENCE`, `SAFEGUARD`, `CAPABILITY`, and `CLAIM`. Edges are typed as `SUPPORTS`, `ENABLES`, `MITIGATES`, or `REQUIRES`. Stable SHA-256-derived identities make semantic graph elements comparable across scans.

Threat hypotheses use explicit epistemic states: `PROVEN`, `SUPPORTED`, `CONTRADICTED`, `REFUTED`, `UNKNOWN`, and `UNTESTED`. Missing evidence is not evidence of absence. In v0.5, `REFUTED` is reserved for future explicit negative-evidence providers rather than being inferred from a clean scan.

Attack paths are ordered threat-model stages and are marked `VIABLE`, `PARTIAL`, or `BLOCKED`. Counterfactual remediation re-runs the pure reasoning core after removing one proven charge at a time, then ranks which evidence removal would eliminate the most currently viable paths or downgrade the most high-impact hypotheses. This is causal prioritization over the current evidence model, not a safety certification.

The legacy deterministic verdict remains authoritative in v0.5. Reasoning enriches and explains the case file without changing established verdict thresholds. This compatibility boundary allows the project to collect evidence about the reasoning model before a future policy version chooses whether verified hypotheses should participate directly in gating.

## Trust invariants

Provider failures are data. They return disabled/skipped/unavailable/error states and diagnostics; they do not convert unknown evidence into a clean verdict. Coverage omissions prevent `TRUSTED`.

All persisted untrusted values pass the iterative redaction/bounding path. Child processes use argument arrays and `shell: false`. Contract shapes have explicit schema versions. The reasoning engine is deterministic under charge reordering, never treats provider absence as refutation, and does not mutate the evidence supplied by acquisition providers.
