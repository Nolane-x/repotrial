# RepoTrial architecture

RepoTrial v0.4 is a provider-oriented evidence pipeline with deterministic trust calculation.

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
          ↓
   deterministic verdict + differential identities
          ↓
   portable HTML / JSON / SARIF / SBOM
          ↓
   artifact proof + in-toto/SLSA provenance
          ↓
   optional DSSE and/or Sigstore signature
```

## Boundaries

- `src/core`: discovery, parser, rules, verdict, differential, redaction, report, SARIF.
- `src/runtime`: disposable sandbox provider; never invoked implicitly outside configured runtime mode.
- `src/supply`: lockfile inventory, CycloneDX, OSV, container normalization.
- `src/bridge`: native surface construction and versioned ForgeOS client.
- `integrations/forgeos`: authenticated loopback sidecar.
- `src/integrity`: artifact proof, deterministic invariants, provenance, DSSE, Cosign.
- `src/server.mjs`: local script-free report server with real-path containment.

Provider failures are data. They return disabled/skipped/unavailable/error states and diagnostics; they do not convert unknown evidence into a clean verdict. Coverage omissions prevent `TRUSTED`.

All persisted untrusted values pass the iterative redaction/bounding path. Child processes use argument arrays and `shell: false`. Contract shapes have explicit schema versions.
