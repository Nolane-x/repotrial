# RepoTrial v0.4 Completion Design

## Goal

Close the remaining production gaps from v0.3 with a bounded dynamic-analysis sandbox, structured YAML/TOML parsing, cryptographic provenance, differential PR analysis, dependency/SBOM/CVE evidence, stronger secret redaction, and release verification across supported Node and Docker environments.

## Product boundary

RepoTrial remains useful without ForgeOS, network access, Docker, external scanners, or signing keys. Every enhanced provider is capability-detected and reports one of `ok`, `disabled`, `unavailable`, `timeout`, or `error`; unavailable enrichment never masquerades as completed evidence. ForgeOS remains the strongest optional control-plane integration.

## Architecture

1. **Static evidence core** keeps deterministic repository discovery, rule evaluation, verdicts, SARIF, HTML, and ForgeOS bridge behavior.
2. **Structured configuration engine** parses JSON, YAML 1.2-style mappings/sequences/anchors/block scalars, and TOML tables/arrays/multiline strings with strict node/depth/alias/byte budgets. Parse diagnostics are evidence, not crashes.
3. **Runtime evidence provider** copies the target into a disposable workspace and executes explicitly selected or discovered scripts inside a Linux user/mount/PID/network namespace. It applies resource limits, a minimal environment, network-command traps, Node preload instrumentation, output caps, timeouts, and before/after filesystem snapshots. No process fallback is used unless explicitly enabled.
4. **Supply-chain provider** inventories dependencies, produces CycloneDX 1.6 SBOM, extracts licenses, optionally queries OSV in bounded batches, and normalizes optional container scanners (`trivy`, `grype`, or Docker Scout).
5. **Differential engine** compares stable finding identities against a report or Git ref and labels findings `new`, `existing`, and `resolved`. CI can gate only new findings.
6. **Integrity layer** creates an in-toto/SLSA-style provenance statement, a machine-checkable proof artifact, and optional Ed25519 DSSE signatures. Optional Cosign integration creates a Sigstore bundle when the binary and credentials exist.
7. **Release gates** validate schemas/invariants, install the packed npm artifact in a clean directory, run ForgeOS CLI/HTTP acceptance, run supported Node versions, and build/run the Docker image when a daemon is available.

## Safety constraints

- Dynamic execution is opt-in.
- Namespace sandbox is required for `runtime=sandbox`; absence is an explicit unavailable result.
- Target source is never executed in-place.
- Network is disabled in the namespace.
- Host spawning always uses `shell: false`.
- Runtime candidates, duration, output, files, bytes, processes, and environment are bounded.
- Artifact text is redacted before persistence.
- HTTP providers require HTTPS except loopback or explicit unsafe override.
- OSV network access is opt-in.
- Signing private keys are never copied into reports.

## New artifacts

- `runtime.json`
- `repotrial.cdx.json`
- `vulnerabilities.json`
- `licenses.json`
- `container.json`
- `differential.json`
- `proof.json`
- `provenance.intoto.json`
- `attestation.dsse.json` when signed
- `sigstore.bundle.json` when Cosign succeeds

## CLI additions

- `scan --runtime off|auto|sandbox --runtime-script <name> --runtime-timeout <ms>`
- `scan --supply-chain off|offline|osv --osv-url <url>`
- `scan --baseline-report <file> | --baseline-ref <git-ref> --fail-on-new`
- `scan --signing-key <pem> --sigstore`
- `diff <baseline-report> <current-report> [--json]`
- `keygen --private <file> --public <file>`
- `verify <artifact-directory> [--public-key <pem>] [--json]`

## Compatibility decision

Node.js 20 reached end of life on 2026-03-24. RepoTrial v0.4 supports Node.js 22 and 24 LTS rather than claiming production support for an EOL runtime. The CLI performs an early runtime-version check and CI tests both supported majors.

## Success criteria

- All old tests remain green.
- New tests cover parser bombs, alias cycles, sandbox escape attempts, timeout/output limits, runtime observations, OSV response bounds, diff stability, signature tampering, proof invariants, and provider failures.
- Coverage remains at least 90% lines.
- Packed npm install works from a clean directory.
- ForgeOS v0.6.1 CLI and HTTP acceptance pass.
- Node 22 and Node 24 suites pass.
- Dockerfile builds and runs where a daemon is available; otherwise release verification reports the exact environmental blocker without claiming completion.
