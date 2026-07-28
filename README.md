<div align="center">

# ⚖ RepoTrial

[**English**](README.md) · [Tiếng Việt](README-VN.md)

**Put any AI-agent repository on trial — statically, dynamically, and across its software supply chain.**

Deterministic charges · Hash-and-line evidence · Linux sandbox detonation · CycloneDX/OSV · PR differential gates · DSSE/Sigstore provenance · Native ForgeOS-powered remediation

[Quick start](#quick-start) · [Complete scan](#complete-scan) · [ForgeOS Powered](#forgeos-powered) · [GitHub Action](#github-action) · [Security model](#security-model)

</div>

---

RepoTrial is an independent security and trust-analysis tool for AI-agent repositories. It works without ForgeOS, an API key, a model, or a cloud account. When ForgeOS v0.6+ is connected, RepoTrial adds a second security engine, ForgeOS runtime/kernel evidence, and an evidence-obligation-aware remediation RoutePlan.

RepoTrial does not convert a repository into a binary “safe/unsafe” certification. It produces a bounded, reproducible case file: what was inspected, what was omitted, which facts were proven, which dynamic behaviors were observed, which dependencies are exposed, and how every artifact can be verified.

## Why teams choose RepoTrial

- **One case file, not five dashboards:** static analysis, runtime evidence, supply-chain inventory, differential findings, and provenance share deterministic identities.
- **Useful before ForgeOS, deeper with it:** offline local analysis is complete on its own; ForgeOS adds independently anchored runtime and remediation evidence.
- **CI-ready outputs:** portable HTML, JSON, SARIF, CycloneDX, proofs, and optional signatures are produced from the same scan.

## Evidence pipeline

```text
repository → bounded discovery → local rules / optional providers → canonical charges
          → coverage-aware verdict + differential identities       → portable artifacts
          → proof + provenance + optional signatures               → CI or human review
```

Providers are explicit and fail as recorded evidence states, never as a silent clean verdict. See the [architecture](docs/architecture.md) for boundaries and [runtime sandbox](docs/runtime-sandbox.md) for execution isolation.

## Quick start

Requirements:

- Node.js 22.14+ or Node.js 24;
- Linux with unprivileged user namespaces for optional runtime detonation;
- zero npm runtime dependencies.

```bash
npm install
node bin/repotrial.mjs scan path/to/agent-repo --forgeos off
node bin/repotrial.mjs serve .repotrial
```

After publishing to npm:

```bash
npx repotrial scan .
```

A conservative offline CI gate:

```bash
repotrial scan . \
  --forgeos off \
  --runtime off \
  --supply-chain offline \
  --fail-on reckless \
  --json
```

## Complete scan

The full local pipeline combines deterministic static evidence, opt-in sandbox detonation, lockfile/SBOM analysis, OSV lookup, a Git baseline, cryptographic provenance, and ForgeOS enrichment:

```bash
repotrial keygen --output .repotrial-keys

repotrial scan . \
  --runtime sandbox \
  --supply-chain osv \
  --baseline-ref origin/main \
  --fail-on-new reckless \
  --signing-key .repotrial-keys/repotrial-private.pem \
  --cosign \
  --forgeos cli \
  --forgeos-root ../forge-os \
  --forgeos-depth full

repotrial verify .repotrial \
  --public-key .repotrial-keys/repotrial-public.pem \
  --cosign \
  --certificate-identity '<workflow-identity>' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Runtime execution, OSV networking, container scanners, and signing are all explicit. If a provider is unavailable, RepoTrial records the state; it never silently upgrades trust.

## Artifacts

A complete scan can produce:

```text
.repotrial/
├── report.html                  # Script-free offline courtroom UI
├── verdict.json                 # Complete machine-readable report v2
├── evidence.json                # Hash-anchored evidence ledger
├── repotrial-badge.svg          # README/website verdict badge
├── forgeos-agent-surface.json   # Native ForgeOS v0.6 surface contract
├── repotrial.sarif              # SARIF 2.1.0 for code scanning
├── runtime.json                 # Sandbox candidates, runs, events, file diff
├── supply-chain.json            # Components, licenses, OSV/container findings
├── sbom.cdx.json                # CycloneDX 1.6 SBOM
├── differential.json            # New, existing, and resolved findings
├── artifact-proof.json          # Artifact hashes + machine-checked invariants
├── provenance.intoto.json       # in-toto Statement with SLSA provenance v1
├── provenance.dsse.json         # Optional local Ed25519 DSSE envelope
└── provenance.sigstore.json     # Optional Cosign/Sigstore bundle
```

All repository-controlled persisted text passes the shared bounded redaction path. Absolute machine paths are omitted unless `--include-absolute-paths` is explicitly enabled.

## Analysis layers

### 1. Deterministic agent-surface analysis

RepoTrial recognizes nested and repository-level surfaces for:

- `AGENTS.md`, `CLAUDE.md`, and `GEMINI.md`;
- GitHub Copilot repository/path instructions and custom agents;
- Cursor, Cline, Windsurf, and Continue rules/configuration;
- MCP configuration, hooks, package scripts, command allowlists, secret references, and egress controls;
- JSON, YAML, and TOML, including bounded anchors/aliases, merge keys, block scalars, custom tags, dotted tables, arrays of tables, inline collections, and multiline strings.

Rule families cover dangerous lifecycle execution, pipe-to-shell, unrestricted shell capability, wildcard MCP permissions, secret-to-egress reachability, instruction-boundary override, self-certified completion, fake/missing verification, destructive capability without approval, and incomplete coverage.

### 2. Runtime sandbox detonation

`--runtime sandbox` copies the repository into a disposable root filesystem and detonates bounded package lifecycle scripts or explicitly requested scripts. On supported Linux hosts it uses separate user, mount, UTS, IPC, network, PID, and cgroup namespaces; a chroot; a private mount propagation policy; no inherited secret environment; wall-clock/output/process/file limits; network-command traps; Node network/DNS/child-process instrumentation; and before/after filesystem hashing.

The original repository is never the execution directory. Source copy is preflight-bounded to 20,000 files and 256 MiB by default (`--runtime-max-source-files`, `--runtime-max-source-bytes`), and the active output subtree is excluded. Runtime evidence records attempted network activity, filesystem mutations, stdout/stderr, exit status, timeout, and truncation. See [runtime sandbox documentation](docs/runtime-sandbox.md).

### 3. Supply-chain evidence

Offline mode inventories npm, pnpm, Yarn, requirements, Poetry, uv, Pipfile, Cargo, Go, Composer, Gem, and Dockerfile sources. It emits CycloneDX 1.6 and license coverage. `--supply-chain osv` performs bounded HTTPS `querybatch` requests and computes normalized severity, including CVSS v3 vectors.

Optional external container adapters accept bounded JSON/SARIF from Trivy-, Grype-, or SARIF-compatible commands without making those scanners runtime dependencies. See [supply-chain documentation](docs/supply-chain.md).

### 4. Differential PR analysis

Use a prior report or an isolated Git worktree baseline:

```bash
repotrial scan . --baseline-ref origin/main --fail-on-new reckless
repotrial diff old/verdict.json new/verdict.json --json
```

RepoTrial gives each proven finding a stable identity and classifies it as `new`, `existing`, or `resolved`. SARIF receives `baselineState`, and CI can gate only newly introduced risk with exit code `3`. See [differential analysis](docs/differential-analysis.md).

### 5. Integrity and provenance

Every scan generates SHA-256 artifact proofs and recomputes deterministic report invariants: artifact digests, report receipt, portable evidence paths, deterministic verdict, and the requirement that `TRUSTED` has complete coverage.

Local signing uses Ed25519 DSSE. Optional Cosign creates a Sigstore bundle with a key or OIDC keyless identity. Provenance is an in-toto Statement using the SLSA provenance v1 predicate. See [attestations](docs/attestations.md).

## Verdicts

| Verdict | Meaning |
|---|---|
| `TRUSTED` | No known proven signal in completely inspected scope; not a certification |
| `CAUTIOUS` | Lower-risk signals, provider uncertainty, or incomplete coverage |
| `RECKLESS` | Multiple high-severity signals or accumulated risk |
| `DANGEROUS` | Critical direct evidence or the dangerous score threshold |
| `UNPROVEN` | No inspectable evidence was available |

Every direct evidence anchor contains a relative path, line range, redacted snippet, complete-file SHA-256, stable fingerprint, rule ID, and severity. External ForgeOS locations are re-anchored to repository files when possible.

## ForgeOS Powered

Recommended workspace:

```text
workspace/
├── forge-os/
└── repotrial/
```

Verify and scan:

```bash
repotrial forgeos-doctor --forgeos-root ../forge-os
repotrial scan . --forgeos cli --forgeos-root ../forge-os --forgeos-depth full
```

`full` imports:

- ForgeOS native agent-surface security findings and report SHA-256;
- ForgeOS version and deterministic-fabric inventory;
- adversarial-corpus/runtime evidence;
- an explainable remediation RoutePlan;
- technique, provider, outcomes, and evidence obligations.

Versioned sidecar:

```bash
export REPOTRIAL_BRIDGE_TOKEN='use-a-long-random-token'
export FORGEOS_ROOT='../forge-os'
node integrations/forgeos/bridge-server.mjs

repotrial scan . \
  --forgeos http \
  --forgeos-url http://127.0.0.1:8791 \
  --forgeos-token "$REPOTRIAL_BRIDGE_TOKEN" \
  --forgeos-depth full
```

The boundary is `repotrial.forgeos.bridge.v1`. The sidecar exposes `GET /health`, authenticated `GET /ready`, and authenticated `POST /v1/scan`. Plain HTTP is restricted to loopback unless explicitly overridden. See [ForgeOS bridge documentation](docs/forgeos-bridge.md).

## GitHub Action

```yaml
name: RepoTrial
on: [pull_request, push]
permissions:
  contents: read
  security-events: write
  id-token: write
jobs:
  trial:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: casioreview20-glitch/repotrial@v1
        with:
          path: .
          exclude-paths: tests/fixtures
          baseline-ref: origin/main
          fail-on-new: reckless
          runtime-mode: off
          supply-chain-mode: osv
          sigstore: 'true'
          forgeos-mode: off
          upload-sarif: 'true'
```

The action exposes verdict, score, new-finding count, HTML, SARIF, SBOM, proof, DSSE, Sigstore, receipt, ForgeOS version, and remediation technique. It uploads the report even when a gate fails. Keyless signing requires `id-token: write`.

## Docker

```bash
docker build -t repotrial:0.4.1 .
docker run --rm repotrial:0.4.1 version

docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.repotrial:/output" \
  repotrial:0.4.1 scan /workspace \
  --output /output \
  --forgeos off \
  --runtime off \
  --supply-chain offline
```

The image runs as the non-root `node` user. Runtime detonation inside a container depends on the host container runtime permitting unprivileged namespaces; when unavailable, RepoTrial reports `runtime.unavailable` rather than weakening isolation.

## CLI

```text
repotrial scan [path] [options]
repotrial diff <baseline.json> <current.json> [--json]
repotrial keygen [--output keys] [--passphrase-env NAME]
repotrial verify [report-directory] [--public-key key.pub.pem] [--cosign]
repotrial serve [report-directory] [--port 4177]
repotrial bridge-manifest [path]
repotrial forgeos-doctor [--forgeos-root ../forge-os]
repotrial version
```

Important scan controls:

```text
--exclude <path-a,path-b>
--runtime off|auto|sandbox
--runtime-script <a,b>
--runtime-timeout <ms>
--runtime-max-runs <n>
--runtime-max-source-files <n>
--runtime-max-source-bytes <n>
--supply-chain off|offline|osv
--osv-url <https-url>
--osv-timeout <ms>
--container-scanner-command <path>
--container-scanner-args <json-array>
--baseline-report <verdict.json>
--baseline-ref <git-ref>
--fail-on cautious|reckless|dangerous
--fail-on-new cautious|reckless|dangerous
--signing-key <private.pem>
--signing-passphrase-env <NAME>
--cosign [--cosign-key <uri-or-file>] [--cosign-bin <path>]
--forgeos auto|off|cli|http
--forgeos-depth security|full
--forgeos-root <dir> | --forgeos-bin <path> | --forgeos-url <url>
--max-files <n>
--max-file-bytes <n>
--max-total-bytes <n>
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Analysis completed and configured gates passed |
| `1` | Invalid invocation, verification failure, or analysis failure |
| `2` | Overall verdict met `--fail-on` |
| `3` | New-findings verdict met `--fail-on-new` |

## Security model

RepoTrial treats repository text, executable scripts, parser input, bridge responses, scanner output, and report URLs as hostile. Bounded parsing/traversal, no-shell child processes, output/time limits, protocol validation, loopback transport policy, symlink containment, redaction, script-free HTML, portable paths, and cryptographic receipts are defense layers.

Dynamic detonation remains opt-in and is not a proof that arbitrary hostile native code is harmless. OSV/container results inherit the coverage and freshness of their providers. A good verdict is evidence about the inspected scope, not permission to execute unknown software without normal review. Read [SECURITY.md](SECURITY.md).

## Development

```bash
npm ci
npm test
npm run check
npm run test:coverage
npm audit --omit=dev
npm pack --dry-run
npm run verify:forgeos -- --forge-root ../forge-os
```

The CI matrix runs maintained Node.js 22 and 24 lines and performs an actual Docker build/run gate.

## License

MIT
