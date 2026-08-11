<div align="center">

# ⚖ RepoTrial

[**English**](README.md) · [Tiếng Việt](README-VN.md)

**Put any AI-agent repository on trial — then prove how the evidence composes into real attack paths.**

Deterministic charges · Evidence Graph · Threat Hypotheses · Attack Paths · Security Invariants · Explicit Negative Evidence · Counterfactual Remediation · Linux Sandbox · CycloneDX/OSV · Reasoning Differential · DSSE/Sigstore · ForgeOS

[Quick start](#quick-start) · [Evidence reasoning](#evidence-reasoning-engine) · [Complete scan](#complete-scan) · [GitHub Action](#github-action) · [Security model](#security-model)

</div>

---

RepoTrial is an independent security, trust, and evidence-analysis tool for AI-agent repositories. It works without ForgeOS, an API key, a model, or a cloud account. When ForgeOS v0.6+ is connected, RepoTrial adds a second security engine, ForgeOS runtime/kernel evidence, and evidence-obligation-aware remediation.

RepoTrial does **not** convert a repository into a binary “safe/unsafe” certification. It creates a bounded, reproducible case file: what was inspected, what was omitted, what was proven, what was explicitly disproven, which capabilities compose into attack paths, which security invariants are violated, what changed relative to a baseline, and which remediation removes the most modeled risk.

## Why RepoTrial 0.5 is different

- **Evidence, not scanner output:** findings become stable evidence nodes connected to capabilities and security claims.
- **Composition-aware security:** shell, secrets, network, lifecycle execution, tool power, and instruction control are reasoned about as attack chains instead of isolated scores.
- **Epistemically explicit:** `PROVEN`, `SUPPORTED`, `CONTRADICTED`, `REFUTED`, `UNKNOWN`, and `UNTESTED` remain distinct. Missing evidence is never silently treated as proof of safety.
- **Invariant proof:** policies such as “destructive capability requires human approval” are evaluated as `VIOLATED`, `SATISFIED`, `UNKNOWN`, or `NOT_APPLICABLE`.
- **Counterfactual remediation:** RepoTrial simulates removal of each proven charge and ranks which fix eliminates the most viable attack paths and invariant violations.
- **Reasoning-aware PR gates:** differential analysis detects new capabilities, new viable attack paths, hypothesis regressions, and new invariant violations.
- **One case file:** static analysis, runtime evidence, supply-chain inventory, reasoning, differential state, provenance, and signatures share deterministic identities.
- **Useful without ForgeOS, deeper with it:** the local engine is complete on its own; ForgeOS adds independently anchored runtime/security/remediation evidence.

## Evidence pipeline

```text
repository
   ↓
bounded discovery
   ├── deterministic agent-surface rules
   ├── optional Linux runtime sandbox
   ├── optional supply-chain / OSV / container evidence
   └── optional ForgeOS evidence
   ↓
canonical charges + safeguards + coverage
   ├───────────────→ deterministic legacy verdict
   │
   └───────────────→ Evidence Reasoning Engine
                       ├── typed evidence graph
                       ├── normalized capabilities
                       ├── threat hypotheses
                       ├── attack paths
                       ├── explicit negative evidence
                       ├── security invariant proof
                       └── counterfactual remediation
                              ↓
                    reasoning differential
                              ↓
portable JSON / HTML / SARIF / SBOM
   ↓
artifact proof + SLSA provenance + optional DSSE/Sigstore
```

All reasoning is deterministic and local. The reasoning engine performs no filesystem reads, process spawning, network calls, clock access, random generation, or model calls; it reasons only over canonical bounded evidence produced by the acquisition layer.

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
  --fail-on-reasoning critical \
  --json
```

## Evidence Reasoning Engine

Every scan now embeds `repotrial.reasoning.v1` inside `verdict.json` and the receipt-bound offline HTML case file.

### Evidence graph

```text
POSITIVE EVIDENCE ──SUPPORTS──> CAPABILITY ──ENABLES──> CLAIM
SAFEGUARD ───────────MITIGATES────────────────────────> CLAIM
NEGATIVE EVIDENCE ───REFUTES──> CAPABILITY
```

Known rule families normalize into powers such as:

- `shell-exec`;
- `dependency-execution`;
- `network-egress`;
- `secret-access`;
- `broad-tool-access`;
- `instruction-control`;
- `destructive-action`;
- `filesystem-write`;
- `supply-chain-exposure`.

Unknown third-party rules remain evidence nodes but **cannot invent capabilities** unless RepoTrial has an explicit normalization rule.

### Built-in threat hypotheses

RepoTrial currently reasons about:

1. credential/secret exfiltration;
2. arbitrary or attacker-influenced code execution;
3. destructive action without effective human approval;
4. prompt/instruction control escalating into powerful tools;
5. high-impact supply-chain exposure reaching an execution surface.

A multi-stage path becomes `VIABLE` only when its hypothesis is `PROVEN` or `SUPPORTED`. `UNKNOWN` becomes a `PARTIAL` path. `CONTRADICTED` or explicitly `REFUTED` becomes `BLOCKED`.

### Explicit negative evidence

RepoTrial never equates “not found” with “proven absent”. A provider must explicitly state the capability, source, method, scope, and confidence before negative evidence can refute a hypothesis or satisfy a forbidden-composition invariant.

```js
import { normalizeNegativeEvidence, reasonAboutEvidence } from 'repotrial';

const negativeEvidence = normalizeNegativeEvidence([{
  capability: 'network-egress',
  state: 'absent',
  source: 'runtime-sandbox',
  method: 'network-namespace-observation',
  scope: 'bounded-runtime-experiments',
  confidence: 'high'
}]);

const reasoning = reasonAboutEvidence({
  charges,
  safeguards,
  coverage,
  negativeEvidence
});
```

### Security invariant proof

Built-in invariants include:

```text
secret-access + network-egress            → forbidden composition

destructive-action                       → requires human-approval
instruction-control                       → requires least-privilege
dependency-execution + network-egress     → forbidden composition
```

Custom deterministic invariants can also be evaluated through the public API:

```js
import { evaluateSecurityInvariants } from 'repotrial';

const proof = evaluateSecurityInvariants({
  observedCapabilities: ['shell-exec', 'network-egress'],
  safeguards: [],
  negativeEvidence: [],
  definitions: [{
    id: 'custom-no-shell-network',
    title: 'Shell and network must not compose',
    severity: 'critical',
    kind: 'forbid-all',
    capabilities: ['shell-exec', 'network-egress']
  }]
});
```

### Counterfactual remediation

For every proven charge, RepoTrial recomputes the reasoning model without that evidence and ranks the candidate by:

1. viable attack paths eliminated;
2. invariant violations eliminated;
3. high/critical hypotheses downgraded;
4. severity.

This is causal prioritization over the observed case, **not** proof that applying a single recommendation makes the repository safe.

## Complete scan

The complete pipeline combines static evidence, runtime detonation, supply-chain analysis, an isolated Git baseline, reasoning differential, cryptographic provenance, and ForgeOS enrichment:

```bash
repotrial keygen --output .repotrial-keys

repotrial scan . \
  --runtime sandbox \
  --supply-chain osv \
  --baseline-ref origin/main \
  --fail-on-new reckless \
  --fail-on-new-reasoning critical \
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

Runtime execution, OSV networking, container scanners, and signing remain explicit. Provider failure is recorded as evidence state and never silently upgraded to trust.

## Artifacts

A complete scan can produce:

```text
.repotrial/
├── report.html                  # Script-free offline courtroom UI + reasoning/invariants
├── verdict.json                 # Complete machine-readable report v2 + reasoning v1
├── evidence.json                # Hash-anchored direct evidence ledger
├── repotrial-badge.svg          # README/website verdict badge
├── forgeos-agent-surface.json   # Native ForgeOS v0.6 surface contract
├── repotrial.sarif              # SARIF 2.1.0 for code scanning
├── runtime.json                 # Sandbox candidates, runs, events, file diff
├── supply-chain.json            # Components, licenses, OSV/container findings
├── sbom.cdx.json                # CycloneDX 1.6 SBOM
├── differential.json            # Finding + reasoning differential
├── artifact-proof.json          # Artifact hashes + machine-checked invariants
├── provenance.intoto.json       # in-toto Statement with SLSA provenance v1
├── provenance.dsse.json         # Optional local Ed25519 DSSE envelope
└── provenance.sigstore.json     # Optional Cosign/Sigstore bundle
```

All repository-controlled persisted text passes the shared bounded redaction path. Absolute machine paths are omitted unless `--include-absolute-paths` is explicitly enabled.

## Analysis layers

### 1. Deterministic agent-surface analysis

RepoTrial recognizes repository and nested surfaces including `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, GitHub Copilot instructions/custom agents, Cursor, Cline, Windsurf, Continue, MCP configuration, hooks, package scripts, command allowlists, secret references, and egress controls.

JSON, YAML, and TOML parsing is bounded and includes anchors/aliases, merge keys, block scalars, custom tags, dotted tables, arrays of tables, inline collections, and multiline strings.

Rule families cover dangerous lifecycle execution, pipe-to-shell, unrestricted shell capability, wildcard MCP permissions, secret-to-egress reachability, instruction-boundary override, self-certified completion, fake/missing verification, destructive capability without approval, and incomplete coverage.

### 2. Runtime sandbox detonation

`--runtime sandbox` copies the repository into a disposable root filesystem and detonates bounded package lifecycle scripts or explicitly requested scripts. On supported Linux hosts it uses separate user, mount, UTS, IPC, network, PID, and cgroup namespaces; a chroot; private mount propagation; no inherited secret environment; wall-clock/output/process/file limits; network-command traps; Node network/DNS/child-process instrumentation; and before/after filesystem hashing.

The original repository is never the execution directory. Runtime evidence records attempted network activity, filesystem mutations, stdout/stderr, exit status, timeout, and truncation. See `docs/runtime-sandbox.md`.

### 3. Supply-chain evidence

Offline mode inventories npm, pnpm, Yarn, requirements, Poetry, uv, Pipfile, Cargo, Go, Composer, Gem, and Dockerfile sources. It emits CycloneDX 1.6 and license coverage. `--supply-chain osv` performs bounded HTTPS `querybatch` requests and normalized severity analysis.

Optional external container adapters accept bounded JSON/SARIF from Trivy-, Grype-, or SARIF-compatible commands without becoming runtime dependencies.

### 4. Reasoning-aware differential analysis

```bash
repotrial scan . \
  --baseline-ref origin/main \
  --fail-on-new reckless \
  --fail-on-new-reasoning critical
```

The traditional differential still classifies stable findings as `new`, `existing`, or `resolved`. When both reports contain reasoning v1, RepoTrial additionally computes:

- new/existing/resolved capabilities;
- new/existing/resolved **viable attack paths**;
- threat-hypothesis regressions and improvements;
- new/existing/resolved invariant violations;
- a dedicated reasoning-differential SHA-256 receipt.

Legacy reports without reasoning remain compatible and receive the original finding-only differential.

### 5. Integrity and provenance

Every scan generates SHA-256 artifact proofs and recomputes deterministic report invariants. Local signing uses Ed25519 DSSE. Optional Cosign creates a Sigstore bundle with a key or OIDC keyless identity. Provenance is an in-toto Statement using the SLSA provenance v1 predicate.

## Verdicts

| Verdict | Meaning |
|---|---|
| `TRUSTED` | No known proven signal in completely inspected scope; not a certification |
| `CAUTIOUS` | Lower-risk signals, provider uncertainty, or incomplete coverage |
| `RECKLESS` | Multiple high-severity signals or accumulated risk |
| `DANGEROUS` | Critical direct evidence or the dangerous score threshold |
| `UNPROVEN` | No inspectable evidence was available |

The v0.4 deterministic verdict remains authoritative for backward compatibility. RepoTrial 0.5 adds a second, richer reasoning layer without silently changing existing verdict thresholds.

## ForgeOS Powered

Recommended workspace:

```text
workspace/
├── forge-os/
└── repotrial/
```

```bash
repotrial forgeos-doctor --forgeos-root ../forge-os
repotrial scan . --forgeos cli --forgeos-root ../forge-os --forgeos-depth full
```

`full` imports ForgeOS agent-surface findings, report SHA-256, deterministic-fabric inventory, adversarial/runtime evidence, and an explainable remediation RoutePlan.

The sidecar boundary remains `repotrial.forgeos.bridge.v1` with authenticated loopback transport by default.

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
      - uses: Nolane-x/repotrial@v1
        with:
          path: .
          baseline-ref: origin/main
          fail-on-new: reckless
          fail-on-reasoning: critical
          fail-on-new-reasoning: critical
          runtime-mode: off
          supply-chain-mode: osv
          sigstore: 'true'
          forgeos-mode: off
          upload-sarif: 'true'
```

The Action exports verdict/score, new findings, viable attack paths, invariant violations, new viable attack paths, new invariant violations, HTML/SARIF/SBOM/proof/signature paths, receipt, ForgeOS version, and remediation technique. The step summary surfaces reasoning state directly in the PR.

## Docker

```bash
docker build -t repotrial:0.5.0 .
docker run --rm repotrial:0.5.0 version

docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.repotrial:/output" \
  repotrial:0.5.0 scan /workspace \
  --output /output \
  --forgeos off \
  --runtime off \
  --supply-chain offline
```

The image runs as the non-root `node` user. If runtime namespace isolation is unavailable, RepoTrial reports `runtime.unavailable`; it does not silently weaken isolation.

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

Reasoning-aware gates:

```text
--fail-on-reasoning info|low|medium|high|critical
--fail-on-new-reasoning info|low|medium|high|critical
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Analysis completed and all configured gates passed |
| `1` | Invalid invocation, verification failure, or analysis failure |
| `2` | Overall legacy verdict met `--fail-on` |
| `3` | New-finding legacy verdict met `--fail-on-new` |
| `4` | Active hypothesis/invariant risk met `--fail-on-reasoning` |
| `5` | New reasoning regression met `--fail-on-new-reasoning` |

## Security model

RepoTrial treats repository text, executable scripts, parser input, bridge responses, scanner output, report URLs, evidence claims, and policy inputs as hostile unless established otherwise. Bounded parsing/traversal, no-shell child processes, output/time limits, protocol validation, loopback transport policy, symlink containment, redaction, script-free HTML, portable paths, deterministic identities, and cryptographic receipts are defense layers.

Dynamic detonation remains opt-in and is not proof that arbitrary hostile native code is harmless. OSV/container evidence inherits provider coverage/freshness. Explicit negative evidence is accepted only as an explicit evidence claim; provider silence is never converted into absence. A good verdict, a blocked attack path, or a satisfied invariant is evidence about the inspected scope, not permission to execute unknown software without normal review.

Read `SECURITY.md`, `docs/architecture.md`, and `docs/evidence-reasoning.md` for the trust boundaries.

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

CI runs maintained Node.js 22 and 24 lines plus fixture scanning, package checks, and an actual Docker build/run gate.

## License

MIT
