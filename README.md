<div align="center">

# ⚖ RepoTrial

[**English**](README.md) · [Tiếng Việt](README-VN.md)

**Deterministic security evidence, causal attack-chain synthesis, and bounded adversarial verification for AI-agent repositories.**

Static evidence · Evidence Graph · Causal Capability Graph · Multi-Chain Synthesis · Active Verification · Linux Sandbox · Supply Chain · Differential Gates · Provenance · ForgeOS

</div>

RepoTrial is a zero-runtime-dependency security and trust analysis engine for AI-agent repositories. It does not certify a repository as “safe”. It creates a reproducible case file containing what was inspected, what was omitted, what was proven, how capabilities compose into attacks, which conclusions remain uncertain, and what changed relative to a baseline.

## RepoTrial 0.7

0.7 adds the **Causal Adversarial Reasoning Engine** on top of the 0.5 evidence-reasoning system and the 0.6 adaptive experiment engine.

```text
repository evidence
      ↓
Evidence Reasoning Engine
      ↓
Causal Capability Graph
      ↓
bounded multi-chain synthesis
      ↓
uncertainty / high-impact chain analysis
      ↓
optional active high-information probes
      ↓
bounded sandbox episodes
      ↓
causal trace + evidence assimilation
      ↓
re-synthesized attack chains
```

The built-in threat registry is declarative and receipt-bound. It covers 12 threat families including credential exfiltration, code execution, destructive action, prompt-to-tool escalation, supply-chain compromise, persistent goal hijacking, memory/context poisoning, identity/privilege abuse, unauthorized tool use, CI lifecycle credential abuse, cross-agent delegation escalation, and verification-bypass unsafe actions.

Causal analysis remains **off by default**. `--causal analyze` never executes repository code. `--causal active` may execute bounded synthetic episodes through the existing Linux copied-rootfs + namespaces + chroot containment boundary.

## Quick start

Requirements: Node.js 22.14+; Linux user namespaces only for optional sandbox execution; no npm runtime dependencies.

```bash
npm install
node bin/repotrial.mjs scan path/to/repo --forgeos off
node bin/repotrial.mjs serve .repotrial
```

Causal analysis without execution:

```bash
repotrial scan . \
  --runtime off \
  --supply-chain offline \
  --causal analyze \
  --fail-on-causal critical \
  --json
```

Active causal verification on a supported Linux host:

```bash
repotrial scan . \
  --runtime sandbox \
  --causal active \
  --causal-max-runs 4 \
  --causal-max-per-candidate 2
```

Repository-native benchmark:

```bash
npm run benchmark:adversarial
```

## Security model

RepoTrial preserves explicit epistemic states. **Missing evidence is not evidence of absence.** In particular:

- `NOT_OBSERVED` is episode-scoped and never becomes global `ABSENT` evidence;
- sandbox unavailability or truncation is `INCONCLUSIVE`, never “clean”;
- no real host secret is injected into adaptive/causal scenarios;
- raw synthetic canaries are not persisted verbatim;
- active causal mode cannot weaken the runtime containment boundary;
- every satisfied causal stage retains evidence ancestry;
- more evidence can make a repository look more dangerous.

See [`docs/causal-adversarial-reasoning.md`](docs/causal-adversarial-reasoning.md), [`docs/evidence-reasoning.md`](docs/evidence-reasoning.md), [`docs/runtime-sandbox.md`](docs/runtime-sandbox.md), and [`SECURITY.md`](SECURITY.md).

## Main analysis layers

### Deterministic repository analysis

RepoTrial recognizes agent instructions/configuration, MCP surfaces, package lifecycle hooks, command permissions, secret references, egress controls, verification commands, destructive capabilities, JSON/YAML/TOML configuration, and bounded repository structure.

### Evidence reasoning

Canonical charges map into stable evidence and capability nodes. Built-in hypotheses and security invariants distinguish `PROVEN`, `SUPPORTED`, `CONTRADICTED`, `REFUTED`, `UNKNOWN`, and `UNTESTED`. Counterfactual remediation ranks evidence removal by modeled attack-path and invariant impact.

### Causal attack synthesis

The 0.7 registry and causal graph synthesize multiple bounded variants per threat rather than one hard-coded path. Chains are `PROVEN`, `SUPPORTED`, `CONTRADICTED`, `BLOCKED`, or `PARTIAL`, with deterministic receipts and dominance pruning.

### Active adversarial verification

The active planner ranks probes by threat impact, uncertainty, severity-weighted chain centrality, discrimination power, expected evidence strength, execution cost, and redundancy. Supported stateful episodes use synthetic canaries/sentinels and the existing sandbox. Unsupported persistence semantics fail closed as `INCONCLUSIVE`.

### Runtime and supply chain

Optional runtime detonation uses a disposable copied rootfs with user/mount/UTS/IPC/network/PID/cgroup namespaces, chroot, time/output/process/file bounds, network traps, instrumentation, and filesystem diffs. Supply-chain analysis supports lockfile inventory, CycloneDX 1.6, OSV and normalized container findings.

### Integrity

Reports can include deterministic SARIF, SBOM, artifact proofs, in-toto/SLSA provenance, Ed25519 DSSE and optional Cosign/Sigstore bundles.

## Core artifacts

```text
.repotrial/
├── verdict.json
├── evidence.json
├── report.html
├── repotrial.sarif
├── runtime.json
├── supply-chain.json
├── sbom.cdx.json
├── experiments.json          # when adaptive experiments are enabled
├── causal.json               # when causal mode is analyze/active
├── differential.json         # when a baseline is supplied
├── artifact-proof.json
├── provenance.intoto.json
├── provenance.dsse.json      # optional
└── provenance.sigstore.json  # optional
```

`causal.json` and `experiments.json` are artifact-proof/provenance subjects when present.

## Differential gates

Legacy gates remain unchanged:

```text
--fail-on cautious|reckless|dangerous              exit 2
--fail-on-new cautious|reckless|dangerous          exit 3
--fail-on-reasoning info|low|medium|high|critical  exit 4
--fail-on-new-reasoning ...                        exit 5
```

0.7 adds:

```text
--fail-on-causal info|low|medium|high|critical      exit 6
--fail-on-new-causal info|low|medium|high|critical  exit 7
```

Causal differential compares exact active chains and threat-level epistemic transitions, so a `PARTIAL → PROVEN` regression is detected even when the detailed chain identity changes after a missing stage becomes observed.

## GitHub Action

```yaml
- uses: Nolane-x/repotrial@v1
  with:
    path: .
    baseline-ref: origin/main
    runtime-mode: off
    experiment-mode: off
    causal-mode: analyze
    fail-on-new: reckless
    fail-on-new-reasoning: critical
    fail-on-new-causal: critical
    supply-chain-mode: offline
```

The Action exposes causal chain counts, newly active causal chains, `causal.json`, reasoning metrics, experiment metrics, SARIF/SBOM/proof/signature artifacts, and the report receipt.

## Public API

```js
import {
  scanRepository,
  reasonAboutEvidence,
  getThreatRegistry,
  buildCausalSecurityGraph,
  synthesizeCausalAttackChains,
  analyzeCausalEvidence,
  planActiveExperiments,
  runCausalActiveExperiments
} from 'repotrial';
```

## Development gates

```bash
npm ci
npm test
npm run check
npm run test:coverage
npm run benchmark:adversarial
npm audit --omit=dev --audit-level=high
npm pack --dry-run
```

CI runs the maintained Node.js 22 and 24 lines, the repository-native causal benchmark, fixture scan, npm package check, and Docker build/version E2E.

## ForgeOS

RepoTrial works independently. When ForgeOS is connected, it can import a second evidence engine, runtime/kernel evidence, security receipts, and remediation RoutePlans.

```bash
repotrial forgeos-doctor --forgeos-root ../forge-os
repotrial scan . --forgeos cli --forgeos-root ../forge-os --forgeos-depth full
```

## License

MIT
