# RepoTrial Production v1 Design

## Product goal

RepoTrial is an independent, zero-runtime-dependency Node.js product that scans AI-agent repositories, produces evidence-anchored charges and a deterministic verdict, renders a portable single-file HTML trial report, and optionally imports additional findings through a versioned ForgeOS bridge.

## Product boundaries

- RepoTrial must produce useful results without ForgeOS, a network connection, an API key, or an LLM.
- ForgeOS integration is additive and failure-tolerant; a bridge outage never prevents the local verdict.
- Findings describe observable risk signals, not proof that a repository is exploitable or safe.
- The scanner never executes target repository code.
- Local command execution uses `spawn` with `shell: false` and bounded output.

## Architecture

1. **Discovery and evidence core** walks a bounded repository scope, skips binaries and ignored directories, hashes every inspected file, and records omissions.
2. **Deterministic rule engine** evaluates ten agent-surface risk families and emits proven, mitigated, or unproven charges with line anchors and remediation.
3. **Verdict engine** computes one of TRUSTED, CAUTIOUS, RECKLESS, DANGEROUS, or UNPROVEN from explicit severity weights and coverage.
4. **Artifact renderer** writes `verdict.json`, `evidence.json`, `report.html`, `repotrial-badge.svg`, and `forgeos-agent-surface.json` atomically.
5. **ForgeOS client** supports off, auto, CLI, and HTTP-sidecar modes. The sidecar protocol is `repotrial.forgeos.bridge.v1` and isolates RepoTrial from ForgeOS internal API changes.
6. **Delivery surfaces** include an npm CLI, static report server, Docker image, composite GitHub Action, CI, and documented ForgeOS sidecar.

## Initial rule families

- Dangerous package lifecycle scripts
- Pipe-to-shell commands
- Unrestricted shell capability
- Broad MCP permissions
- Secret-to-egress reachability
- Prompt-boundary override instructions
- Self-certified completion or explicit test skipping
- Missing verification evidence
- Destructive capability without approval language
- Incomplete scan coverage

## Data contract

The primary report schema is `repotrial.report.v1`. Evidence anchors include relative path, line range, snippet, file SHA-256, and a stable evidence fingerprint. Bridge requests use `repotrial.forgeos.bridge.v1` and contain only the generated agent-surface manifest, never raw secret values.

## Security and privacy

- Symlinks are not followed.
- File count, file size, total bytes, HTTP body, process output, and process duration are bounded.
- HTML output escapes all repository-controlled strings.
- Static serving rejects traversal and only serves files beneath the report directory.
- The sidecar binds to loopback by default and can require a bearer token.

## Acceptance criteria

- A reckless fixture produces at least one high-severity proven charge and a RECKLESS or DANGEROUS verdict.
- A cautious fixture produces no high/critical proven charges.
- Every evidence anchor matches a file hash and valid line range.
- Report artifacts are deterministic apart from scan time and scan identifier.
- ForgeOS unavailable state is represented explicitly without failing the local scan.
- CLI exits nonzero only for invalid invocation, scan failure, or a configured verdict threshold.
- Tests, syntax checks, self-scan, package dry-run, and Dockerfile static validation pass.
