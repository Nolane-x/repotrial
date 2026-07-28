# RepoTrial v0.3.0 Hardening and Adoption Design

## Goal

Make RepoTrial safer to publish, harder to bypass, more accurate across current AI coding-agent instruction surfaces, and easier to adopt in GitHub security workflows while preserving the zero-runtime-dependency independent mode and native ForgeOS v0.6 bridge.

## Confirmed defects

- The report server follows symlinks and can serve a file outside the report directory.
- A trivial package script such as `test: "true"` is accepted as verification evidence.
- Repository instructions used by GitHub Copilot, Cursor, Cline, Windsurf, and Continue are not consistently evaluated by the local rule engine.
- A direct `shell: true` capability is not charged unless a wildcard permission is also present.
- A custom output directory inside the target repository is included in subsequent scans.
- Reports expose the absolute local scan path by default.
- HTTP bridge responses are accepted without strict protocol validation, and non-loopback plaintext HTTP is allowed without an explicit opt-in.
- ForgeOS readiness data is unauthenticated even when the sidecar token is configured.

## v0.3.0 behavior

### Filesystem and privacy

- Resolve and contain report-server paths after symlink resolution.
- Reject a scan output directory equal to the repository root.
- Exclude the exact output subtree from discovery when it is inside the repository.
- Record unreadable, changed-during-scan, and invalid-UTF-8 files as omissions instead of crashing the entire scan.
- Do not expose an absolute target path in portable artifacts unless explicitly requested.

### Agent-surface coverage

Recognize repository instruction surfaces used by:

- AGENTS.md, CLAUDE.md, GEMINI.md, and nested variants.
- GitHub Copilot repository and path-specific instruction files.
- Cursor project rules and legacy `.cursorrules`.
- Cline workspace rules and legacy compatible rule files.
- Windsurf workspace rules and legacy `.windsurfrules`.
- Continue workspace rules.

The same predicate must be used by local rules and the ForgeOS manifest builder.

### Rule accuracy

- Reject no-op verification scripts including `true`, `:`, echo-only commands, and unconditional successful exits.
- Search nested package manifests for credible verification commands.
- Detect unrestricted shell capability independently of wildcard permission.
- Detect common wildcard forms such as `*`, `filesystem:**`, `network:**`, `Bash(*)`, and `Shell(*)` across JSON, YAML, TOML, and instruction text.
- Bound evidence count per rule/file and calculate line numbers without repeated full-prefix scans.

### Bridge and sidecar hardening

- Require HTTPS for non-loopback bridge URLs unless an explicit insecure-remote option is enabled.
- Validate bridge schema version, status, mode, findings, and enrichment objects before import.
- Use iterative traversal for nested bridge payload normalization.
- Require bearer authentication for `/ready` when a token is configured.
- Bound request-body duration as well as size and return a reliable 413/408 response without resetting the socket.

### GitHub adoption

- Generate `repotrial.sarif` on every scan with evidence-anchored results.
- Expose the SARIF path from the CLI and GitHub Action.
- Keep SARIF free of absolute local paths and raw secret values.

## Compatibility

- Node.js remains >=20.12.
- Runtime npm dependency count remains zero.
- Existing report and ForgeOS bridge schemas remain readable; v0.3 adds fields/artifacts without invalidating v0.2 consumers.
- ForgeOS v0.6.1 acceptance remains a required release gate.

## Acceptance criteria

- Every confirmed defect has a regression test that fails on v0.2 and passes on v0.3.
- Current official instruction locations for Copilot, Cursor, Cline, Windsurf, Continue, Claude, Gemini, and AGENTS are represented by fixtures/tests.
- Independent cautious and reckless fixtures preserve expected verdicts.
- Real ForgeOS v0.6.1 CLI and HTTP sidecar acceptance pass.
- Full tests, syntax, coverage, package install, SARIF parse, self-scan, archive CRC, and Docker static checks pass.
