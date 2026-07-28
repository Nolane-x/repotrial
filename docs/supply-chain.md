# Supply-chain analysis

## Offline inventory

RepoTrial recognizes package-lock/npm-shrinkwrap, pnpm, Yarn v1, requirements, Poetry, uv, Pipfile, Cargo, go.sum, Composer, Gemfile.lock, and Dockerfiles. Components are normalized to package URLs, deduplicated, linked to source lockfiles, and emitted as CycloneDX 1.6. The active RepoTrial output subtree and other generated-output exclusions are not inventoried, preventing self-generated SBOM/report files from contaminating later scans.

License coverage records observed identifiers and components lacking license metadata. This is inventory evidence, not legal advice or a complete license-policy engine.

## OSV

`--supply-chain osv` submits bounded `querybatch` requests over HTTPS. Loopback HTTP is allowed for tests and private local mirrors. Batch count, response bytes, and timeout are bounded. OSV findings are normalized by package URL and advisory ID. Numeric and vector CVSS v3 values are mapped into RepoTrial severities.

## Containers

Dockerfiles are inventoried even without an external scanner. An optional command can emit Trivy JSON, Grype JSON, or SARIF 2.1.0:

```bash
repotrial scan . \
  --container-scanner-command trivy \
  --container-scanner-args '["fs","--format","json","."]'
```

The command is invoked without a shell, with bounded time/output and a minimal environment. Exit codes 0 and 1 are treated as completed scans because common security tools use 1 to signal findings.

## Coverage boundaries

Generated dependencies not present in recognized lockfiles, packages downloaded only at runtime, private advisory databases, image layers not scanned by an external provider, and ambiguous ecosystem/version mappings can remain unknown. Diagnostics and truncation counts are persisted.
