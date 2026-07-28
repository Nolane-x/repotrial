# Differential analysis

RepoTrial compares proven findings by a stable identity derived from rule ID and evidence fingerprints. If direct fingerprints are unavailable, it uses bounded relative locations and rationale.

## Baseline report

```bash
repotrial scan . --baseline-report previous/verdict.json
```

## Git baseline

```bash
repotrial scan . --baseline-ref origin/main
```

The Git path verifies the ref, creates a detached temporary worktree, scans it with the same ForgeOS, runtime, and supply-chain settings as the current scan, compares the reports, removes the worktree, and leaves the current working tree untouched. Provider outages or sandbox unavailability are recorded independently for each side; they are never converted into resolved findings.

## Output

`differential.json` contains `new`, `existing`, `resolved`, counts, baseline/current receipts, and its own SHA-256 receipt. SARIF sets `baselineState` to `new` or `unchanged`.

## CI gate

`--fail-on-new cautious|reckless|dangerous` recomputes a verdict using only new findings and exits `3` when the threshold is met. Overall repository gating remains independent through `--fail-on` and exit `2`.


## Stable identity

Direct findings use a stable fingerprint derived from the rule, source surface, and normalized evidence rather than volatile file hashes or line numbers. Moving an unchanged finding therefore remains `existing`; changing its security meaning creates a new identity. Artifact fingerprints still include file digests for tamper evidence.
