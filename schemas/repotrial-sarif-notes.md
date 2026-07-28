# RepoTrial SARIF notes

Every scan writes `repotrial.sarif` using SARIF 2.1.0. The artifact is intended for GitHub Code Scanning and other SARIF consumers.

## Mapping

- RepoTrial `critical` and `high` charges map to SARIF `error`.
- `medium` maps to `warning`.
- `low` and `info` map to `note`.
- Evidence paths are repository-relative and use `%SRCROOT%` as the URI base.
- Start/end lines come from RepoTrial evidence anchors.
- Stable evidence fingerprints and the RepoTrial receipt are included in result properties.

## Privacy and trust

RepoTrial removes absolute target paths by default and applies its common secret redactor before SARIF generation. Consumers should still treat SARIF as potentially sensitive because repository-relative filenames, rule titles, and bounded evidence snippets are intentionally present.

SARIF output is static-analysis evidence, not a security certification. GitHub may deduplicate or display results differently from RepoTrial's offline courtroom report.
