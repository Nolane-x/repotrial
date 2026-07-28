# RepoTrial Native ForgeOS v0.6.1 Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. This plan records the completed red-green implementation path.

**Goal:** Connect RepoTrial to the real ForgeOS v0.6.1 public CLI while preserving a complete independent product path.

**Architecture:** RepoTrial generates a native bounded surface, invokes ForgeOS through a source-root or installed-CLI adapter, normalizes receipts/findings/routes, reconciles semantic locations to repository evidence, and renders the result through the existing portable report.

**Tech Stack:** Node.js ESM, built-in test runner, child process spawn without shell, HTTP sidecar, JSON Schemas.

## Completed tasks

- [x] Add failing tests for the native six-field ForgeOS surface.
- [x] Implement secret-redacted instruction, hook, MCP, package, command, and environment extraction.
- [x] Add failing tests for blocked exit code 2 and full enrichment.
- [x] Implement source-checkout invocation, runtime probe, security receipt import, and RoutePlan normalization.
- [x] Add failing tests for CLI root/depth options and `forgeos-doctor`.
- [x] Implement CLI and machine-readable summary additions.
- [x] Add failing tests for sidecar readiness and full scan forwarding.
- [x] Implement `/ready`, source-root support, and depth forwarding.
- [x] Add failing tests for repository anchor reconciliation.
- [x] Implement package, MCP, env, hook, and direct-path anchor resolution.
- [x] Add failing tests for quoted secret redaction.
- [x] Harden redaction and publish native/bridge schemas.
- [x] Add ForgeOS Powered report panel, GitHub Action inputs/outputs, documentation, and acceptance script.
- [x] Run final test, coverage, syntax, JSON, independent scans, package, archive, and real ForgeOS CLI/HTTP acceptance gates.
