# RepoTrial Native ForgeOS v0.6.1 Bridge Design

## Goal

Keep RepoTrial independently useful while making ForgeOS integration a measurable product upgrade rather than a branding-only dependency.

## Required behavior

- Emit the exact semantic surface consumed by ForgeOS v0.6: instructions, hooks, MCP servers, packages, allowed commands, and environment references.
- Never include discovered secret values in the surface.
- Treat ForgeOS security exit code 2 as a successful blocked report.
- Support both an installed `forge` command and a sibling ForgeOS source checkout.
- Offer security-only and full-powered depths.
- Full depth must import runtime inventory, adversarial-corpus evidence, security receipt, and a remediation RoutePlan.
- Re-anchor semantic ForgeOS locations to files and lines when evidence exists.
- Keep ForgeOS outages fail-open for the independent RepoTrial scan while representing the outage explicitly.
- Provide a loopback sidecar with separate liveness and readiness endpoints.
- Include a real compatibility acceptance command for a ForgeOS source checkout.

## Public surfaces

```text
repotrial forgeos-doctor --forgeos-root <path>
repotrial scan . --forgeos cli --forgeos-root <path> --forgeos-depth full
GET /health
GET /ready
POST /v1/scan
npm run verify:forgeos -- --forge-root <path>
```

## Security constraints

- No shell invocation.
- Temporary surface files use mode 0600 and are deleted.
- Process time and output are bounded.
- Sidecar bodies are bounded and bearer-token protected when configured.
- Repository text is escaped in HTML and redacted before crossing the bridge.
- An unavailable enrichment command cannot erase the native security result.

## Acceptance criteria

- RepoTrial independent tests remain green.
- A native surface produced from the reckless fixture triggers real ForgeOS findings.
- Real ForgeOS v0.6.1 returns a security SHA-256 receipt and a non-empty RoutePlan.
- ForgeOS package/MCP/env locations are anchored to inspected files when resolvable.
- The report displays ForgeOS version, scan status, receipt prefix, corpus counts, and primary technique.
