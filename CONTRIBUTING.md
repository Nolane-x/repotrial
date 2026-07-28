# Contributing

RepoTrial accepts focused changes that improve evidence quality, reduce false positives, add bounded formats/providers, strengthen runtime isolation, improve ForgeOS interoperability, or make artifacts easier to verify.

## Development loop

```bash
npm ci
npm test
npm run check
npm run test:coverage
npm audit --omit=dev
npm pack --dry-run
node bin/repotrial.mjs scan tests/fixtures/cautious-agent --forgeos off --runtime off --supply-chain offline --output .repotrial-dev
```

ForgeOS integration:

```bash
npm run verify:forgeos -- --forge-root ../forge-os
```

## Test-first requirement

Every behavior change starts with a failing test that demonstrates the security, correctness, or compatibility property. A provider must include successful, failure, timeout, malformed-input, resource-bound, redaction, and nearby-safe cases.

## Rule requirements

A rule must have a narrow observable condition, reckless fixture, nearby safe fixture, deterministic severity/status, direct anchors when available, concrete remediation, and documented blind spots. LLM-only judgments cannot silently override deterministic evidence.

## Runtime provider requirements

Never execute in the source directory. Never fall back to unsandboxed execution. Keep all process calls shell-free, bound time/output/resources, forward only explicit environment variables, and prove source immutability plus escape resistance in tests.

## Schema and release discipline

Update contract schemas and changelog for persisted shape changes. Run the Node 22/24 CI matrix, Docker build/run job, ForgeOS compatibility gate, clean npm installation, self-scan, and signature verification before release.
