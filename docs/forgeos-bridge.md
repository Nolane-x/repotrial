# ForgeOS bridge

RepoTrial remains fully functional without ForgeOS. The bridge is additive: it imports native ForgeOS security evidence and, in full mode, runtime inventory plus an evidence-obligation-aware remediation RoutePlan.

## Compatibility target

RepoTrial v0.4 is acceptance-tested against ForgeOS v0.6.1. The current CI baseline is ForgeOS [`cebf9dc671bc838465dcb4651eaed04d57a17f7d`](https://github.com/casioreview20-glitch/forge-os/commit/cebf9dc671bc838465dcb4651eaed04d57a17f7d), so a later upstream change requires an explicit compatibility update rather than silently changing this contract. It calls public CLI surfaces only and does not import ForgeOS internal modules.

ForgeOS's authenticated Streamable HTTP MCP transport, quarantined skill intake, Universal Lanes, and optional remote microVM boundary are outside this bridge's authority. The sidecar protects its own loopback HTTP API with its bearer token; it is not an MCP proxy and does not turn a lane selection or sandbox configuration into an execution receipt.

The generated `forgeos-agent-surface.json` is the native v0.6 input shape:

```json
{
  "instructions": [],
  "hooks": [],
  "mcpServers": [],
  "packages": [],
  "allowedCommands": [],
  "envReferences": []
}
```

JSON/JSONC, YAML, and TOML configuration are structurally parsed with bounded depth, node, alias, duplicate-key, and scalar limits. Relevant agent configurations are converted into bounded synthetic MCP/permission surfaces so ForgeOS can see wildcard, shell, filesystem, and network capability indicators. RepoTrial never executes them.

## Direct source-checkout mode

```bash
repotrial forgeos-doctor --forgeos-root ../forge-os
repotrial scan . --forgeos cli --forgeos-root ../forge-os --forgeos-depth full
```

RepoTrial launches Node against `<forge-root>/src/cli/forge.mjs`. This avoids requiring a global install during local development.

## Installed CLI mode

```bash
repotrial forgeos-doctor --forgeos-bin forge
repotrial scan . --forgeos cli --forgeos-bin forge --forgeos-depth full
```

Environment equivalents:

```text
FORGEOS_ROOT
FORGEOS_BIN
```

## Depths

### `security`

Runs:

```text
forge security scan --file <temporary-surface.json> --json
```

ForgeOS exit code `0` and exit code `2` are both valid scan executions. Exit code `2` means the report status is `blocked`; RepoTrial parses and imports the findings.

### `full`

Runs the security command plus:

```text
forge v06 status --json
forge route --query <bounded finding summary> --assurance A1 --operation code-review --task-class security --json
```

The bridge stores a bounded normalized subset:

- ForgeOS version and kernel inventory;
- adversarial-corpus counts and receipt;
- security status, summary, and report receipt;
- remediation steps, providers, outcomes, execution groups, blockers, and evidence obligations.

Arbitrarily deep or oversized enrichment structures are truncated before they reach report serialization.

## Sidecar mode

```bash
export REPOTRIAL_BRIDGE_TOKEN="replace-with-a-long-random-token"
export FORGEOS_ROOT="../forge-os"
node integrations/forgeos/bridge-server.mjs
```

Then:

```bash
repotrial scan . \
  --forgeos http \
  --forgeos-depth full \
  --forgeos-url http://127.0.0.1:8791 \
  --forgeos-token "$REPOTRIAL_BRIDGE_TOKEN"
```

Endpoints:

- `GET /health` — process liveness, no ForgeOS probe;
- `GET /ready` — executes bounded `forge v06 status`; bearer-protected when a token is configured;
- `POST /v1/scan` — accepts `repotrial.forgeos.bridge.v1` with `manifest` and `depth`.

The server binds to loopback by default, limits request bodies to 1 MiB, bounds body duration, process output and process time, and can require a bearer token. The client rejects non-loopback plaintext HTTP unless `--allow-insecure-forgeos-http` is explicitly set. Do not expose the sidecar publicly without TLS, authentication, rate limits, and network policy.

## Protocol validation

The HTTP client validates:

- exact `schemaVersion`;
- known bridge `status` and `mode` values;
- findings array and error type;
- object shape of diagnostics, security, engine, and RoutePlan enrichments;
- a valid ForgeOS security status before importing it.

Finding discovery and enrichment cloning are bounded and avoid recursive traversal over untrusted data.

## Secret handling

The temporary native surface is written with mode `0600` and deleted after the CLI call. Secret names and environment references may be preserved for analysis, but common secret literal forms are redacted. Imported ForgeOS titles, rationales, remediation text, locations, summaries, and RoutePlan data pass through the same bounded/redacted report path.

## Failure semantics

`disabled`, `unavailable`, `timeout`, and `error` are bridge states, not local scan failures. RepoTrial's deterministic scan and artifacts still complete. The report never turns an unavailable ForgeOS integration into a false clean result.

## Acceptance verification

```bash
npm run verify:forgeos -- --forge-root ../forge-os
```

The acceptance script checks a real source checkout for:

- runtime readiness and version;
- a valid blocked scan with a SHA-256 receipt;
- imported `pipe-to-shell` evidence;
- a non-empty remediation RoutePlan;
- a final RepoTrial report receipt.

## v0.4 evidence pipeline

ForgeOS findings are merged with local static, runtime, supply-chain, and differential evidence before deterministic verdict calculation. ForgeOS does not replace RepoTrial's independent engine and cannot silently certify a repository. The resulting report, ForgeOS native surface, and re-anchored findings are included in the artifact proof and provenance subjects.
