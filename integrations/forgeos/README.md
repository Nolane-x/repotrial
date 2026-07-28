# RepoTrial ↔ ForgeOS native sidecar

This sidecar exposes the stable `repotrial.forgeos.bridge.v1` boundary while invoking only public ForgeOS CLI commands.

```bash
export REPOTRIAL_BRIDGE_TOKEN="change-me-to-a-long-random-token"
export FORGEOS_ROOT="../forge-os"
node integrations/forgeos/bridge-server.mjs
```

Verify readiness when authentication is enabled:

```bash
curl -H "Authorization: Bearer $REPOTRIAL_BRIDGE_TOKEN" \
  http://127.0.0.1:8791/ready
```

Connect RepoTrial:

```bash
repotrial scan . \
  --forgeos http \
  --forgeos-depth full \
  --forgeos-url http://127.0.0.1:8791 \
  --forgeos-token "$REPOTRIAL_BRIDGE_TOKEN"
```

Use `FORGEOS_BIN=forge` instead of `FORGEOS_ROOT` for an installed CLI. The sidecar binds to loopback by default, bounds request size/duration and process resources, and requires HTTPS for non-loopback client connections unless the caller explicitly opts into insecure HTTP. See `docs/forgeos-bridge.md` for protocol and security details.
