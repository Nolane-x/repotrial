# Artifact integrity and attestations

## Artifact proof

`artifact-proof.json` records every primary generated artifact name, size, SHA-256, report receipt, machine-checkable invariant list/results, and a proof receipt. `repotrial verify` re-reads every file and recomputes the report verdict and coverage constraints.

## Local DSSE

```bash
repotrial keygen --output keys
repotrial scan . --signing-key keys/repotrial-private.pem
repotrial verify .repotrial --public-key keys/repotrial-public.pem
```

Private keys are PEM Ed25519 keys written with restricted permissions. Optional passphrases are read from an environment variable name, not a command-line secret. The signed payload is an in-toto Statement encoded in a DSSE envelope.

## SLSA provenance

`provenance.intoto.json` uses in-toto Statement v1 and the SLSA provenance v1 predicate. Subjects are the primary artifact hashes. External parameters include repository/revision/report receipt; internal parameters include proof receipt; run details include builder and invocation identity.

## Sigstore/Cosign

```bash
repotrial scan . --cosign
repotrial verify .repotrial --cosign \
  --certificate-identity '<identity>' \
  --certificate-oidc-issuer '<issuer>'
```

Use `--cosign-key` for key-based signing/verification. RepoTrial invokes `cosign sign-blob` and `verify-blob` without a shell, creates a bundle, limits time/output, redacts failures, and forwards only allowlisted Sigstore/OIDC environment variables. GitHub keyless signing requires `id-token: write`.

A valid signature proves control of the configured key or OIDC identity over the provenance statement. Trust still depends on key custody, identity policy, CI runner integrity, and source revision policy.
