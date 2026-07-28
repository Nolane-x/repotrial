# Security policy

## Supported versions

The latest minor release receives security fixes. RepoTrial v0.4 supports maintained Node.js 22 (22.14+) and 24 lines.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that can expose secrets, escape runtime isolation, execute in the source repository, traverse report roots, forge evidence/provenance, poison differential identity, or impersonate ForgeOS. Use GitHub Security Advisories and include the affected version, platform, reproduction, expected behavior, and the smallest safe proof of concept.

## Threat model

Repository files, scripts, parser inputs, lockfiles, child-process output, OSV/container responses, ForgeOS bridge payloads, Git history, and report URLs are untrusted.

Defense layers include:

- bounded file, byte, match, node, depth, alias, process, output, request, and response limits;
- full bounded JSON/YAML/TOML parsing without evaluation or template execution;
- symlink skipping during discovery and lexical plus real-path containment in the report server;
- output-subtree exclusion, explicit operator path exclusion propagated to every provider, and rejection of output-at-source-root;
- shared redaction for local findings, runtime output, external scanners, ForgeOS, HTML, JSON, SARIF, SBOM metadata, and provenance parameters;
- no-shell child process invocation and allowlisted environment forwarding;
- HTTPS requirements for remote OSV and ForgeOS HTTP providers;
- exact ForgeOS bridge protocol/status/mode/enrichment validation;
- script-free offline HTML and portable relative paths by default;
- SHA-256 artifact manifests, deterministic verdict invariants, DSSE signatures, and optional Sigstore bundles.

## Runtime sandbox

Runtime detonation is opt-in. RepoTrial never executes in the source directory. It creates a disposable copy and, on supported Linux hosts, uses user, mount, UTS, IPC, network, PID, and cgroup namespaces; private mount propagation; chroot; no inherited secret environment; limited PATH; trapped network tools; Node instrumentation; resource limits; process-group termination; and filesystem diffing.

The sandbox is intended to collect bounded behavior evidence from package scripts, not to be a universal malware-analysis hypervisor. Native-kernel vulnerabilities, hostile privileged runtimes, unsupported interpreters, device access granted by the host, and container configurations that disable user namespaces remain outside its guarantee. If the required isolation probe fails, runtime analysis returns `unavailable`; RepoTrial does not fall back to unsandboxed execution.

## Supply-chain providers

Offline inventory and SBOM generation are deterministic over recognized lockfiles. OSV and container findings inherit provider freshness, ecosystem mapping, and scanner coverage. External container commands execute only when explicitly configured and receive a bounded environment with no shell. Their JSON/SARIF is treated as hostile and normalized.

## Redaction limits

Redaction recognizes common credential prefixes, authorization headers, private keys, JWTs, URL credentials, sensitive assignments, and contextual encoded values. It is defense in depth, not a complete DLP system. Split, encrypted, steganographic, novel-provider, or deliberately obfuscated secrets may evade recognition. Treat reports as security artifacts and apply CI retention/access controls.

## Integrity semantics

Artifact proof verifies generated-file digests, the report receipt, portable evidence paths, deterministic verdict recomputation, and complete coverage for `TRUSTED`. DSSE and Sigstore prove that a holder of the configured key/identity signed the provenance statement. They do not prove the runner itself was uncompromised unless the surrounding CI identity and policy are trusted.

## Verdict semantics

`TRUSTED` means only that no known signal was proven in completely inspected scope and that machine-checkable report invariants passed. It is not permission to execute unknown software and is not a certification of absence of vulnerabilities.
