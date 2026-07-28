# Runtime sandbox

RepoTrial runtime analysis is opt-in and Linux-only. It detonates selected package scripts to collect behavior evidence without using the source directory as an execution root.

## Candidate selection

Without `--runtime-script`, RepoTrial selects `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, and `prepublishOnly` from nested `package.json` files. It also discovers commands in recognized Claude, Cursor, Cline, Windsurf, and Continue hook configurations. `--runtime-script a,b` restricts package-script selection to explicit names. The default maximum is four runs and the hard maximum is sixteen.

## Isolation sequence

1. Preflight the source tree and refuse detonation if it exceeds the configured source-copy budget. The defaults are 20,000 files and 256 MiB; override them with `--runtime-max-source-files` and `--runtime-max-source-bytes`.
2. Copy the repository to a temporary rootfs, excluding `.git`, `node_modules`, the active output subtree, and ignored generated paths.
3. Copy only required shell, Node, environment, chroot, and shared-library files.
4. Start `unshare` with new user, mount, UTS, IPC, network, PID, and cgroup namespaces; root mapping; private mount propagation; child-kill semantics; and no host network namespace.
5. Enter chroot and a minimal environment containing only PATH, HOME, TMPDIR, LANG, Node instrumentation, and the event-file path.
6. Execute with shell CPU/file/process limits, wall-clock timeout, output byte cap, network-command traps, and a process-group kill path.
7. Hash the workspace before and after, parse bounded events, redact output, and delete the complete temporary rootfs.

## Evidence

`runtime.json` records candidate, status, exit/signal, duration, timeout, bounded stdout/stderr, network/DNS/tool/child-process events, output truncation, and created/modified/deleted files.

## Failure behavior

RepoTrial probes the full isolation mechanism before execution. If the platform, user namespaces, `unshare`, chroot, required binaries, or source-copy budget are unavailable, runtime status is `unavailable` with a machine-readable reason such as `source-copy-limit`. There is no unsandboxed fallback.

## Container note

Container runtimes can block nested user namespaces through seccomp or host policy. Static and supply-chain analysis still operate. Runtime detonation should normally run on a dedicated Linux CI worker whose user-namespace policy is known.
