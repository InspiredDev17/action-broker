# Sandbox and Execution Controls

## Scope

Action Broker combines capability restriction, input validation, least
privilege, and operating-system controls. “Sandbox” in this document describes
those layered controls; it is not a claim of perfect isolation or a portable
kernel security boundary.

The broker itself must run as a dedicated unprivileged account. It should have
no ambient access beyond its configuration, socket, replay ledger, audit log,
Agent Green spool, and configured filesystem roots. It must not run as root
merely to make a capability work.

## Layered model

```text
typed request and bounds
  -> identity / permission / approval / risk policy
  -> capability-specific scope validation
  -> minimal executor and cleared environment
  -> timeout / output / resource enforcement
  -> OS and deployment isolation
  -> audit and mandatory security-event reporting
```

Failure of a required layer is a denial. No executor may retry through a broader
capability when its preferred isolation mechanism is missing.

## Filesystem confinement

### Explicit roots

Administrators configure stable root IDs. At startup the broker opens those
directories using capability-oriented filesystem APIs; requests carry a root ID
and relative path, not an ambient host path. This design narrows path authority
and makes configuration changes auditable.

Validation rejects:

- absolute paths, empty paths where disallowed, `..`, NUL, and platform prefix
  or separator ambiguities;
- paths into `/proc`, `/sys`, device files, and similar pseudo-filesystems unless
  an explicit, separately reviewed root intentionally exposes a safe subset;
- roots or descendants designated as secrets, including SSH material,
  credential stores, keychains, cloud credentials, and broker keys;
- symlinks or other link-like entries when their resolution cannot be proven to
  remain inside the configured root;
- non-regular file types for operations that require regular files; and
- race-prone operations when the backend cannot safely bind validation to the
  opened object.

Each path component and final object must be checked using handle-relative
operations. Lexical prefix checks such as “starts with `/allowed`” are
insufficient. Move source and destination, temporary files, backup locations,
and replacement targets all remain under configured roots.

Capability filesystem APIs reduce ambient path authority but do not by
themselves prove race-free behavior on every OS and filesystem. The executor
fails closed when it cannot obtain the needed handle-relative semantics or
validate an object type. Network filesystems and unusual mount behavior require
deployment-specific testing.

### Mutation and recovery

Where supported, writes are staged in the destination directory, flushed as
required by policy, and atomically renamed. The executor records pre- and
post-change digests and backup metadata when measurable. It does not call a
cross-device copy/delete sequence an atomic move, and it does not call a delete
reversible without a configured, verified recovery mechanism.

## Process execution

`ExecuteApprovedCommand` launches an executable directly. Its input is:

```text
configured program ID
+ validated argv array
+ configured root ID and relative working directory
+ explicit allowed environment entries
```

The program registry resolves the executable independently of requester input.
Arguments are validated as data against program-specific constraints. There is
no implicit shell, glob expansion, command substitution, redirection, or
pipeline parsing.

Before launch the Linux executor:

1. requires canonical, root-owned/non-broker-owned executable paths, immutable
   parent directories, regular single-link files without setuid/setgid bits,
   and exact configured SHA-256 digests;
2. verifies the working directory through its configured root capability;
3. clears the inherited environment;
4. constructs a minimal environment only from broker-owned defaults and
   descriptor-allowed request keys;
5. rejects `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, arbitrary `PATH`, and
   equivalent loader/runtime injection controls;
6. configures available resource limits and process-group handling;
7. connects bounded stdout/stderr collectors; and
8. starts deadline and cancellation supervision before accepting output.

Secrets held by the broker must not be placed in child arguments, environment,
stdin, or inherited descriptors. All nonessential file descriptors are closed
or marked close-on-exec.

### Resource controls

Descriptor policy sets hard ceilings for wall time, CPU time, address space,
file size, open files, child processes where the OS mechanism is available,
stdout, stderr, and total captured output. Requests can reduce but never raise
these ceilings. File and HTTP reads return an explicitly marked bounded prefix
where supported. Approved-command stdout or stderr beyond its configured limit
terminates the process and returns a resource-limit failure; no misleading
partial success is reported.

A deadline expires even when no output is produced. Cancellation targets the
request's process group or isolated worker where supported, waits a bounded
grace period, and escalates termination. The broker records `timed_out` or
`cancelled` only after recording any measurable side effects.

Portable `setrlimit`-style controls do not reliably contain every fork bomb,
descendant that escapes a process group, shared-kernel resource, or already
running helper. Strong process-count and aggregate memory/CPU containment on
Linux normally requires cgroups and possibly PID namespaces. If those controls
are required by policy but unavailable, command execution must remain disabled.

## Network confinement

The HTTP executor does not rely on URL parsing or DNS filtering alone. For the
original request and every redirect it:

1. parses and normalizes the URL;
2. allows only configured schemes and explicit/default ports;
3. rejects userinfo and ambiguous host encodings;
4. checks host policy before DNS;
5. resolves all addresses with bounded time and result count;
6. rejects any disallowed address, including loopback, unspecified, link-local,
   private, multicast, and configured metadata ranges unless an exact policy
   explicitly permits the destination;
7. pins the connection to an approved resolved address while preserving the
   verified hostname for TLS SNI and certificate validation;
8. disables automatic redirects and re-runs the complete policy for each
   redirect; and
9. records the complete effective destination trace on success and the original
   attempted destination on a failed request.

The policy specifically denies common cloud metadata endpoints and their
alternate address representations. IPv4-in-IPv6, integer/hex/octal forms,
trailing-dot and Unicode hostname issues, DNS search domains, and zone
identifiers are normalized or rejected before comparison.

Proxy environment variables are not inherited. A proxy, if ever supported,
must be an explicit policy object because it changes the effective destination
and DNS trust boundary.

DNS pinning prevents an approved hostname from being transparently re-resolved
to a forbidden address for the actual connection. It does not make DNS
trustworthy, prevent a permitted public service from proxying a request, or
replace TLS authentication. Egress firewall rules remain a valuable independent
layer.

The blocking system resolver is isolated behind a bounded broker wait, but the
OS resolver call itself cannot be force-cancelled by portable Rust once issued;
an underlying resolver that never returns can leave its resolver thread until
the OS call completes. Connection/action admission bounds the rate, and
production deployments should also bound resolver behavior at the OS/service
boundary. A future native asynchronous resolver may remove this limitation.

## Read-only Git confinement

`GitRead` is not implemented through `ExecuteApprovedCommand`. The broker opens
only the exact root-relative worktree through libgit2 with repository discovery,
remote transports, global/system configuration, linked worktrees, bare
repositories, submodules, hooks, and credential helpers excluded. Before open,
it walks at most 100,000 `.git` entries and rejects metadata not owned by root
or the broker UID, group/other-writable objects, symlinks, hard links, special
files, cross-filesystem metadata, alternates, external configuration includes,
and path-bearing or executable configuration. Output is limited to 512 KiB.

Generic filesystem capabilities deny `.git` paths. The read backend holds the
selected root's mutation lock from path resolution through output generation,
preventing another broker filesystem action from swapping validated metadata.

Cancellation and the ten-second deadline are checked before repository access,
during metadata validation, and during output-producing iterations. Some
individual synchronous libgit2 calls, notably repository open and initial
status calculation, do not provide a preemption callback; a hostile or damaged
repository could therefore occupy its current worker after the broker deadline
until that call returns. Keep repository metadata broker-controlled, bound
repository size, monitor saturation, and use a separately contained worker if
strict preemption is required by the deployment threat model.

## Operating-system support

### Linux

The current approved-command backend invokes digest-pinned `prlimit`, which
sets CPU, address-space, file-size, open-file, process, and core limits, then a
digest-pinned `bubblewrap`. `bubblewrap` creates new user, mount, network, PID,
IPC, UTS, and cgroup namespaces, clears the environment, exposes read-only
system runtime trees, and binds only the validated working directory at
`/work`. The broker supervises a process group, wall deadline, cancellation,
and bounded output. If either configured executable is absent, mutable, or has
the wrong digest, command execution fails closed.

Deployments whose threat model requires syscall filtering, aggregate cgroup v2
accounting, Landlock, or a narrower runtime filesystem must add and qualify
those controls before enabling affected program profiles.

Those stronger mechanisms are not assumed merely because the host is Linux.
Kernel version, distribution policy, container nesting, filesystem type, and
service-manager configuration affect availability. The daemon must report the
controls it actually enabled, and a configured mandatory control must gate
readiness.

### macOS

The core schemas and source-level filesystem tests compile on macOS, but the
current daemon does not serve requests there because it lacks an implemented
safe peer-credential binding, and `ExecuteApprovedCommand` returns
`sandbox_unavailable`. The deprecated `sandbox-exec` interface is represented
only so old configuration is rejected explicitly; it is not an enabled
fallback. A future macOS worker/VM boundary needs its own review and tests.

### Shared limitations

On either OS, a process can interact with resources exposed inside its OS
boundary. Command allowlisting is useful but does not make a complex
interpreter, compiler, browser, package manager, or plugin host safe for
attacker-controlled arguments. Such programs require a dedicated capability and
sandbox review or must remain forbidden.

The foundation is not a defense against a compromised kernel, root
administrator, malicious broker binary, or supply-chain compromise of an
approved executable. These remain deployment and host-integrity concerns.

## Sandbox failure behavior

Before dispatch, each executor calculates the controls required by its
descriptor and deployment profile. Missing, failed, or unverifiable mandatory
controls cause a denial before side effects. A failure after launch triggers
bounded termination, a finalized audit record, and an Agent Green
`sandbox_failure` event.

An unexpected broker effective UID triggers denial and an
`unexpected_privilege_elevation` event. The current foundation does not inspect
Linux capability sets, supplementary groups, macOS entitlements, or post-exec
child privilege state; program validation rejects setuid/setgid executables and
the broker is never root. Deployments needing those additional checks must keep
approved commands disabled until they are implemented and qualified.

## Verification expectations

Unit and integration tests cover path traversal, symlink escape, shell and
argument injection, environment injection, timeout, output flooding,
fork/resource abuse where the platform supports containment, unauthorized
network access, DNS rebinding defenses, metadata endpoints, secret files,
privilege escalation attempts, concurrency, and cancellation.

Platform tests must state what they actually exercised. A skipped namespace or
cgroup test is evidence of an unverified guarantee, not a passing sandbox test.
