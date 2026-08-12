# Capability Model

## Principles

Action Broker grants narrow capabilities, not ambient authority. A capability
name selects one input schema, one output schema, one permission, and one
executor. It cannot be converted into another capability by changing arguments.

The protocol uses a tagged action-input union (`CapabilityAction` in the Rust
API) with these variants:

```text
ReadFile                 WriteFile              CreateFile
MoveFile                 DeleteFile             ListDirectory
ExecuteApprovedCommand   GitRead                GitWrite
HttpRequest              BrowserAction          ProcessInspect
ServiceInspect           ServiceControl         ContainerAction
NodeAction
```

Unknown variants, unknown fields where the schema forbids them, malformed
values, unavailable backends, and policy/configuration mismatches are rejected.
There is no `Shell`, `Eval`, `RunAnything`, or hidden administrative variant.

## Capability descriptor

Every variant resolves to broker-owned metadata containing:

| Field | Meaning |
| --- | --- |
| Input schema | Exact accepted request shape, types, bounds, and normalization |
| Output schema | Exact result shape and truncation/digest behavior |
| Permission required | Stable permission identifier evaluated for the requester and agent |
| Approval policy | Whether an approval is required and the minimum acceptable approval type |
| Filesystem scope | Allowed root IDs and operation-specific relative path rules |
| Network scope | Allowed schemes, hosts, IP ranges, ports, and redirect policy |
| Timeout | Broker-owned default and maximum; a request can only reduce it |
| Resource limits | CPU/memory/process/file/output ceilings available to the executor |
| Audit behavior | Required fields, digests, and measurable side effects |
| Reversibility | A concrete declaration such as `NotReversible`, `AtomicReplacementWithPrechangeDigest`, `BackupMetadataAndAtomicRename`, `GitHistory`, or `RuntimeDependent` |
| Risk class | Deterministic minimum risk class, strengthen-only by target policy |

Descriptors are immutable for a single daemon configuration generation. A
client does not submit or override descriptor values.

## Risk classes and approval baseline

| Risk class | Meaning | Baseline approval behavior |
| --- | --- | --- |
| `READ_ONLY` | No intended mutation or external side effect | Permission is always required; approval may be pre-authorized by narrow policy |
| `LOW_RISK_WRITE` | Bounded local write with limited consequence | Short-lived approval or an explicit standing grant scoped to the exact root/operation |
| `REVERSIBLE_CHANGE` | Mutation with a tested, recorded recovery path | Short-lived approval; record pre-change evidence and rollback metadata |
| `PRIVILEGED_CHANGE` | Changes service/system state or crosses an elevated trust boundary | Strong interactive approval and a backend that can prove required isolation |
| `DESTRUCTIVE` | Deletion or mutation without a guaranteed rollback | Strong interactive approval; no claim of reversibility |
| `EXTERNAL_SIDE_EFFECT` | Network or remote effect outside the local recovery boundary | Short-lived approval bound to exact destination and payload digest; stronger rules by destination |

These are minimums. Policy may require stronger approval based on a protected
root, executable, destination, service, container, node, or argument pattern.
Policy cannot downgrade a capability below its declared minimum. Deny rules win
over allow rules. The broker never infers approval from natural-language text.

## Schema conventions

The canonical wire schemas are generated from or kept in lockstep with the Rust
types. At the conceptual level:

- `ActionRequest` contains a protocol version, request ID, requester identity
  (user, agent, and task IDs), `ExecutionTarget`, one tagged capability action,
  and an approval token when required. Capability-specific inputs carry their
  bounded timeout requests where applicable.
- Filesystem locations are `{root_id, relative_path}`, never ambient absolute
  paths. `root_id` names an administrator-opened directory capability.
- Byte content is explicitly encoded and bounded; it is not interpreted as a
  command or template.
- Durations, collection sizes, payloads, and returned data have hard maxima.
- `ExecutionTarget` is either local or a named node. It participates in the
  arguments/target digest and authorization decision.
- Outputs include structured status and bounded data. Large or truncated output
  is represented by metadata and a digest, not silently treated as complete.

Canonicalization occurs only after validation. The canonical arguments hash is
SHA-256 over deterministic RFC 8785/JCS serialization. The approval claims bind
that digest alongside the protocol version, request ID, capability, identity,
and execution target.

## Capability inventory

“Foundation backend” describes implementation availability, not permission.
Every invocation still requires descriptor and policy checks.

| Capability | Conceptual input -> output | Baseline risk | Foundation backend |
| --- | --- | --- | --- |
| `ReadFile` | root-relative path, byte/size bound -> bounded bytes, digest, metadata | `READ_ONLY` | Local filesystem |
| `WriteFile` | root-relative path, bytes, expected pre-change digest and explicit create policy -> resulting digest and change metadata | `REVERSIBLE_CHANGE` | Local filesystem |
| `CreateFile` | root-relative new path, bytes, create semantics -> resulting digest and metadata | `LOW_RISK_WRITE` | Local filesystem |
| `MoveFile` | source and destination root-relative paths, overwrite policy -> move/change metadata | `REVERSIBLE_CHANGE` when rollback is provable; otherwise stronger | Local filesystem |
| `DeleteFile` | root-relative path and explicit expected pre-change state -> deletion metadata | `DESTRUCTIVE` unless a configured recovery backend proves otherwise | Local filesystem |
| `ListDirectory` | root-relative directory, entry/metadata bounds -> bounded entries and continuation state | `READ_ONLY` | Local filesystem |
| `ExecuteApprovedCommand` | approved program ID, argument vector, working directory, environment entries -> bounded exit/output result | Descriptor-specific; at least `PRIVILEGED_CHANGE` for consequential programs | Local process |
| `GitRead` | repository root ID and typed read operation -> bounded Git result | `READ_ONLY` | Local read-only libgit2 backend |
| `GitWrite` | repository root ID and typed mutation -> structured Git result/change evidence | `REVERSIBLE_CHANGE` or `EXTERNAL_SIDE_EFFECT` for remote writes | Declared; fail closed until explicit backend |
| `HttpRequest` | method, URL, bounded headers/body -> status, bounded headers/body, destination trace | `EXTERNAL_SIDE_EFFECT` | Local HTTP |
| `BrowserAction` | browser/session ID and typed navigation/input operation -> structured browser result | `EXTERNAL_SIDE_EFFECT` | Declared; fail closed until explicit backend |
| `ProcessInspect` | typed list or PID selection -> bounded, redacted process records | `READ_ONLY` | Linux `/proc`, disabled unless UID-scoped in policy |
| `ServiceInspect` | service manager/name and typed query -> structured service state | `READ_ONLY` | Declared; fail closed until explicit backend |
| `ServiceControl` | service manager/name and typed transition -> before/after state | `PRIVILEGED_CHANGE` | Declared; fail closed until explicit backend |
| `ContainerAction` | runtime/container ID and typed operation -> structured runtime result | `PRIVILEGED_CHANGE` or `DESTRUCTIVE` | Declared; fail closed until explicit backend |
| `NodeAction` | node ID and a typed node-management operation -> structured node result | `PRIVILEGED_CHANGE` or `EXTERNAL_SIDE_EFFECT` | Declared; fail closed until explicit backend |

## Filesystem capabilities

Filesystem inputs identify a configured root and a validated relative path.

## Git read capability

`GitRead` implements only `status`, `diff`, bounded `log`, full-object-ID
`show`, and restricted revision resolution. The output field `text_base64`
contains bounded operation text or blob bytes; `truncated` truthfully marks a
bounded prefix. Revision syntax excludes ranges, reflog selectors, peel/path
operators, abbreviated object IDs for `show`, and option-like values.

The selected repository and its `.git` metadata must be owned by root or the
broker UID and must not be group/other writable. The backend rejects symlinks,
hard links, special files, linked worktrees, bare repositories, object
alternates, configuration includes, and path-bearing/executable configuration.
It installs only the validated local repository configuration into libgit2;
global and system Git configuration are not consulted. It has no remote
transport feature and does not execute hooks, filters, credential helpers,
submodules, `git`, or a shell.

`GitWrite` remains a separate signed-approval capability and has no backend.
Generic filesystem capabilities treat `.git` as protected metadata and cannot
be used to approximate either Git capability. Git reads hold the configured
root's mutation lock for the complete operation so broker-mediated filesystem
mutations cannot race metadata validation.

## Process inspection capability

`ProcessInspect` supports a bounded process list and one exact PID lookup. The
trusted daemon configuration must explicitly enable it, list one or more
unprivileged numeric UIDs, and set the maximum result count. UID 0 is always
rejected. A request cannot widen either scope.

The Linux backend reads `/proc/<pid>/status`, `/proc/<pid>/stat`, and the
kernel-owned `exe` link directly. It compares UID, PID, parent PID, and process
start time before and after inspection so a recycled PID does not silently
change identity. It returns only the executable basename. The
`arguments_redacted` array is empty because the backend never opens `cmdline`;
it also never opens `environ`, file descriptors, memory, namespaces, or process
roots. Listing silently omits processes outside policy and processes that exit
during the bounded scan. Exact lookup returns one generic unavailable error so
it does not reveal whether a denied PID exists. The complete inspection has a
two-second wall-clock deadline and observes cancellation between bounded reads.

The backend fails closed on non-Linux hosts. Fixture tests exercise parsing,
UID filtering, output bounds, cancellation, malformed metadata, and symlink
rejection on every development platform; production qualification still
requires the Linux deployment profile and its actual procfs mount policy.

Policy rejects absolute paths, parent traversal, platform prefix tricks,
forbidden pseudo-filesystems, device files, secret roots, and symlink/reparse
escapes. Both endpoints of a move are resolved independently; allowing the
source does not imply permission to the destination.

Writes use temporary files and atomic rename where the operation and filesystem
permit it. `WriteFile` must not silently become create, and `CreateFile` must not
silently overwrite. Expected pre-change digests may be required to avoid
time-of-check/time-of-use and lost-update mistakes.

Audit records contain paths in a configured redacted form, pre/post digests when
measurable, and the operation result. File contents and secret material are not
audit fields.

## Approved command capability

`ExecuteApprovedCommand` is not a shell API. A program ID resolves through
broker configuration to an exact executable plus argument constraints. The
executor accepts a validated argument array, a permitted root-relative working
directory, and only explicitly allowed environment keys and values.

It rejects shell strings, command substitution, implicit globbing, uncontrolled
redirection, unbounded pipelines, inherited environment, arbitrary `PATH`
changes, loader injection such as `LD_PRELOAD`/`DYLD_*`, and any executable not
in the program registry. A request cannot substitute the executable through
`argv[0]`, environment values, or a writable search path.

If an operation genuinely needs shell semantics, it requires a separately named
higher-risk capability with a fixed reviewed script or grammar and stronger
approval. The foundation deliberately does not provide one.

## HTTP capability

`HttpRequest` has bounded methods, headers, body, response, deadline, and
redirect count. Policy validates scheme, normalized host, port, DNS answers, IP
ranges, and every redirect hop. The connection is pinned to an approved
resolution so a second implicit DNS lookup cannot redirect it to localhost,
private networks, or cloud metadata services.

Host headers, SNI, certificate validation, and the pinned destination must
remain coherent. A response redirect is new input to policy, not implicit
permission. Unsupported proxy settings are not inherited from the broker
environment.

## Remaining declared host-specific capabilities

Git write, browser, service, container, and node actions must be
implemented as typed backends. Dispatching them through
`ExecuteApprovedCommand` as a fallback would collapse their schemas and
permission boundaries, so it is forbidden. An implementation is enabled only
after it defines:

1. supported typed operations and output schemas;
2. platform and version detection;
3. exact permission, approval, and risk mapping;
4. target/resource identity rules resistant to name swapping;
5. isolation, deadline, cancellation, and output behavior;
6. audit and Agent Green behavior; and
7. adversarial and platform integration tests.

## Reversibility

Reversibility is an evidenced property of a particular operation and deployment,
not a reassuring label:

- atomic temporary-file replacement plus a retained pre-image may make a write
  reversible;
- a Git mutation may be recoverable only if the old object/reflog is retained
  and no external actor has relied on the new state;
- a move across filesystems may degrade into copy/delete and is not inherently
  atomic;
- deletion without a configured snapshot/trash/backup is destructive;
- an HTTP request, remote push, sent message, or external service transition is
  not made reversible by writing a compensating-action note.

When recovery prerequisites are absent or cannot be verified, policy and audit
must say `RuntimeDependent` or `NotReversible`. Rollback failure is a new
security-relevant action, not permission to retry with broader authority.

## Concurrency and cancellation

Executors enforce bounded concurrency globally and, where necessary, per root,
program, destination, or node. Conflicting filesystem mutations use expected
state/digests or locks rather than last-writer-wins assumptions. Cancellation is
authenticated and scoped to the originating request or an administrator; it
does not authorize a new action.

Cancellation and timeout are outcomes, not rollback guarantees. The broker
records whether execution started and any measurable side effects before
reporting either result.
