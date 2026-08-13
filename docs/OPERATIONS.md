# Operations

## Deployment rule

Run Action Broker as a dedicated, unprivileged service account. Do not run it as
root to gain filesystem, service, container, or sandbox access. If a capability
needs authority the broker account does not have, add a narrowly designed
backend and deployment boundary or leave that capability disabled.

The daemon is a Linux local security service, not an internet listener. The
foundation uses a Unix-domain socket and Linux peer credentials. Remote node execution requires a future separately
authenticated transport and Node Runtime; it is not enabled by exposing the
local socket through TCP or a tunnel.

## Required configuration

Configuration is administrative and must not be writable by the daemon account
or socket clients. Exact file/flag names are defined by the daemon interface;
regardless of representation, production configuration must provide:

| Area | Required state |
| --- | --- |
| Identity | distinct unprivileged broker UID and Platform UID; exact Platform UID -> user/agent mapping |
| Broker privilege | expected non-root UID/GID, exact supplementary GIDs, empty active capability sets, `NoNewPrivileges=true` |
| Socket | absolute path, broker-owned setgid directory, Platform access group, `0660` socket, global/per-peer admission, fixed workers, frame and read/write bounds |
| Approval trust | accepted token/schema versions, unique Ed25519 public-key IDs, required activation, optional retirement/revocation cutoffs, max lifetime and clock skew |
| Replay | dedicated durable ledger path, permissions, full synchronization, maximum rows, post-expiration retention |
| Permissions | user/agent permission source and fail-closed refresh behavior |
| Risk/approval | deterministic risk mapping and acceptable approval types |
| Filesystem | explicit root ID -> opened directory mapping, operations, secret exclusions, per-root limits; repository roots and `.git` metadata broker/root-owned and non-writable by group/other |
| Programs | program ID -> canonical executable path + SHA-256, argv grammar, working roots, environment allowlist; digest-pinned `prlimit` + `bubblewrap` |
| Network | schemes, hosts, ports, IP ranges, redirect limits, DNS behavior, metadata/private/localhost deny rules |
| Process inspection | explicit enable flag, non-root numeric UID allowlist, bounded maximum entries; disabled by default |
| Resources | request/queue/concurrency, wall/CPU/memory/process/file/output limits |
| Audit | protected append-only log, chain genesis/head state, rotation, external anchor destination |
| Agent Green | mandatory protected local spool, explicit 1 MiB-1 GiB capacity, retention, read-only collector access, acknowledgement monitoring |
| OS profile | detected/required isolation controls and fail-closed capability gates |

Never store approval signing keys in the broker configuration. Avoid secrets in
root names, command IDs, environment values, URLs, or service arguments. If a
backend eventually needs a credential, supply it through a dedicated broker-owned
secret mechanism that child output/audit cannot expose; do not inherit the
daemon environment.

## Files and permissions

A typical installation separates immutable configuration from mutable runtime
state:

```text
read-only configuration and Ed25519 verification keys   root owned, not group/other writable
Unix socket directory                                   broker owned, setgid Platform group, no group write
replay ledger                                           broker only
audit log and chain state                               broker append, monitor read
Agent Green spool                                       broker append, collector read/ack
temporary execution state                              broker only, size bounded
configured action roots                                least privilege per root
```

Do not place the replay ledger, audit chain state, or Agent Green spool inside an
action-accessible root. Do not expose the broker's configuration, executable,
keys, state, socket directory, SSH directory, credential stores, or OS secret
locations through a root ID.

The service umask and explicit modes should deny access by unrelated users.
Use a broker-owned socket directory such as mode `2750` whose group is the
dedicated Platform/broker IPC group; the daemon creates a `0660` socket and
refuses an owner/group/mode mismatch. Each admitted Linux peer UID maps to
exactly one configured user/agent pair, and must differ from the broker UID.
Socket group membership is only access to request the service; the broker still
validates peer identity, permission, and approval. The Go client also requires
the expected distinct broker UID and verifies stable endpoint ownership.

## Startup and readiness

Startup should fail before accepting requests unless all configured mandatory
controls pass:

1. all real/effective/saved/fs IDs and supplementary groups match the configured
   unprivileged broker profile, active Linux capability masks are zero, and
   `NoNewPrivs` is enabled;
2. configuration ownership, mode, schema, and cross-references are valid;
3. every enabled filesystem root opens to the expected object and is not a
   prohibited secret/pseudo-filesystem target;
4. every enabled program resolves to the expected non-writable executable and
   has a complete argument/environment/sandbox policy;
5. approval verification keys have unique IDs, secure files, coherent lifecycle
   windows, and valid time policy;
6. the replay ledger opens transactionally and passes a durable write/read
   check appropriate to the configured profile;
7. audit chain state is internally consistent and writable;
8. the Agent Green spool is writable, bounded, protected, and not disabled;
9. required OS sandbox controls are detected and successfully activated; and
10. the socket can be created with the configured owner/group/mode without
    replacing an unexpected filesystem object.

“Process is running” is liveness, not readiness. Readiness means the daemon can
authorize, record, emit security events, and enforce the configured profile.
When a mandatory subsystem later fails, consequential actions stop until it
recovers. Read-only actions may continue only if explicit policy allows and
their required audit/event guarantees remain intact.

The strict JSON configuration includes these admission and process-inspection
fields:

```json
{
  "audit_initial_previous_hash": null,
  "agent_green_event_spool_maximum_bytes": 67108864,
  "replay_ledger": {
    "maximum_entries": 1000000,
    "retention_after_expiration_seconds": 86400
  },
  "privilege_profile": {
    "expected_user_id": 1001,
    "expected_group_id": 1001,
    "allowed_supplementary_group_ids": [1001, 2001]
  },
  "process_inspection": {
    "enabled": false,
    "allowed_user_ids": [],
    "maximum_entries": 256
  },
  "transport_limits": {
    "maximum_open_connections": 32,
    "maximum_open_connections_per_peer": 8,
    "worker_threads": 8,
    "maximum_queued_connections": 16,
    "maximum_queue_wait_milliseconds": 1000,
    "maximum_authentication_failures_per_window": 16,
    "authentication_failure_window_milliseconds": 1000,
    "maximum_protocol_failures_per_window": 16,
    "protocol_failure_window_milliseconds": 1000,
    "shutdown_grace_milliseconds": 5000,
    "read_timeout_milliseconds": 5000,
    "write_timeout_milliseconds": 5000
  },
  "broker_limits": {
    "maximum_concurrent_actions": 8,
    "maximum_concurrent_actions_per_principal": 4,
    "maximum_concurrent_actions_per_capability": 4,
    "concurrency_wait_milliseconds": 1000
  }
}
```

`replay_ledger` is required. Its maximum must be nonzero and no greater than
10,000,000 rows; post-expiration retention must be 3,600 through 31,536,000
seconds. Startup runs SQLite `quick_check`, transactionally prunes only rows
whose expiry plus retention is no later than the current time, and refuses a
ledger with no admission headroom. Each nonce consumption repeats the same safe
prune and capacity check inside an `IMMEDIATE`, fully synchronous transaction.
Capacity exhaustion denies the action before dispatch and emits an Agent Green
resource-abuse event; raising capacity requires storage planning, not deleting
unexpired rows. The ledger persists its last observed wall time. If the clock
moves backward, approval consumption remains disabled until operators verify
time integrity and reconcile replay state; do not edit the high-water mark as a
shortcut.

`privilege_profile` is required and must exactly describe the dedicated broker
account. UID 0, GID 0, group 0, and more than 16 supplementary groups are
rejected. Configure the service manager with `NoNewPrivileges=true`, a fixed
`User=` and `Group=`, and only the explicitly listed `SupplementaryGroups=`.
The profile is checked at readiness and again on each request thread. All four
kernel UID and GID slots must match, every listed supplementary GID must match
exactly, and the inheritable, permitted, effective, and ambient Linux capability
masks must be zero. A readiness mismatch stops startup before the socket is
bound; a mismatch detected during an action denies it and emits an Agent Green
`unexpected_privilege_elevation` event. The check verifies the opened status
file is procfs and never trusts an environment variable or caller field.

`process_inspection` may be omitted only to select the same disabled default.
Enabling it requires at least one UID, forbids UID 0, and never authorizes more
than 1,024 returned records. Both per-scope concurrency values are required,
must be nonzero, and cannot exceed the global limit. Waiting requests observe
cancellation and fail with a resource-limit outcome when the bounded wait
expires; they do not consume a slot before admission.

`transport_limits` is required. Open connections must be 1 through 128, the
per-peer maximum must be nonzero and no greater than the global maximum, and
the fixed worker count must be 1 through 64 and no greater than the global
maximum. The queue capacity must be 1 through the configured global connection
maximum. Queue residence, shutdown grace, read, and write timeouts must each be
100 through 30,000 milliseconds. The authentication-failure threshold must be 1 through
1,024 and its window must be 100 through 30,000 milliseconds. The authenticated
protocol-failure threshold and window have the same bounds. These are
startup-validated administrative limits, not caller-controlled hints.
Connection admission increments global and per-peer counts in one critical
section and releases both through an owned permit.
Capacity saturation or queue expiry closes the socket without parsing a request
and emits an Agent Green resource-abuse event. The accept loop fails closed when
it cannot durably record its saturation event; a worker that cannot record a
queue-expiry event marks the pool unhealthy instead of processing the expired
socket, causing the listener health poll to terminate the daemon.

Missing peer credentials and unconfigured peer UIDs also close before parsing
and durably emit `permission_bypass_attempt` without logging the numeric UID or
any client bytes. Once the configured number occurs inside one window, the
single accept loop sleeps only for that window's remaining duration. This bounds
event-spool growth and intentionally delays authorized traffic during an active
local authentication flood. An event-spool failure stops the daemon rather than
accepting an unaudited peer. Keep socket group membership narrow and alert on
both reason codes: `peer_credentials_unavailable` and
`unauthorized_platform_peer`.

After identity binding, malformed protocol input is reported with one of:
`request_frame_prefix_incomplete`, `request_frame_size_invalid`,
`request_frame_incomplete`, `request_schema_invalid`, or
`request_trailing_data`. These events include only the configured user/agent
identity and the fixed reason code—never frame bytes. The failure window is
shared across connection workers. At its threshold the rejecting worker waits
for the remainder of the window; no malformed request advances to policy or an
executor. A mandatory event failure marks the worker pool unhealthy; the
nonblocking listener health poll terminates the daemon within 10 milliseconds.
A fatal listener accept error emits `sandbox_failure` with reason
`socket_accept_failure` and terminates. Treat any such shutdown as a service
health failure requiring storage or socket repair before restart.

Worker readiness additionally requires the exact configured live-worker count.
Every worker return or unwind atomically decrements that count and poisons the
pool, even if the exit was not one of the anticipated error branches. The
listener emits `sandbox_failure` with reason `connection_worker_lost` and exits
within its 10 millisecond health interval. Configure the service manager to
restart only after retaining the Agent Green spool and crash diagnostics; do not
mask repeated exits by dynamically adding unreviewed worker threads.

## Socket shutdown and crash recovery

On the first `SIGTERM` or `SIGINT`, the daemon stops accepting sockets, closes
the bounded worker queue, requests cancellation of active broker waits, and
waits no longer than `shutdown_grace_milliseconds` for every fixed worker to
exit. Queued sockets are closed without parsing. Authentication and
protocol-failure backoffs are interruptible. A completed drain returns normally;
grace exhaustion emits the secret-free Agent Green event
`shutdown_grace_exhausted` and returns a timeout so the service exits nonzero.
Do not treat cancellation as rollback or assume an external effect was retracted.

A second `SIGTERM` or `SIGINT` forces immediate process exit. Use it only as an
operator escalation after preserving diagnostics; it bypasses the bounded drain
and may bypass socket cleanup. Service managers should send one termination
signal, allow the configured grace plus a small supervision margin, and use
`SIGKILL` only after that deadline.

On normal return, completed first-signal drain, or fail-closed Rust unwinding,
the daemon closes and removes
only the socket pathname whose device and inode match the socket it created.
If another object replaced that pathname, cleanup leaves it untouched. This
prevents shutdown code from deleting an attacker- or operator-created file based
only on a familiar name.

Forced second-signal exit, `SIGKILL`, process abort, power loss, and host crash
bypass this cleanup. Startup
intentionally refuses any existing socket pathname. Before recovering, stop the
service, confirm no process has the socket open or is listening, inspect that
the parent is the configured broker-owned non-group-writable directory, and
verify the object is a socket with the configured broker UID, IPC GID, and mode.
Move the stale socket to a broker-only quarantine name in the same directory,
restart, verify the new socket identity and readiness, then remove the quarantined
object through the host's reviewed administrative workflow. Never add automatic
"unlink whatever exists" startup behavior. A second process under the same
dedicated broker UID is outside the supported single-instance deployment and
must not manipulate the socket directory.

For the first audit segment, omit `audit_initial_previous_hash` to use the
all-zero genesis. For every rotated segment, set it to the exact final
`head_sha256` of the preceding segment. The daemon validates this linkage before
readiness; a nonempty rotated segment fails startup when the configured initial
head does not match its first record.

## OS profiles

### Linux

Use a service manager to set a dedicated user/group, restrictive umask, no new
privileges, a narrow filesystem view, and explicit resource limits. For approved
commands whose threat model needs it, configure and verify cgroup v2 controls,
namespaces, seccomp, and/or Landlock as appropriate. Availability varies by
kernel, distribution, container context, and filesystem; record detected state
at startup.

Do not label a profile “isolated” solely because one rlimit or `no_new_privs` is
active. Aggregate descendant containment and network isolation require the
corresponding kernel/service-manager controls.

Before host qualification, run `tests/linux-service-lifecycle.sh` with absolute
paths to release builds of `action-brokerd` and the internal lifecycle client,
as documented in the README. The harness uses root only to construct isolated
numeric identities, then runs the daemon under a distinct unprivileged UID with
empty supplementary groups, zero active capabilities, and `NoNewPrivs`. It
verifies a typed read allow path, an
unconfigured same-IPC-group UID deny path and Agent Green event, an in-flight
partial-frame first-signal drain, exact socket cleanup, the audit chain, and a
restart using the same durable files. It also issues a short-lived, exact-scope
test approval through the repository's Rust/JCS model. First it submits a
correctly signed but expired token, requires a broker-confirmed
`approval_expired` rejection and Agent Green evidence, and proves no audit start
or process launch occurred. It then issues a current token with the same request
ID and nonce, changes the signed command argument without changing that token,
and requires `approval_invalid` with the same no-effect guarantees. The original
current token must still authorize the exact command, proving neither expiry nor
failed binding consumed its nonce. The harness sends `SIGTERM`, requires a
broker-confirmed cancelled result, and proves no process under the broker test
UID survives. After reopening the same SQLite ledger, it resubmits that exact
token and requires a broker-confirmed `approval_replayed` rejection, no second
command or audit start, and mandatory Agent Green identity/capability evidence.
The embedded fixture signing key must never appear in production trust
configuration; its binary is excluded from normal builds unless the
`lifecycle-test-fixture` feature is explicitly enabled. A pass qualifies this
narrow lifecycle on the tested Linux host only; it does not attest cgroups,
seccomp, general command containment, external effects, or the production
service-manager profile.

Containerized qualification requires an outer runner that permits unprivileged
user namespaces and their private mounts. If the container runtime blocks
those primitives, Bubblewrap must fail closed and the run is not qualification
evidence. Do not weaken the production host profile merely to make the harness
pass.

### macOS

The current daemon deliberately refuses all peers on macOS because a supported
peer-UID binding has not been implemented, and approved commands return
`sandbox_unavailable`. A macOS deployment needs a separately reviewed
transport and worker/VM boundary; there is no weaker enabled fallback.

## Capability rollout

Enable one narrow descriptor at a time:

1. define typed input/output and canonicalization test vectors;
2. configure the least permission, scope, and resource bounds;
3. classify risk and reversibility honestly;
4. map an appropriate approval type;
5. run adversarial and platform integration tests on the deployment host;
6. verify audit records and Agent Green events for allow and deny paths;
7. exercise timeout, cancellation, restart, storage failure, and concurrent
   requests; and
8. enable for a small identity/target scope before widening policy.

The foundation has local filesystem, read-only Git, approved-command, HTTP,
and opt-in Linux process-inspection executor paths. Git repositories must be
ordinary local worktrees whose
bounded metadata tree passes ownership, mode, link, indirection, and local
configuration checks. Repack unusually large loose-object stores before
enabling them; a metadata tree above 100,000 entries fails closed.

Git write, browser, service, container, and node variants remain
disabled until explicit typed backends satisfy this rollout. Do not implement
them by granting a broad command as a shortcut.

## Monitoring

Monitor at least:

- authorization allow/deny counts by capability and reason code;
- expired, tampered, and replayed approval attempts;
- replay-ledger latency, durability errors, size, and prune status;
- audit append/chain verification failures and time since external anchoring;
- Agent Green spool depth, oldest age, capacity, collector acknowledgements, and
  rejected/corrupt records;
- path escape, secret access, forbidden executable/destination, sandbox failure,
  unexpected elevation, and resource-abuse events;
- active actions, admission wait/denial, timeouts, cancellations, output
  truncation, and global/per-principal/per-capability saturation;
- DNS answer changes, redirect denials, and effective destination traces; and
- clock health and deviation beyond approval skew policy.

Metrics and alerts must use bounded identifiers and reason codes. Do not put raw
arguments, file contents, command output, HTTP bodies, approval envelopes,
credentials, or query tokens in metric labels or logs.

## Approval key lifecycle operations

Plan routine rotation with two unique key IDs. Add the new public key with a
future `active_from_unix_seconds`; configure the old key's
`retire_at_unix_seconds` as the exclusive issuance cutoff; deploy matching
signer policy; then perform a validated broker restart. Keep the old public key
configured until its last pre-retirement token has expired plus allowed clock
skew and incident margin. Removing it earlier creates an availability failure,
not a security bypass.

For compromise, stop approval-required execution first, set
`revoke_at_unix_seconds` to the incident cutoff, deploy root-owned configuration
and replacement public key material, and restart through the complete readiness
sequence. At the revocation instant all tokens under that key fail, including
tokens issued before the cutoff. Preserve audit, replay, and Agent Green state
for investigation. Do not wait for the ordinary retirement overlap when the
key is suspected compromised.

The current daemon does not live-reload keys or lifecycle policy. Monitoring
must therefore alert on configuration generation, restart success, active key
set, upcoming activation/retirement, and revocation state without exposing key
bytes or token material. A configuration file edit alone is not proof that a
revocation is enforced by the running process.

## Audit chain operations

Each audit record links to the prior record hash and includes a canonical record
hash. Verification detects mutation, deletion, insertion, or reordering from a
known chain head. Periodically anchor signed/checkpointed chain heads to an
independently protected destination; a local chain with a locally rewritable
head is not tamper-proof against full host compromise.

Verify the first segment and print its bounded, secret-free summary:

```text
action-brokerd verify-audit \
  --path /var/lib/action-broker/audit-0001.jsonl \
  --expected-head <independently-protected-final-head>
```

Verify a rotated segment by binding both ends:

```text
action-brokerd verify-audit \
  --path /var/lib/action-broker/audit-0002.jsonl \
  --initial-previous-head <audit-0001-final-head> \
  --expected-head <audit-0002-protected-final-head>
```

The verifier is read-only and does not require `serve`. It accepts only regular,
private audit files opened without following the final symlink, limits a segment
to 1 GiB, each record to 256 KiB, and the record count to 4,000,000. It rejects
unknown JSON fields, missing final newlines, concurrent size changes, invalid
hash syntax, chain discontinuity, and external-checkpoint mismatch. Rotate well
before a bound is reached; increasing a limit is an administrative review, not
an incident workaround.

Rotation must set `audit_initial_previous_hash` to carry the final hash of the
previous segment into the next and
must not delete segments before retention/anchoring policy permits. Verify the
chain:

- at startup before readiness;
- after rotation and backup;
- during routine monitoring; and
- before and after incident collection or restore.

Audit storage exhaustion is a fail-closed condition for actions requiring audit.
Never “temporarily” disable audit to recover space while continuing execution.

## Agent Green spool operations

The local spool is mandatory. Action Broker cannot disable it, and action
requests contain no suppression field. Configuration must set
`agent_green_event_spool_maximum_bytes` from 1 MiB through 1 GiB. Individual
records are limited to 64 KiB. Startup strictly validates every JSONL record,
rejects unknown fields and unsupported versions, and requires at least 64 KiB
of remaining headroom. The writer checks capacity and file identity/change
timestamps around durable appends; any external append, rewrite, truncation, or
replacement causes subsequent emission to fail closed.

Remote collector success is not implied by a successful local append. Monitor
the oldest unacknowledged event and remaining bytes. The collector may tail a
read-only descriptor and store acknowledgements outside the spool, but it must
not modify the JSONL file. Live truncation and rotation are intentionally not
implemented. To reclaim an acknowledged segment, stop the broker, preserve and
verify/ship the file under incident-retention policy, create a new owner-only
empty spool at the configured path, and complete startup/readiness checks. If
the spool reaches capacity or cannot durably append a required event, the
relevant action path fails closed; do not delete records while continuing
execution.

## Backup and restore

Back up configuration versions, public keys, replay ledger, audit segments and
chain checkpoints, and Agent Green spool/acknowledgement state using encrypted,
access-controlled storage. Do not back up transient child output unless policy
explicitly requires it and secret classification permits it.

Restore is security-sensitive:

1. keep the socket unavailable;
2. verify configuration ownership and hashes;
3. verify audit continuity against an external anchor;
4. establish that the replay ledger is at least as current as the accepted
   approval-key epoch;
5. if ledger freshness is uncertain, revoke/rotate affected keys or epochs and
   wait out the maximum token lifetime plus skew;
6. reconcile Agent Green delivery state without dropping unacknowledged events;
7. rerun startup/readiness checks; and
8. enable capabilities gradually.

Restoring files does not reverse external side effects. Restoring an old replay
ledger without invalidating approvals can re-enable replay and is prohibited.

## Action rollback

Rollback metadata is capability-specific. For a reversible filesystem write it
may contain a pre-change digest, protected pre-image/backup locator, atomicity
result, and expected current digest. A rollback is a new typed action with its
own current permission, approval, validation, audit, and concurrency checks.

Never automatically overwrite a resource whose current digest differs from the
recorded post-change digest. Never describe delete, cross-filesystem move,
remote Git push, HTTP call, browser submission, service transition, or node
action as reversible unless that particular backend can verify a real recovery
mechanism. A compensating action is not the same as reversal.

## Incident response

For permission bypass, replay/tampering, path/secret escape, forbidden
destination/executable, sandbox failure, privilege elevation, audit corruption,
or Agent Green suppression:

1. stop accepting consequential actions without deleting evidence;
2. preserve the socket peer metadata, replay ledger, audit chain/checkpoint, and
   Agent Green spool;
3. revoke affected approval keys/tokens and narrow policy/permissions;
4. terminate affected workers within the bounded supervisor path;
5. inspect measurable file, process, and network side effects using independent
   tooling;
6. rotate any credential that may have crossed the boundary;
7. repair from a known-good binary/configuration rather than broadening a
   capability to diagnose itself;
8. run adversarial and deployment qualification tests; and
9. resume only the verified capability subset.

Avoid placing raw secrets or attacker-controlled output in tickets or chat.
Reference redacted audit and event correlation IDs.

## Upgrades and rollback of the service

Build artifacts should be reproducible or otherwise provenance-checked and
deployed immutably. Before upgrade, run Rust and Go tests, schema compatibility
tests, approval canonicalization vectors, replay concurrency/restart tests, and
the target OS profile tests.

Drain or cancel work through the authenticated control path, checkpoint audit
and event state, stop the daemon, deploy, and run readiness checks before
reopening the socket. Protocol/schema changes require explicit version handling;
never reinterpret an older signed approval under new semantics.

Rolling the binary back does not permit rolling security state back. Keep the
newest safe replay ledger and audit/event state. If an older binary cannot read
them without loss, remain stopped and perform a reviewed forward migration.

## Operational non-claims

- Passing startup checks is not proof against a kernel or root compromise.
- A Unix socket ACL is not approval.
- A local Agent Green spool append is not remote-delivery confirmation.
- A hash chain without an independently protected checkpoint is not immutable.
- A timeout or cancellation is not rollback.
- A typed capability whose backend is absent is not partially supported.
- macOS and Linux do not provide identical isolation guarantees.
