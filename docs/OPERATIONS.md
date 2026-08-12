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
| Socket | absolute path, broker-owned setgid directory, Platform access group, `0660` socket, frame/request bounds |
| Approval trust | accepted token/schema versions, Ed25519 public keys, key lifecycle, max lifetime and clock skew |
| Replay | dedicated durable ledger path, permissions, synchronization/durability policy, retention |
| Permissions | user/agent permission source and fail-closed refresh behavior |
| Risk/approval | deterministic risk mapping and acceptable approval types |
| Filesystem | explicit root ID -> opened directory mapping, operations, secret exclusions, per-root limits |
| Programs | program ID -> canonical executable path + SHA-256, argv grammar, working roots, environment allowlist; digest-pinned `prlimit` + `bubblewrap` |
| Network | schemes, hosts, ports, IP ranges, redirect limits, DNS behavior, metadata/private/localhost deny rules |
| Resources | request/queue/concurrency, wall/CPU/memory/process/file/output limits |
| Audit | protected append-only log, chain genesis/head state, rotation, external anchor destination |
| Agent Green | mandatory protected local spool, capacity/retention, collector ownership and acknowledgement monitoring |
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

1. the effective UID is the configured unprivileged broker identity and no
   unexpected privilege/capability is present;
2. configuration ownership, mode, schema, and cross-references are valid;
3. every enabled filesystem root opens to the expected object and is not a
   prohibited secret/pseudo-filesystem target;
4. every enabled program resolves to the expected non-writable executable and
   has a complete argument/environment/sandbox policy;
5. approval verification keys and time policy are valid;
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

The foundation has local filesystem, approved-command, and HTTP executor paths.
Git, browser, process, service, container, and node variants remain disabled
until explicit typed backends satisfy this rollout. Do not implement them by
granting a broad command as a shortcut.

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
- queue depth, active actions, timeouts, cancellations, output truncation, and
  per-scope concurrency saturation;
- DNS answer changes, redirect denials, and effective destination traces; and
- clock health and deviation beyond approval skew policy.

Metrics and alerts must use bounded identifiers and reason codes. Do not put raw
arguments, file contents, command output, HTTP bodies, approval envelopes,
credentials, or query tokens in metric labels or logs.

## Audit chain operations

Each audit record links to the prior record hash and includes a canonical record
hash. Verification detects mutation, deletion, insertion, or reordering from a
known chain head. Periodically anchor signed/checkpointed chain heads to an
independently protected destination; a local chain with a locally rewritable
head is not tamper-proof against full host compromise.

Rotation must carry the final hash of the previous segment into the next and
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
requests contain no suppression field. The spool must persist records safely,
bound individual and total sizes, expose backpressure/health, and permit the
Agent Green collector to acknowledge delivery without letting it rewrite
unrelated entries.

Remote collector success is not implied by a successful local append. Monitor
the oldest unacknowledged event. If the spool reaches its safe capacity or
cannot durably append a required event, the relevant action path fails closed.

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
