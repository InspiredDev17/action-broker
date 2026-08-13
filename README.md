# Action Broker

Action Broker is the trusted execution broker for a sovereign Personal AI
ecosystem. It accepts only typed, policy-checked action requests and is the only
normal path by which an AI-originated tool action may affect the host.

The model never executes tools directly:

```text
LLM (untrusted proposals)
  -> Personal AI Platform
  -> schema validation
  -> identity
  -> permissions
  -> approvals
  -> deterministic security policy
  -> Action Broker
  -> constrained local or remote execution target
```

There is deliberately no generic `execute anything` capability and no hidden
bypass. Command execution uses an approved program, a validated argument array,
a validated working directory, and an explicit environment allowlist. It does
not treat a shell string as its normal API.

## Foundation

The foundation consists of:

- a Rust security core and Linux Unix-domain-socket daemon with peer-UID
  authentication;
- a Go standard-library client for the Personal AI Platform;
- typed request variants for every capability in the capability model;
- local executors for filesystem actions, read-only Git inspection, approved
  commands, HTTP requests, and policy-scoped Linux process inspection;
- Ed25519 approval verification using a maintained cryptographic library and a
  durable bounded anti-replay ledger with expiry-safe pruning and clock-rollback
  detection, plus per-key activation, retirement, and hard revocation
  enforcement;
- explicit filesystem root IDs backed by capability-oriented filesystem APIs;
- destination validation, DNS resolution and address pinning, and manually
  validated redirects for HTTP;
- Linux `bubblewrap` isolation wrapped by policy-pinned `prlimit`, subprocess
  environment clearing, deadlines, and bounded output, without shell expansion;
- an append-only, hash-chained audit log and a mandatory local Agent Green
  security-event spool with strict startup validation, explicit capacity, and
  external-modification detection; and
- an `ExecutionTarget` boundary that preserves capability semantics for a future
  remote Node Runtime.

Host-specific capabilities that do not yet have an explicit backend are still
represented in the protocol, but fail closed as unsupported. Their presence in
the schema is not a claim that they can execute.

`ProcessInspect` is disabled by default. On Linux it can be enabled only with a
non-root UID allowlist and a bounded result limit. It reads kernel-owned
`/proc` status, start-time, and executable-link metadata in process, rechecks
identity to detect PID reuse, returns only the executable basename, and never
opens process command lines or environments.

`GitRead` is local-only and implemented directly through a vendored libgit2
library with remote transports disabled. It does not invoke `git`, hooks,
credential helpers, shells, submodules, or remote endpoints. `GitWrite` remains
disabled, and generic filesystem capabilities cannot access `.git` metadata as
a substitute.

## Capabilities

The protocol defines `ReadFile`, `WriteFile`, `CreateFile`, `MoveFile`,
`DeleteFile`, `ListDirectory`, `ExecuteApprovedCommand`, `GitRead`, `GitWrite`,
`HttpRequest` (the HTTP request capability), `BrowserAction`, `ProcessInspect`, `ServiceInspect`,
`ServiceControl`, `ContainerAction`, and `NodeAction`.

Each capability descriptor binds input and output schemas, the required
permission, approval policy, filesystem and network scope, timeout and resource
limits, audit behavior, reversibility, and risk class. See
[Capability Model](docs/CAPABILITY-MODEL.md).

## Security posture

Action Broker is designed to fail closed:

- approval tokens bind the user, agent, task, capability, canonical arguments
  digest, target, expiration, approval type, and nonce;
- a valid signature is necessary but not sufficient: identity, permission,
  scope, risk, expiry, target, and replay checks must also pass;
- filesystem paths are root-relative and do not grant ambient access to the
  host filesystem;
- HTTP policy checks the scheme, host, resolved IPs, port, redirects, localhost,
  private ranges, and metadata endpoints;
- child processes do not inherit the broker environment or its secrets;
- global, per-principal, and per-capability admission bounds prevent one peer or
  one capability from consuming every execution slot;
- the local transport uses atomic global/per-peer connection admission, a fixed
  worker set, an explicitly bounded socket queue with a residence deadline, and
  configured read/write deadlines;
- unavailable peer credentials and unconfigured peer UIDs are denied before
  parsing and produce bounded, secret-free Agent Green bypass events;
- malformed, truncated, oversized, and schema-invalid authenticated frames emit
  bounded protocol-abuse events before broker authorization or execution;
- exact worker-liveness accounting terminates the daemon if any configured
  connection worker returns or unwinds unexpectedly;
- the first `SIGTERM` or `SIGINT` stops admission, cancels active broker waits,
  drains workers within an explicit grace, and reports grace exhaustion before
  exiting nonzero; a second termination signal forces immediate exit;
- normal and fail-closed daemon exits remove only the exact device/inode socket
  created by that process and preserve any replacement object;
- daemon readiness and every action verify exact real/effective/saved/fs IDs,
  supplementary groups, empty active Linux capability sets, and inherited
  `NoNewPrivs`; and
- security events cannot be disabled by an action request.

The Personal AI Platform and Action Broker must run under different
unprivileged UIDs. Linux peer credentials map each allowed Platform UID to one
configured user/agent principal; requester JSON cannot select another identity.
Configuration and approval public keys are root-owned and non-writable, while
runtime replay/audit/event state is broker-owned.

This project does **not** claim that argument validation and resource limits are
a complete operating-system sandbox. The current daemon and approved-command
backend are Linux-only. Approved commands fail closed on macOS because the
foundation does not yet have a supported backend that meets its isolation and
resource requirements. Additional Linux guarantees may still require seccomp,
cgroups, Landlock, or a separately sandboxed worker. Unsupported guarantees
fail closed or are documented as residual risk in
[Sandbox](docs/SANDBOX.md) and [Threat Model](docs/THREAT-MODEL.md).

Run the broker as a dedicated, unprivileged account. Running it as root expands
the blast radius and is not a supported shortcut.

## Repository layout

```text
crates/action-broker-core/   Rust schemas, policy, approvals, audit, and executors
crates/action-brokerd/       local Unix-domain-socket daemon
client-go/                   Go standard-library client
docs/                        architecture, security, and operating guidance
```

The production runtime has no TypeScript and no Python dependency.

Audit segments can be verified without serving requests or modifying state:

```text
action-brokerd verify-audit --path /var/lib/action-broker/audit.jsonl
```

For rotated segments, pass the prior segment head with
`--initial-previous-head`; pass an independently protected checkpoint with
`--expected-head`. Verification emits only record count, chain heads, and time
bounds.

## Development

Use the repository toolchains to build and test the complete workspace:

```text
cargo fmt --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
go -C client-go test ./...
```

The Linux lifecycle qualification is intentionally separate from portable unit
tests. On a disposable Linux host, build the shipped daemon and internal Go
transport probe, then run the root-only fixture:

```text
cargo build --locked --release -p action-brokerd
cargo build --locked --release -p action-broker-core \
  --features lifecycle-test-fixture --example issue_lifecycle_approval
go -C client-go build -trimpath -o ../target/lifecycletestclient ./internal/lifecycletestclient
sudo tests/linux-service-lifecycle.sh \
  --daemon "$PWD/target/release/action-brokerd" \
  --client "$PWD/target/lifecycletestclient" \
  --issuer "$PWD/target/release/examples/issue_lifecycle_approval"
```

The harness establishes distinct numeric broker, Platform, unauthorized-peer,
and IPC-group identities. It passes only after a typed policy-only read,
mandatory unauthorized-peer evidence, an interrupted partial-frame drain,
not-yet-valid/expired approval and signed-arguments-tamper rejection without
nonce consumption, approved-command cancellation with no surviving child,
socket cleanup, post-restart rejection of the consumed approval, mandatory
time-window/tamper/replay evidence, audit-chain verification, and clean
restarts against the same durable state.
The issuer is excluded from normal builds behind the explicit
`lifecycle-test-fixture` feature and embeds a test key that must never be trusted
by a production broker. The harness requires Linux, root for creating
disposable identities, and the tools it checks at startup. Unsupported hosts
exit with status 77 rather than manufacturing platform evidence. A
containerized run additionally needs an outer runner that permits nested
unprivileged namespaces and private mounts; a blocked Bubblewrap launch is a
failed qualification, not a reason to weaken the production profile.

Treat successful unit tests as source-level evidence, not proof that a
particular deployed host provides every desired sandbox primitive. Before
operation, configure explicit roots, executable and network allowlists, approval
verification keys, the replay ledger, audit storage, the Agent Green spool, and
the socket's ownership and mode. The deployment checklist is in
[Operations](docs/OPERATIONS.md).

## Documents

- [Architecture](docs/ARCHITECTURE.md)
- [Capability Model](docs/CAPABILITY-MODEL.md)
- [Sandbox](docs/SANDBOX.md)
- [Approvals](docs/APPROVALS.md)
- [Threat Model](docs/THREAT-MODEL.md)
- [Operations](docs/OPERATIONS.md)

Action Broker is an early security foundation. Audit the code and deployment
configuration before trusting it with consequential host or external actions.
