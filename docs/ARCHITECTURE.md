# Architecture

## Purpose and invariant

Action Broker turns an explicitly authorized, typed action into a bounded
execution attempt. Its central invariant is:

> AI output is a proposal, never execution authority.

The broker is the only normal pathway from AI-originated proposals to host or
network effects. There is no generic tool escape hatch. An operator may still
administer a machine outside Action Broker, but that administrative path is not
available to the model, platform client, action schema, or broker request.

## Data flow

```text
UNTRUSTED                                      TRUSTED CONTROL PLANE

  LLM
   |  proposed typed action
   v
  Personal AI Platform
   |-- schema validation
   |-- authenticated user and agent identity
   |-- permission evaluation
   |-- human/policy approval when required
   |-- deterministic security-policy evaluation
   |-- signed, short-lived approval token
   |
   |  Linux Unix-domain socket (distinct Platform UID)
   v
+--------------------------- Action Broker -----------------------------+
| decode with limits -> validate schema -> bind identity/permission     |
| -> resolve capability descriptor -> verify token and consume nonce    |
| -> validate target/scopes -> dispatch typed executor                  |
|                                                                      |
| audit hash chain                         Agent Green event spool       |
+----------+--------------------------------------+---------------------+
           |                                      |
           v                                      v
  ExecutionTarget::Local                 mandatory local handoff
           |
           +-- capability filesystem roots
           +-- approved subprocess
           +-- policy-bound HTTP client
           |
           v
  operating-system controls / remote destinations

FUTURE:
  ExecutionTarget::Node(node_id) -> mutually authenticated Node Runtime
                                     -> same typed request semantics
```

The Personal AI Platform performs the first policy pass and creates approvals;
the broker independently revalidates all security-relevant bindings. The broker
does not trust a client assertion merely because it arrived over the local
socket.

## Components

### Personal AI Platform

The platform owns user interaction, agent/task context, permission assignment,
and approval issuance. Its Go client serializes the typed protocol and talks to
the local daemon. The client is a convenience and compatibility boundary, not a
security boundary: the daemon treats all client bytes as untrusted.

### Unix-domain-socket daemon

The Rust daemon provides a bounded Linux local request/response transport. The
Platform and broker use different unprivileged UIDs. Kernel peer credentials
select a root-configured `{platform UID -> user ID, agent ID}` principal before
broker policy; requester JSON must match it exactly. The setgid socket directory
and `0660` socket admit the configured Platform group without making the
Platform owner of the endpoint. Frame, connection, and read timeouts bound
transport abuse. Peer access never substitutes for permission or approval.

The daemon fails closed on platforms where this implementation cannot obtain a
supported peer UID. A future macOS transport must provide an equally explicit,
tested principal binding before `serve` is enabled there.

### Rust security core

The core owns canonical schemas, capability metadata, deterministic policy,
approval verification, replay prevention, audit records, Agent Green events,
and executor dispatch. Security-sensitive behavior remains in Rust. Unsafe Rust
is denied by workspace lint policy.

### Executors

The initial local executor surface is intentionally narrow:

- filesystem operations use configured root IDs and capability-relative APIs;
- `ExecuteApprovedCommand` launches a digest-pinned configured program through
  digest-pinned Linux `prlimit` and `bubblewrap`, with a validated argument
  vector and cleared environment; and
- `HttpRequest` uses a policy-bound HTTP implementation with explicit DNS and
  redirect handling.

Other declared capabilities require a separately reviewed backend. Until such a
backend is configured, dispatch returns an unsupported-capability error and
does not approximate the request through a shell or a more powerful executor.

### Approval verifier and replay ledger

Approval signatures use Ed25519 through a maintained library. The verifier
checks the signed fields against the validated request and atomically consumes
the nonce in durable storage before starting a consequential action. A token
that has been consumed remains consumed even when execution later fails.

### Audit and Agent Green outputs

Every accepted execution attempt produces structured audit state, including
requester, agent, task, capability, target, validated-argument hash, approval
metadata, timestamps, result, output digest, redacted error details, measurable
file changes, and contacted network destinations. Audit records form a hash
chain so deletion or reordering is detectable when the chain head is anchored
outside the file.

Security-relevant rejections and sandbox failures also go to a mandatory local
Agent Green spool. The request and capability schemas contain no switch that can
disable this path. Local spooling is a durable handoff, not proof that a remote
Agent Green collector received the event.

## Trust boundaries

| Boundary | Untrusted side | Trusted side | Required controls |
| --- | --- | --- | --- |
| TB1: proposal | LLM output | Personal AI Platform | typed schema, identity, permissions, approval UX |
| TB2: local IPC | socket client | Action Broker daemon | socket ACL, frame bounds, schema validation, independent authorization |
| TB3: authorization | signed request assertions | verifier/policy core | Ed25519 verification, exact field binding, expiry, durable nonce consumption |
| TB4: host effect | validated action | OS/filesystem/process | explicit roots, allowlists, least privilege, deadlines, resource/output bounds |
| TB5: network | URL/DNS/redirect data | HTTP executor | destination policy on every resolution and redirect, address pinning |
| TB6: telemetry | request/error/output data | audit and Agent Green | structured allowlisted fields, redaction, integrity chain, restricted storage |
| TB7: future node | local broker | remote Node Runtime | mutually authenticated channel, node authorization, same digest and capability semantics |

## Request lifecycle

Processing order is deterministic and fail closed:

1. Bound the transport frame and decode the protocol version.
2. Validate the tagged capability input and reject unknown fields/variants as
   defined by the versioned schema.
3. Authenticate or bind the transport principal and validate user, agent, and
   task identifiers.
4. Resolve the immutable capability descriptor and required permission.
5. Canonicalize the validated arguments and calculate their digest; bind the
   validated target as a separate signed field.
6. Evaluate risk, filesystem/network scope, timeout, and resource limits.
7. When approval is required, verify the signature and all bindings, then
   atomically consume the nonce in the durable replay ledger.
8. Create the initial audit record before dispatch.
9. Dispatch only to the executor registered for that exact typed capability and
   execution target. A missing backend is a rejection.
10. Enforce deadline, cancellation, output bounds, and executor-specific policy.
11. Finalize the audit record and emit any required Agent Green event.
12. Return a typed result or a redacted error; never return broker secrets.

Validation order may avoid unnecessary work, but it must not create a cheaper
path around approval, scope, or replay checks. Errors exposed to clients should
not reveal secret-path existence or verification-key details.

## Deterministic policy ownership

Capability descriptors and broker configuration are administrative inputs, not
per-request suggestions. A request may ask for less authority (for example, a
shorter timeout), but cannot expand an allowed root, network destination,
executable, approval lifetime, resource ceiling, or risk class.

Risk classes are explicit categories rather than properties inferred from which
executor handles an action:

```text
READ_ONLY              LOW_RISK_WRITE        REVERSIBLE_CHANGE
PRIVILEGED_CHANGE      DESTRUCTIVE           EXTERNAL_SIDE_EFFECT
```

Policy maps each category explicitly to permissions and approval types; it does
not rely on enum/string ordering. A capability- or target-specific rule may only
strengthen its declared minimum. Equal validated inputs and equal configuration
produce the same allow/deny decision.

## Remote execution boundary

`ExecutionTarget` is part of request canonicalization and approval binding.
`Local` and a future `Node(node_id)` use the same capability input and output
schemas. The node identifier, node policy version, and target resources must be
authorized; a remote runtime must repeat validation and enforcement rather than
trusting a prevalidated blob.

The local foundation does not tunnel unsupported actions to a node. Until a
mutually authenticated Node Runtime backend, node permission model, replay
coordination, and audit correlation are implemented, remote targets fail
closed.

## Language and dependency boundary

Security-sensitive runtime components are Rust. The Personal AI Platform client
is Go and uses the Go standard library. There is no TypeScript and no Python
production dependency. Development-only tooling must not become a runtime
prerequisite.

## Isolation limitations

The broker's validation, capability discipline, and process controls reduce
authority; they are not a formal containment proof. The current Linux command
path requires namespace isolation through `bubblewrap`; deployments can add
seccomp, cgroups, Landlock, or a dedicated worker where needed. The daemon and
approved-command capability are disabled on macOS until a separately reviewed
transport and isolation backend exists.

If a required sandbox property is unavailable, startup or the affected
capability must fail closed when that property is configured as mandatory.
Otherwise the limitation must be accepted explicitly in deployment policy and
recorded as residual risk. See [Sandbox](SANDBOX.md) and
[Operations](OPERATIONS.md).
