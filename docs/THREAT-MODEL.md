# Threat Model

## Security objective

Action Broker should execute only the exact typed action that a currently
authorized user and agent may perform, under the required approval, against the
approved target and scopes, with bounded resources and durable evidence.

The model is untrusted. Natural-language intent, model confidence, a local
socket connection, and a validly shaped request are not authorization.

## Assets

- host files, processes, services, credentials, devices, and user data;
- network identities, destinations, APIs, and externally visible state;
- approval signing keys and trusted verification-key configuration;
- replay ledger correctness and durability;
- capability, permission, risk, root, command, and network policy;
- broker and Agent Green availability and integrity;
- audit completeness, ordering, redaction, and chain integrity; and
- remote-node identity and policy when node execution is introduced.

## Adversaries and failure sources

- a prompt-injected, compromised, or simply mistaken model;
- malicious content returned by files, websites, tools, or remote nodes;
- a compromised or buggy Personal AI Platform client;
- a compromised Personal AI Platform running under its separately configured
  unprivileged UID and able to reach the group-restricted Unix socket;
- a user/agent with some valid permissions attempting to cross scopes;
- an attacker holding a stolen, expired, modified, or already-used approval;
- a malicious DNS authority, redirecting server, or public proxy target;
- a hostile approved subprocess exploiting argument, environment, filesystem,
  or resource behavior;
- races among concurrent requests, cancellation, restart, or ledger writes; and
- operator misconfiguration, unsupported OS behavior, clock failure, disk
  failure, or incomplete telemetry delivery.

## Assumptions

- The host kernel, broker binary, trusted Rust/Go dependencies, and deployment
  administrator are not already fully compromised.
- The approval service authenticates its approver and protects Ed25519 signing
  keys. The broker independently protects its trusted public-key configuration.
- The broker runs unprivileged with filesystem access limited by its service
  account and deployment isolation.
- Agent Green can consume the protected local spool, but remote delivery may be
  delayed. The spool itself remains mandatory and fail-closed when it cannot
  durably accept required events.
- TLS verification roots and the host resolver are managed as security-sensitive
  dependencies. DNS is not treated as proof that an address is safe.

If these assumptions do not hold, the deployment must not claim the
corresponding security property.

## Threats, controls, and residual risk

| Threat | Primary controls | Residual risk / limitation |
| --- | --- | --- |
| Model invokes a tool directly | No tool handles in model boundary; platform emits typed proposal; broker is only normal effect path | Another independently installed automation path is outside this broker and must be removed from model reach |
| Generic command smuggling | No generic executor; tagged schemas; exact executor dispatch; unsupported capabilities fail closed | An approved complex interpreter can recreate generic execution and must remain forbidden or separately sandboxed |
| Shell/argument injection | Direct process spawn, validated argv, fixed executable registry, no shell expansion | Bugs or dangerous option combinations in the approved program need program-specific validators |
| Environment/loader injection | `env_clear`, explicit key/value allowlist, loader-variable and arbitrary `PATH` rejection, closed descriptors | Approved runtimes may read configuration from files in their accessible view |
| Path traversal or prefix confusion | root IDs, relative-path validation, capability-oriented directory handles, component/type checks | Filesystem/OS semantics and race resistance vary; unsupported safe operations must deny |
| Symlink/hard-link/mount escape | handle-relative lookup, link rejection where required, object identity checks, least-privilege service account | Bind mounts, network filesystems, hard links, and concurrent mount changes require deployment controls |
| Secret access | secret-root deny policy, minimal broker account, no child inheritance, redacted output/audit | Secrets located inside an intentionally allowed root remain exposed unless classified and denied |
| Approval tampering/substitution | library Ed25519 verification; canonical payload binds identity, task, capability, args, target, expiry, type, nonce | Compromised signing service can issue valid malicious approvals |
| Stolen or retired approval key | required activation, exclusive issuance-retirement cutoff, hard revocation cutoff, bounded token TTL, root-owned immutable configuration | Lifecycle changes require a validated daemon restart; execution must stay stopped during emergency revocation |
| Approval replay/race, clock rollback, or ledger flooding | durable `IMMEDIATE` nonce transaction before dispatch, expiry-safe retention pruning, clock high-water mark, integrity check, configured row ceiling and startup headroom | Restoring stale ledger state requires key/epoch invalidation before resuming; a backward clock or full ledger intentionally stops consequential actions |
| Permission bypass | independent broker permission and descriptor checks; deny wins | Compromised policy/configuration authority can broaden access |
| SSRF and DNS rebinding | scheme/host/port policy, all-address validation, address pinning, manual redirect validation, metadata/private/localhost denial | A permitted public service can proxy internally; use egress controls and destination trust review |
| Redirect or hostname confusion | strict URL normalization, no userinfo, bounded manual redirects, TLS/SNI/Host coherence | Differences in external proxies or resolvers must not be silently introduced |
| Timeout/output flooding | deadlines, bounded collectors, output digest/truncation, bounded response frames | Kernel buffers, files written by the child, or remote side effects may occur before termination |
| Fork/resource abuse | rlimits, process groups, concurrency bounds; cgroups/PID namespace when required on Linux | Portable controls do not guarantee descendant or aggregate containment, especially on macOS |
| Privilege escalation | distinct unprivileged broker UID, exact real/effective/saved/fs IDs and supplementary groups, zero active Linux capability masks, inherited `NoNewPrivs`, immutable digest-pinned executables, setuid/setgid rejection | macOS entitlements and child post-exec privilege are not independently attested; keep profiles disabled where required |
| Concurrent lost update | expected pre-change digest/object identity, per-resource coordination, atomic ledger writes | External actors outside the broker can still race; operations that cannot bind state must fail or report conditional semantics |
| Git metadata indirection | exact rooted worktree, broker/root-owned bounded metadata walk, no links/alternates/includes, local-only isolated libgit2 configuration | Synchronous library calls are not forcibly preemptible; unusually large or corrupt repositories require a contained worker or must remain disabled |
| Process metadata disclosure or PID reuse | disabled-by-default non-root UID allowlist, bounded procfs reads, start-time and identity recheck, basename-only executable, no `cmdline` or `environ` access | Linux procfs visibility and mount policy vary; production evidence is host-specific |
| Cancellation ambiguity | authenticated scoped cancellation, process-group/worker termination, audit side effects | Cancellation cannot retract external effects or guarantee child cleanup without OS containment |
| Audit deletion/reordering or parser ambiguity | strict bounded JSONL, same-file no-symlink validation, hash chain, explicit cross-segment initial head, external final-head comparison | A local attacker controlling both log and every unanchored checkpoint can rewrite history |
| Secret leakage in telemetry | structured allowlisted audit/event fields, redaction, output digest rather than full output | Novel secret formats can evade redaction; avoid logging payloads by design |
| Agent Green disabled, suppressed, or storage-flooded | no request toggle, mandatory durable spool, strict bounded startup validation, configured capacity/headroom, active-file modification detection | A fully compromised host can tamper with both broker and spool; remote receipt and stop/archive/restart rotation are separately operated |
| Remote node semantic drift | target bound into approval; same schemas; node repeats policy; version/attestation gates | Future Node Runtime is not implemented by the local foundation and remote execution remains denied |

## Security events

The broker emits structured Agent Green events for at least:

| Event | Trigger |
| --- | --- |
| `permission_bypass_attempt` | Missing permission, unavailable peer credentials, unconfigured peer UID, privilege/scope downgrade attempt, or conflicting identity assertion |
| `expired_approval` | Approval outside its accepted time window |
| `replayed_approval` | Nonce already consumed or concurrent replay loses atomic consumption |
| `path_escape` | Absolute/traversal/link/mount resolution outside the selected root |
| `secret_access_attempt` | Target matches protected credential or secret policy |
| `forbidden_executable` | Program absent from registry or executable identity/arguments violate policy |
| `forbidden_destination` | Scheme, host, IP, port, redirect, localhost/private/metadata target violates policy |
| `resource_abuse_pattern` | Malformed protocol frames, connection, output, time, concurrency, process, CPU, memory, or file limit abuse |
| `sandbox_failure` | Required isolation/control could not be established or failed during execution |
| `unexpected_privilege_elevation` | Effective privilege exceeds the validated execution profile |

Events include request correlation, redacted identity/target metadata, reason
code, policy/configuration generation, and time. They exclude approval bearer
material, keys, credentials, file contents, request bodies, and raw sensitive
output. Requests cannot disable or lower the severity of event emission.

## Adversarial test matrix

The following cases are required. Each test must assert denial or bounded
termination, no unauthorized side effect, the correct redacted audit result,
and the expected Agent Green event where applicable.

| Test | Representative attempts | Required result |
| --- | --- | --- |
| Path traversal | `../`, absolute path, encoded separators, prefix collision, destination traversal | Deny before filesystem effect; `path_escape` |
| Symlink escape | final/intermediate link swapped before and during operation | No access outside root; deny on unverifiable race |
| Shell injection | metacharacters, substitution syntax, newline, redirection, pipeline text | Treated as invalid argv/data; no shell interpretation |
| Argument injection | leading option, split argument, `argv[0]` confusion, program-specific dangerous flag | Descriptor validator denies; executable unchanged |
| Environment injection | `PATH`, `LD_PRELOAD`, `DYLD_*`, proxy variables, inherited secret probes | Deny and child receives only allowlisted environment |
| Approval replay | sequential, concurrent, and post-restart reuse | Exactly one atomic consume; subsequent requests denied with `replayed_approval` |
| Approval tampering | change user, agent, task, capability, args, target, expiry, type, nonce, signature | Signature/binding denial; no nonce consumed for unauthenticated forgery |
| Key lifecycle | pre-activation use, issuance at retirement boundary, use at revocation boundary, duplicate key ID, incoherent windows | Deterministic denial before nonce consumption; invalid configuration fails startup |
| Timeout | silent hang, signal handling, descendant sleep | Bounded termination and truthful side-effect/audit state |
| Output flooding | stdout, stderr, alternating streams, binary data | Memory and response stay bounded; truncation/digest recorded |
| Fork/resource abuse | rapid descendants, memory/CPU/file-descriptor/file growth | Required host containment limits effect; otherwise capability disabled for that profile |
| Unauthorized network | disallowed scheme/host/port/IP and alternate IP encodings | Deny with `forbidden_destination` before request bytes are sent |
| DNS rebinding | approved answer changes before connect or redirect | Connection uses checked pinned address; new resolution is revalidated |
| Metadata endpoint | IPv4/IPv6/link-local/hostname and redirect aliases | Deny all unapproved representations |
| Secret file | SSH, cloud credentials, broker keys, credential-store paths through direct/link aliases | Deny with `secret_access_attempt`; do not reveal existence/content |
| Privilege escalation | setuid/capability executable, unexpected effective IDs, privileged helper | Deny/terminate; `unexpected_privilege_elevation` |
| Concurrent execution | conflicting writes, duplicate nonce, capacity saturation | Deterministic conflict/queue/deny; no lost authorization state |
| Cancellation | before dispatch, while queued, while running, after effect | Authenticated idempotent outcome; no false rollback claim |

Tests for cgroups, namespaces, seccomp, filesystem race behavior, and service
managers must be platform-gated and report a skip as unavailable evidence, not
as a successful guarantee. Production qualification requires running relevant
tests on the actual OS/filesystem/deployment profile.

## Denial-of-service posture

Action Broker protects bounded availability, not unlimited service. It caps
configured open connections at a hard ceiling of 128, applies a separate
per-peer ceiling, services a bounded queue with at most 64 fixed connection
workers, rejects sockets whose bounded queue-residence deadline expires, bounds
frames and socket reads/writes, and limits active actions, DNS/redirect work,
subprocess output, and audit/event record size. Admission is one atomic
global/per-peer state transition, so concurrent accepts cannot overshoot either
bound. Capacity and queue-age rejection of authenticated peers produce mandatory
secret-free Agent Green resource-abuse events before request parsing.
Peer-credential failures and unconfigured peer UIDs are likewise rejected and
recorded before parsing. A configured failure-window breaker pauses the accept
loop after its threshold, bounding event growth without silently accepting or
sampling an already accepted authentication failure. This deliberately permits
a member of the local IPC group to delay service; narrow group membership and
host-level connection controls remain part of the availability boundary.
Authenticated malformed, truncated, oversized, schema-invalid, and trailing
frame data are classified without retaining their bytes and recorded with the
bound principal. A worker-shared failure-window breaker bounds rejection rate.
Failures that occur only while returning an already computed response are not
misclassified as malicious request input.
Mandatory event failure marks the fixed worker pool unhealthy and the listener
terminates rather than continuing with reduced monitoring. Fatal accept errors
also emit a secret-free `sandbox_failure` before daemon shutdown.
Every fixed connection worker has an unwind-safe liveness guard. Readiness
requires the exact configured live count; return, panic, receiver failure, or
poisoned synchronization cannot silently reduce capacity. Lost-worker shutdown
is reported as `connection_worker_lost` when the mandatory event sink remains
available.
The broker enforces bounded global, per-principal, and per-capability in-flight
counts. Admission waits are bounded and cancellation-aware. It does not provide
weighted fairness, persistent queues, or per-principal scheduling guarantees;
deployments that require those properties must keep the peer set narrow or add
an external admission tier without bypassing broker authorization.

If audit, replay, or mandatory Agent Green storage is unavailable, consequential
execution stops. This permits an availability attack, but continuing without
authorization or evidence would violate the primary security objective.

## Out of scope / non-claims

The foundation does not claim protection from a compromised kernel or root,
formal noninterference, perfect secret detection, universal rollback, equivalent
Linux/macOS isolation, safe arbitrary interpreters, or delivery confirmation to
a remote Agent Green system. It also does not yet implement remote Node Runtime
execution or host-specific Git-write/browser/service/container backends merely
because their typed variants exist.
