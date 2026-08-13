# Approval Tokens

## Purpose

Permissions answer whether a user/agent may request a class of action. Approval
tokens answer whether the approval service authorized this exact consequential
action for a short period. An approval is neither a session credential nor a
general delegation.

A valid token is necessary only where policy requires it, and is never
sufficient on its own. The broker also enforces current identity, permission,
risk, target, scope, sandbox, and capability policy.

## Signed bindings

The signed payload binds at least:

| Field | Security purpose |
| --- | --- |
| Token/schema version | Prevents ambiguous interpretation across protocol changes |
| Request ID | Binds the approval to one request envelope |
| User ID | Binds the approving/requesting user identity |
| Agent ID | Prevents transfer to another agent |
| Task ID | Limits authority to one task context |
| Capability | Prevents capability substitution |
| Arguments digest | Binds canonical validated arguments, including omitted/default semantics |
| Target | Binds local vs node execution and exact target identity |
| Issued at | Supports maximum-lifetime and future-token checks |
| Expiration | Bounds exposure; the maximum lifetime is broker policy |
| Approval type | Must satisfy the deterministic risk policy |
| Nonce | Provides single-use replay protection |

Deployment policy may additionally require issuer, audience, and not-before
fields. Adding a field must be versioned and included inside the
signed canonical payload, not supplied as unsigned envelope metadata.

The arguments digest is SHA-256 over RFC 8785/JCS serialization of the validated
typed arguments, not raw client JSON. Security-relevant defaults must therefore
be represented consistently. Changes in whitespace or field order do not
change the digest; the separately signed capability and token version prevent
the same arguments from being substituted into another capability/version.

## Envelope and cryptography

The compact v1 token is
`ab1.<key-id>.<base64url(JCS claims)>.<base64url(signature)>`. The key ID routes
verification to an administratively trusted public key; the signature covers
the exact canonical claims bytes. Changing the key ID cannot make an invalid
signature valid under the selected trusted key.

Signatures use Ed25519 through a maintained cryptographic library. Action Broker
does not implement curve arithmetic, hashing constructions, signature parsing,
or constant-time primitives from scratch.

The approval service holds signing keys. The broker receives verification keys
only. Verification keys are loaded from a restricted configuration source and
selected by key ID from an explicit trust set; clients cannot add a trusted key.

Signature encoding is strict and canonical. Malformed, noncanonical, unknown
version, unknown key, or invalid signature inputs are rejected without exposing
which internal verification step failed to an untrusted client.

## Verification sequence

For a request requiring approval, the broker:

1. validates request framing and the typed capability schema;
2. resolves the capability descriptor and canonicalizes validated arguments and
   `ExecutionTarget`;
3. parses the approval envelope with size and format bounds;
4. selects a configured verification key by exact key ID;
5. verifies the Ed25519 signature over the exact canonical signed payload;
6. validates version, issued-at/future bounds, expiry, and maximum token lifetime
   using the broker's clock policy;
7. compares user, agent, task, capability, arguments digest, and target with the
   request using exact typed equality;
8. checks that the approval type satisfies the action's effective risk policy;
9. enforces that key's activation, retirement, and revocation policy;
10. atomically inserts/consumes the nonce in the durable replay ledger; and
11. records approval metadata in audit state before dispatch.

The broker never edits a request to make it fit a token. Any mismatch is a
denial. Nonce consumption occurs only after the signature and bindings are
valid, so an unauthenticated caller cannot burn arbitrary signed nonces by
guessing them. It occurs before execution, so a crash, timeout, cancellation, or
executor error cannot make the token usable again.

## Durable replay ledger

The foundation stores consumed nonces in a durable SQLite ledger. Nonces are
globally single-use while retained in that ledger; the approval service must
generate them with sufficient uniqueness across keys. A primary-key constraint
and `IMMEDIATE` transaction make concurrent use deterministic: at most one
request consumes a token.

Ledger requirements are:

- durable across daemon restarts and process crashes;
- written and synchronized according to the configured durability profile
  before a consequential executor starts;
- inaccessible to socket clients and child processes;
- retained through token expiry plus a configured one-hour-to-one-year
  post-expiration interval (the one-hour floor exceeds the verifier's hard
  clock-skew maximum and supplies incident-response margin);
- bounded by a configured nonzero maximum of at most 10,000,000 rows and pruned
  in the same write transaction only after the retention interval has elapsed;
- failed closed before dispatch when the configured row capacity is exhausted;
- checked for SQLite integrity and admission headroom at startup;
- protected by a durable last-observed clock high-water mark so a backward
  correction after pruning stops authorization instead of reopening a replay
  window; and
- included in backup/restore and disaster-recovery procedures.

Restoring an old replay ledger can make previously consumed tokens appear
unused. After a rollback or uncertain restore, operators must keep execution
disabled, rotate/invalidate affected approval keys or epochs, and establish a
safe ledger state before resuming. Audit records alone are not a race-safe
replacement for the replay ledger.

A replay attempt generates an Agent Green `replayed_approval` event. Capacity
exhaustion generates a `resource_abuse_pattern` event. Ledger unavailability or
durability failure is an authorization failure, never a reason to skip replay
protection.

## Expiry and clocks

Tokens are deliberately short-lived. Broker configuration sets a maximum token
lifetime and bounded allowed clock skew; a token cannot request a longer window.
The expiration check occurs before nonce consumption and again immediately
before dispatch if validation or queuing could cross the deadline.

Expired and not-yet-valid tokens both return the external `approval_expired`
classification and generate an `expired_approval` event. This avoids exposing a
separate timing oracle while still denying outside the signed validity window.
A wall-clock jump is security-relevant: the daemon should use a monitored
trusted time source and a monotonic clock for elapsed execution deadlines. When
wall-clock correctness is uncertain beyond configured skew, approval-required
operations fail closed.

## Approval types

Approval types are stable, machine-readable policy values rather than free-form
labels. Protocol version 1 recognizes `EXPLICIT_USER`, `ELEVATED_USER`, and
`ADMINISTRATOR`. Bounded read-only descriptors may instead declare `PolicyOnly`,
which means permission and deterministic policy are sufficient and no token is
accepted as a substitute for missing permission. The policy maps each effective
risk and target to an explicit set of accepted types.

A correctly signed token with an approval type outside that exact accepted set
is rejected before nonce consumption. The external response remains the generic
`approval_invalid` classification so a caller cannot use the broker as an
approval-policy discovery oracle. The mandatory local security event uses the
same secret-free invalid-approval classification; it does not log the token or
approver evidence.

Approval ordering is explicit in configuration/code. String ordering or client
claims never establish that one type is stronger than another. A standing grant
must still be narrowly scoped and cannot authorize a capability, root,
destination, or program absent from current permission policy.

## Key rotation and revocation

The trust set and lifecycle policy are root-owned daemon configuration. Each key
entry requires:

- `active_from_unix_seconds`: inclusive broker-clock instant at which the key
  and approvals issued under it may first be accepted;
- `retire_at_unix_seconds`: optional exclusive issuance cutoff. Approvals issued
  before it may complete their ordinary short lifetime; approvals issued at or
  after it are rejected; and
- `revoke_at_unix_seconds`: optional hard cutoff. At or after it, every approval
  under the key is rejected regardless of issuance or expiration.

Activation is checked against both broker time and signed `issued_at`. Retirement
is checked against signed `issued_at`, permitting a deliberate overlap window
without extending any token's normal TTL. Revocation is checked against broker
time and signed issuance time. Lifecycle denial happens after signature and
claims validation but before nonce consumption, so an inactive, retired, or
revoked key cannot authorize execution and an invalid lifecycle attempt cannot
burn a nonce.

Key IDs are unique within a configuration; duplicate IDs, negative activation,
and retirement/revocation instants at or before activation fail startup. Rotation
lists old and new public keys simultaneously with non-overlapping issuance
windows and a bounded validation overlap no longer than the maximum approval
lifetime. Emergency response sets a hard revocation instant.

Lifecycle configuration is immutable for the running daemon. A root-owned
configuration change takes effect only after a validated restart; live atomic
reload is not implemented. Removing a key also invalidates its tokens after
restart, but explicit revocation preserves the reason and cutoff in reviewed
configuration. Operators must keep approval-required execution stopped between
deciding a revocation and completing the validated restart.

Compromise response includes:

1. disable approval-required execution;
2. set a hard revocation cutoff for the affected key ID/epoch in root-owned
   configuration;
3. preserve ledger, audit, and Agent Green evidence;
4. identify tokens and requests associated with the key without logging token
   bodies or signatures unnecessarily;
5. rotate signing and verification material through the platform's key process;
6. reconcile measurable side effects; and
7. restart and resume only after the known-good lifecycle policy, key material,
   clock, and ledger state are verified.

## Audit and secret handling

Audit records include whether approval was required, its verified key ID,
approval type, and a SHA-256 digest of the compact token for correlation. They
do not currently record a separate nonce digest or token expiry. They never
include signing keys, full bearer tokens,
signatures, secrets embedded in inputs, or raw approval-service responses.

Approval tampering, invalid binding, expiry, replay, and permission bypass
attempts produce structured Agent Green events with redacted identifiers. Event
delivery cannot be disabled by the request that caused the event.

## Non-goals

Approval tokens do not:

- authenticate the human approval user interface by themselves;
- make an unsafe capability implementation safe;
- make external side effects reversible;
- authorize privilege escalation or an unavailable sandbox;
- replace transport access controls, permissions, or deterministic policy; or
- allow the broker to execute arbitrary natural-language instructions.
