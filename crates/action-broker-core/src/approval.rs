//! Verification of short-lived, signed, request-bound approval tokens.
//!
//! Tokens use Ed25519 from `ed25519-dalek`; this crate does not implement any
//! signature primitive. A compact token has four dot-separated fields:
//! `ab1.<key_id>.<base64url(JCS claims)>.<base64url(signature)>`.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use parking_lot::Mutex;
use rusqlite::{Connection, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::capability::{ApprovalType, CapabilityKind};
use crate::model::{ActionRequest, ExecutionTarget, ModelError};

/// Compact wire prefix for signed approval tokens.
pub const APPROVAL_TOKEN_PREFIX: &str = "ab1";
/// Claims version accepted by this verifier.
pub const APPROVAL_TOKEN_VERSION: u8 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const SHA256_HEX_BYTES: usize = 64;
const MAX_WIRE_TOKEN_BYTES: usize = 32 * 1024;
const MAX_KEY_ID_BYTES: usize = 64;
const MAX_NONCE_BYTES: usize = 128;
const HARD_MAXIMUM_TTL_SECONDS: i64 = 900;
const HARD_MAXIMUM_CLOCK_SKEW_SECONDS: i64 = 60;

/// Exact v1 claims signed by the platform approval service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalClaimsV1 {
    pub version: u8,
    pub request_id: Uuid,
    pub user_id: String,
    pub agent_id: String,
    pub task_id: String,
    pub capability: CapabilityKind,
    pub arguments_digest_sha256: String,
    pub target_digest_sha256: String,
    pub target: ExecutionTarget,
    pub issued_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
    pub approval_type: ApprovalType,
    pub nonce: String,
}

/// Parsed fields of the compact v1 wire token. `payload` and `signature` are
/// unpadded canonical base64url strings; the decoded payload bytes are what
/// Ed25519 signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalTokenV1 {
    pub key_id: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApproval {
    pub key_id: String,
    pub claims: ApprovalClaimsV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalVerifierConfig {
    pub maximum_ttl_seconds: i64,
    pub allowed_clock_skew_seconds: i64,
    pub maximum_payload_bytes: usize,
}

impl Default for ApprovalVerifierConfig {
    fn default() -> Self {
        Self {
            maximum_ttl_seconds: 300,
            allowed_clock_skew_seconds: 30,
            maximum_payload_bytes: 16 * 1024,
        }
    }
}

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("approval token is missing")]
    MissingToken,
    #[error("approval token format is invalid: {0}")]
    MalformedToken(&'static str),
    #[error("approval token references an untrusted key")]
    UntrustedKey,
    #[error("approval verification key is not active")]
    KeyNotActive,
    #[error("approval was issued after the verification key retired")]
    KeyRetired,
    #[error("approval verification key is revoked")]
    KeyRevoked,
    #[error("approval verification key lifecycle is invalid")]
    InvalidKeyLifecycle,
    #[error("approval verification key ID is duplicated")]
    DuplicateKeyId,
    #[error("approval signature is invalid")]
    InvalidSignature,
    #[error("approval payload is not canonical JCS JSON")]
    NonCanonicalPayload,
    #[error("approval payload is invalid: {0}")]
    InvalidPayload(#[source] serde_json::Error),
    #[error("approval token version is unsupported")]
    UnsupportedVersion,
    #[error("approval token was issued in the future")]
    NotYetValid,
    #[error("approval token has expired")]
    Expired,
    #[error("approval token lifetime is invalid")]
    InvalidLifetime,
    #[error("approval type does not satisfy this capability")]
    ApprovalTypeMismatch,
    #[error("approval does not bind the request field: {field}")]
    BindingMismatch { field: &'static str },
    #[error("approval token nonce has already been consumed")]
    ReplayDetected,
    #[error("replay store is unavailable: {0}")]
    ReplayStoreUnavailable(String),
    #[error("system clock precedes the Unix epoch")]
    InvalidSystemClock,
    #[error(transparent)]
    ArgumentsDigest(#[from] ModelError),
    #[error("could not serialize approval claims canonically: {0}")]
    CanonicalSerialization(#[source] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum ReplayStoreError {
    #[error("nonce has already been consumed")]
    ReplayDetected,
    #[error("replay backend failure: {0}")]
    Backend(String),
}

/// Atomically records nonce consumption. Implementations must return exactly
/// one success for concurrent calls with the same nonce.
pub trait ReplayStore: Send + Sync {
    /// Consumes a nonce for the first time.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayStoreError::ReplayDetected`] if the nonce is already
    /// present, or [`ReplayStoreError::Backend`] on storage failure.
    fn consume(
        &self,
        nonce: &str,
        request_id: Uuid,
        expires_at_unix_seconds: i64,
    ) -> Result<(), ReplayStoreError>;
}

/// Durable `SQLite` replay protection. The nonce primary key makes consumption
/// atomic across threads, verifier instances, and processes using the same DB.
pub struct SqliteReplayStore {
    connection: Mutex<Connection>,
}

impl SqliteReplayStore {
    /// Opens or creates a durable replay database.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayStoreError::Backend`] if `SQLite` cannot open or
    /// initialize the database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayStoreError> {
        let connection = Connection::open(path).map_err(|error| replay_backend(&error))?;
        Self::from_connection(connection)
    }

    /// Creates a process-local `SQLite` replay database, intended for tests.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayStoreError::Backend`] if `SQLite` cannot initialize the
    /// database.
    pub fn in_memory() -> Result<Self, ReplayStoreError> {
        let connection = Connection::open_in_memory().map_err(|error| replay_backend(&error))?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, ReplayStoreError> {
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS consumed_approval_nonces (
                     nonce TEXT PRIMARY KEY NOT NULL,
                     request_id TEXT NOT NULL,
                     expires_at_unix_seconds INTEGER NOT NULL,
                     consumed_at_unix_seconds INTEGER NOT NULL
                 ) WITHOUT ROWID;",
            )
            .map_err(|error| replay_backend(&error))?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
}

impl ReplayStore for SqliteReplayStore {
    fn consume(
        &self,
        nonce: &str,
        request_id: Uuid,
        expires_at_unix_seconds: i64,
    ) -> Result<(), ReplayStoreError> {
        let consumed_at =
            unix_time_now().map_err(|error| ReplayStoreError::Backend(error.to_string()))?;
        let changed = self
            .connection
            .lock()
            .execute(
                "INSERT INTO consumed_approval_nonces
                 (nonce, request_id, expires_at_unix_seconds, consumed_at_unix_seconds)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(nonce) DO NOTHING",
                params![
                    nonce,
                    request_id.to_string(),
                    expires_at_unix_seconds,
                    consumed_at
                ],
            )
            .map_err(|error| replay_backend(&error))?;

        if changed == 1 {
            Ok(())
        } else {
            Err(ReplayStoreError::ReplayDetected)
        }
    }
}

fn replay_backend(error: &rusqlite::Error) -> ReplayStoreError {
    ReplayStoreError::Backend(error.to_string())
}

/// Lightweight replay store for deterministic tests and non-durable harnesses.
/// Production broker configurations should use [`SqliteReplayStore`].
#[derive(Default)]
pub struct InMemoryReplayStore {
    consumed: Mutex<HashSet<String>>,
}

impl ReplayStore for InMemoryReplayStore {
    fn consume(
        &self,
        nonce: &str,
        _request_id: Uuid,
        _expires_at_unix_seconds: i64,
    ) -> Result<(), ReplayStoreError> {
        if self.consumed.lock().insert(nonce.to_owned()) {
            Ok(())
        } else {
            Err(ReplayStoreError::ReplayDetected)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedKeyLifecycle {
    /// Inclusive instant at which the key may begin verifying approvals.
    pub active_from_unix_seconds: i64,
    /// Exclusive approval issuance cutoff. Tokens issued before this instant
    /// may finish their normal short lifetime unless the key is revoked.
    pub retire_at_unix_seconds: Option<i64>,
    /// Hard cutoff. At or after this instant every token under the key fails.
    pub revoke_at_unix_seconds: Option<i64>,
}

struct TrustedKey {
    key: VerifyingKey,
    lifecycle: TrustedKeyLifecycle,
}

#[derive(Default)]
pub struct TrustedKeyRegistry {
    keys: BTreeMap<String, TrustedKey>,
}

impl TrustedKeyRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Adds a trusted Ed25519 public key and its immutable lifecycle under a
    /// policy-controlled key ID.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::MalformedToken`] for an invalid key ID,
    /// [`ApprovalError::InvalidKeyLifecycle`] for invalid time bounds, or
    /// [`ApprovalError::DuplicateKeyId`] when the ID is already present.
    pub fn insert(
        &mut self,
        key_id: impl Into<String>,
        key: VerifyingKey,
        lifecycle: TrustedKeyLifecycle,
    ) -> Result<(), ApprovalError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        validate_key_lifecycle(lifecycle)?;
        if self.keys.contains_key(&key_id) {
            return Err(ApprovalError::DuplicateKeyId);
        }
        self.keys.insert(key_id, TrustedKey { key, lifecycle });
        Ok(())
    }

    fn get(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.get(key_id)
    }
}

/// Approval verifier with immutable trusted keys and an atomic replay store.
pub struct ApprovalVerifier {
    trusted_keys: TrustedKeyRegistry,
    replay_store: Arc<dyn ReplayStore>,
    config: ApprovalVerifierConfig,
}

impl ApprovalVerifier {
    /// Creates a verifier after checking all fail-closed limits.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::InvalidLifetime`] when TTL, clock-skew, or
    /// payload bounds are not positive and bounded.
    pub fn new(
        trusted_keys: TrustedKeyRegistry,
        replay_store: Arc<dyn ReplayStore>,
        config: ApprovalVerifierConfig,
    ) -> Result<Self, ApprovalError> {
        if config.maximum_ttl_seconds <= 0
            || config.maximum_ttl_seconds > HARD_MAXIMUM_TTL_SECONDS
            || config.allowed_clock_skew_seconds < 0
            || config.allowed_clock_skew_seconds > HARD_MAXIMUM_CLOCK_SKEW_SECONDS
            || config.maximum_payload_bytes == 0
            || config.maximum_payload_bytes > MAX_WIRE_TOKEN_BYTES
        {
            return Err(ApprovalError::InvalidLifetime);
        }
        Ok(Self {
            trusted_keys,
            replay_store,
            config,
        })
    }

    /// Verifies the token embedded in a request using the current system time.
    ///
    /// # Errors
    ///
    /// Returns an [`ApprovalError`] if the token, signature, claims, request
    /// bindings, time bounds, approval type, or replay check fails.
    pub fn verify_embedded(
        &self,
        request: &ActionRequest,
        accepted_types: &[ApprovalType],
    ) -> Result<VerifiedApproval, ApprovalError> {
        let now = unix_time_now()?;
        let token = request
            .approval_token
            .as_deref()
            .ok_or(ApprovalError::MissingToken)?;
        self.verify_at(token, request, accepted_types, now)
    }

    /// Verifies and atomically consumes a token at an explicit Unix time.
    /// Replay consumption happens only after every other verification step.
    ///
    /// # Errors
    ///
    /// Returns an [`ApprovalError`] if the token, signature, claims, request
    /// bindings, time bounds, approval type, or replay check fails.
    pub fn verify_at(
        &self,
        compact_token: &str,
        request: &ActionRequest,
        accepted_types: &[ApprovalType],
        now_unix_seconds: i64,
    ) -> Result<VerifiedApproval, ApprovalError> {
        let token = SignedApprovalTokenV1::parse_compact(compact_token)?;
        let payload = decode_canonical_base64url(&token.payload, "payload encoding")?;
        if payload.len() > self.config.maximum_payload_bytes {
            return Err(ApprovalError::MalformedToken("payload is too large"));
        }
        let signature_bytes = decode_canonical_base64url(&token.signature, "signature encoding")?;
        if signature_bytes.len() != ED25519_SIGNATURE_BYTES {
            return Err(ApprovalError::MalformedToken("signature length is invalid"));
        }

        let trusted_key = self
            .trusted_keys
            .get(&token.key_id)
            .ok_or(ApprovalError::UntrustedKey)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| ApprovalError::MalformedToken("signature bytes are invalid"))?;
        trusted_key
            .key
            .verify_strict(&payload, &signature)
            .map_err(|_| ApprovalError::InvalidSignature)?;

        let claims: ApprovalClaimsV1 =
            serde_json::from_slice(&payload).map_err(ApprovalError::InvalidPayload)?;
        let canonical =
            serde_jcs::to_vec(&claims).map_err(ApprovalError::CanonicalSerialization)?;
        if canonical != payload {
            return Err(ApprovalError::NonCanonicalPayload);
        }

        self.validate_claims(&claims, request, accepted_types, now_unix_seconds)?;
        validate_key_use(trusted_key.lifecycle, &claims, now_unix_seconds)?;
        self.replay_store
            .consume(
                &claims.nonce,
                claims.request_id,
                claims.expires_at_unix_seconds,
            )
            .map_err(|error| match error {
                ReplayStoreError::ReplayDetected => ApprovalError::ReplayDetected,
                ReplayStoreError::Backend(message) => {
                    ApprovalError::ReplayStoreUnavailable(message)
                }
            })?;

        Ok(VerifiedApproval {
            key_id: token.key_id,
            claims,
        })
    }

    fn validate_claims(
        &self,
        claims: &ApprovalClaimsV1,
        request: &ActionRequest,
        accepted_types: &[ApprovalType],
        now_unix_seconds: i64,
    ) -> Result<(), ApprovalError> {
        if claims.version != APPROVAL_TOKEN_VERSION {
            return Err(ApprovalError::UnsupportedVersion);
        }
        validate_nonce(&claims.nonce)?;
        validate_sha256(&claims.arguments_digest_sha256)?;
        validate_sha256(&claims.target_digest_sha256)?;

        let lifetime = claims
            .expires_at_unix_seconds
            .checked_sub(claims.issued_at_unix_seconds)
            .ok_or(ApprovalError::InvalidLifetime)?;
        if claims.issued_at_unix_seconds < 0
            || lifetime <= 0
            || lifetime > self.config.maximum_ttl_seconds
        {
            return Err(ApprovalError::InvalidLifetime);
        }
        if claims.issued_at_unix_seconds
            > now_unix_seconds.saturating_add(self.config.allowed_clock_skew_seconds)
        {
            return Err(ApprovalError::NotYetValid);
        }
        if now_unix_seconds
            >= claims
                .expires_at_unix_seconds
                .saturating_add(self.config.allowed_clock_skew_seconds)
        {
            return Err(ApprovalError::Expired);
        }
        if !accepted_types.contains(&claims.approval_type) {
            return Err(ApprovalError::ApprovalTypeMismatch);
        }

        binding(claims.request_id == request.request_id, "request_id")?;
        binding(
            claims.user_id == request.requester.user_id,
            "requester.user_id",
        )?;
        binding(
            claims.agent_id == request.requester.agent_id,
            "requester.agent_id",
        )?;
        binding(
            claims.task_id == request.requester.task_id,
            "requester.task_id",
        )?;
        binding(claims.capability == request.capability(), "capability")?;
        binding(claims.target == request.target, "target")?;
        binding(
            claims.target_digest_sha256 == request.target_digest()?,
            "target_digest_sha256",
        )?;
        binding(
            claims.arguments_digest_sha256 == request.arguments_digest()?,
            "arguments_digest_sha256",
        )?;
        Ok(())
    }
}

impl SignedApprovalTokenV1 {
    /// Strictly parses the compact v1 token and validates each encoding.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::MalformedToken`] if the token does not use the
    /// exact four-part `ab1` format or canonical unpadded base64url.
    pub fn parse_compact(compact: &str) -> Result<Self, ApprovalError> {
        if compact.len() > MAX_WIRE_TOKEN_BYTES {
            return Err(ApprovalError::MalformedToken("token is too large"));
        }
        let mut parts = compact.split('.');
        let fields = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        );
        let (Some(prefix), Some(key_id), Some(payload), Some(signature), None) = fields else {
            return Err(ApprovalError::MalformedToken(
                "expected ab1.key_id.payload.signature",
            ));
        };
        if prefix != APPROVAL_TOKEN_PREFIX {
            return Err(ApprovalError::MalformedToken(
                "expected ab1.key_id.payload.signature",
            ));
        }
        validate_key_id(key_id)?;
        let _payload_bytes = decode_canonical_base64url(payload, "payload encoding")?;
        let signature_bytes = decode_canonical_base64url(signature, "signature encoding")?;
        if signature_bytes.len() != ED25519_SIGNATURE_BYTES {
            return Err(ApprovalError::MalformedToken("signature length is invalid"));
        }

        Ok(Self {
            key_id: key_id.to_owned(),
            payload: payload.to_owned(),
            signature: signature.to_owned(),
        })
    }

    /// Serializes the validated compact wire representation.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::MalformedToken`] if any public field has been
    /// changed to an invalid value.
    pub fn to_compact(&self) -> Result<String, ApprovalError> {
        validate_key_id(&self.key_id)?;
        let _payload = decode_canonical_base64url(&self.payload, "payload encoding")?;
        let signature = decode_canonical_base64url(&self.signature, "signature encoding")?;
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(ApprovalError::MalformedToken("signature length is invalid"));
        }
        Ok(format!(
            "{APPROVAL_TOKEN_PREFIX}.{}.{}.{}",
            self.key_id, self.payload, self.signature
        ))
    }
}

fn binding(condition: bool, field: &'static str) -> Result<(), ApprovalError> {
    if condition {
        Ok(())
    } else {
        Err(ApprovalError::BindingMismatch { field })
    }
}

fn validate_key_id(key_id: &str) -> Result<(), ApprovalError> {
    if key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_BYTES
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ApprovalError::MalformedToken("key ID is invalid"));
    }
    Ok(())
}

fn validate_key_lifecycle(lifecycle: TrustedKeyLifecycle) -> Result<(), ApprovalError> {
    if lifecycle.active_from_unix_seconds < 0
        || lifecycle
            .retire_at_unix_seconds
            .is_some_and(|retirement| retirement <= lifecycle.active_from_unix_seconds)
        || lifecycle
            .revoke_at_unix_seconds
            .is_some_and(|revocation| revocation <= lifecycle.active_from_unix_seconds)
    {
        return Err(ApprovalError::InvalidKeyLifecycle);
    }
    Ok(())
}

fn validate_key_use(
    lifecycle: TrustedKeyLifecycle,
    claims: &ApprovalClaimsV1,
    now_unix_seconds: i64,
) -> Result<(), ApprovalError> {
    if now_unix_seconds < lifecycle.active_from_unix_seconds
        || claims.issued_at_unix_seconds < lifecycle.active_from_unix_seconds
    {
        return Err(ApprovalError::KeyNotActive);
    }
    if lifecycle
        .retire_at_unix_seconds
        .is_some_and(|retirement| claims.issued_at_unix_seconds >= retirement)
    {
        return Err(ApprovalError::KeyRetired);
    }
    if lifecycle.revoke_at_unix_seconds.is_some_and(|revocation| {
        now_unix_seconds >= revocation || claims.issued_at_unix_seconds >= revocation
    }) {
        return Err(ApprovalError::KeyRevoked);
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<(), ApprovalError> {
    if nonce.len() < 16
        || nonce.len() > MAX_NONCE_BYTES
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ApprovalError::MalformedToken("nonce is invalid"));
    }
    Ok(())
}

fn validate_sha256(digest: &str) -> Result<(), ApprovalError> {
    if digest.len() != SHA256_HEX_BYTES
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApprovalError::MalformedToken(
            "SHA-256 digest must be lowercase hexadecimal",
        ));
    }
    Ok(())
}

fn decode_canonical_base64url(
    encoded: &str,
    context: &'static str,
) -> Result<Vec<u8>, ApprovalError> {
    if encoded.is_empty() || encoded.contains('=') {
        return Err(ApprovalError::MalformedToken(context));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApprovalError::MalformedToken(context))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(ApprovalError::MalformedToken(context));
    }
    Ok(decoded)
}

fn unix_time_now() -> Result<i64, ApprovalError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApprovalError::InvalidSystemClock)?;
    i64::try_from(duration.as_secs()).map_err(|_| ApprovalError::InvalidSystemClock)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::{
        ApprovalClaimsV1, ApprovalError, ApprovalVerifier, ApprovalVerifierConfig,
        InMemoryReplayStore, SignedApprovalTokenV1, SqliteReplayStore, TrustedKeyLifecycle,
        TrustedKeyRegistry,
    };
    use crate::capability::{
        ApprovalType, CapabilityAction, ReadFileInput, RootedPath, WriteFileInput,
    };
    use crate::model::{
        ACTION_BROKER_PROTOCOL_VERSION, ActionRequest, ExecutionTarget, RequesterIdentity,
    };

    const NOW: i64 = 2_000_000_000;
    const KEY_ID: &str = "approval-key-1";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn request() -> ActionRequest {
        ActionRequest {
            protocol_version: ACTION_BROKER_PROTOCOL_VERSION,
            request_id: Uuid::from_u128(42),
            requester: RequesterIdentity {
                user_id: "user-1".to_owned(),
                agent_id: "agent-1".to_owned(),
                task_id: "task-1".to_owned(),
            },
            target: ExecutionTarget::Local,
            action: CapabilityAction::WriteFile(WriteFileInput {
                path: RootedPath {
                    root_id: "workspace".to_owned(),
                    relative_path: "notes/approved.txt".to_owned(),
                },
                content_base64: "c2FmZQ".to_owned(),
                expected_prechange_sha256: None,
                create_if_missing: false,
            }),
            approval_token: None,
        }
    }

    fn claims(request: &ActionRequest, nonce: &str) -> Result<ApprovalClaimsV1, ApprovalError> {
        Ok(ApprovalClaimsV1 {
            version: 1,
            request_id: request.request_id,
            user_id: request.requester.user_id.clone(),
            agent_id: request.requester.agent_id.clone(),
            task_id: request.requester.task_id.clone(),
            capability: request.capability(),
            arguments_digest_sha256: request.arguments_digest()?,
            target_digest_sha256: request.target_digest()?,
            target: request.target.clone(),
            issued_at_unix_seconds: NOW - 1,
            expires_at_unix_seconds: NOW + 60,
            approval_type: ApprovalType::ExplicitUser,
            nonce: nonce.to_owned(),
        })
    }

    fn sign(claims: &ApprovalClaimsV1) -> Result<String, ApprovalError> {
        let payload = serde_jcs::to_vec(claims).map_err(ApprovalError::CanonicalSerialization)?;
        let signature = signing_key().sign(&payload);
        SignedApprovalTokenV1 {
            key_id: KEY_ID.to_owned(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
        .to_compact()
    }

    fn verifier(store: Arc<dyn super::ReplayStore>) -> Result<ApprovalVerifier, ApprovalError> {
        verifier_with_lifecycle(
            store,
            TrustedKeyLifecycle {
                active_from_unix_seconds: NOW - 10_000,
                retire_at_unix_seconds: None,
                revoke_at_unix_seconds: None,
            },
        )
    }

    fn verifier_with_lifecycle(
        store: Arc<dyn super::ReplayStore>,
        lifecycle: TrustedKeyLifecycle,
    ) -> Result<ApprovalVerifier, ApprovalError> {
        let mut keys = TrustedKeyRegistry::new();
        keys.insert(KEY_ID, signing_key().verifying_key(), lifecycle)?;
        ApprovalVerifier::new(keys, store, ApprovalVerifierConfig::default())
    }

    #[test]
    fn verifies_once_then_rejects_replay() -> Result<(), Box<dyn Error>> {
        let request = request();
        let token = sign(&claims(&request, "nonce-replay-0001")?)?;
        let verifier = verifier(Arc::new(InMemoryReplayStore::default()))?;

        assert!(
            verifier
                .verify_at(&token, &request, &[ApprovalType::ExplicitUser], NOW)
                .is_ok()
        );
        assert!(matches!(
            verifier.verify_at(&token, &request, &[ApprovalType::ExplicitUser], NOW),
            Err(ApprovalError::ReplayDetected)
        ));
        Ok(())
    }

    #[test]
    fn rejects_tampered_payload_before_consuming_nonce() -> Result<(), Box<dyn Error>> {
        let request = request();
        let claims = claims(&request, "nonce-tamper-0001")?;
        let token = sign(&claims)?;
        let parsed = SignedApprovalTokenV1::parse_compact(&token)?;
        let mut tampered_claims = claims.clone();
        tampered_claims.task_id = "attacker-task".to_owned();
        let tampered_payload = serde_jcs::to_vec(&tampered_claims)?;
        let tampered = SignedApprovalTokenV1 {
            payload: URL_SAFE_NO_PAD.encode(tampered_payload),
            ..parsed
        }
        .to_compact()?;
        let verifier = verifier(Arc::new(InMemoryReplayStore::default()))?;

        assert!(matches!(
            verifier.verify_at(&tampered, &request, &[ApprovalType::ExplicitUser], NOW),
            Err(ApprovalError::InvalidSignature)
        ));
        assert!(
            verifier
                .verify_at(&token, &request, &[ApprovalType::ExplicitUser], NOW)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn rejects_expiry_and_excessive_ttl() -> Result<(), Box<dyn Error>> {
        let request = request();
        let mut expired_claims = claims(&request, "nonce-expired-001")?;
        expired_claims.issued_at_unix_seconds = NOW - 100;
        expired_claims.expires_at_unix_seconds = NOW - 31;
        let expired = sign(&expired_claims)?;
        let verifier = verifier(Arc::new(InMemoryReplayStore::default()))?;
        assert!(matches!(
            verifier.verify_at(&expired, &request, &[ApprovalType::ExplicitUser], NOW),
            Err(ApprovalError::Expired)
        ));

        let mut long_claims = claims(&request, "nonce-too-long-001")?;
        long_claims.expires_at_unix_seconds = NOW + 600;
        let too_long = sign(&long_claims)?;
        assert!(matches!(
            verifier.verify_at(&too_long, &request, &[ApprovalType::ExplicitUser], NOW),
            Err(ApprovalError::InvalidLifetime)
        ));
        Ok(())
    }

    #[test]
    fn rejects_every_wrong_request_binding() -> Result<(), Box<dyn Error>> {
        let approved_request = request();
        let expected = claims(&approved_request, "nonce-bindings-001")?;

        let mut variants = Vec::new();
        let mut changed = approved_request.clone();
        changed.request_id = Uuid::from_u128(99);
        variants.push(changed);
        let mut changed = approved_request.clone();
        changed.requester.user_id = "other-user".to_owned();
        variants.push(changed);
        let mut changed = approved_request.clone();
        changed.requester.agent_id = "other-agent".to_owned();
        variants.push(changed);
        let mut changed = approved_request.clone();
        changed.requester.task_id = "other-task".to_owned();
        variants.push(changed);
        let mut changed = approved_request.clone();
        changed.target = ExecutionTarget::Node {
            node_id: "node-1".to_owned(),
        };
        variants.push(changed);
        let mut changed = approved_request.clone();
        changed.action = CapabilityAction::ReadFile(ReadFileInput {
            path: RootedPath {
                root_id: "workspace".to_owned(),
                relative_path: "notes/approved.txt".to_owned(),
            },
            maximum_bytes: 1_024,
        });
        variants.push(changed);
        let mut changed = approved_request.clone();
        if let CapabilityAction::WriteFile(arguments) = &mut changed.action {
            arguments.path.relative_path = "notes/different.txt".to_owned();
        }
        variants.push(changed);

        for (index, changed_request) in variants.iter().enumerate() {
            let mut unique_claims = expected.clone();
            unique_claims.nonce = format!("nonce-binding-{index:04}");
            let token = sign(&unique_claims)?;
            let verifier = verifier(Arc::new(InMemoryReplayStore::default()))?;
            assert!(matches!(
                verifier.verify_at(&token, changed_request, &[ApprovalType::ExplicitUser], NOW),
                Err(ApprovalError::BindingMismatch { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn enforces_approval_type() -> Result<(), Box<dyn Error>> {
        let request = request();
        let token = sign(&claims(&request, "nonce-type-000001")?)?;
        let verifier = verifier(Arc::new(InMemoryReplayStore::default()))?;
        assert!(matches!(
            verifier.verify_at(&token, &request, &[ApprovalType::Administrator], NOW),
            Err(ApprovalError::ApprovalTypeMismatch)
        ));
        Ok(())
    }

    #[test]
    fn enforces_key_activation_boundary_without_consuming_nonce() -> Result<(), Box<dyn Error>> {
        let request = request();
        let mut approval = claims(&request, "nonce-activation-01")?;
        approval.issued_at_unix_seconds = NOW;
        let token = sign(&approval)?;
        let lifecycle = TrustedKeyLifecycle {
            active_from_unix_seconds: NOW,
            retire_at_unix_seconds: None,
            revoke_at_unix_seconds: None,
        };
        let store = Arc::new(InMemoryReplayStore::default());
        let early = verifier_with_lifecycle(store.clone(), lifecycle)?;
        assert!(matches!(
            early.verify_at(&token, &request, &[ApprovalType::ExplicitUser], NOW - 1),
            Err(ApprovalError::KeyNotActive)
        ));
        let active = verifier_with_lifecycle(store, lifecycle)?;
        assert!(
            active
                .verify_at(&token, &request, &[ApprovalType::ExplicitUser], NOW)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn retirement_blocks_new_issuance_but_honors_prior_short_lived_token()
    -> Result<(), Box<dyn Error>> {
        let request = request();
        let lifecycle = TrustedKeyLifecycle {
            active_from_unix_seconds: NOW - 10_000,
            retire_at_unix_seconds: Some(NOW),
            revoke_at_unix_seconds: None,
        };
        let mut prior = claims(&request, "nonce-retired-prior")?;
        prior.issued_at_unix_seconds = NOW - 1;
        let prior_token = sign(&prior)?;
        let verifier =
            verifier_with_lifecycle(Arc::new(InMemoryReplayStore::default()), lifecycle)?;
        assert!(
            verifier
                .verify_at(&prior_token, &request, &[ApprovalType::ExplicitUser], NOW)
                .is_ok()
        );

        let mut retired = claims(&request, "nonce-retired-new01")?;
        retired.issued_at_unix_seconds = NOW;
        let retired_token = sign(&retired)?;
        let verifier =
            verifier_with_lifecycle(Arc::new(InMemoryReplayStore::default()), lifecycle)?;
        assert!(matches!(
            verifier.verify_at(&retired_token, &request, &[ApprovalType::ExplicitUser], NOW),
            Err(ApprovalError::KeyRetired)
        ));
        Ok(())
    }

    #[test]
    fn revocation_is_a_hard_cutoff_and_does_not_consume_nonce() -> Result<(), Box<dyn Error>> {
        let request = request();
        let token = sign(&claims(&request, "nonce-revoked-0001")?)?;
        let shared_store = Arc::new(InMemoryReplayStore::default());
        let revoked = verifier_with_lifecycle(
            shared_store.clone(),
            TrustedKeyLifecycle {
                active_from_unix_seconds: NOW - 10_000,
                retire_at_unix_seconds: None,
                revoke_at_unix_seconds: Some(NOW),
            },
        )?;
        assert!(matches!(
            revoked.verify_at(&token, &request, &[ApprovalType::ExplicitUser], NOW),
            Err(ApprovalError::KeyRevoked)
        ));

        let unrevoked = verifier_with_lifecycle(
            shared_store,
            TrustedKeyLifecycle {
                active_from_unix_seconds: NOW - 10_000,
                retire_at_unix_seconds: None,
                revoke_at_unix_seconds: None,
            },
        )?;
        assert!(
            unrevoked
                .verify_at(&token, &request, &[ApprovalType::ExplicitUser], NOW)
                .is_ok()
        );

        let mut post_revocation = claims(&request, "nonce-revoked-future")?;
        post_revocation.issued_at_unix_seconds = NOW + 10;
        let post_revocation_token = sign(&post_revocation)?;
        let scheduled = verifier_with_lifecycle(
            Arc::new(InMemoryReplayStore::default()),
            TrustedKeyLifecycle {
                active_from_unix_seconds: NOW - 10_000,
                retire_at_unix_seconds: None,
                revoke_at_unix_seconds: Some(NOW + 10),
            },
        )?;
        assert!(matches!(
            scheduled.verify_at(
                &post_revocation_token,
                &request,
                &[ApprovalType::ExplicitUser],
                NOW
            ),
            Err(ApprovalError::KeyRevoked)
        ));
        Ok(())
    }

    #[test]
    fn registry_rejects_invalid_lifecycle_and_duplicate_key_id() -> Result<(), Box<dyn Error>> {
        let mut keys = TrustedKeyRegistry::new();
        assert!(matches!(
            keys.insert(
                KEY_ID,
                signing_key().verifying_key(),
                TrustedKeyLifecycle {
                    active_from_unix_seconds: NOW,
                    retire_at_unix_seconds: Some(NOW),
                    revoke_at_unix_seconds: None,
                }
            ),
            Err(ApprovalError::InvalidKeyLifecycle)
        ));
        let lifecycle = TrustedKeyLifecycle {
            active_from_unix_seconds: NOW - 1,
            retire_at_unix_seconds: None,
            revoke_at_unix_seconds: None,
        };
        keys.insert(KEY_ID, signing_key().verifying_key(), lifecycle)?;
        assert!(matches!(
            keys.insert(KEY_ID, signing_key().verifying_key(), lifecycle),
            Err(ApprovalError::DuplicateKeyId)
        ));
        Ok(())
    }

    #[test]
    fn sqlite_replay_state_survives_reopen() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let database = directory.path().join("replay.sqlite3");
        let request = request();
        let token = sign(&claims(&request, "nonce-durable-0001")?)?;

        let first = verifier(Arc::new(SqliteReplayStore::open(&database)?))?;
        assert!(
            first
                .verify_at(&token, &request, &[ApprovalType::ExplicitUser], NOW)
                .is_ok()
        );
        drop(first);

        let second = verifier(Arc::new(SqliteReplayStore::open(&database)?))?;
        assert!(matches!(
            second.verify_at(&token, &request, &[ApprovalType::ExplicitUser], NOW),
            Err(ApprovalError::ReplayDetected)
        ));
        Ok(())
    }

    #[test]
    fn concurrent_replay_has_exactly_one_winner() -> Result<(), Box<dyn Error>> {
        const WORKERS: usize = 16;
        let request = Arc::new(request());
        let token = Arc::new(sign(&claims(&request, "nonce-concurrent01")?)?);
        let verifier = Arc::new(verifier(Arc::new(SqliteReplayStore::in_memory()?))?);
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut handles = Vec::new();

        for _ in 0..WORKERS {
            let thread_request = Arc::clone(&request);
            let thread_token = Arc::clone(&token);
            let thread_verifier = Arc::clone(&verifier);
            let thread_barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                thread_barrier.wait();
                thread_verifier
                    .verify_at(
                        &thread_token,
                        &thread_request,
                        &[ApprovalType::ExplicitUser],
                        NOW,
                    )
                    .is_ok()
            }));
        }

        let winners = handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
        Ok(())
    }
}
