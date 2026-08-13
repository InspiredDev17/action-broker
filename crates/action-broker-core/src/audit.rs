use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{BrokerError, BrokerResult, ErrorCode};

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const AUDIT_EVENT_VERSION: u8 = 1;
const MAX_AUDIT_LINE_BYTES: usize = 256 * 1024;
const MAX_AUDIT_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_AUDIT_RECORDS: u64 = 4_000_000;
const MAX_PENDING_AUDITS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    Started,
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAudit {
    pub required: bool,
    pub approval_type: Option<String>,
    pub token_digest: Option<String>,
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_digest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileChangeAudit {
    pub root_id: String,
    pub relative_path_digest: String,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub operation: String,
}

/// Caller-controlled content and secret values must be represented only by
/// digests before reaching this structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub version: u8,
    pub audit_id: Uuid,
    pub phase: AuditPhase,
    pub request_id: Uuid,
    pub user_id: String,
    pub agent_id: String,
    pub task_id: String,
    pub capability: String,
    pub target: String,
    pub validated_arguments_hash: String,
    pub approval: ApprovalAudit,
    pub started_at_unix_ms: i128,
    pub finished_at_unix_ms: Option<i128>,
    pub exit_status: Option<i32>,
    pub output_digest: Option<String>,
    pub error_code: Option<ErrorCode>,
    pub files_changed: Vec<FileChangeAudit>,
    pub network_destinations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainedAuditEvent {
    previous_hash: String,
    event: AuditEvent,
    record_hash: String,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent) -> BrokerResult<()>;
}

/// Secret-free result of validating one complete audit segment. Operators can
/// compare `head_sha256` with an independently protected checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditVerificationSummary {
    pub record_count: u64,
    pub unfinished_action_count: u64,
    pub initial_previous_sha256: String,
    pub head_sha256: String,
    pub first_event_at_unix_ms: Option<i128>,
    pub last_event_at_unix_ms: Option<i128>,
}

struct AuditWriter {
    writer: BufWriter<File>,
    previous_hash: String,
    record_count: u64,
    current_bytes: u64,
    pending: BTreeMap<Uuid, AuditStartBinding>,
    #[cfg(unix)]
    file_stamp: FileStamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditStartBinding {
    request_id: Uuid,
    user_id: String,
    agent_id: String,
    task_id: String,
    capability: String,
    target: String,
    validated_arguments_hash: String,
    approval: ApprovalAudit,
    started_at_unix_ms: i128,
}

struct ValidatedAuditChain {
    summary: AuditVerificationSummary,
    pending: BTreeMap<Uuid, AuditStartBinding>,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

/// Append-only, hash-chained JSONL audit log. The chain detects truncation or
/// rewriting during startup validation; external immutable shipping remains an
/// operational responsibility.
pub struct HashChainedJsonlAuditSink {
    state: Mutex<AuditWriter>,
}

impl HashChainedJsonlAuditSink {
    pub fn open(path: &Path) -> BrokerResult<Self> {
        Self::open_with_initial_hash(path, GENESIS_HASH)
    }

    /// Opens an append-only segment whose first record must extend the supplied
    /// prior segment head. The all-zero genesis hash is used only for the first
    /// segment in a chain.
    pub fn open_with_initial_hash(path: &Path, initial_previous_hash: &str) -> BrokerResult<Self> {
        validate_hash(initial_previous_hash, "initial audit head is invalid")?;
        let file = open_audit_file(path, true)?;
        let validated = validate_existing_chain(&file, initial_previous_hash)?;
        let current_bytes = file
            .metadata()
            .map_err(|_| audit_error("audit log metadata failed"))?
            .len();
        #[cfg(unix)]
        let file_stamp = file_stamp(&file)?;
        Ok(Self {
            state: Mutex::new(AuditWriter {
                writer: BufWriter::new(file),
                previous_hash: validated.summary.head_sha256,
                record_count: validated.summary.record_count,
                current_bytes,
                pending: validated.pending,
                #[cfg(unix)]
                file_stamp,
            }),
        })
    }
}

/// Validates a complete audit segment without modifying it. When supplied, the
/// expected head must be the exact lowercase SHA-256 checkpoint for this file.
pub fn verify_audit_chain(
    path: &Path,
    initial_previous_hash: Option<&str>,
    expected_head: Option<&str>,
) -> BrokerResult<AuditVerificationSummary> {
    let initial_previous_hash = initial_previous_hash.unwrap_or(GENESIS_HASH);
    validate_hash(initial_previous_hash, "initial audit head is invalid")?;
    if let Some(expected) = expected_head {
        validate_hash(expected, "expected audit head is invalid")?;
    }
    let file = open_audit_file(path, false)?;
    let summary = validate_existing_chain(&file, initial_previous_hash)?.summary;
    if expected_head.is_some_and(|expected| expected != summary.head_sha256) {
        return Err(audit_error(
            "audit chain head does not match the external checkpoint",
        ));
    }
    Ok(summary)
}

impl AuditSink for HashChainedJsonlAuditSink {
    fn record(&self, event: &AuditEvent) -> BrokerResult<()> {
        validate_event(event)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| audit_error("audit log lock failed"))?;
        validate_lifecycle_event(&state.pending, event)?;
        let record_hash = compute_record_hash(&state.previous_hash, event)?;
        let record = ChainedAuditEvent {
            previous_hash: state.previous_hash.clone(),
            event: event.clone(),
            record_hash: record_hash.clone(),
        };
        let encoded =
            serde_json::to_vec(&record).map_err(|_| audit_error("audit serialization failed"))?;
        let line_bytes = encoded.len().saturating_add(1);
        let encoded_bytes =
            u64::try_from(line_bytes).map_err(|_| audit_error("audit record size is invalid"))?;
        if line_bytes > MAX_AUDIT_LINE_BYTES {
            return Err(audit_error("audit record exceeds size limit"));
        }
        if state.record_count >= MAX_AUDIT_RECORDS
            || state.current_bytes.saturating_add(encoded_bytes) > MAX_AUDIT_FILE_BYTES
        {
            return Err(audit_error(
                "audit segment limit reached; rotation is required",
            ));
        }
        let observed_bytes = state
            .writer
            .get_ref()
            .metadata()
            .map_err(|_| audit_error("audit log metadata failed"))?
            .len();
        if observed_bytes != state.current_bytes {
            return Err(audit_error("audit log changed outside the active writer"));
        }
        #[cfg(unix)]
        if file_stamp(state.writer.get_ref())? != state.file_stamp {
            return Err(audit_error("audit log changed outside the active writer"));
        }
        state
            .writer
            .write_all(&encoded)
            .and_then(|()| state.writer.write_all(b"\n"))
            .and_then(|()| state.writer.flush())
            .and_then(|()| state.writer.get_ref().sync_data())
            .map_err(|_| audit_error("audit durability write failed"))?;
        let expected_bytes = state.current_bytes.saturating_add(encoded_bytes);
        let durable_bytes = state
            .writer
            .get_ref()
            .metadata()
            .map_err(|_| audit_error("audit log metadata failed"))?
            .len();
        if durable_bytes != expected_bytes {
            return Err(audit_error("audit durability size check failed"));
        }
        state.previous_hash = record_hash;
        state.record_count = state.record_count.saturating_add(1);
        state.current_bytes = durable_bytes;
        apply_lifecycle_event(&mut state.pending, event);
        #[cfg(unix)]
        {
            state.file_stamp = file_stamp(state.writer.get_ref())?;
        }
        Ok(())
    }
}

fn compute_record_hash(previous_hash: &str, event: &AuditEvent) -> BrokerResult<String> {
    let canonical =
        serde_jcs::to_vec(event).map_err(|_| audit_error("audit canonicalization failed"))?;
    let mut hasher = Sha256::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn validate_existing_chain(
    file: &File,
    initial_previous_hash: &str,
) -> BrokerResult<ValidatedAuditChain> {
    let expected_length = file
        .metadata()
        .map_err(|_| audit_error("audit log metadata failed"))?
        .len();
    #[cfg(unix)]
    let expected_stamp = file_stamp(file)?;
    let validation_file = file
        .try_clone()
        .map_err(|_| audit_error("audit log validation handle failed"))?;
    let mut previous = initial_previous_hash.to_owned();
    let mut record_count = 0_u64;
    let mut first_event_at_unix_ms = None;
    let mut last_event_at_unix_ms = None;
    let mut pending = BTreeMap::new();
    let mut reader = BufReader::new(validation_file);
    loop {
        let mut line = Vec::with_capacity(4096);
        let bytes_read = Read::by_ref(&mut reader)
            .take((MAX_AUDIT_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| audit_error("audit log read failed"))?;
        if bytes_read == 0 {
            break;
        }
        if line.len() > MAX_AUDIT_LINE_BYTES {
            return Err(audit_error("audit record exceeds size limit"));
        }
        if line.last() != Some(&b'\n') {
            return Err(audit_error("audit log has an incomplete final record"));
        }
        line.pop();
        let record: ChainedAuditEvent = serde_json::from_slice(&line)
            .map_err(|_| audit_error("audit chain contains invalid JSON"))?;
        validate_event(&record.event)?;
        validate_lifecycle_event(&pending, &record.event)?;
        if record.previous_hash != previous
            || compute_record_hash(&previous, &record.event)? != record.record_hash
        {
            return Err(audit_error("audit chain validation failed"));
        }
        apply_lifecycle_event(&mut pending, &record.event);
        record_count = record_count.saturating_add(1);
        if record_count > MAX_AUDIT_RECORDS {
            return Err(audit_error("audit log exceeds the record count limit"));
        }
        first_event_at_unix_ms.get_or_insert(record.event.started_at_unix_ms);
        last_event_at_unix_ms = Some(
            record
                .event
                .finished_at_unix_ms
                .unwrap_or(record.event.started_at_unix_ms),
        );
        previous = record.record_hash;
    }
    if file
        .metadata()
        .map_err(|_| audit_error("audit log metadata failed"))?
        .len()
        != expected_length
    {
        return Err(audit_error("audit log changed during validation"));
    }
    #[cfg(unix)]
    if file_stamp(file)? != expected_stamp {
        return Err(audit_error("audit log changed during validation"));
    }
    Ok(ValidatedAuditChain {
        summary: AuditVerificationSummary {
            record_count,
            unfinished_action_count: pending.len() as u64,
            initial_previous_sha256: initial_previous_hash.to_owned(),
            head_sha256: previous,
            first_event_at_unix_ms,
            last_event_at_unix_ms,
        },
        pending,
    })
}

fn validate_lifecycle_event(
    pending: &BTreeMap<Uuid, AuditStartBinding>,
    event: &AuditEvent,
) -> BrokerResult<()> {
    match event.phase {
        AuditPhase::Started => {
            if pending.contains_key(&event.audit_id) {
                return Err(audit_error("audit action has a duplicate start"));
            }
            if pending.len() >= MAX_PENDING_AUDITS {
                return Err(audit_error("audit segment has too many unfinished actions"));
            }
        }
        AuditPhase::Finished => {
            let Some(start) = pending.get(&event.audit_id) else {
                return Err(audit_error("audit finish has no matching start"));
            };
            if *start != AuditStartBinding::from(event) {
                return Err(audit_error("audit finish does not match its start"));
            }
        }
    }
    Ok(())
}

fn apply_lifecycle_event(pending: &mut BTreeMap<Uuid, AuditStartBinding>, event: &AuditEvent) {
    match event.phase {
        AuditPhase::Started => {
            let prior = pending.insert(event.audit_id, AuditStartBinding::from(event));
            debug_assert!(prior.is_none(), "lifecycle was validated before append");
        }
        AuditPhase::Finished => {
            let prior = pending.remove(&event.audit_id);
            debug_assert!(prior.is_some(), "lifecycle was validated before append");
        }
    }
}

impl From<&AuditEvent> for AuditStartBinding {
    fn from(event: &AuditEvent) -> Self {
        Self {
            request_id: event.request_id,
            user_id: event.user_id.clone(),
            agent_id: event.agent_id.clone(),
            task_id: event.task_id.clone(),
            capability: event.capability.clone(),
            target: event.target.clone(),
            validated_arguments_hash: event.validated_arguments_hash.clone(),
            approval: event.approval.clone(),
            started_at_unix_ms: event.started_at_unix_ms,
        }
    }
}

fn validate_event(event: &AuditEvent) -> BrokerResult<()> {
    if event.version != AUDIT_EVENT_VERSION {
        return Err(audit_error("audit event version is unsupported"));
    }
    validate_hash(
        &event.validated_arguments_hash,
        "audit arguments digest is invalid",
    )?;
    validate_approval(&event.approval)?;
    if event.started_at_unix_ms < 0 {
        return Err(audit_error("audit start time is invalid"));
    }

    match event.phase {
        AuditPhase::Started => {
            if event.finished_at_unix_ms.is_some()
                || event.exit_status.is_some()
                || event.output_digest.is_some()
                || event.error_code.is_some()
                || !event.files_changed.is_empty()
                || !event.network_destinations.is_empty()
            {
                return Err(audit_error("audit start record contains result state"));
            }
        }
        AuditPhase::Finished => {
            let finished_at = event
                .finished_at_unix_ms
                .ok_or_else(|| audit_error("audit finish time is missing"))?;
            if finished_at < event.started_at_unix_ms {
                return Err(audit_error("audit finish time precedes its start"));
            }
            if event.error_code.is_some() {
                if event.output_digest.is_some()
                    || event.exit_status.is_some()
                    || !event.files_changed.is_empty()
                {
                    return Err(audit_error(
                        "failed audit record contains successful result state",
                    ));
                }
            } else if event.output_digest.is_none() {
                return Err(audit_error(
                    "successful audit record lacks an output digest",
                ));
            }
        }
    }

    validate_optional_hash(
        event.output_digest.as_deref(),
        "audit output digest is invalid",
    )?;
    for change in &event.files_changed {
        if change.root_id.is_empty()
            || !matches!(
                change.operation.as_str(),
                "write" | "create" | "move_source" | "move_destination" | "recoverable_delete"
            )
            || change.before_digest.is_none() && change.after_digest.is_none()
        {
            return Err(audit_error("audit file-change metadata is invalid"));
        }
        validate_hash(&change.relative_path_digest, "audit path digest is invalid")?;
        validate_optional_hash(
            change.before_digest.as_deref(),
            "audit pre-change digest is invalid",
        )?;
        validate_optional_hash(
            change.after_digest.as_deref(),
            "audit post-change digest is invalid",
        )?;
    }
    if event.network_destinations.iter().any(String::is_empty) {
        return Err(audit_error("audit network destination is invalid"));
    }
    Ok(())
}

fn validate_approval(approval: &ApprovalAudit) -> BrokerResult<()> {
    if !approval.required {
        if approval.approval_type.is_some()
            || approval.token_digest.is_some()
            || approval.key_id.is_some()
            || approval.nonce_digest_sha256.is_some()
            || approval.expires_at_unix_seconds.is_some()
        {
            return Err(audit_error(
                "policy-only audit record contains approval metadata",
            ));
        }
        return Ok(());
    }

    if approval.approval_type.as_deref().is_none_or(str::is_empty)
        || approval.key_id.as_deref().is_none_or(str::is_empty)
        || approval.token_digest.is_none()
        || approval.nonce_digest_sha256.is_some() != approval.expires_at_unix_seconds.is_some()
        || approval
            .expires_at_unix_seconds
            .is_some_and(|value| value <= 0)
    {
        return Err(audit_error("approval audit metadata is inconsistent"));
    }
    validate_optional_hash(
        approval.token_digest.as_deref(),
        "audit approval token digest is invalid",
    )?;
    validate_optional_hash(
        approval.nonce_digest_sha256.as_deref(),
        "audit approval nonce digest is invalid",
    )?;
    Ok(())
}

fn validate_optional_hash(value: Option<&str>, message: &'static str) -> BrokerResult<()> {
    if let Some(value) = value {
        validate_hash(value, message)?;
    }
    Ok(())
}

fn open_audit_file(path: &Path, append: bool) -> BrokerResult<File> {
    let before = match path.symlink_metadata() {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > MAX_AUDIT_FILE_BYTES
            {
                return Err(audit_error("audit log is unsafe or exceeds the size limit"));
            }
            Some(metadata)
        }
        Err(error) if append && error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(audit_error("audit log metadata failed")),
    };
    let mut options = OpenOptions::new();
    options.read(true).append(append).create(append);
    #[cfg(unix)]
    {
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| audit_error("audit log cannot be securely opened"))?;
    verify_private_file(&file)?;
    let after = file
        .metadata()
        .map_err(|_| audit_error("audit log metadata failed"))?;
    if !after.is_file() || after.len() > MAX_AUDIT_FILE_BYTES {
        return Err(audit_error("audit log is unsafe or exceeds the size limit"));
    }
    #[cfg(unix)]
    if before
        .as_ref()
        .is_some_and(|metadata| metadata.dev() != after.dev() || metadata.ino() != after.ino())
    {
        return Err(audit_error("audit log changed while opening"));
    }
    Ok(file)
}

fn validate_hash(value: &str, message: &'static str) -> BrokerResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(audit_error(message));
    }
    Ok(())
}

#[cfg(unix)]
fn file_stamp(file: &File) -> BrokerResult<FileStamp> {
    let metadata = file
        .metadata()
        .map_err(|_| audit_error("audit log metadata failed"))?;
    Ok(FileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn verify_private_file(file: &File) -> BrokerResult<()> {
    let mode = file
        .metadata()
        .map_err(|_| audit_error("audit log metadata failed"))?
        .mode();
    if mode & 0o077 != 0 {
        return Err(audit_error("audit log permissions are too broad"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_file(_file: &File) -> BrokerResult<()> {
    Err(audit_error(
        "secure auditing is unsupported on this platform",
    ))
}

fn audit_error(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::AuditFailure, message)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Seek, SeekFrom};

    use super::*;

    fn event() -> AuditEvent {
        AuditEvent {
            version: 1,
            audit_id: Uuid::nil(),
            phase: AuditPhase::Started,
            request_id: Uuid::nil(),
            user_id: "user".to_owned(),
            agent_id: "agent".to_owned(),
            task_id: "task".to_owned(),
            capability: "read_file".to_owned(),
            target: "local:root".to_owned(),
            validated_arguments_hash: "00".repeat(32),
            approval: ApprovalAudit {
                required: false,
                approval_type: None,
                token_digest: None,
                key_id: None,
                nonce_digest_sha256: None,
                expires_at_unix_seconds: None,
            },
            started_at_unix_ms: 1,
            finished_at_unix_ms: None,
            exit_status: None,
            output_digest: None,
            error_code: None,
            files_changed: Vec::new(),
            network_destinations: Vec::new(),
        }
    }

    fn approved_event() -> AuditEvent {
        AuditEvent {
            approval: ApprovalAudit {
                required: true,
                approval_type: Some("ElevatedUser".to_owned()),
                token_digest: Some("11".repeat(32)),
                key_id: Some("approval-key".to_owned()),
                nonce_digest_sha256: Some("22".repeat(32)),
                expires_at_unix_seconds: Some(60),
            },
            ..event()
        }
    }

    fn finished_event() -> AuditEvent {
        AuditEvent {
            phase: AuditPhase::Finished,
            finished_at_unix_ms: Some(2),
            output_digest: Some("33".repeat(32)),
            ..event()
        }
    }

    #[test]
    fn legacy_approval_shape_remains_canonical() -> Result<(), Box<dyn std::error::Error>> {
        let approval = event().approval;
        let encoded = serde_jcs::to_vec(&approval)?;
        assert_eq!(
            encoded,
            br#"{"approval_type":null,"key_id":null,"required":false,"token_digest":null}"#
        );
        assert!(
            !encoded
                .windows(b"nonce".len())
                .any(|value| value == b"nonce")
        );
        assert!(
            !encoded
                .windows(b"expires_at".len())
                .any(|value| value == b"expires_at")
        );

        let legacy_token_digest = "44".repeat(32);
        let legacy_approved = format!(
            r#"{{"approval_type":"ElevatedUser","key_id":"legacy-key","required":true,"token_digest":"{legacy_token_digest}"}}"#
        );
        let parsed: ApprovalAudit = serde_json::from_slice(legacy_approved.as_bytes())?;
        assert_eq!(parsed.nonce_digest_sha256, None);
        assert_eq!(parsed.expires_at_unix_seconds, None);
        assert_eq!(serde_jcs::to_vec(&parsed)?, legacy_approved.as_bytes());
        validate_event(&AuditEvent {
            approval: parsed,
            ..event()
        })?;
        Ok(())
    }

    #[test]
    fn writer_rejects_unsupported_or_inconsistent_events_without_append()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&path)?;
        let invalid = [
            AuditEvent {
                version: 2,
                ..event()
            },
            AuditEvent {
                finished_at_unix_ms: Some(2),
                ..event()
            },
            AuditEvent {
                phase: AuditPhase::Finished,
                finished_at_unix_ms: Some(0),
                output_digest: Some("33".repeat(32)),
                ..event()
            },
            AuditEvent {
                phase: AuditPhase::Finished,
                finished_at_unix_ms: Some(2),
                ..event()
            },
            AuditEvent {
                phase: AuditPhase::Finished,
                finished_at_unix_ms: Some(2),
                error_code: Some(ErrorCode::ExecutionFailure),
                output_digest: Some("33".repeat(32)),
                ..event()
            },
            AuditEvent {
                approval: ApprovalAudit {
                    required: false,
                    key_id: Some("unexpected-key".to_owned()),
                    ..event().approval
                },
                ..event()
            },
            AuditEvent {
                validated_arguments_hash: "not-a-sha256".to_owned(),
                ..event()
            },
            AuditEvent {
                approval: ApprovalAudit {
                    expires_at_unix_seconds: None,
                    ..approved_event().approval
                },
                ..event()
            },
            AuditEvent {
                approval: ApprovalAudit {
                    token_digest: Some("not-a-sha256".to_owned()),
                    ..approved_event().approval
                },
                ..event()
            },
        ];
        for invalid_event in invalid {
            assert!(sink.record(&invalid_event).is_err());
        }
        assert_eq!(fs::metadata(path)?.len(), 0);
        Ok(())
    }

    #[test]
    fn verifier_rejects_semantically_invalid_but_correctly_hashed_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let invalid = AuditEvent {
            version: 2,
            ..event()
        };
        let record = ChainedAuditEvent {
            previous_hash: GENESIS_HASH.to_owned(),
            record_hash: compute_record_hash(GENESIS_HASH, &invalid)?,
            event: invalid,
        };
        let mut encoded = serde_json::to_vec(&record)?;
        encoded.push(b'\n');
        fs::write(&path, encoded)?;
        assert!(verify_audit_chain(&path, None, None).is_err());
        assert!(HashChainedJsonlAuditSink::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn writer_enforces_bounded_start_finish_pairing() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&path)?;
        assert!(sink.record(&finished_event()).is_err());
        assert_eq!(fs::metadata(&path)?.len(), 0);

        let started = event();
        sink.record(&started)?;
        assert!(sink.record(&started).is_err());
        let mut mismatched = finished_event();
        mismatched.capability = "WriteFile".to_owned();
        assert!(sink.record(&mismatched).is_err());
        sink.record(&finished_event())?;
        assert!(sink.record(&finished_event()).is_err());

        let summary = verify_audit_chain(&path, None, None)?;
        assert_eq!(summary.record_count, 2);
        assert_eq!(summary.unfinished_action_count, 0);
        Ok(())
    }

    #[test]
    fn verification_summary_reports_unfinished_actions() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&path)?;
        sink.record(&event())?;
        drop(sink);

        let summary = verify_audit_chain(&path, None, None)?;
        assert_eq!(summary.record_count, 1);
        assert_eq!(summary.unfinished_action_count, 1);
        Ok(())
    }

    #[test]
    fn pending_audit_limit_is_exact_and_releases_on_finish() -> BrokerResult<()> {
        let mut pending = BTreeMap::new();
        for index in 0..MAX_PENDING_AUDITS {
            let mut started = event();
            started.audit_id = Uuid::from_u128(index as u128 + 1);
            validate_lifecycle_event(&pending, &started)?;
            apply_lifecycle_event(&mut pending, &started);
        }
        assert_eq!(pending.len(), MAX_PENDING_AUDITS);

        let mut denied = event();
        denied.audit_id = Uuid::from_u128(MAX_PENDING_AUDITS as u128 + 1);
        assert!(validate_lifecycle_event(&pending, &denied).is_err());

        let mut finished = finished_event();
        finished.audit_id = Uuid::from_u128(1);
        validate_lifecycle_event(&pending, &finished)?;
        apply_lifecycle_event(&mut pending, &finished);
        validate_lifecycle_event(&pending, &denied)?;
        Ok(())
    }

    #[test]
    fn verifier_rejects_correctly_hashed_cross_record_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let start = event();
        let start_hash = compute_record_hash(GENESIS_HASH, &start)?;
        let mut finish = finished_event();
        finish.task_id = "different-task".to_owned();
        let records = [
            ChainedAuditEvent {
                previous_hash: GENESIS_HASH.to_owned(),
                record_hash: start_hash.clone(),
                event: start,
            },
            ChainedAuditEvent {
                previous_hash: start_hash.clone(),
                record_hash: compute_record_hash(&start_hash, &finish)?,
                event: finish,
            },
        ];
        let mut encoded = Vec::new();
        for record in records {
            serde_json::to_writer(&mut encoded, &record)?;
            encoded.push(b'\n');
        }
        fs::write(&path, encoded)?;
        assert!(verify_audit_chain(&path, None, None).is_err());
        assert!(HashChainedJsonlAuditSink::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn detects_tampering_on_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&path)?;
        sink.record(&event())?;
        drop(sink);
        let contents = std::fs::read_to_string(&path)?;
        std::fs::write(&path, contents.replace("read_file", "write_file"))?;
        assert!(HashChainedJsonlAuditSink::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn verification_summary_binds_external_head() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&path)?;
        sink.record(&event())?;
        sink.record(&finished_event())?;
        drop(sink);

        let summary = verify_audit_chain(&path, None, None)?;
        assert_eq!(summary.record_count, 2);
        assert_eq!(summary.unfinished_action_count, 0);
        assert_eq!(summary.initial_previous_sha256, GENESIS_HASH);
        assert_eq!(summary.first_event_at_unix_ms, Some(1));
        assert_eq!(summary.last_event_at_unix_ms, Some(2));
        assert_eq!(summary.head_sha256.len(), 64);
        assert_eq!(
            verify_audit_chain(&path, None, Some(&summary.head_sha256))?,
            summary
        );
        assert!(verify_audit_chain(&path, None, Some(&"f".repeat(64))).is_err());
        assert!(verify_audit_chain(&path, None, Some("not-a-hash")).is_err());
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_and_incomplete_records() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&path)?;
        sink.record(&event())?;
        drop(sink);

        let original = fs::read_to_string(&path)?;
        fs::write(
            &path,
            original.replace(
                "\"record_hash\"",
                "\"unprotected_extension\":true,\"record_hash\"",
            ),
        )?;
        assert!(verify_audit_chain(&path, None, None).is_err());

        fs::write(&path, original.trim_end_matches('\n'))?;
        assert!(verify_audit_chain(&path, None, None).is_err());
        Ok(())
    }

    #[test]
    fn oversized_line_is_rejected_before_unbounded_allocation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&path)?;
        drop(sink);
        fs::write(&path, vec![b'x'; MAX_AUDIT_LINE_BYTES + 1])?;
        assert!(verify_audit_chain(&path, None, None).is_err());
        Ok(())
    }

    #[test]
    fn writer_refuses_oversized_record_and_external_append()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&path)?;
        let oversized = AuditEvent {
            user_id: "x".repeat(MAX_AUDIT_LINE_BYTES),
            ..event()
        };
        assert!(sink.record(&oversized).is_err());
        assert_eq!(fs::metadata(&path)?.len(), 0);

        let mut external = OpenOptions::new().append(true).open(&path)?;
        external.write_all(b"external\n")?;
        external.sync_all()?;
        assert!(sink.record(&event()).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn writer_detects_same_size_external_rewrite() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&path)?;
        sink.record(&event())?;
        let original_length = fs::metadata(&path)?.len();

        let mut external = OpenOptions::new().write(true).open(&path)?;
        external.seek(SeekFrom::Start(0))?;
        external.write_all(b"X")?;
        external.sync_all()?;
        assert_eq!(fs::metadata(&path)?.len(), original_length);
        assert!(sink.record(&event()).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn read_only_verifier_rejects_symlink() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let real = directory.path().join("real.jsonl");
        let link = directory.path().join("audit.jsonl");
        let sink = HashChainedJsonlAuditSink::open(&real)?;
        drop(sink);
        std::os::unix::fs::symlink(&real, &link)?;
        assert!(verify_audit_chain(&link, None, None).is_err());
        Ok(())
    }

    #[test]
    fn rotated_segment_extends_prior_head() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let first_path = directory.path().join("audit-1.jsonl");
        let first = HashChainedJsonlAuditSink::open(&first_path)?;
        first.record(&event())?;
        drop(first);
        let first_summary = verify_audit_chain(&first_path, None, None)?;

        let second_path = directory.path().join("audit-2.jsonl");
        let second = HashChainedJsonlAuditSink::open_with_initial_hash(
            &second_path,
            &first_summary.head_sha256,
        )?;
        second.record(&AuditEvent {
            started_at_unix_ms: 3,
            ..event()
        })?;
        drop(second);
        let second_summary =
            verify_audit_chain(&second_path, Some(&first_summary.head_sha256), None)?;
        assert_eq!(
            second_summary.initial_previous_sha256,
            first_summary.head_sha256
        );
        assert!(verify_audit_chain(&second_path, None, None).is_err());
        Ok(())
    }
}
