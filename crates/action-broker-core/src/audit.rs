use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{BrokerError, BrokerResult, ErrorCode};

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_AUDIT_LINE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    Started,
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalAudit {
    pub required: bool,
    pub approval_type: Option<String>,
    pub token_digest: Option<String>,
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
struct ChainedAuditEvent {
    previous_hash: String,
    event: AuditEvent,
    record_hash: String,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent) -> BrokerResult<()>;
}

struct AuditWriter {
    writer: BufWriter<File>,
    previous_hash: String,
}

/// Append-only, hash-chained JSONL audit log. The chain detects truncation or
/// rewriting during startup validation; external immutable shipping remains an
/// operational responsibility.
pub struct HashChainedJsonlAuditSink {
    state: Mutex<AuditWriter>,
}

impl HashChainedJsonlAuditSink {
    pub fn open(path: &Path) -> BrokerResult<Self> {
        reject_unsafe_existing_file(path)?;
        let previous_hash = validate_existing_chain(path)?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(path)
            .map_err(|_| audit_error("audit log cannot be opened"))?;
        verify_private_file(&file)?;
        Ok(Self {
            state: Mutex::new(AuditWriter {
                writer: BufWriter::new(file),
                previous_hash,
            }),
        })
    }
}

impl AuditSink for HashChainedJsonlAuditSink {
    fn record(&self, event: &AuditEvent) -> BrokerResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| audit_error("audit log lock failed"))?;
        let record_hash = compute_record_hash(&state.previous_hash, event)?;
        let record = ChainedAuditEvent {
            previous_hash: state.previous_hash.clone(),
            event: event.clone(),
            record_hash: record_hash.clone(),
        };
        let encoded =
            serde_json::to_vec(&record).map_err(|_| audit_error("audit serialization failed"))?;
        state
            .writer
            .write_all(&encoded)
            .and_then(|()| state.writer.write_all(b"\n"))
            .and_then(|()| state.writer.flush())
            .and_then(|()| state.writer.get_ref().sync_data())
            .map_err(|_| audit_error("audit durability write failed"))?;
        state.previous_hash = record_hash;
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

fn validate_existing_chain(path: &Path) -> BrokerResult<String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GENESIS_HASH.to_owned());
        }
        Err(_) => return Err(audit_error("audit log validation open failed")),
    };
    let mut previous = GENESIS_HASH.to_owned();
    for line_result in BufReader::new(file).lines() {
        let line = line_result.map_err(|_| audit_error("audit log read failed"))?;
        if line.len() as u64 > MAX_AUDIT_LINE_BYTES {
            return Err(audit_error("audit record exceeds size limit"));
        }
        let record: ChainedAuditEvent = serde_json::from_str(&line)
            .map_err(|_| audit_error("audit chain contains invalid JSON"))?;
        if record.previous_hash != previous
            || compute_record_hash(&previous, &record.event)? != record.record_hash
        {
            return Err(audit_error("audit chain validation failed"));
        }
        previous = record.record_hash;
    }
    Ok(previous)
}

fn reject_unsafe_existing_file(path: &Path) -> BrokerResult<()> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(audit_error("audit log is not a regular file"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(audit_error("audit log metadata failed")),
    }
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
}
