use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{BrokerError, BrokerResult, ErrorCode};

const MAX_EVENT_LINE_BYTES: usize = 64 * 1024;
const MINIMUM_SPOOL_BYTES: u64 = 1024 * 1024;
const MAXIMUM_SPOOL_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_SPOOL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventKind {
    PermissionBypassAttempt,
    ExpiredApproval,
    ReplayedApproval,
    ApprovalTampering,
    PathEscape,
    SecretAccessAttempt,
    ForbiddenExecutable,
    ForbiddenDestination,
    ResourceAbusePattern,
    SandboxFailure,
    UnexpectedPrivilegeElevation,
}

/// Secret-free event contract consumed by Agent Green. Arbitrary caller text is
/// intentionally excluded; sensitive targets are represented by a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub version: u8,
    pub event_id: Uuid,
    pub occurred_at_unix_ms: i128,
    pub kind: SecurityEventKind,
    pub request_id: Option<Uuid>,
    pub user_id: Option<String>,
    pub agent_id: Option<String>,
    pub task_id: Option<String>,
    pub capability: Option<String>,
    pub target_digest: Option<String>,
    pub reason_code: String,
}

impl SecurityEvent {
    #[must_use]
    pub fn new(kind: SecurityEventKind, reason_code: impl Into<String>) -> Self {
        Self {
            version: 1,
            event_id: Uuid::new_v4(),
            occurred_at_unix_ms: OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,
            kind,
            request_id: None,
            user_id: None,
            agent_id: None,
            task_id: None,
            capability: None,
            target_digest: None,
            reason_code: reason_code.into(),
        }
    }
}

pub trait SecurityEventSink: Send + Sync {
    /// Emission is mandatory. A sink error causes the associated action to fail
    /// closed; callers cannot replace this dependency with an optional sink.
    fn emit(&self, event: &SecurityEvent) -> BrokerResult<()>;
}

/// Durable local spool. Agent Green may tail or ship this file, but Action
/// Broker retains no API for disabling event creation.
pub struct JsonlSecurityEventSink {
    state: Mutex<SecurityEventWriter>,
}

struct SecurityEventWriter {
    writer: BufWriter<File>,
    current_bytes: u64,
    maximum_bytes: u64,
    #[cfg(unix)]
    file_stamp: FileStamp,
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

impl JsonlSecurityEventSink {
    pub fn open(path: &Path) -> BrokerResult<Self> {
        Self::open_with_maximum_bytes(path, DEFAULT_SPOOL_BYTES)
    }

    pub fn open_with_maximum_bytes(path: &Path, maximum_bytes: u64) -> BrokerResult<Self> {
        validate_maximum_bytes(maximum_bytes)?;
        let file = open_spool_file(path, maximum_bytes)?;
        validate_existing_spool(&file, maximum_bytes)?;
        let current_bytes = file
            .metadata()
            .map_err(|_| event_error("security event spool metadata failed"))?
            .len();
        if current_bytes.saturating_add(MAX_EVENT_LINE_BYTES as u64) > maximum_bytes {
            return Err(event_error(
                "security event spool lacks required event headroom",
            ));
        }
        #[cfg(unix)]
        let file_stamp = file_stamp(&file)?;
        Ok(Self {
            state: Mutex::new(SecurityEventWriter {
                writer: BufWriter::new(file),
                current_bytes,
                maximum_bytes,
                #[cfg(unix)]
                file_stamp,
            }),
        })
    }
}

impl SecurityEventSink for JsonlSecurityEventSink {
    fn emit(&self, event: &SecurityEvent) -> BrokerResult<()> {
        if event.version != 1 {
            return Err(event_error("security event version is unsupported"));
        }
        let encoded = serde_json::to_vec(event).map_err(|_| {
            BrokerError::new(
                ErrorCode::SecurityEventFailure,
                "security event serialization failed",
            )
        })?;
        let line_bytes = encoded.len().saturating_add(1);
        let encoded_bytes =
            u64::try_from(line_bytes).map_err(|_| event_error("security event size is invalid"))?;
        if line_bytes > MAX_EVENT_LINE_BYTES {
            return Err(event_error("security event exceeds the size limit"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| event_error("security event spool lock failed"))?;
        if state.current_bytes.saturating_add(encoded_bytes) > state.maximum_bytes {
            return Err(event_error("security event spool capacity is exhausted"));
        }
        let observed_bytes = state
            .writer
            .get_ref()
            .metadata()
            .map_err(|_| event_error("security event spool metadata failed"))?
            .len();
        if observed_bytes != state.current_bytes {
            return Err(event_error(
                "security event spool changed outside the active writer",
            ));
        }
        #[cfg(unix)]
        if file_stamp(state.writer.get_ref())? != state.file_stamp {
            return Err(event_error(
                "security event spool changed outside the active writer",
            ));
        }
        state
            .writer
            .write_all(&encoded)
            .and_then(|()| state.writer.write_all(b"\n"))
            .map_err(|_| {
                BrokerError::new(
                    ErrorCode::SecurityEventFailure,
                    "security event spool write failed",
                )
            })?;
        state
            .writer
            .flush()
            .and_then(|()| state.writer.get_ref().sync_data())
            .map_err(|_| {
                BrokerError::new(
                    ErrorCode::SecurityEventFailure,
                    "security event spool durability failed",
                )
            })?;
        let expected_bytes = state.current_bytes.saturating_add(encoded_bytes);
        let durable_bytes = state
            .writer
            .get_ref()
            .metadata()
            .map_err(|_| event_error("security event spool metadata failed"))?
            .len();
        if durable_bytes != expected_bytes {
            return Err(event_error(
                "security event spool durability size check failed",
            ));
        }
        state.current_bytes = durable_bytes;
        #[cfg(unix)]
        {
            state.file_stamp = file_stamp(state.writer.get_ref())?;
        }
        Ok(())
    }
}

fn validate_maximum_bytes(maximum_bytes: u64) -> BrokerResult<()> {
    if !(MINIMUM_SPOOL_BYTES..=MAXIMUM_SPOOL_BYTES).contains(&maximum_bytes) {
        return Err(event_error(
            "security event spool capacity is outside the safe bound",
        ));
    }
    Ok(())
}

fn open_spool_file(path: &Path, maximum_bytes: u64) -> BrokerResult<File> {
    let before = match path.symlink_metadata() {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > maximum_bytes
            {
                return Err(event_error(
                    "security event spool is unsafe or exceeds capacity",
                ));
            }
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(event_error("security event spool metadata failed")),
    };
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| event_error("security event spool cannot be securely opened"))?;
    verify_private_file(&file)?;
    let after = file
        .metadata()
        .map_err(|_| event_error("security event spool metadata failed"))?;
    if !after.is_file() || after.len() > maximum_bytes {
        return Err(event_error(
            "security event spool is unsafe or exceeds capacity",
        ));
    }
    #[cfg(unix)]
    if before
        .as_ref()
        .is_some_and(|metadata| metadata.dev() != after.dev() || metadata.ino() != after.ino())
    {
        return Err(event_error("security event spool changed while opening"));
    }
    Ok(file)
}

fn validate_existing_spool(file: &File, maximum_bytes: u64) -> BrokerResult<()> {
    let expected_length = file
        .metadata()
        .map_err(|_| event_error("security event spool metadata failed"))?
        .len();
    if expected_length > maximum_bytes {
        return Err(event_error("security event spool exceeds capacity"));
    }
    #[cfg(unix)]
    let expected_stamp = file_stamp(file)?;
    let validation_file = file
        .try_clone()
        .map_err(|_| event_error("security event spool validation handle failed"))?;
    let mut reader = BufReader::new(validation_file);
    loop {
        let mut line = Vec::with_capacity(1024);
        let bytes_read = Read::by_ref(&mut reader)
            .take((MAX_EVENT_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| event_error("security event spool read failed"))?;
        if bytes_read == 0 {
            break;
        }
        if line.len() > MAX_EVENT_LINE_BYTES {
            return Err(event_error("security event exceeds the size limit"));
        }
        if line.last() != Some(&b'\n') {
            return Err(event_error(
                "security event spool has an incomplete final record",
            ));
        }
        line.pop();
        let event: SecurityEvent = serde_json::from_slice(&line)
            .map_err(|_| event_error("security event spool contains invalid JSON"))?;
        if event.version != 1 {
            return Err(event_error("security event version is unsupported"));
        }
    }
    if file
        .metadata()
        .map_err(|_| event_error("security event spool metadata failed"))?
        .len()
        != expected_length
    {
        return Err(event_error(
            "security event spool changed during validation",
        ));
    }
    #[cfg(unix)]
    if file_stamp(file)? != expected_stamp {
        return Err(event_error(
            "security event spool changed during validation",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn file_stamp(file: &File) -> BrokerResult<FileStamp> {
    let metadata = file
        .metadata()
        .map_err(|_| event_error("security event spool metadata failed"))?;
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

fn event_error(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::SecurityEventFailure, message)
}

#[cfg(unix)]
fn verify_private_file(file: &File) -> BrokerResult<()> {
    let mode = file
        .metadata()
        .map_err(|_| {
            BrokerError::new(
                ErrorCode::SecurityEventFailure,
                "security event spool metadata failed",
            )
        })?
        .mode();
    if mode & 0o077 != 0 {
        return Err(BrokerError::new(
            ErrorCode::SecurityEventFailure,
            "security event spool permissions are too broad",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_file(_file: &File) -> BrokerResult<()> {
    Err(BrokerError::new(
        ErrorCode::SecurityEventFailure,
        "secure event spooling is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::io::{Seek, SeekFrom};

    use super::*;

    fn event() -> SecurityEvent {
        let mut event = SecurityEvent::new(SecurityEventKind::PathEscape, "path_escape");
        event.event_id = Uuid::nil();
        event.occurred_at_unix_ms = 1;
        event.user_id = Some("user".to_owned());
        event
    }

    #[test]
    fn event_spool_rejects_symlink() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let real = directory.path().join("real");
        std::fs::write(&real, b"")?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, directory.path().join("events"))?;
            let result = JsonlSecurityEventSink::open(&directory.path().join("events"));
            assert!(result.is_err());
        }
        Ok(())
    }

    #[test]
    fn spool_capacity_policy_is_bounded() {
        assert!(
            JsonlSecurityEventSink::open_with_maximum_bytes(
                Path::new("unused"),
                MINIMUM_SPOOL_BYTES - 1,
            )
            .is_err()
        );
        assert!(
            JsonlSecurityEventSink::open_with_maximum_bytes(
                Path::new("unused"),
                MAXIMUM_SPOOL_BYTES + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn valid_events_survive_strict_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("events.jsonl");
        let sink = JsonlSecurityEventSink::open_with_maximum_bytes(&path, MINIMUM_SPOOL_BYTES)?;
        sink.emit(&event())?;
        drop(sink);
        let reopened = JsonlSecurityEventSink::open_with_maximum_bytes(&path, MINIMUM_SPOOL_BYTES)?;
        reopened.emit(&event())?;
        assert_eq!(fs::read_to_string(path)?.lines().count(), 2);
        Ok(())
    }

    #[test]
    fn malformed_unknown_incomplete_and_oversized_records_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("events.jsonl");
        let sink = JsonlSecurityEventSink::open(&path)?;
        sink.emit(&event())?;
        drop(sink);
        let original = fs::read_to_string(&path)?;

        fs::write(
            &path,
            original.replace("\"reason_code\"", "\"bypass\":true,\"reason_code\""),
        )?;
        assert!(JsonlSecurityEventSink::open(&path).is_err());
        fs::write(&path, original.trim_end_matches('\n'))?;
        assert!(JsonlSecurityEventSink::open(&path).is_err());
        fs::write(&path, vec![b'x'; MAX_EVENT_LINE_BYTES + 1])?;
        assert!(JsonlSecurityEventSink::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn startup_requires_one_maximum_event_of_headroom() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("events.jsonl");
        let sink = JsonlSecurityEventSink::open_with_maximum_bytes(&path, MINIMUM_SPOOL_BYTES)?;
        drop(sink);
        let mut line = serde_json::to_vec(&event())?;
        line.push(b'\n');
        let target = MINIMUM_SPOOL_BYTES - MAX_EVENT_LINE_BYTES as u64 + 1;
        let mut contents = Vec::new();
        while (contents.len() as u64) < target {
            contents.extend_from_slice(&line);
        }
        assert!(contents.len() as u64 <= MINIMUM_SPOOL_BYTES);
        fs::write(&path, contents)?;
        assert!(
            JsonlSecurityEventSink::open_with_maximum_bytes(&path, MINIMUM_SPOOL_BYTES).is_err()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn active_writer_detects_external_append_and_same_size_rewrite()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let append_path = directory.path().join("append.jsonl");
        let append_sink = JsonlSecurityEventSink::open(&append_path)?;
        let mut external = OpenOptions::new().append(true).open(&append_path)?;
        external.write_all(b"external\n")?;
        external.sync_all()?;
        assert!(append_sink.emit(&event()).is_err());

        let rewrite_path = directory.path().join("rewrite.jsonl");
        let rewrite_sink = JsonlSecurityEventSink::open(&rewrite_path)?;
        rewrite_sink.emit(&event())?;
        let original_length = fs::metadata(&rewrite_path)?.len();
        let mut external = OpenOptions::new().write(true).open(&rewrite_path)?;
        external.seek(SeekFrom::Start(0))?;
        external.write_all(b"X")?;
        external.sync_all()?;
        assert_eq!(fs::metadata(&rewrite_path)?.len(), original_length);
        assert!(rewrite_sink.emit(&event()).is_err());
        Ok(())
    }

    #[test]
    fn writer_rejects_unsupported_version_and_oversized_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("events.jsonl");
        let sink = JsonlSecurityEventSink::open(&path)?;
        let mut unsupported = event();
        unsupported.version = 2;
        assert!(sink.emit(&unsupported).is_err());
        let mut oversized = event();
        oversized.user_id = Some("x".repeat(MAX_EVENT_LINE_BYTES));
        assert!(sink.emit(&oversized).is_err());
        assert_eq!(fs::metadata(path)?.len(), 0);
        Ok(())
    }
}
