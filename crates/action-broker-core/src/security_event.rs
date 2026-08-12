use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{BrokerError, BrokerResult, ErrorCode};

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
    writer: Mutex<BufWriter<File>>,
}

impl JsonlSecurityEventSink {
    pub fn open(path: &Path) -> BrokerResult<Self> {
        reject_unsafe_existing_file(path)?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path).map_err(|_| {
            BrokerError::new(
                ErrorCode::SecurityEventFailure,
                "security event spool cannot be opened",
            )
        })?;
        verify_private_file(&file)?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }
}

impl SecurityEventSink for JsonlSecurityEventSink {
    fn emit(&self, event: &SecurityEvent) -> BrokerResult<()> {
        let encoded = serde_json::to_vec(event).map_err(|_| {
            BrokerError::new(
                ErrorCode::SecurityEventFailure,
                "security event serialization failed",
            )
        })?;
        let mut writer = self.writer.lock().map_err(|_| {
            BrokerError::new(
                ErrorCode::SecurityEventFailure,
                "security event spool lock failed",
            )
        })?;
        writer
            .write_all(&encoded)
            .and_then(|()| writer.write_all(b"\n"))
            .map_err(|_| {
                BrokerError::new(
                    ErrorCode::SecurityEventFailure,
                    "security event spool write failed",
                )
            })?;
        writer
            .flush()
            .and_then(|()| writer.get_ref().sync_data())
            .map_err(|_| {
                BrokerError::new(
                    ErrorCode::SecurityEventFailure,
                    "security event spool durability failed",
                )
            })
    }
}

fn reject_unsafe_existing_file(path: &Path) -> BrokerResult<()> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(BrokerError::new(
                ErrorCode::SecurityEventFailure,
                "security event spool is not a regular file",
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BrokerError::new(
            ErrorCode::SecurityEventFailure,
            "security event spool metadata failed",
        )),
    }
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
    use super::*;

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
}
