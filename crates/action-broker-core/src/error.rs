use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type BrokerResult<T> = Result<T, BrokerError>;

/// Stable, non-secret error classes exposed across the broker boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    PermissionDenied,
    ApprovalRequired,
    ApprovalInvalid,
    ApprovalExpired,
    ApprovalReplayed,
    PathEscape,
    SecretAccess,
    ForbiddenExecutable,
    ForbiddenDestination,
    ResourceLimit,
    Timeout,
    Cancelled,
    SandboxUnavailable,
    SandboxFailure,
    UnexpectedPrivilegeElevation,
    BackendUnavailable,
    AuditFailure,
    SecurityEventFailure,
    ExecutionFailure,
    Internal,
}

/// Internal error with a deliberately bounded, operator-safe message.
#[derive(Debug, Error)]
#[error("{code:?}: {message}")]
pub struct BrokerError {
    pub code: ErrorCode,
    pub message: String,
}

impl BrokerError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, message)
    }

    #[must_use]
    pub fn internal() -> Self {
        Self::new(ErrorCode::Internal, "internal broker failure")
    }
}

/// Wire-safe error. It never includes child output, tokens, environment values,
/// URLs with queries, or raw filesystem contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicError {
    pub code: ErrorCode,
    pub message: String,
}

impl From<&BrokerError> for PublicError {
    fn from(value: &BrokerError) -> Self {
        Self {
            code: value.code,
            message: value.message.clone(),
        }
    }
}
