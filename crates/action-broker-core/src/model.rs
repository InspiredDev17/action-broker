//! Versioned request and response envelopes shared by broker clients.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::capability::{
    BrowserOperation, CapabilityAction, CapabilityKind, CapabilityOutput, ContainerRuntime,
    GitReadOperation, GitWriteOperation, ProcessInspectOperation, RootedPath,
};

pub const ACTION_BROKER_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequesterIdentity {
    pub user_id: String,
    pub agent_id: String,
    pub task_id: String,
}

/// The execution location is part of the authorized request. Selecting a node
/// does not alter the capability's semantics or weaken its policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ExecutionTarget {
    Local,
    Node { node_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub protocol_version: u16,
    pub request_id: Uuid,
    pub requester: RequesterIdentity,
    pub target: ExecutionTarget,
    pub action: CapabilityAction,
    /// Compact `ab1` approval token. It is optional on the wire because a
    /// small set of read-only capabilities may be authorized by deterministic
    /// policy alone; policy rejects a missing token everywhere else.
    pub approval_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ActionErrorResponse {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ActionResponse {
    pub protocol_version: u16,
    pub request_id: Uuid,
    pub target: ExecutionTarget,
    pub capability: CapabilityKind,
    pub status: ActionStatus,
    pub output: Option<CapabilityOutput>,
    pub error: Option<ActionErrorResponse>,
    pub started_at_unix_milliseconds: i64,
    pub finished_at_unix_milliseconds: i64,
    pub output_sha256: Option<String>,
}

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("could not serialize validated capability arguments canonically: {0}")]
    CanonicalSerialization(#[from] serde_json::Error),
    #[error("capability target URL is invalid: {0}")]
    InvalidTargetUrl(#[from] url::ParseError),
}

impl ActionRequest {
    /// Returns the lowercase hexadecimal SHA-256 digest of the RFC 8785/JCS
    /// encoding of the typed capability arguments. The capability kind is
    /// separately bound into an approval claim.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::CanonicalSerialization`] if canonical JSON
    /// serialization fails.
    pub fn arguments_digest(&self) -> Result<String, ModelError> {
        let bytes = match &self.action {
            CapabilityAction::ReadFile(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::WriteFile(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::CreateFile(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::MoveFile(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::DeleteFile(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::ListDirectory(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::ExecuteApprovedCommand(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::GitRead(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::GitWrite(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::HttpRequest(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::BrowserAction(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::ProcessInspect(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::ServiceInspect(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::ServiceControl(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::ContainerAction(arguments) => canonical_arguments(arguments)?,
            CapabilityAction::NodeAction(arguments) => canonical_arguments(arguments)?,
        };

        Ok(sha256_hex(&bytes))
    }

    /// Returns the lowercase hexadecimal SHA-256 digest of a canonical target
    /// projection. It binds the local-or-node execution target and the
    /// capability's actual resource target independently of the full argument
    /// digest, making target authorization directly auditable.
    ///
    /// HTTP and browser navigation URLs are parsed and normalized before this
    /// digest is calculated. The broker still applies destination policy and
    /// resolved-address checks separately.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidTargetUrl`] for an invalid URL, or
    /// [`ModelError::CanonicalSerialization`] if JCS serialization fails.
    pub fn target_digest(&self) -> Result<String, ModelError> {
        let resource_target = match &self.action {
            CapabilityAction::ReadFile(arguments) => ResourceTarget::Path {
                path: &arguments.path,
            },
            CapabilityAction::WriteFile(arguments) => ResourceTarget::Path {
                path: &arguments.path,
            },
            CapabilityAction::CreateFile(arguments) => ResourceTarget::Path {
                path: &arguments.path,
            },
            CapabilityAction::MoveFile(arguments) => ResourceTarget::Move {
                source: &arguments.source,
                destination: &arguments.destination,
            },
            CapabilityAction::DeleteFile(arguments) => ResourceTarget::Path {
                path: &arguments.path,
            },
            CapabilityAction::ListDirectory(arguments) => ResourceTarget::Path {
                path: &arguments.path,
            },
            CapabilityAction::ExecuteApprovedCommand(arguments) => ResourceTarget::Command {
                program_id: &arguments.program_id,
                working_directory: &arguments.working_directory,
            },
            CapabilityAction::GitRead(arguments) => ResourceTarget::GitRead {
                repository_path: &arguments.repository_path,
                operation: &arguments.operation,
            },
            CapabilityAction::GitWrite(arguments) => ResourceTarget::GitWrite {
                repository_path: &arguments.repository_path,
                operation: &arguments.operation,
            },
            CapabilityAction::HttpRequest(arguments) => ResourceTarget::Http {
                normalized_url: normalize_url(&arguments.url)?,
            },
            CapabilityAction::BrowserAction(arguments) => ResourceTarget::Browser {
                browser_session_id: &arguments.browser_session_id,
                operation: BrowserTarget::from_operation(&arguments.operation)?,
            },
            CapabilityAction::ProcessInspect(arguments) => ResourceTarget::Process {
                operation: &arguments.operation,
            },
            CapabilityAction::ServiceInspect(arguments) => ResourceTarget::Service {
                service_name: &arguments.service_name,
            },
            CapabilityAction::ServiceControl(arguments) => ResourceTarget::Service {
                service_name: &arguments.service_name,
            },
            CapabilityAction::ContainerAction(arguments) => ResourceTarget::Container {
                runtime: arguments.runtime,
                container_id: &arguments.container_id,
            },
            CapabilityAction::NodeAction(arguments) => ResourceTarget::Node {
                node_id: &arguments.node_id,
            },
        };
        let material = TargetDigestMaterial {
            execution_target: &self.target,
            capability: self.capability(),
            resource_target,
        };
        let canonical = serde_jcs::to_vec(&material)?;
        Ok(sha256_hex(&canonical))
    }

    #[must_use]
    pub const fn capability(&self) -> CapabilityKind {
        self.action.kind()
    }
}

fn canonical_arguments<T: Serialize>(arguments: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_jcs::to_vec(arguments)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn normalize_url(raw: &str) -> Result<String, url::ParseError> {
    url::Url::parse(raw).map(|url| url.to_string())
}

#[derive(Serialize)]
struct TargetDigestMaterial<'a> {
    execution_target: &'a ExecutionTarget,
    capability: CapabilityKind,
    resource_target: ResourceTarget<'a>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ResourceTarget<'a> {
    Path {
        path: &'a RootedPath,
    },
    Move {
        source: &'a RootedPath,
        destination: &'a RootedPath,
    },
    Command {
        program_id: &'a str,
        working_directory: &'a RootedPath,
    },
    GitRead {
        repository_path: &'a RootedPath,
        operation: &'a GitReadOperation,
    },
    GitWrite {
        repository_path: &'a RootedPath,
        operation: &'a GitWriteOperation,
    },
    Http {
        normalized_url: String,
    },
    Browser {
        browser_session_id: &'a str,
        operation: BrowserTarget<'a>,
    },
    Process {
        operation: &'a ProcessInspectOperation,
    },
    Service {
        service_name: &'a str,
    },
    Container {
        runtime: ContainerRuntime,
        container_id: &'a str,
    },
    Node {
        node_id: &'a str,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrowserTarget<'a> {
    Navigate { normalized_url: String },
    Click { selector: &'a str },
    TypeText { selector: &'a str },
    ReadText { selector: &'a str },
    Screenshot,
}

impl<'a> BrowserTarget<'a> {
    fn from_operation(operation: &'a BrowserOperation) -> Result<Self, url::ParseError> {
        match operation {
            BrowserOperation::Navigate { url } => Ok(Self::Navigate {
                normalized_url: normalize_url(url)?,
            }),
            BrowserOperation::Click { selector } => Ok(Self::Click { selector }),
            BrowserOperation::TypeText { selector, .. } => Ok(Self::TypeText { selector }),
            BrowserOperation::ReadText { selector } => Ok(Self::ReadText { selector }),
            BrowserOperation::Screenshot => Ok(Self::Screenshot),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use uuid::Uuid;

    use super::{
        ACTION_BROKER_PROTOCOL_VERSION, ActionRequest, ExecutionTarget, RequesterIdentity,
    };
    use crate::capability::{
        CapabilityAction, ExecuteApprovedCommandInput, HttpMethod, HttpRequestInput, RootedPath,
    };

    fn request(environment: BTreeMap<String, String>) -> ActionRequest {
        ActionRequest {
            protocol_version: ACTION_BROKER_PROTOCOL_VERSION,
            request_id: Uuid::nil(),
            requester: RequesterIdentity {
                user_id: "user-1".to_owned(),
                agent_id: "agent-1".to_owned(),
                task_id: "task-1".to_owned(),
            },
            target: ExecutionTarget::Local,
            action: CapabilityAction::ExecuteApprovedCommand(ExecuteApprovedCommandInput {
                program_id: "git.readonly".to_owned(),
                arguments: vec!["status".to_owned(), "--short".to_owned()],
                working_directory: RootedPath {
                    root_id: "workspace".to_owned(),
                    relative_path: "repository".to_owned(),
                },
                environment,
                timeout_milliseconds: Some(5_000),
            }),
            approval_token: None,
        }
    }

    fn http_request(url: &str) -> ActionRequest {
        ActionRequest {
            protocol_version: ACTION_BROKER_PROTOCOL_VERSION,
            request_id: Uuid::nil(),
            requester: RequesterIdentity {
                user_id: "user-1".to_owned(),
                agent_id: "agent-1".to_owned(),
                task_id: "task-1".to_owned(),
            },
            target: ExecutionTarget::Local,
            action: CapabilityAction::HttpRequest(HttpRequestInput {
                method: HttpMethod::Get,
                url: url.to_owned(),
                headers: BTreeMap::new(),
                body_base64: None,
                maximum_response_bytes: 1_024,
                timeout_milliseconds: Some(5_000),
            }),
            approval_token: None,
        }
    }

    #[test]
    fn argument_digest_is_deterministic_across_map_insertion_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut first = BTreeMap::new();
        first.insert("LANG".to_owned(), "C".to_owned());
        first.insert("TZ".to_owned(), "UTC".to_owned());

        let mut second = BTreeMap::new();
        second.insert("TZ".to_owned(), "UTC".to_owned());
        second.insert("LANG".to_owned(), "C".to_owned());

        assert_eq!(
            request(first).arguments_digest()?,
            request(second).arguments_digest()?
        );
        Ok(())
    }

    #[test]
    fn argument_digest_changes_when_an_argument_changes() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut changed = request(BTreeMap::new());
        let original = changed.arguments_digest()?;
        if let CapabilityAction::ExecuteApprovedCommand(arguments) = &mut changed.action {
            arguments.arguments.push("--branch".to_owned());
        }
        assert_ne!(original, changed.arguments_digest()?);
        Ok(())
    }

    #[test]
    fn target_digest_normalizes_http_urls() -> Result<(), Box<dyn std::error::Error>> {
        let first = http_request("HTTPS://EXAMPLE.COM:443/a/../resource");
        let second = http_request("https://example.com/resource");

        assert_eq!(first.target_digest()?, second.target_digest()?);
        assert_eq!(
            second.target_digest()?,
            "3bc70351ca05b0ef40036eb118aa1798d15fa620472dc48120c929c9abc4e5ce"
        );
        assert_eq!(
            second.arguments_digest()?,
            "6d1bc8f896f25e8a63be1cc27398d4a54e1ee0cb376f7d2142c525889ba1ac3e"
        );
        assert_ne!(first.arguments_digest()?, second.arguments_digest()?);
        Ok(())
    }
}
