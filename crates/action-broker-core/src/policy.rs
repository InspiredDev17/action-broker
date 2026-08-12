use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::capability::{
    ApprovalRequirement, CapabilityDescriptor, CapabilityKind, Permission, RiskClass,
};
use crate::error::{BrokerError, BrokerResult, ErrorCode};
use crate::model::{ACTION_BROKER_PROTOCOL_VERSION, ActionRequest};

const MAX_ID_LENGTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalGrant {
    pub user_id: String,
    pub agent_id: String,
    pub permissions: BTreeSet<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub grants: Vec<PrincipalGrant>,
    /// Explicitly disabled capabilities stay disabled even when a permission
    /// grant exists. There is no wildcard grant or bypass switch.
    #[serde(default)]
    pub disabled_capabilities: BTreeSet<CapabilityKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub descriptor: CapabilityDescriptor,
    pub approval_required: bool,
    pub risk_class: RiskClass,
}

/// Exact user+agent grants compiled from trusted configuration. Task IDs remain
/// mandatory audit and approval bindings but never grant permissions.
pub struct DeterministicPolicy {
    grants: BTreeMap<(String, String), BTreeSet<Permission>>,
    disabled_capabilities: BTreeSet<CapabilityKind>,
}

impl DeterministicPolicy {
    pub fn from_config(config: PolicyConfig) -> BrokerResult<Self> {
        let mut grants = BTreeMap::new();
        for grant in config.grants {
            validate_identifier(&grant.user_id, "user_id")?;
            validate_identifier(&grant.agent_id, "agent_id")?;
            if grant.permissions.is_empty() {
                return Err(BrokerError::invalid("permission grant cannot be empty"));
            }
            let key = (grant.user_id, grant.agent_id);
            if grants.insert(key, grant.permissions).is_some() {
                return Err(BrokerError::invalid(
                    "duplicate user and agent permission grant",
                ));
            }
        }
        if grants.is_empty() {
            return Err(BrokerError::invalid(
                "at least one permission grant is required",
            ));
        }
        Ok(Self {
            grants,
            disabled_capabilities: config.disabled_capabilities,
        })
    }

    pub fn evaluate(&self, request: &ActionRequest) -> BrokerResult<PolicyDecision> {
        if request.protocol_version != ACTION_BROKER_PROTOCOL_VERSION {
            return Err(BrokerError::invalid("unsupported protocol version"));
        }
        validate_identifier(&request.requester.user_id, "user_id")?;
        validate_identifier(&request.requester.agent_id, "agent_id")?;
        validate_identifier(&request.requester.task_id, "task_id")?;
        let capability = request.capability();
        if self.disabled_capabilities.contains(&capability) {
            return Err(BrokerError::new(
                ErrorCode::PermissionDenied,
                "capability is disabled by broker policy",
            ));
        }
        let permissions = self
            .grants
            .get(&(
                request.requester.user_id.clone(),
                request.requester.agent_id.clone(),
            ))
            .ok_or_else(|| {
                BrokerError::new(
                    ErrorCode::PermissionDenied,
                    "requester has no broker permission grant",
                )
            })?;
        let descriptor = request.action.descriptor();
        if !permissions.contains(&descriptor.permission_required) {
            return Err(BrokerError::new(
                ErrorCode::PermissionDenied,
                "required capability permission was not granted",
            ));
        }
        let approval_required = matches!(
            descriptor.approval_policy.requirement,
            ApprovalRequirement::SignedToken
        );
        Ok(PolicyDecision {
            risk_class: descriptor.risk_class,
            descriptor,
            approval_required,
        })
    }
}

fn validate_identifier(value: &str, field: &'static str) -> BrokerResult<()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_ID_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if !valid {
        return Err(BrokerError::invalid(format!("{field} is invalid")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use uuid::Uuid;

    use super::*;
    use crate::capability::{
        CapabilityAction, ExecuteApprovedCommandInput, ReadFileInput, RootedPath,
    };
    use crate::model::{ExecutionTarget, RequesterIdentity};

    fn request(action: CapabilityAction) -> ActionRequest {
        ActionRequest {
            protocol_version: ACTION_BROKER_PROTOCOL_VERSION,
            request_id: Uuid::nil(),
            requester: RequesterIdentity {
                user_id: "user".to_owned(),
                agent_id: "agent".to_owned(),
                task_id: "task".to_owned(),
            },
            target: ExecutionTarget::Local,
            action,
            approval_token: None,
        }
    }

    #[test]
    fn missing_permission_fails_closed() -> BrokerResult<()> {
        let policy = DeterministicPolicy::from_config(PolicyConfig {
            grants: vec![PrincipalGrant {
                user_id: "user".to_owned(),
                agent_id: "agent".to_owned(),
                permissions: BTreeSet::from([Permission::FilesystemRead]),
            }],
            disabled_capabilities: BTreeSet::new(),
        })?;
        let result = policy.evaluate(&request(CapabilityAction::ExecuteApprovedCommand(
            ExecuteApprovedCommandInput {
                program_id: "git".to_owned(),
                arguments: vec!["status".to_owned()],
                working_directory: RootedPath {
                    root_id: "workspace".to_owned(),
                    relative_path: ".".to_owned(),
                },
                environment: BTreeMap::new(),
                timeout_milliseconds: None,
            },
        )));
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::PermissionDenied,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn read_permission_does_not_require_approval() -> BrokerResult<()> {
        let policy = DeterministicPolicy::from_config(PolicyConfig {
            grants: vec![PrincipalGrant {
                user_id: "user".to_owned(),
                agent_id: "agent".to_owned(),
                permissions: BTreeSet::from([Permission::FilesystemRead]),
            }],
            disabled_capabilities: BTreeSet::new(),
        })?;
        let decision = policy.evaluate(&request(CapabilityAction::ReadFile(ReadFileInput {
            path: RootedPath {
                root_id: "workspace".to_owned(),
                relative_path: "notes.txt".to_owned(),
            },
            maximum_bytes: 1024,
        })))?;
        assert!(!decision.approval_required);
        Ok(())
    }
}
