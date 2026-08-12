use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::approval::{ApprovalError, ApprovalVerifier, VerifiedApproval};
use crate::audit::{ApprovalAudit, AuditEvent, AuditPhase, AuditSink, FileChangeAudit};
use crate::capability::{
    ApprovalRequirement, CapabilityAction, CapabilityOutput, HttpRequestOutput, RootedPath,
};
use crate::command::{ApprovedCommandExecutor, CancellationToken};
use crate::error::{BrokerError, BrokerResult, ErrorCode};
use crate::filesystem::ScopedFilesystem;
use crate::git::GitReadExecutor;
use crate::model::{
    ACTION_BROKER_PROTOCOL_VERSION, ActionErrorResponse, ActionRequest, ActionResponse,
    ActionStatus, ExecutionTarget,
};
use crate::network::SecureHttpClient;
use crate::policy::DeterministicPolicy;
use crate::security_event::{SecurityEvent, SecurityEventKind, SecurityEventSink};

#[derive(Debug, Clone, Copy)]
pub struct BrokerLimits {
    pub maximum_concurrent_actions: usize,
    pub concurrency_wait_milliseconds: u64,
}

impl Default for BrokerLimits {
    fn default() -> Self {
        Self {
            maximum_concurrent_actions: 8,
            concurrency_wait_milliseconds: 1_000,
        }
    }
}

struct ConcurrencyState {
    in_flight: usize,
}

struct ConcurrencyGate {
    state: Mutex<ConcurrencyState>,
    available: Condvar,
    maximum: usize,
    wait: Duration,
}

struct ConcurrencyPermit<'a>(&'a ConcurrencyGate);

impl Drop for ConcurrencyPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.in_flight = state.in_flight.saturating_sub(1);
            self.0.available.notify_one();
        }
    }
}

impl ConcurrencyGate {
    fn new(limits: BrokerLimits) -> BrokerResult<Self> {
        if limits.maximum_concurrent_actions == 0
            || limits.maximum_concurrent_actions > 256
            || limits.concurrency_wait_milliseconds == 0
            || limits.concurrency_wait_milliseconds > 30_000
        {
            return Err(BrokerError::invalid(
                "broker concurrency limits are invalid",
            ));
        }
        Ok(Self {
            state: Mutex::new(ConcurrencyState { in_flight: 0 }),
            available: Condvar::new(),
            maximum: limits.maximum_concurrent_actions,
            wait: Duration::from_millis(limits.concurrency_wait_milliseconds),
        })
    }

    fn acquire(&self) -> BrokerResult<ConcurrencyPermit<'_>> {
        let deadline = Instant::now() + self.wait;
        let mut state = self
            .state
            .lock()
            .map_err(|_| BrokerError::new(ErrorCode::Internal, "concurrency lock failed"))?;
        while state.in_flight >= self.maximum {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(BrokerError::new(
                    ErrorCode::ResourceLimit,
                    "broker concurrency limit reached",
                ));
            }
            let (next, timeout) = self
                .available
                .wait_timeout(state, remaining)
                .map_err(|_| BrokerError::new(ErrorCode::Internal, "concurrency wait failed"))?;
            state = next;
            if timeout.timed_out() && state.in_flight >= self.maximum {
                return Err(BrokerError::new(
                    ErrorCode::ResourceLimit,
                    "broker concurrency limit reached",
                ));
            }
        }
        state.in_flight = state.in_flight.saturating_add(1);
        Ok(ConcurrencyPermit(self))
    }
}

/// The deterministic broker boundary. Agent Green emission and audit sinks are
/// required constructor arguments; there is no request or config flag that can
/// disable them.
pub struct ActionBroker {
    policy: DeterministicPolicy,
    approvals: ApprovalVerifier,
    filesystem: Arc<ScopedFilesystem>,
    commands: ApprovedCommandExecutor,
    git: GitReadExecutor,
    http: SecureHttpClient,
    audit: Arc<dyn AuditSink>,
    security_events: Arc<dyn SecurityEventSink>,
    concurrency: ConcurrencyGate,
    expected_effective_uid: u32,
}

/// Identity established by the transport before request JSON is trusted.
/// The broker compares it with the asserted requester before policy lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRequester {
    pub user_id: String,
    pub agent_id: String,
}

impl ActionBroker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: DeterministicPolicy,
        approvals: ApprovalVerifier,
        filesystem: Arc<ScopedFilesystem>,
        commands: ApprovedCommandExecutor,
        http: SecureHttpClient,
        audit: Arc<dyn AuditSink>,
        security_events: Arc<dyn SecurityEventSink>,
        limits: BrokerLimits,
    ) -> BrokerResult<Self> {
        let git = GitReadExecutor::new(Arc::clone(&filesystem));
        Ok(Self {
            policy,
            approvals,
            filesystem,
            commands,
            git,
            http,
            audit,
            security_events,
            concurrency: ConcurrencyGate::new(limits)?,
            expected_effective_uid: rustix::process::geteuid().as_raw(),
        })
    }

    /// Executes one exact typed request. Unsupported capabilities and remote
    /// targets fail closed after permission and approval checks, preserving
    /// protocol semantics without claiming an absent backend.
    pub fn execute(
        &self,
        request: ActionRequest,
        authenticated_requester: &AuthenticatedRequester,
        cancellation: &CancellationToken,
    ) -> ActionResponse {
        let started_at = unix_milliseconds();
        let capability = request.capability();
        let target = request.target.clone();
        let result =
            self.execute_inner(&request, authenticated_requester, cancellation, started_at);
        let finished_at = unix_milliseconds();
        match result {
            Ok(output) => {
                let output_digest = output_digest(&output).ok();
                ActionResponse {
                    protocol_version: ACTION_BROKER_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    target,
                    capability,
                    status: ActionStatus::Succeeded,
                    output: Some(output),
                    error: None,
                    started_at_unix_milliseconds: started_at,
                    finished_at_unix_milliseconds: finished_at,
                    output_sha256: output_digest,
                }
            }
            Err(error) => ActionResponse {
                protocol_version: ACTION_BROKER_PROTOCOL_VERSION,
                request_id: request.request_id,
                target,
                capability,
                status: status_for_error(error.code),
                output: None,
                error: Some(ActionErrorResponse {
                    code: error_code_name(error.code).to_owned(),
                    message: error.message,
                    // A timeout, resource breach, or audit failure may follow
                    // a partial host effect. Automatic retries are never safe.
                    retryable: false,
                }),
                started_at_unix_milliseconds: started_at,
                finished_at_unix_milliseconds: finished_at,
                output_sha256: None,
            },
        }
    }

    fn execute_inner(
        &self,
        request: &ActionRequest,
        authenticated_requester: &AuthenticatedRequester,
        cancellation: &CancellationToken,
        started_at: i64,
    ) -> BrokerResult<CapabilityOutput> {
        if let Err(error) = ensure_expected_effective_uid(
            self.expected_effective_uid,
            rustix::process::geteuid().as_raw(),
        ) {
            self.emit_for_error(request, &error)?;
            return Err(error);
        }
        if request.requester.user_id != authenticated_requester.user_id
            || request.requester.agent_id != authenticated_requester.agent_id
        {
            let error = BrokerError::new(
                ErrorCode::PermissionDenied,
                "request identity does not match the authenticated transport principal",
            );
            self.emit_for_error(request, &error)?;
            return Err(error);
        }
        let _permit = match self.concurrency.acquire() {
            Ok(permit) => permit,
            Err(error) => {
                self.emit_for_error(request, &error)?;
                return Err(error);
            }
        };
        if cancellation.is_cancelled() {
            return Err(BrokerError::new(
                ErrorCode::Cancelled,
                "action was cancelled",
            ));
        }
        let decision = match self.policy.evaluate(request) {
            Ok(decision) => decision,
            Err(error) => {
                self.emit_for_error(request, &error)?;
                return Err(error);
            }
        };
        let arguments_hash = request
            .arguments_digest()
            .map_err(|_| BrokerError::invalid("capability arguments cannot be canonicalized"))?;
        let verified_approval = match decision.descriptor.approval_policy.requirement {
            ApprovalRequirement::PolicyOnly => {
                if request.approval_token.is_some() {
                    return Err(BrokerError::invalid(
                        "approval token is not accepted for policy-only capability",
                    ));
                }
                None
            }
            ApprovalRequirement::SignedToken => {
                match self
                    .approvals
                    .verify_embedded(request, &decision.descriptor.approval_policy.accepted_types)
                {
                    Ok(approval) => Some(approval),
                    Err(error) => {
                        let broker_error = map_approval_error(&error);
                        self.emit_for_error(request, &broker_error)?;
                        return Err(broker_error);
                    }
                }
            }
        };
        if let Some(approval) = &verified_approval {
            let lifetime = approval
                .claims
                .expires_at_unix_seconds
                .saturating_sub(approval.claims.issued_at_unix_seconds);
            let descriptor_ttl =
                i64::try_from(decision.descriptor.approval_policy.maximum_ttl_seconds)
                    .unwrap_or(i64::MAX);
            if lifetime > descriptor_ttl {
                let error = BrokerError::new(
                    ErrorCode::ApprovalInvalid,
                    "approval lifetime exceeds the capability policy",
                );
                self.emit_for_error(request, &error)?;
                return Err(error);
            }
            if OffsetDateTime::now_utc().unix_timestamp() >= approval.claims.expires_at_unix_seconds
            {
                let error = BrokerError::new(
                    ErrorCode::ApprovalExpired,
                    "approval expired before dispatch",
                );
                self.emit_for_error(request, &error)?;
                return Err(error);
            }
        }
        let approval_audit = approval_audit(request, verified_approval.as_ref());
        let audit_id = Uuid::new_v4();
        let start_event = base_audit_event(
            audit_id,
            request,
            &arguments_hash,
            approval_audit.clone(),
            started_at,
            AuditPhase::Started,
        );
        self.audit.record(&start_event)?;

        let execution_result = self.dispatch(request, cancellation);
        let finished_at = unix_milliseconds();
        let finish_event = finish_audit_event(
            audit_id,
            request,
            &arguments_hash,
            approval_audit,
            started_at,
            finished_at,
            execution_result.as_ref(),
        );
        self.audit.record(&finish_event)?;
        if let Err(error) = &execution_result {
            self.emit_for_error(request, error)?;
        }
        execution_result
    }

    fn dispatch(
        &self,
        request: &ActionRequest,
        cancellation: &CancellationToken,
    ) -> BrokerResult<CapabilityOutput> {
        if !matches!(request.target, ExecutionTarget::Local) {
            return Err(BrokerError::new(
                ErrorCode::BackendUnavailable,
                "remote Node Runtime backend is not configured",
            ));
        }
        match &request.action {
            CapabilityAction::ReadFile(input) => self
                .filesystem
                .read_file(input)
                .map(CapabilityOutput::ReadFile),
            CapabilityAction::WriteFile(input) => self
                .filesystem
                .write_file(input)
                .map(CapabilityOutput::WriteFile),
            CapabilityAction::CreateFile(input) => self
                .filesystem
                .create_file(input)
                .map(CapabilityOutput::CreateFile),
            CapabilityAction::MoveFile(input) => self
                .filesystem
                .move_file(input)
                .map(CapabilityOutput::MoveFile),
            CapabilityAction::DeleteFile(input) => self
                .filesystem
                .delete_file(input)
                .map(CapabilityOutput::DeleteFile),
            CapabilityAction::ListDirectory(input) => self
                .filesystem
                .list_directory(input)
                .map(CapabilityOutput::ListDirectory),
            CapabilityAction::ExecuteApprovedCommand(input) => self
                .commands
                .execute(input, cancellation)
                .map(CapabilityOutput::ExecuteApprovedCommand),
            CapabilityAction::HttpRequest(input) => self
                .http
                .execute(input, cancellation)
                .map(CapabilityOutput::HttpRequest),
            CapabilityAction::GitRead(input) => self
                .git
                .execute(input, cancellation)
                .map(CapabilityOutput::GitRead),
            CapabilityAction::GitWrite(_)
            | CapabilityAction::BrowserAction(_)
            | CapabilityAction::ProcessInspect(_)
            | CapabilityAction::ServiceInspect(_)
            | CapabilityAction::ServiceControl(_)
            | CapabilityAction::ContainerAction(_)
            | CapabilityAction::NodeAction(_) => Err(BrokerError::new(
                ErrorCode::BackendUnavailable,
                "capability backend is not configured",
            )),
        }
    }

    fn emit_for_error(&self, request: &ActionRequest, error: &BrokerError) -> BrokerResult<()> {
        emit_security_event(self.security_events.as_ref(), request, error)
    }
}

fn emit_security_event(
    sink: &dyn SecurityEventSink,
    request: &ActionRequest,
    error: &BrokerError,
) -> BrokerResult<()> {
    let Some(kind) = security_event_kind(error.code) else {
        return Ok(());
    };
    let mut event = SecurityEvent::new(kind, error_code_name(error.code));
    event.request_id = Some(request.request_id);
    event.user_id = Some(request.requester.user_id.clone());
    event.agent_id = Some(request.requester.agent_id.clone());
    event.task_id = Some(request.requester.task_id.clone());
    event.capability = Some(format!("{:?}", request.capability()));
    event.target_digest = request.target_digest().ok();
    sink.emit(&event)
}

fn base_audit_event(
    audit_id: Uuid,
    request: &ActionRequest,
    arguments_hash: &str,
    approval: ApprovalAudit,
    started_at: i64,
    phase: AuditPhase,
) -> AuditEvent {
    AuditEvent {
        version: 1,
        audit_id,
        phase,
        request_id: request.request_id,
        user_id: request.requester.user_id.clone(),
        agent_id: request.requester.agent_id.clone(),
        task_id: request.requester.task_id.clone(),
        capability: format!("{:?}", request.capability()),
        target: target_audit_label(request),
        validated_arguments_hash: arguments_hash.to_owned(),
        approval,
        started_at_unix_ms: i128::from(started_at),
        finished_at_unix_ms: None,
        exit_status: None,
        output_digest: None,
        error_code: None,
        files_changed: Vec::new(),
        network_destinations: Vec::new(),
    }
}

fn finish_audit_event(
    audit_id: Uuid,
    request: &ActionRequest,
    arguments_hash: &str,
    approval: ApprovalAudit,
    started_at: i64,
    finished_at: i64,
    result: Result<&CapabilityOutput, &BrokerError>,
) -> AuditEvent {
    let mut event = base_audit_event(
        audit_id,
        request,
        arguments_hash,
        approval,
        started_at,
        AuditPhase::Finished,
    );
    event.finished_at_unix_ms = Some(i128::from(finished_at));
    match result {
        Ok(output) => {
            event.output_digest = output_digest(output).ok();
            event.exit_status = command_exit_status(output);
            event.files_changed = changed_files(request, output);
            event.network_destinations = network_destinations(output);
        }
        Err(error) => {
            event.error_code = Some(error.code);
            event.network_destinations = attempted_network_destinations(request);
        }
    }
    event
}

fn approval_audit(request: &ActionRequest, approval: Option<&VerifiedApproval>) -> ApprovalAudit {
    ApprovalAudit {
        required: approval.is_some(),
        approval_type: approval.map(|value| format!("{:?}", value.claims.approval_type)),
        token_digest: request
            .approval_token
            .as_deref()
            .map(|token| hex::encode(Sha256::digest(token.as_bytes()))),
        key_id: approval.map(|value| value.key_id.clone()),
    }
}

fn output_digest(output: &CapabilityOutput) -> BrokerResult<String> {
    let bytes = serde_jcs::to_vec(output)
        .map_err(|_| BrokerError::new(ErrorCode::Internal, "output canonicalization failed"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn changed_files(request: &ActionRequest, output: &CapabilityOutput) -> Vec<FileChangeAudit> {
    match (&request.action, output) {
        (CapabilityAction::WriteFile(input), CapabilityOutput::WriteFile(result)) => {
            vec![file_change(
                &input.path,
                result.previous_sha256.clone(),
                Some(result.current_sha256.clone()),
                "write",
            )]
        }
        (CapabilityAction::CreateFile(input), CapabilityOutput::CreateFile(result)) => {
            vec![file_change(
                &input.path,
                None,
                Some(result.current_sha256.clone()),
                "create",
            )]
        }
        (CapabilityAction::MoveFile(input), CapabilityOutput::MoveFile(result)) => vec![
            file_change(
                &input.source,
                Some(result.moved_sha256.clone()),
                None,
                "move_source",
            ),
            file_change(
                &input.destination,
                result.replaced_sha256.clone(),
                Some(result.moved_sha256.clone()),
                "move_destination",
            ),
        ],
        (CapabilityAction::DeleteFile(input), CapabilityOutput::DeleteFile(result)) => {
            vec![file_change(
                &input.path,
                Some(result.previous_sha256.clone()),
                None,
                "recoverable_delete",
            )]
        }
        _ => Vec::new(),
    }
}

fn file_change(
    path: &RootedPath,
    before_digest: Option<String>,
    after_digest: Option<String>,
    operation: &str,
) -> FileChangeAudit {
    FileChangeAudit {
        root_id: path.root_id.clone(),
        relative_path_digest: hex::encode(Sha256::digest(path.relative_path.as_bytes())),
        before_digest,
        after_digest,
        operation: operation.to_owned(),
    }
}

fn network_destinations(output: &CapabilityOutput) -> Vec<String> {
    match output {
        CapabilityOutput::HttpRequest(HttpRequestOutput {
            contacted_destinations,
            ..
        }) => contacted_destinations.clone(),
        _ => Vec::new(),
    }
}

fn attempted_network_destinations(request: &ActionRequest) -> Vec<String> {
    let CapabilityAction::HttpRequest(input) = &request.action else {
        return Vec::new();
    };
    let Ok(url) = url::Url::parse(&input.url) else {
        return Vec::new();
    };
    let Some(host) = url.host_str() else {
        return Vec::new();
    };
    let Some(port) = url.port_or_known_default() else {
        return Vec::new();
    };
    vec![format!("attempted:{}://{}:{port}", url.scheme(), host)]
}

fn command_exit_status(output: &CapabilityOutput) -> Option<i32> {
    match output {
        CapabilityOutput::ExecuteApprovedCommand(output) => output.exit_code,
        _ => None,
    }
}

fn target_audit_label(request: &ActionRequest) -> String {
    let target = match &request.target {
        ExecutionTarget::Local => "local".to_owned(),
        ExecutionTarget::Node { node_id } => {
            format!("node:{}", hex::encode(Sha256::digest(node_id.as_bytes())))
        }
    };
    request
        .target_digest()
        .map_or(target.clone(), |digest| format!("{target}:{digest}"))
}

fn map_approval_error(error: &ApprovalError) -> BrokerError {
    match error {
        ApprovalError::MissingToken => {
            BrokerError::new(ErrorCode::ApprovalRequired, "signed approval is required")
        }
        ApprovalError::Expired | ApprovalError::NotYetValid => BrokerError::new(
            ErrorCode::ApprovalExpired,
            "approval is not currently valid",
        ),
        ApprovalError::ReplayDetected => BrokerError::new(
            ErrorCode::ApprovalReplayed,
            "approval has already been used",
        ),
        ApprovalError::ReplayStoreUnavailable(_) => BrokerError::new(
            ErrorCode::ApprovalInvalid,
            "approval replay protection is unavailable",
        ),
        _ => BrokerError::new(ErrorCode::ApprovalInvalid, "approval is invalid"),
    }
}

fn ensure_expected_effective_uid(expected: u32, observed: u32) -> BrokerResult<()> {
    if observed == expected {
        return Ok(());
    }
    Err(BrokerError::new(
        ErrorCode::UnexpectedPrivilegeElevation,
        "broker effective user identity changed unexpectedly",
    ))
}

const fn status_for_error(code: ErrorCode) -> ActionStatus {
    match code {
        ErrorCode::Timeout => ActionStatus::TimedOut,
        ErrorCode::Cancelled => ActionStatus::Cancelled,
        ErrorCode::PermissionDenied
        | ErrorCode::ApprovalRequired
        | ErrorCode::ApprovalInvalid
        | ErrorCode::ApprovalExpired
        | ErrorCode::ApprovalReplayed
        | ErrorCode::PathEscape
        | ErrorCode::SecretAccess
        | ErrorCode::ForbiddenExecutable
        | ErrorCode::ForbiddenDestination => ActionStatus::Rejected,
        _ => ActionStatus::Failed,
    }
}

const fn security_event_kind(code: ErrorCode) -> Option<SecurityEventKind> {
    match code {
        ErrorCode::PermissionDenied => Some(SecurityEventKind::PermissionBypassAttempt),
        ErrorCode::ApprovalExpired => Some(SecurityEventKind::ExpiredApproval),
        ErrorCode::ApprovalReplayed => Some(SecurityEventKind::ReplayedApproval),
        ErrorCode::ApprovalInvalid => Some(SecurityEventKind::ApprovalTampering),
        ErrorCode::PathEscape => Some(SecurityEventKind::PathEscape),
        ErrorCode::SecretAccess => Some(SecurityEventKind::SecretAccessAttempt),
        ErrorCode::ForbiddenExecutable => Some(SecurityEventKind::ForbiddenExecutable),
        ErrorCode::ForbiddenDestination => Some(SecurityEventKind::ForbiddenDestination),
        ErrorCode::ResourceLimit => Some(SecurityEventKind::ResourceAbusePattern),
        ErrorCode::SandboxFailure | ErrorCode::SandboxUnavailable => {
            Some(SecurityEventKind::SandboxFailure)
        }
        ErrorCode::UnexpectedPrivilegeElevation => {
            Some(SecurityEventKind::UnexpectedPrivilegeElevation)
        }
        _ => None,
    }
}

const fn error_code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidRequest => "invalid_request",
        ErrorCode::PermissionDenied => "permission_denied",
        ErrorCode::ApprovalRequired => "approval_required",
        ErrorCode::ApprovalInvalid => "approval_invalid",
        ErrorCode::ApprovalExpired => "approval_expired",
        ErrorCode::ApprovalReplayed => "approval_replayed",
        ErrorCode::PathEscape => "path_escape",
        ErrorCode::SecretAccess => "secret_access",
        ErrorCode::ForbiddenExecutable => "forbidden_executable",
        ErrorCode::ForbiddenDestination => "forbidden_destination",
        ErrorCode::ResourceLimit => "resource_limit",
        ErrorCode::Timeout => "timeout",
        ErrorCode::Cancelled => "cancelled",
        ErrorCode::SandboxUnavailable => "sandbox_unavailable",
        ErrorCode::SandboxFailure => "sandbox_failure",
        ErrorCode::UnexpectedPrivilegeElevation => "unexpected_privilege_elevation",
        ErrorCode::BackendUnavailable => "backend_unavailable",
        ErrorCode::AuditFailure => "audit_failure",
        ErrorCode::SecurityEventFailure => "security_event_failure",
        ErrorCode::ExecutionFailure => "execution_failure",
        ErrorCode::Internal => "internal",
    }
}

fn unix_milliseconds() -> i64 {
    let milliseconds = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    i64::try_from(milliseconds).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;
    use crate::capability::{CapabilityAction, ReadFileInput, RootedPath};
    use crate::model::{ExecutionTarget, RequesterIdentity};

    struct FailingSecurityEventSink;

    impl SecurityEventSink for FailingSecurityEventSink {
        fn emit(&self, _event: &SecurityEvent) -> BrokerResult<()> {
            Err(BrokerError::new(
                ErrorCode::SecurityEventFailure,
                "test sink failure",
            ))
        }
    }

    #[test]
    fn concurrency_gate_releases_permit() -> BrokerResult<()> {
        let gate = ConcurrencyGate::new(BrokerLimits {
            maximum_concurrent_actions: 1,
            concurrency_wait_milliseconds: 10,
        })?;
        let permit = gate.acquire()?;
        assert!(gate.acquire().is_err());
        drop(permit);
        assert!(gate.acquire().is_ok());
        Ok(())
    }

    #[test]
    fn concurrency_gate_rejects_excess_parallel_action() -> BrokerResult<()> {
        let gate = Arc::new(ConcurrencyGate::new(BrokerLimits {
            maximum_concurrent_actions: 1,
            concurrency_wait_milliseconds: 20,
        })?);
        let first = gate.acquire()?;
        let competing_gate = Arc::clone(&gate);
        let competing = thread::spawn(move || competing_gate.acquire().map(drop));
        let result = competing
            .join()
            .map_err(|_| BrokerError::new(ErrorCode::Internal, "test worker failed"))?;

        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::ResourceLimit,
                ..
            })
        ));
        drop(first);
        assert!(gate.acquire().is_ok());
        Ok(())
    }

    #[test]
    fn effective_uid_change_is_detected_and_security_relevant() {
        assert!(ensure_expected_effective_uid(501, 501).is_ok());
        let result = ensure_expected_effective_uid(501, 0);
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::UnexpectedPrivilegeElevation,
                ..
            })
        ));
        assert_eq!(
            security_event_kind(ErrorCode::UnexpectedPrivilegeElevation),
            Some(SecurityEventKind::UnexpectedPrivilegeElevation)
        );
    }

    #[test]
    fn mandatory_security_event_failure_is_propagated() {
        let request = ActionRequest {
            protocol_version: ACTION_BROKER_PROTOCOL_VERSION,
            request_id: Uuid::nil(),
            requester: RequesterIdentity {
                user_id: "user".to_owned(),
                agent_id: "agent".to_owned(),
                task_id: "task".to_owned(),
            },
            target: ExecutionTarget::Local,
            action: CapabilityAction::ReadFile(ReadFileInput {
                path: RootedPath {
                    root_id: "workspace".to_owned(),
                    relative_path: "file".to_owned(),
                },
                maximum_bytes: 1,
            }),
            approval_token: None,
        };
        let result = emit_security_event(
            &FailingSecurityEventSink,
            &request,
            &BrokerError::new(ErrorCode::PermissionDenied, "denied"),
        );
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::SecurityEventFailure,
                ..
            })
        ));
    }
}
