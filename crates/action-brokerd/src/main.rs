use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use action_broker_core::approval::{
    ApprovalVerifier, ApprovalVerifierConfig, ReplayLedgerConfig, SqliteReplayStore,
    TrustedKeyLifecycle, TrustedKeyRegistry,
};
use action_broker_core::audit::{HashChainedJsonlAuditSink, verify_audit_chain};
use action_broker_core::broker::{ActionBroker, AuthenticatedRequester, BrokerLimits};
use action_broker_core::command::{
    ApprovedCommandExecutor, CancellationToken, CommandPolicyConfig,
};
use action_broker_core::error::{BrokerError, ErrorCode};
use action_broker_core::filesystem::{FilesystemPolicyConfig, ScopedFilesystem};
#[cfg(test)]
use action_broker_core::model::{
    ACTION_BROKER_PROTOCOL_VERSION, ActionErrorResponse, ActionStatus, ExecutionTarget,
};
use action_broker_core::model::{ActionRequest, ActionResponse};
use action_broker_core::network::{NetworkPolicyConfig, SecureHttpClient};
use action_broker_core::policy::{DeterministicPolicy, PolicyConfig};
use action_broker_core::privilege::{RuntimePrivilegeMonitor, RuntimePrivilegeProfileConfig};
use action_broker_core::process::{ProcessInspectExecutor, ProcessInspectPolicyConfig};
use action_broker_core::security_event::{
    JsonlSecurityEventSink, SecurityEvent, SecurityEventKind, SecurityEventSink,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use rustix::process::{self, Uid};
use serde::Deserialize;
use sha2::{Digest, Sha256};
#[cfg(test)]
use uuid::Uuid;

const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_KEY_BYTES: u64 = 4096;
const SOCKET_MODE: u32 = 0o660;
const MAXIMUM_OPEN_CONNECTIONS: usize = 128;
const MAXIMUM_CONNECTION_WORKERS: usize = 64;
const MAXIMUM_FAILURES_PER_WINDOW: usize = 1_024;
const MINIMUM_TRANSPORT_TIMEOUT_MILLISECONDS: u64 = 100;
const MAXIMUM_TRANSPORT_TIMEOUT_MILLISECONDS: u64 = 30_000;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Default)]
struct ConnectionAdmissionState {
    open_connections: usize,
    open_connections_by_peer: BTreeMap<u32, usize>,
}

#[derive(Debug, Clone)]
struct ConnectionAdmission {
    state: Arc<Mutex<ConnectionAdmissionState>>,
    maximum_open_connections: usize,
    maximum_open_connections_per_peer: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionAdmissionDenial {
    GlobalLimit,
    PeerLimit,
}

#[derive(Debug)]
struct FailureWindowGate {
    window_started_at: Instant,
    failures_in_window: usize,
    maximum_failures_per_window: usize,
    window: Duration,
}

impl FailureWindowGate {
    fn new(maximum_failures_per_window: usize, window: Duration) -> Self {
        Self {
            window_started_at: Instant::now(),
            failures_in_window: 0,
            maximum_failures_per_window,
            window,
        }
    }

    fn record_failure_at(&mut self, now: Instant) -> Option<Duration> {
        let elapsed = now.saturating_duration_since(self.window_started_at);
        if elapsed >= self.window {
            self.window_started_at = now;
            self.failures_in_window = 0;
        }
        self.failures_in_window = self.failures_in_window.saturating_add(1);
        if self.failures_in_window < self.maximum_failures_per_window {
            return None;
        }
        Some(
            self.window
                .saturating_sub(now.saturating_duration_since(self.window_started_at)),
        )
    }
}

#[derive(Debug)]
struct ProtocolRejection {
    reason_code: &'static str,
}

impl std::fmt::Display for ProtocolRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for ProtocolRejection {}

#[derive(Debug)]
struct ConnectionPermit {
    state: Arc<Mutex<ConnectionAdmissionState>>,
    peer_uid: u32,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.open_connections = state.open_connections.saturating_sub(1);
        let should_remove = match state.open_connections_by_peer.get_mut(&self.peer_uid) {
            Some(count) => {
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => false,
        };
        if should_remove {
            state.open_connections_by_peer.remove(&self.peer_uid);
        }
    }
}

impl ConnectionAdmission {
    fn new(limits: &TransportLimitsWireConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionAdmissionState::default())),
            maximum_open_connections: limits.maximum_open_connections,
            maximum_open_connections_per_peer: limits.maximum_open_connections_per_peer,
        }
    }

    fn try_acquire(
        &self,
        peer_uid: u32,
    ) -> Result<Result<ConnectionPermit, ConnectionAdmissionDenial>, BrokerError> {
        let mut state = self.state.lock().map_err(|_| {
            BrokerError::new(
                ErrorCode::Internal,
                "connection admission state is unavailable",
            )
        })?;
        if state.open_connections >= self.maximum_open_connections {
            return Ok(Err(ConnectionAdmissionDenial::GlobalLimit));
        }
        let peer_count = state
            .open_connections_by_peer
            .get(&peer_uid)
            .copied()
            .unwrap_or(0);
        if peer_count >= self.maximum_open_connections_per_peer {
            return Ok(Err(ConnectionAdmissionDenial::PeerLimit));
        }
        state.open_connections += 1;
        state
            .open_connections_by_peer
            .insert(peer_uid, peer_count + 1);
        Ok(Ok(ConnectionPermit {
            state: Arc::clone(&self.state),
            peer_uid,
        }))
    }
}

struct ConnectionJob {
    stream: UnixStream,
    authenticated_requester: AuthenticatedRequester,
    connection_permit: ConnectionPermit,
    accepted_at: Instant,
}

struct ConnectionWorkerPool {
    sender: SyncSender<ConnectionJob>,
    healthy: Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,
    expected_workers: usize,
    _workers: Vec<thread::JoinHandle<()>>,
}

struct WorkerLivenessGuard {
    healthy: Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,
}

impl Drop for WorkerLivenessGuard {
    fn drop(&mut self) {
        self.active_workers.fetch_sub(1, Ordering::AcqRel);
        self.healthy.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
struct ConnectionWorkerRuntime {
    broker: Arc<ActionBroker>,
    security_events: Arc<dyn SecurityEventSink>,
    protocol_failure_gate: Arc<Mutex<FailureWindowGate>>,
    healthy: Arc<AtomicBool>,
    maximum_queue_wait: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl ConnectionWorkerPool {
    fn new(
        broker: Arc<ActionBroker>,
        security_events: Arc<dyn SecurityEventSink>,
        limits: &TransportLimitsWireConfig,
    ) -> Result<Self, BrokerError> {
        let (sender, receiver) = mpsc::sync_channel(limits.maximum_queued_connections);
        let receiver = Arc::new(Mutex::new(receiver));
        let protocol_failure_gate = Arc::new(Mutex::new(FailureWindowGate::new(
            limits.maximum_protocol_failures_per_window,
            Duration::from_millis(limits.protocol_failure_window_milliseconds),
        )));
        let healthy = Arc::new(AtomicBool::new(true));
        let active_workers = Arc::new(AtomicUsize::new(limits.worker_threads));
        let maximum_queue_wait = Duration::from_millis(limits.maximum_queue_wait_milliseconds);
        let read_timeout = Duration::from_millis(limits.read_timeout_milliseconds);
        let write_timeout = Duration::from_millis(limits.write_timeout_milliseconds);
        let runtime = ConnectionWorkerRuntime {
            broker,
            security_events,
            protocol_failure_gate,
            healthy: Arc::clone(&healthy),
            maximum_queue_wait,
            read_timeout,
            write_timeout,
        };
        let mut workers = Vec::with_capacity(limits.worker_threads);
        for worker_index in 0..limits.worker_threads {
            let receiver = Arc::clone(&receiver);
            let runtime = runtime.clone();
            let worker_active_workers = Arc::clone(&active_workers);
            let worker_healthy = Arc::clone(&healthy);
            let worker = thread::Builder::new()
                .name(format!("action-broker-connection-{worker_index}"))
                .spawn(move || {
                    let _liveness = WorkerLivenessGuard {
                        healthy: worker_healthy,
                        active_workers: worker_active_workers,
                    };
                    connection_worker(receiver, runtime);
                })
                .map_err(|_| {
                    BrokerError::new(ErrorCode::Internal, "connection worker could not start")
                })?;
            workers.push(worker);
        }
        Ok(Self {
            sender,
            healthy,
            active_workers,
            expected_workers: limits.worker_threads,
            _workers: workers,
        })
    }

    fn try_submit(&self, job: ConnectionJob) -> Result<(), TrySendError<ConnectionJob>> {
        self.sender.try_send(job)
    }

    fn is_healthy(&self) -> bool {
        worker_pool_is_healthy(
            self.healthy.load(Ordering::Acquire),
            self.active_workers.load(Ordering::Acquire),
            self.expected_workers,
        )
    }
}

fn worker_pool_is_healthy(healthy: bool, active_workers: usize, expected_workers: usize) -> bool {
    healthy && active_workers == expected_workers
}

fn connection_worker(
    receiver: Arc<Mutex<Receiver<ConnectionJob>>>,
    runtime: ConnectionWorkerRuntime,
) {
    loop {
        if !runtime.healthy.load(Ordering::Acquire) {
            return;
        }
        let job = {
            let Ok(receiver) = receiver.lock() else {
                return;
            };
            receiver.recv()
        };
        let Ok(job) = job else {
            return;
        };
        let ConnectionJob {
            stream,
            authenticated_requester,
            connection_permit,
            accepted_at,
        } = job;
        let _connection_permit = connection_permit;
        match reject_expired_connection(
            runtime.security_events.as_ref(),
            &authenticated_requester,
            accepted_at.elapsed(),
            runtime.maximum_queue_wait,
        ) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(_) => {
                runtime.healthy.store(false, Ordering::Release);
                return;
            }
        }
        if let Ok(Some(reason_code)) = handle_connection(
            Arc::clone(&runtime.broker),
            &authenticated_requester,
            stream,
            runtime.read_timeout,
            runtime.write_timeout,
        ) && report_authenticated_protocol_failure(
            runtime.security_events.as_ref(),
            &runtime.protocol_failure_gate,
            &authenticated_requester,
            reason_code,
        )
        .is_err()
        {
            runtime.healthy.store(false, Ordering::Release);
            return;
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "action-brokerd",
    about = "Fail-closed local Action Broker daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Prints capability descriptors; it never executes an action.
    Capabilities,
    /// Verifies one audit segment without modifying it or executing an action.
    VerifyAudit {
        #[arg(long)]
        path: PathBuf,
        /// Prior segment head; omit only for the first genesis segment.
        #[arg(long)]
        initial_previous_head: Option<String>,
        /// Optional independently protected lowercase SHA-256 chain head.
        #[arg(long)]
        expected_head: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonConfig {
    socket_path: PathBuf,
    socket_group_id: u32,
    platform_peers: Vec<PlatformPeerConfig>,
    privilege_profile: RuntimePrivilegeProfileConfig,
    replay_database_path: PathBuf,
    replay_ledger: ReplayLedgerConfig,
    audit_log_path: PathBuf,
    #[serde(default)]
    audit_initial_previous_hash: Option<String>,
    agent_green_event_spool_path: PathBuf,
    agent_green_event_spool_maximum_bytes: u64,
    approval_keys: Vec<ApprovalKeyConfig>,
    approval_verifier: ApprovalVerifierWireConfig,
    policy: PolicyConfig,
    filesystem: FilesystemPolicyConfig,
    commands: CommandPolicyConfig,
    network: NetworkPolicyConfig,
    #[serde(default)]
    process_inspection: ProcessInspectPolicyConfig,
    transport_limits: TransportLimitsWireConfig,
    broker_limits: BrokerLimitsWireConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformPeerConfig {
    uid: u32,
    user_id: String,
    agent_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalKeyConfig {
    key_id: String,
    public_key_path: PathBuf,
    active_from_unix_seconds: i64,
    retire_at_unix_seconds: Option<i64>,
    revoke_at_unix_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalVerifierWireConfig {
    maximum_ttl_seconds: i64,
    allowed_clock_skew_seconds: i64,
    maximum_payload_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerLimitsWireConfig {
    maximum_concurrent_actions: usize,
    maximum_concurrent_actions_per_principal: usize,
    maximum_concurrent_actions_per_capability: usize,
    concurrency_wait_milliseconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportLimitsWireConfig {
    maximum_open_connections: usize,
    maximum_open_connections_per_peer: usize,
    worker_threads: usize,
    maximum_queued_connections: usize,
    maximum_queue_wait_milliseconds: u64,
    maximum_authentication_failures_per_window: usize,
    authentication_failure_window_milliseconds: u64,
    maximum_protocol_failures_per_window: usize,
    protocol_failure_window_milliseconds: u64,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
}

fn main() {
    let exit_code = match run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("action-brokerd failed: {error}");
            1
        }
    };
    std::process::exit(exit_code);
}

fn run() -> Result<(), BrokerError> {
    match Cli::parse().command {
        Command::Serve { config } => serve(&config),
        Command::Capabilities => print_capabilities(),
        Command::VerifyAudit {
            path,
            initial_previous_head,
            expected_head,
        } => print_audit_verification(
            &path,
            initial_previous_head.as_deref(),
            expected_head.as_deref(),
        ),
    }
}

fn print_audit_verification(
    path: &Path,
    initial_previous_head: Option<&str>,
    expected_head: Option<&str>,
) -> Result<(), BrokerError> {
    let summary = verify_audit_chain(path, initial_previous_head, expected_head)?;
    serde_json::to_writer_pretty(std::io::stdout().lock(), &summary)
        .map_err(|_| BrokerError::new(ErrorCode::Internal, "audit summary serialization failed"))?;
    println!();
    Ok(())
}

fn print_capabilities() -> Result<(), BrokerError> {
    use action_broker_core::capability::CapabilityKind;
    let kinds = [
        CapabilityKind::ReadFile,
        CapabilityKind::WriteFile,
        CapabilityKind::CreateFile,
        CapabilityKind::MoveFile,
        CapabilityKind::DeleteFile,
        CapabilityKind::ListDirectory,
        CapabilityKind::ExecuteApprovedCommand,
        CapabilityKind::GitRead,
        CapabilityKind::GitWrite,
        CapabilityKind::HttpRequest,
        CapabilityKind::BrowserAction,
        CapabilityKind::ProcessInspect,
        CapabilityKind::ServiceInspect,
        CapabilityKind::ServiceControl,
        CapabilityKind::ContainerAction,
        CapabilityKind::NodeAction,
    ];
    let descriptors: Vec<_> = kinds.into_iter().map(CapabilityKind::descriptor).collect();
    serde_json::to_writer_pretty(std::io::stdout().lock(), &descriptors)
        .map_err(|_| BrokerError::new(ErrorCode::Internal, "descriptor serialization failed"))?;
    println!();
    Ok(())
}

fn serve(config_path: &Path) -> Result<(), BrokerError> {
    refuse_root()?;
    let config = read_secure_json::<DaemonConfig>(config_path, MAX_CONFIG_BYTES, "configuration")?;
    let privilege_monitor = RuntimePrivilegeMonitor::from_config(config.privilege_profile.clone())?;
    privilege_monitor.verify()?;
    let peer_principals = validate_platform_peers(&config.platform_peers)?;
    validate_transport_limits(&config.transport_limits)?;
    validate_state_paths(&config)?;
    let security_events: Arc<dyn SecurityEventSink> =
        Arc::new(JsonlSecurityEventSink::open_with_maximum_bytes(
            &config.agent_green_event_spool_path,
            config.agent_green_event_spool_maximum_bytes,
        )?);
    let broker = Arc::new(build_broker(
        &config,
        privilege_monitor,
        Arc::clone(&security_events),
    )?);
    let admission = ConnectionAdmission::new(&config.transport_limits);
    let mut authentication_failure_gate = FailureWindowGate::new(
        config
            .transport_limits
            .maximum_authentication_failures_per_window,
        Duration::from_millis(
            config
                .transport_limits
                .authentication_failure_window_milliseconds,
        ),
    );
    let worker_pool = ConnectionWorkerPool::new(
        Arc::clone(&broker),
        Arc::clone(&security_events),
        &config.transport_limits,
    )?;
    let listener = bind_socket(&config.socket_path, config.socket_group_id)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| transport_error("Unix socket nonblocking setup failed"))?;
    loop {
        if !worker_pool.is_healthy() {
            emit_worker_pool_failure(security_events.as_ref())?;
            return Err(BrokerError::new(
                ErrorCode::SandboxFailure,
                "connection worker pool lost required capacity",
            ));
        }
        let stream = match listener.accept() {
            Ok((stream, _address)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                emit_socket_accept_failure(security_events.as_ref())?;
                return Err(BrokerError::new(
                    ErrorCode::SandboxFailure,
                    "Unix socket accept failed",
                ));
            }
        };
        let Some(peer_uid) = peer_uid(&stream) else {
            report_transport_authentication_failure(
                security_events.as_ref(),
                &mut authentication_failure_gate,
                "peer_credentials_unavailable",
            )?;
            continue;
        };
        let Some(authenticated_requester) = peer_principals.get(&peer_uid).cloned() else {
            report_transport_authentication_failure(
                security_events.as_ref(),
                &mut authentication_failure_gate,
                "unauthorized_platform_peer",
            )?;
            continue;
        };
        let connection_permit = match admission.try_acquire(peer_uid)? {
            Ok(permit) => permit,
            Err(ConnectionAdmissionDenial::GlobalLimit) => {
                emit_connection_overload(
                    security_events.as_ref(),
                    &authenticated_requester,
                    "connection_global_limit",
                )?;
                continue;
            }
            Err(ConnectionAdmissionDenial::PeerLimit) => {
                emit_connection_overload(
                    security_events.as_ref(),
                    &authenticated_requester,
                    "connection_peer_limit",
                )?;
                continue;
            }
        };
        let job = ConnectionJob {
            stream,
            authenticated_requester,
            connection_permit,
            accepted_at: Instant::now(),
        };
        match worker_pool.try_submit(job) {
            Ok(()) => {}
            Err(TrySendError::Full(job)) => {
                emit_connection_overload(
                    security_events.as_ref(),
                    &job.authenticated_requester,
                    "connection_worker_queue_saturated",
                )?;
            }
            Err(TrySendError::Disconnected(_job)) => {
                return Err(BrokerError::new(
                    ErrorCode::Internal,
                    "connection worker pool stopped",
                ));
            }
        }
    }
}

fn build_broker(
    config: &DaemonConfig,
    privilege_monitor: RuntimePrivilegeMonitor,
    security_events: Arc<dyn SecurityEventSink>,
) -> Result<ActionBroker, BrokerError> {
    let mut trusted_keys = TrustedKeyRegistry::new();
    if config.approval_keys.is_empty() {
        return Err(BrokerError::invalid(
            "at least one approval verification key is required",
        ));
    }
    for key in &config.approval_keys {
        let bytes = read_secure_bytes(&key.public_key_path, MAX_KEY_BYTES, "approval public key")?;
        let key_bytes = parse_public_key(&bytes)?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| BrokerError::invalid("approval public key is invalid"))?;
        trusted_keys
            .insert(
                key.key_id.clone(),
                verifying_key,
                TrustedKeyLifecycle {
                    active_from_unix_seconds: key.active_from_unix_seconds,
                    retire_at_unix_seconds: key.retire_at_unix_seconds,
                    revoke_at_unix_seconds: key.revoke_at_unix_seconds,
                },
            )
            .map_err(|_| BrokerError::invalid("approval key configuration is invalid"))?;
    }
    let replay_store = Arc::new(
        SqliteReplayStore::open_with_config(&config.replay_database_path, config.replay_ledger)
            .map_err(|_| {
                BrokerError::new(
                    ErrorCode::ApprovalInvalid,
                    "approval replay database cannot be opened",
                )
            })?,
    );
    let approvals = ApprovalVerifier::new(
        trusted_keys,
        replay_store,
        ApprovalVerifierConfig {
            maximum_ttl_seconds: config.approval_verifier.maximum_ttl_seconds,
            allowed_clock_skew_seconds: config.approval_verifier.allowed_clock_skew_seconds,
            maximum_payload_bytes: config.approval_verifier.maximum_payload_bytes,
        },
    )
    .map_err(|_| BrokerError::invalid("approval verifier configuration is invalid"))?;
    let policy = DeterministicPolicy::from_config(config.policy.clone())?;
    let filesystem = Arc::new(ScopedFilesystem::from_config(config.filesystem.clone())?);
    let commands =
        ApprovedCommandExecutor::from_config(Arc::clone(&filesystem), config.commands.clone())?;
    let http = SecureHttpClient::new(config.network.clone())?;
    let process_inspection =
        ProcessInspectExecutor::from_config(config.process_inspection.clone())?;
    let audit = Arc::new(match config.audit_initial_previous_hash.as_deref() {
        Some(initial_hash) => {
            HashChainedJsonlAuditSink::open_with_initial_hash(&config.audit_log_path, initial_hash)?
        }
        None => HashChainedJsonlAuditSink::open(&config.audit_log_path)?,
    });
    ActionBroker::new(
        policy,
        approvals,
        filesystem,
        commands,
        http,
        process_inspection,
        audit,
        security_events,
        privilege_monitor,
        BrokerLimits {
            maximum_concurrent_actions: config.broker_limits.maximum_concurrent_actions,
            maximum_concurrent_actions_per_principal: config
                .broker_limits
                .maximum_concurrent_actions_per_principal,
            maximum_concurrent_actions_per_capability: config
                .broker_limits
                .maximum_concurrent_actions_per_capability,
            concurrency_wait_milliseconds: config.broker_limits.concurrency_wait_milliseconds,
        },
    )
}

fn handle_connection(
    broker: Arc<ActionBroker>,
    authenticated_requester: &AuthenticatedRequester,
    mut stream: UnixStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<Option<&'static str>, BrokerError> {
    stream
        .set_nonblocking(false)
        .map_err(|_| transport_error("accepted socket blocking setup failed"))?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|_| transport_error("socket read timeout setup failed"))?;
    stream
        .set_write_timeout(Some(write_timeout))
        .map_err(|_| transport_error("socket write timeout setup failed"))?;
    let frame = match read_frame(&mut stream) {
        Ok(frame) => frame,
        Err(rejection) => return Ok(Some(rejection.reason_code)),
    };
    let request = match decode_action_request(&frame) {
        Ok(request) => request,
        Err(rejection) => return Ok(Some(rejection.reason_code)),
    };
    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();
    let execution_requester = authenticated_requester.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let response = broker.execute(request, &execution_requester, &worker_cancellation);
        let _ = sender.send(response);
    });
    stream
        .set_read_timeout(None)
        .and_then(|()| stream.set_nonblocking(true))
        .map_err(|_| transport_error("socket cancellation monitor setup failed"))?;
    let response = loop {
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(response) => break response,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(transport_error("action worker stopped without a response"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let mut probe = [0_u8; 1];
                match stream.read(&mut probe) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    _ => cancellation.cancel(),
                }
            }
        }
    };
    stream
        .set_nonblocking(false)
        .map_err(|_| transport_error("socket blocking mode restore failed"))?;
    write_response(&mut stream, &response)?;
    Ok(None)
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, ProtocolRejection> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| protocol_rejection("request_frame_prefix_incomplete"))?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| protocol_rejection("request_frame_size_invalid"))?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(protocol_rejection("request_frame_size_invalid"));
    }
    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .map_err(|_| protocol_rejection("request_frame_incomplete"))?;
    Ok(frame)
}

fn decode_action_request(bytes: &[u8]) -> Result<ActionRequest, ProtocolRejection> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let request = ActionRequest::deserialize(&mut deserializer)
        .map_err(|_| protocol_rejection("request_schema_invalid"))?;
    deserializer
        .end()
        .map_err(|_| protocol_rejection("request_trailing_data"))?;
    Ok(request)
}

fn write_response(stream: &mut UnixStream, response: &ActionResponse) -> Result<(), BrokerError> {
    let bytes = serde_json::to_vec(response)
        .map_err(|_| transport_error("response serialization failed"))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(transport_error("response frame exceeds the safe bound"));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| transport_error("response frame length is invalid"))?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(&bytes))
        .and_then(|()| stream.flush())
        .map_err(|_| transport_error("response write failed"))
}

fn decode_strict<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, BrokerError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)
        .map_err(|_| BrokerError::invalid("request JSON or schema is invalid"))?;
    deserializer
        .end()
        .map_err(|_| BrokerError::invalid("request contains trailing data"))?;
    Ok(value)
}

fn bind_socket(path: &Path, socket_group_id: u32) -> Result<UnixListener, BrokerError> {
    if !path.is_absolute() {
        return Err(BrokerError::invalid("socket path must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| BrokerError::invalid("socket parent directory is required"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|_| transport_error("socket parent directory cannot be inspected"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != process::geteuid().as_raw()
        || parent_metadata.gid() != socket_group_id
        || parent_metadata.mode() & 0o027 != 0
    {
        return Err(transport_error("socket parent directory is unsafe"));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(transport_error("socket path already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(transport_error("socket path cannot be inspected")),
    }
    let listener =
        UnixListener::bind(path).map_err(|_| transport_error("Unix socket cannot be bound"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|_| transport_error("Unix socket permissions cannot be restricted"))?;
    let socket_metadata = fs::symlink_metadata(path)
        .map_err(|_| transport_error("Unix socket cannot be inspected after binding"))?;
    if socket_metadata.uid() != process::geteuid().as_raw()
        || socket_metadata.gid() != socket_group_id
        || socket_metadata.mode() & 0o777 != SOCKET_MODE
    {
        let _ = fs::remove_file(path);
        return Err(transport_error(
            "Unix socket owner, group, or permissions are not the configured values",
        ));
    }
    Ok(listener)
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        return rustix::net::sockopt::socket_peercred(stream)
            .ok()
            .map(|credentials| credentials.uid.as_raw());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        None
    }
}

fn validate_platform_peers(
    peers: &[PlatformPeerConfig],
) -> Result<BTreeMap<u32, AuthenticatedRequester>, BrokerError> {
    if peers.is_empty() {
        return Err(BrokerError::invalid(
            "at least one authenticated platform peer is required",
        ));
    }
    let broker_uid = process::geteuid().as_raw();
    let mut principals = BTreeMap::new();
    for peer in peers {
        if peer.uid == 0 || peer.uid == broker_uid {
            return Err(BrokerError::invalid(
                "platform peer UID must be unprivileged and distinct from the broker UID",
            ));
        }
        let principal = AuthenticatedRequester {
            user_id: peer.user_id.clone(),
            agent_id: peer.agent_id.clone(),
        };
        if principals.insert(peer.uid, principal).is_some() {
            return Err(BrokerError::invalid("duplicate platform peer UID"));
        }
    }
    Ok(principals)
}

fn validate_transport_limits(limits: &TransportLimitsWireConfig) -> Result<(), BrokerError> {
    if limits.maximum_open_connections == 0
        || limits.maximum_open_connections > MAXIMUM_OPEN_CONNECTIONS
        || limits.maximum_open_connections_per_peer == 0
        || limits.maximum_open_connections_per_peer > limits.maximum_open_connections
        || limits.worker_threads == 0
        || limits.worker_threads > MAXIMUM_CONNECTION_WORKERS
        || limits.worker_threads > limits.maximum_open_connections
        || limits.maximum_queued_connections == 0
        || limits.maximum_queued_connections > limits.maximum_open_connections
        || !(MINIMUM_TRANSPORT_TIMEOUT_MILLISECONDS..=MAXIMUM_TRANSPORT_TIMEOUT_MILLISECONDS)
            .contains(&limits.maximum_queue_wait_milliseconds)
        || limits.maximum_authentication_failures_per_window == 0
        || limits.maximum_authentication_failures_per_window > MAXIMUM_FAILURES_PER_WINDOW
        || !(MINIMUM_TRANSPORT_TIMEOUT_MILLISECONDS..=MAXIMUM_TRANSPORT_TIMEOUT_MILLISECONDS)
            .contains(&limits.authentication_failure_window_milliseconds)
        || limits.maximum_protocol_failures_per_window == 0
        || limits.maximum_protocol_failures_per_window > MAXIMUM_FAILURES_PER_WINDOW
        || !(MINIMUM_TRANSPORT_TIMEOUT_MILLISECONDS..=MAXIMUM_TRANSPORT_TIMEOUT_MILLISECONDS)
            .contains(&limits.protocol_failure_window_milliseconds)
        || !(MINIMUM_TRANSPORT_TIMEOUT_MILLISECONDS..=MAXIMUM_TRANSPORT_TIMEOUT_MILLISECONDS)
            .contains(&limits.read_timeout_milliseconds)
        || !(MINIMUM_TRANSPORT_TIMEOUT_MILLISECONDS..=MAXIMUM_TRANSPORT_TIMEOUT_MILLISECONDS)
            .contains(&limits.write_timeout_milliseconds)
    {
        return Err(BrokerError::invalid(
            "transport admission limits are outside the safe bound",
        ));
    }
    Ok(())
}

fn connection_queue_expired(elapsed: Duration, maximum_queue_wait: Duration) -> bool {
    elapsed >= maximum_queue_wait
}

fn reject_expired_connection(
    security_events: &dyn SecurityEventSink,
    authenticated_requester: &AuthenticatedRequester,
    elapsed: Duration,
    maximum_queue_wait: Duration,
) -> Result<bool, BrokerError> {
    if !connection_queue_expired(elapsed, maximum_queue_wait) {
        return Ok(false);
    }
    emit_connection_overload(
        security_events,
        authenticated_requester,
        "connection_queue_wait_expired",
    )?;
    Ok(true)
}

fn emit_connection_overload(
    security_events: &dyn SecurityEventSink,
    authenticated_requester: &AuthenticatedRequester,
    reason_code: &'static str,
) -> Result<(), BrokerError> {
    let mut event = SecurityEvent::new(SecurityEventKind::ResourceAbusePattern, reason_code);
    event.user_id = Some(authenticated_requester.user_id.clone());
    event.agent_id = Some(authenticated_requester.agent_id.clone());
    security_events.emit(&event)
}

fn emit_socket_accept_failure(security_events: &dyn SecurityEventSink) -> Result<(), BrokerError> {
    security_events.emit(&SecurityEvent::new(
        SecurityEventKind::SandboxFailure,
        "socket_accept_failure",
    ))
}

fn emit_worker_pool_failure(security_events: &dyn SecurityEventSink) -> Result<(), BrokerError> {
    security_events.emit(&SecurityEvent::new(
        SecurityEventKind::SandboxFailure,
        "connection_worker_lost",
    ))
}

fn report_transport_authentication_failure(
    security_events: &dyn SecurityEventSink,
    failure_gate: &mut FailureWindowGate,
    reason_code: &'static str,
) -> Result<(), BrokerError> {
    security_events.emit(&SecurityEvent::new(
        SecurityEventKind::PermissionBypassAttempt,
        reason_code,
    ))?;
    if let Some(backoff) = failure_gate.record_failure_at(Instant::now()) {
        thread::sleep(backoff);
    }
    Ok(())
}

fn report_authenticated_protocol_failure(
    security_events: &dyn SecurityEventSink,
    failure_gate: &Mutex<FailureWindowGate>,
    authenticated_requester: &AuthenticatedRequester,
    reason_code: &'static str,
) -> Result<(), BrokerError> {
    emit_connection_overload(security_events, authenticated_requester, reason_code)?;
    let backoff = failure_gate
        .lock()
        .map_err(|_| BrokerError::new(ErrorCode::Internal, "protocol failure gate is unavailable"))?
        .record_failure_at(Instant::now());
    if let Some(backoff) = backoff {
        thread::sleep(backoff);
    }
    Ok(())
}

fn refuse_root() -> Result<(), BrokerError> {
    if process::geteuid() == Uid::ROOT {
        return Err(BrokerError::new(
            ErrorCode::SandboxFailure,
            "Action Broker refuses to run as root",
        ));
    }
    Ok(())
}

fn read_secure_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    maximum_bytes: u64,
    label: &'static str,
) -> Result<T, BrokerError> {
    let bytes = read_secure_bytes(path, maximum_bytes, label)?;
    decode_strict(&bytes)
}

fn read_secure_bytes(
    path: &Path,
    maximum_bytes: u64,
    label: &'static str,
) -> Result<Vec<u8>, BrokerError> {
    let before = fs::symlink_metadata(path)
        .map_err(|_| BrokerError::invalid(format!("{label} cannot be inspected")))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.uid() != 0
        || before.mode() & 0o022 != 0
        || before.len() > maximum_bytes
    {
        return Err(BrokerError::invalid(format!("{label} is unsafe")));
    }
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| BrokerError::invalid(format!("{label} cannot be opened")))?;
    let after = file
        .metadata()
        .map_err(|_| BrokerError::invalid(format!("{label} cannot be inspected")))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.uid() != 0
        || after.mode() & 0o022 != 0
        || after.len() > maximum_bytes
    {
        return Err(BrokerError::invalid(format!(
            "{label} changed while opening"
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(after.len()).unwrap_or(0));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BrokerError::invalid(format!("{label} cannot be read")))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(BrokerError::invalid(format!(
            "{label} exceeds the size limit"
        )));
    }
    Ok(bytes)
}

fn parse_public_key(bytes: &[u8]) -> Result<[u8; 32], BrokerError> {
    let trimmed = std::str::from_utf8(bytes)
        .map_err(|_| BrokerError::invalid("approval public key is not UTF-8"))?
        .trim();
    let decoded = hex::decode(trimmed)
        .map_err(|_| BrokerError::invalid("approval public key must be hexadecimal"))?;
    decoded
        .try_into()
        .map_err(|_| BrokerError::invalid("approval public key must contain 32 bytes"))
}

fn validate_state_paths(config: &DaemonConfig) -> Result<(), BrokerError> {
    let paths = [
        &config.socket_path,
        &config.replay_database_path,
        &config.audit_log_path,
        &config.agent_green_event_spool_path,
    ];
    if paths.iter().any(|path| !path.is_absolute()) {
        return Err(BrokerError::invalid("broker state paths must be absolute"));
    }
    let digests: Vec<_> = paths
        .iter()
        .map(|path| Sha256::digest(path.as_os_str().as_encoded_bytes()))
        .collect();
    for (index, digest) in digests.iter().enumerate() {
        if digests.iter().skip(index + 1).any(|other| other == digest) {
            return Err(BrokerError::invalid("broker state paths must be distinct"));
        }
    }
    prepare_owner_only_state_file(&config.replay_database_path, "replay database")?;
    prepare_owner_only_state_file(&config.audit_log_path, "audit log")?;
    prepare_owner_only_state_file(
        &config.agent_green_event_spool_path,
        "Agent Green event spool",
    )?;
    Ok(())
}

fn prepare_owner_only_state_file(path: &Path, label: &'static str) -> Result<(), BrokerError> {
    let parent = path
        .parent()
        .ok_or_else(|| BrokerError::invalid(format!("{label} parent is missing")))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|_| BrokerError::invalid(format!("{label} parent cannot be inspected")))?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| BrokerError::invalid(format!("{label} parent cannot be canonicalized")))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || canonical_parent != parent
        || parent_metadata.uid() != process::geteuid().as_raw()
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err(BrokerError::invalid(format!("{label} parent is unsafe")));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(BrokerError::invalid(format!("{label} is unsafe")));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = File::options()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| BrokerError::invalid(format!("{label} cannot be created")))?;
            file.sync_all()
                .map_err(|_| BrokerError::invalid(format!("{label} cannot be synced")))?;
        }
        Err(_) => return Err(BrokerError::invalid(format!("{label} cannot be inspected"))),
    }
    Ok(())
}

fn transport_error(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::InvalidRequest, message)
}

fn protocol_rejection(reason_code: &'static str) -> ProtocolRejection {
    ProtocolRejection { reason_code }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::Barrier;

    use super::*;

    struct RecordingSecurityEventSink {
        events: Mutex<Vec<SecurityEvent>>,
    }

    struct FailingSecurityEventSink;

    impl SecurityEventSink for RecordingSecurityEventSink {
        fn emit(&self, event: &SecurityEvent) -> Result<(), BrokerError> {
            self.events
                .lock()
                .map_err(|_| BrokerError::new(ErrorCode::Internal, "test event lock failed"))?
                .push(event.clone());
            Ok(())
        }
    }

    impl SecurityEventSink for FailingSecurityEventSink {
        fn emit(&self, _event: &SecurityEvent) -> Result<(), BrokerError> {
            Err(BrokerError::new(
                ErrorCode::SecurityEventFailure,
                "test security event failure",
            ))
        }
    }

    fn transport_limits(
        maximum_open_connections: usize,
        maximum_open_connections_per_peer: usize,
        worker_threads: usize,
    ) -> TransportLimitsWireConfig {
        TransportLimitsWireConfig {
            maximum_open_connections,
            maximum_open_connections_per_peer,
            worker_threads,
            maximum_queued_connections: maximum_open_connections,
            maximum_queue_wait_milliseconds: 1_000,
            maximum_authentication_failures_per_window: 16,
            authentication_failure_window_milliseconds: 1_000,
            maximum_protocol_failures_per_window: 16,
            protocol_failure_window_milliseconds: 1_000,
            read_timeout_milliseconds: 5_000,
            write_timeout_milliseconds: 5_000,
        }
    }

    #[test]
    fn audit_verification_cli_binds_both_segment_heads() -> Result<(), Box<dyn Error>> {
        let prior = "a".repeat(64);
        let final_head = "b".repeat(64);
        let cli = Cli::try_parse_from([
            "action-brokerd",
            "verify-audit",
            "--path",
            "/var/lib/action-broker/audit.jsonl",
            "--initial-previous-head",
            &prior,
            "--expected-head",
            &final_head,
        ])?;
        match cli.command {
            Command::VerifyAudit {
                path,
                initial_previous_head,
                expected_head,
            } => {
                assert_eq!(path, Path::new("/var/lib/action-broker/audit.jsonl"));
                assert_eq!(initial_previous_head.as_deref(), Some(prior.as_str()));
                assert_eq!(expected_head.as_deref(), Some(final_head.as_str()));
            }
            _ => return Err("unexpected command".into()),
        }
        Ok(())
    }

    #[test]
    fn oversized_frame_is_rejected_without_allocating_payload() {
        let mut frame = std::io::Cursor::new(u32::MAX.to_be_bytes());
        assert!(matches!(
            read_frame(&mut frame),
            Err(ProtocolRejection {
                reason_code: "request_frame_size_invalid"
            })
        ));
    }

    #[test]
    fn strict_decoder_rejects_unknown_fields() {
        let request = br#"{"protocol_version":1,"request_id":"00000000-0000-0000-0000-000000000000","requester":{"user_id":"u","agent_id":"a","task_id":"t"},"target":{"type":"local"},"action":{"capability":"ReadFile","arguments":{"path":{"root_id":"r","relative_path":"f"},"maximum_bytes":1}},"approval_token":null,"hidden_bypass":true}"#;
        assert!(decode_strict::<ActionRequest>(request).is_err());
    }

    #[test]
    fn framed_response_round_trips_across_unix_socket() -> Result<(), Box<dyn Error>> {
        let request_id = Uuid::from_u128(42);
        let response = ActionResponse {
            protocol_version: ACTION_BROKER_PROTOCOL_VERSION,
            request_id,
            target: ExecutionTarget::Node {
                node_id: "node-7".to_owned(),
            },
            capability: action_broker_core::capability::CapabilityKind::NodeAction,
            status: ActionStatus::Rejected,
            output: None,
            error: Some(ActionErrorResponse {
                code: "permission_denied".to_owned(),
                message: "request was not authorized".to_owned(),
                retryable: false,
            }),
            started_at_unix_milliseconds: 100,
            finished_at_unix_milliseconds: 101,
            output_sha256: None,
        };
        let (mut server, mut client) = UnixStream::pair()?;

        write_response(&mut server, &response)?;
        let frame = read_frame(&mut client)?;
        let decoded = decode_strict::<ActionResponse>(&frame)?;

        assert_eq!(decoded, response);
        assert_eq!(decoded.request_id, request_id);
        Ok(())
    }

    #[test]
    fn incomplete_frame_is_rejected() {
        let mut frame = std::io::Cursor::new([0, 0, 0, 4, b'{', b'}']);
        assert!(matches!(
            read_frame(&mut frame),
            Err(ProtocolRejection {
                reason_code: "request_frame_incomplete"
            })
        ));
    }

    #[test]
    fn action_request_decoder_classifies_schema_and_trailing_data() {
        let invalid = br#"{"protocol_version":1,"hidden_bypass":true}"#;
        assert!(matches!(
            decode_action_request(invalid),
            Err(ProtocolRejection {
                reason_code: "request_schema_invalid"
            })
        ));

        let valid_with_trailing = br#"{"protocol_version":1,"request_id":"00000000-0000-0000-0000-000000000000","requester":{"user_id":"u","agent_id":"a","task_id":"t"},"target":{"type":"local"},"action":{"capability":"ReadFile","arguments":{"path":{"root_id":"r","relative_path":"f"},"maximum_bytes":1}},"approval_token":null}{}"#;
        assert!(matches!(
            decode_action_request(valid_with_trailing),
            Err(ProtocolRejection {
                reason_code: "request_trailing_data"
            })
        ));
    }

    #[test]
    fn strict_decoder_rejects_trailing_protocol_data() {
        let response = br#"{"protocol_version":1,"request_id":"00000000-0000-0000-0000-000000000000","target":{"type":"local"},"capability":"ReadFile","status":"rejected","output":null,"error":{"code":"invalid_request","message":"bad","retryable":false},"started_at_unix_milliseconds":0,"finished_at_unix_milliseconds":0,"output_sha256":null}{}"#;
        assert!(decode_strict::<ActionResponse>(response).is_err());
    }

    #[test]
    fn approval_key_lifecycle_is_required_and_strict() -> Result<(), Box<dyn Error>> {
        let valid = br#"{"key_id":"key-1","public_key_path":"/etc/action-broker/key.pub","active_from_unix_seconds":1700000000,"retire_at_unix_seconds":1700000300,"revoke_at_unix_seconds":null}"#;
        let decoded = decode_strict::<ApprovalKeyConfig>(valid)?;
        assert_eq!(decoded.active_from_unix_seconds, 1_700_000_000);
        assert_eq!(decoded.retire_at_unix_seconds, Some(1_700_000_300));

        let missing_activation =
            br#"{"key_id":"key-1","public_key_path":"/etc/action-broker/key.pub"}"#;
        assert!(decode_strict::<ApprovalKeyConfig>(missing_activation).is_err());
        let unknown = br#"{"key_id":"key-1","public_key_path":"/etc/action-broker/key.pub","active_from_unix_seconds":1700000000,"bypass":true}"#;
        assert!(decode_strict::<ApprovalKeyConfig>(unknown).is_err());
        Ok(())
    }

    #[test]
    fn broker_admission_limits_are_required_and_strict() -> Result<(), Box<dyn Error>> {
        let valid = br#"{"maximum_concurrent_actions":8,"maximum_concurrent_actions_per_principal":4,"maximum_concurrent_actions_per_capability":4,"concurrency_wait_milliseconds":1000}"#;
        let decoded = decode_strict::<BrokerLimitsWireConfig>(valid)?;
        assert_eq!(decoded.maximum_concurrent_actions, 8);
        assert_eq!(decoded.maximum_concurrent_actions_per_principal, 4);
        assert_eq!(decoded.maximum_concurrent_actions_per_capability, 4);

        let missing_scope =
            br#"{"maximum_concurrent_actions":8,"concurrency_wait_milliseconds":1000}"#;
        assert!(decode_strict::<BrokerLimitsWireConfig>(missing_scope).is_err());
        let bypass = br#"{"maximum_concurrent_actions":8,"maximum_concurrent_actions_per_principal":4,"maximum_concurrent_actions_per_capability":4,"concurrency_wait_milliseconds":1000,"bypass":true}"#;
        assert!(decode_strict::<BrokerLimitsWireConfig>(bypass).is_err());
        Ok(())
    }

    #[test]
    fn transport_admission_limits_are_required_strict_and_bounded() -> Result<(), Box<dyn Error>> {
        let valid = br#"{"maximum_open_connections":32,"maximum_open_connections_per_peer":8,"worker_threads":8,"maximum_queued_connections":16,"maximum_queue_wait_milliseconds":1000,"maximum_authentication_failures_per_window":16,"authentication_failure_window_milliseconds":1000,"maximum_protocol_failures_per_window":16,"protocol_failure_window_milliseconds":1000,"read_timeout_milliseconds":5000,"write_timeout_milliseconds":5000}"#;
        let decoded = decode_strict::<TransportLimitsWireConfig>(valid)?;
        validate_transport_limits(&decoded)?;

        let missing_per_peer = br#"{"maximum_open_connections":32,"worker_threads":8,"maximum_queued_connections":16,"maximum_queue_wait_milliseconds":1000,"maximum_authentication_failures_per_window":16,"authentication_failure_window_milliseconds":1000,"maximum_protocol_failures_per_window":16,"protocol_failure_window_milliseconds":1000,"read_timeout_milliseconds":5000,"write_timeout_milliseconds":5000}"#;
        assert!(decode_strict::<TransportLimitsWireConfig>(missing_per_peer).is_err());
        let missing_queue_wait = br#"{"maximum_open_connections":32,"maximum_open_connections_per_peer":8,"worker_threads":8,"maximum_queued_connections":16,"maximum_authentication_failures_per_window":16,"authentication_failure_window_milliseconds":1000,"maximum_protocol_failures_per_window":16,"protocol_failure_window_milliseconds":1000,"read_timeout_milliseconds":5000,"write_timeout_milliseconds":5000}"#;
        assert!(decode_strict::<TransportLimitsWireConfig>(missing_queue_wait).is_err());
        let missing_authentication_window = br#"{"maximum_open_connections":32,"maximum_open_connections_per_peer":8,"worker_threads":8,"maximum_queued_connections":16,"maximum_queue_wait_milliseconds":1000,"maximum_authentication_failures_per_window":16,"maximum_protocol_failures_per_window":16,"protocol_failure_window_milliseconds":1000,"read_timeout_milliseconds":5000,"write_timeout_milliseconds":5000}"#;
        assert!(decode_strict::<TransportLimitsWireConfig>(missing_authentication_window).is_err());
        let missing_protocol_window = br#"{"maximum_open_connections":32,"maximum_open_connections_per_peer":8,"worker_threads":8,"maximum_queued_connections":16,"maximum_queue_wait_milliseconds":1000,"maximum_authentication_failures_per_window":16,"authentication_failure_window_milliseconds":1000,"maximum_protocol_failures_per_window":16,"read_timeout_milliseconds":5000,"write_timeout_milliseconds":5000}"#;
        assert!(decode_strict::<TransportLimitsWireConfig>(missing_protocol_window).is_err());
        let bypass = br#"{"maximum_open_connections":32,"maximum_open_connections_per_peer":8,"worker_threads":8,"maximum_queued_connections":16,"maximum_queue_wait_milliseconds":1000,"maximum_authentication_failures_per_window":16,"authentication_failure_window_milliseconds":1000,"maximum_protocol_failures_per_window":16,"protocol_failure_window_milliseconds":1000,"read_timeout_milliseconds":5000,"write_timeout_milliseconds":5000,"unbounded":true}"#;
        assert!(decode_strict::<TransportLimitsWireConfig>(bypass).is_err());

        assert!(validate_transport_limits(&transport_limits(0, 0, 0)).is_err());
        assert!(validate_transport_limits(&transport_limits(129, 8, 8)).is_err());
        assert!(validate_transport_limits(&transport_limits(8, 9, 8)).is_err());
        assert!(validate_transport_limits(&transport_limits(8, 8, 9)).is_err());
        let mut empty_queue = transport_limits(8, 4, 4);
        empty_queue.maximum_queued_connections = 0;
        assert!(validate_transport_limits(&empty_queue).is_err());
        let mut oversized_queue = transport_limits(8, 4, 4);
        oversized_queue.maximum_queued_connections = 9;
        assert!(validate_transport_limits(&oversized_queue).is_err());
        let mut short_queue_wait = transport_limits(8, 4, 4);
        short_queue_wait.maximum_queue_wait_milliseconds = 99;
        assert!(validate_transport_limits(&short_queue_wait).is_err());
        let mut long_queue_wait = transport_limits(8, 4, 4);
        long_queue_wait.maximum_queue_wait_milliseconds = 30_001;
        assert!(validate_transport_limits(&long_queue_wait).is_err());
        let mut no_authentication_failures = transport_limits(8, 4, 4);
        no_authentication_failures.maximum_authentication_failures_per_window = 0;
        assert!(validate_transport_limits(&no_authentication_failures).is_err());
        let mut excessive_authentication_failures = transport_limits(8, 4, 4);
        excessive_authentication_failures.maximum_authentication_failures_per_window = 1_025;
        assert!(validate_transport_limits(&excessive_authentication_failures).is_err());
        let mut short_authentication_window = transport_limits(8, 4, 4);
        short_authentication_window.authentication_failure_window_milliseconds = 99;
        assert!(validate_transport_limits(&short_authentication_window).is_err());
        let mut long_authentication_window = transport_limits(8, 4, 4);
        long_authentication_window.authentication_failure_window_milliseconds = 30_001;
        assert!(validate_transport_limits(&long_authentication_window).is_err());
        let mut no_protocol_failures = transport_limits(8, 4, 4);
        no_protocol_failures.maximum_protocol_failures_per_window = 0;
        assert!(validate_transport_limits(&no_protocol_failures).is_err());
        let mut excessive_protocol_failures = transport_limits(8, 4, 4);
        excessive_protocol_failures.maximum_protocol_failures_per_window = 1_025;
        assert!(validate_transport_limits(&excessive_protocol_failures).is_err());
        let mut short_protocol_window = transport_limits(8, 4, 4);
        short_protocol_window.protocol_failure_window_milliseconds = 99;
        assert!(validate_transport_limits(&short_protocol_window).is_err());
        let mut long_protocol_window = transport_limits(8, 4, 4);
        long_protocol_window.protocol_failure_window_milliseconds = 30_001;
        assert!(validate_transport_limits(&long_protocol_window).is_err());
        let mut short_timeout = transport_limits(8, 4, 4);
        short_timeout.read_timeout_milliseconds = 99;
        assert!(validate_transport_limits(&short_timeout).is_err());
        let mut long_timeout = transport_limits(8, 4, 4);
        long_timeout.write_timeout_milliseconds = 30_001;
        assert!(validate_transport_limits(&long_timeout).is_err());
        Ok(())
    }

    #[test]
    fn connection_admission_enforces_global_and_per_peer_limits() -> Result<(), Box<dyn Error>> {
        let admission = ConnectionAdmission::new(&transport_limits(3, 2, 1));
        let first = admission.try_acquire(1001)?.map_err(|_| "first denied")?;
        let second = admission.try_acquire(1001)?.map_err(|_| "second denied")?;
        assert!(matches!(
            admission.try_acquire(1001)?,
            Err(ConnectionAdmissionDenial::PeerLimit)
        ));
        let third = admission.try_acquire(1002)?.map_err(|_| "third denied")?;
        assert!(matches!(
            admission.try_acquire(1003)?,
            Err(ConnectionAdmissionDenial::GlobalLimit)
        ));

        drop(first);
        let replacement = admission
            .try_acquire(1003)?
            .map_err(|_| "released capacity was not restored")?;
        drop((second, third, replacement));
        assert_eq!(
            admission
                .state
                .lock()
                .map_err(|_| "state lock")?
                .open_connections,
            0
        );
        Ok(())
    }

    #[test]
    fn concurrent_connection_admission_never_overshoots_peer_limit() -> Result<(), Box<dyn Error>> {
        const CONTENDERS: usize = 32;
        const LIMIT: usize = 8;
        let admission = Arc::new(ConnectionAdmission::new(&transport_limits(16, LIMIT, 4)));
        let admitted = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(Barrier::new(CONTENDERS + 1));
        let release = Arc::new(Barrier::new(CONTENDERS + 1));
        let mut threads = Vec::new();
        for _ in 0..CONTENDERS {
            let admission = Arc::clone(&admission);
            let admitted = Arc::clone(&admitted);
            let ready = Arc::clone(&ready);
            let release = Arc::clone(&release);
            threads.push(thread::spawn(move || {
                let permit = admission.try_acquire(1001).ok().and_then(Result::ok);
                if permit.is_some() {
                    admitted.fetch_add(1, Ordering::SeqCst);
                }
                ready.wait();
                release.wait();
                drop(permit);
            }));
        }
        ready.wait();
        assert_eq!(admitted.load(Ordering::SeqCst), LIMIT);
        assert_eq!(
            admission
                .state
                .lock()
                .map_err(|_| "admission state")?
                .open_connections,
            LIMIT
        );
        release.wait();
        for thread in threads {
            assert!(thread.join().is_ok());
        }
        assert_eq!(
            admission
                .state
                .lock()
                .map_err(|_| "admission state")?
                .open_connections,
            0
        );
        Ok(())
    }

    #[test]
    fn connection_overload_emits_secret_free_agent_green_event() -> Result<(), Box<dyn Error>> {
        let sink = RecordingSecurityEventSink {
            events: Mutex::new(Vec::new()),
        };
        let requester = AuthenticatedRequester {
            user_id: "user-7".to_owned(),
            agent_id: "agent-3".to_owned(),
        };
        emit_connection_overload(&sink, &requester, "connection_peer_limit")?;
        let events = sink.events.lock().map_err(|_| "event lock")?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, SecurityEventKind::ResourceAbusePattern);
        assert_eq!(events[0].reason_code, "connection_peer_limit");
        assert_eq!(events[0].user_id.as_deref(), Some("user-7"));
        assert_eq!(events[0].agent_id.as_deref(), Some("agent-3"));
        assert!(events[0].request_id.is_none());
        assert!(events[0].target_digest.is_none());
        Ok(())
    }

    #[test]
    fn queue_wait_deadline_rejects_before_request_parsing_and_emits_event()
    -> Result<(), Box<dyn Error>> {
        let sink = RecordingSecurityEventSink {
            events: Mutex::new(Vec::new()),
        };
        let requester = AuthenticatedRequester {
            user_id: "user-7".to_owned(),
            agent_id: "agent-3".to_owned(),
        };
        let limit = Duration::from_secs(1);

        assert!(!reject_expired_connection(
            &sink,
            &requester,
            Duration::from_millis(999),
            limit,
        )?);
        assert!(sink.events.lock().map_err(|_| "event lock")?.is_empty());

        assert!(reject_expired_connection(
            &sink,
            &requester,
            Duration::from_secs(1),
            limit,
        )?);
        let events = sink.events.lock().map_err(|_| "event lock")?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, SecurityEventKind::ResourceAbusePattern);
        assert_eq!(events[0].reason_code, "connection_queue_wait_expired");
        assert!(events[0].request_id.is_none());
        Ok(())
    }

    #[test]
    fn queue_expiry_fails_closed_when_agent_green_event_fails() {
        let requester = AuthenticatedRequester {
            user_id: "user-7".to_owned(),
            agent_id: "agent-3".to_owned(),
        };
        assert!(matches!(
            reject_expired_connection(
                &FailingSecurityEventSink,
                &requester,
                Duration::from_secs(1),
                Duration::from_secs(1),
            ),
            Err(error) if error.code == ErrorCode::SecurityEventFailure
        ));
        assert!(matches!(
            reject_expired_connection(
                &FailingSecurityEventSink,
                &requester,
                Duration::from_millis(999),
                Duration::from_secs(1),
            ),
            Ok(false)
        ));
    }

    #[test]
    fn authentication_failure_gate_backs_off_at_threshold_and_resets() {
        let mut gate = FailureWindowGate::new(3, Duration::from_secs(1));
        let started_at = gate.window_started_at;

        assert_eq!(gate.record_failure_at(started_at), None);
        assert_eq!(
            gate.record_failure_at(started_at + Duration::from_millis(250)),
            None
        );
        assert_eq!(
            gate.record_failure_at(started_at + Duration::from_millis(500)),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            gate.record_failure_at(started_at + Duration::from_secs(1)),
            None
        );
        assert_eq!(gate.failures_in_window, 1);
    }

    #[test]
    fn transport_authentication_failure_event_is_secret_free() -> Result<(), Box<dyn Error>> {
        let sink = RecordingSecurityEventSink {
            events: Mutex::new(Vec::new()),
        };
        let mut gate = FailureWindowGate::new(16, Duration::from_secs(1));
        report_transport_authentication_failure(&sink, &mut gate, "unauthorized_platform_peer")?;

        let events = sink.events.lock().map_err(|_| "event lock")?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, SecurityEventKind::PermissionBypassAttempt);
        assert_eq!(events[0].reason_code, "unauthorized_platform_peer");
        assert!(events[0].request_id.is_none());
        assert!(events[0].user_id.is_none());
        assert!(events[0].agent_id.is_none());
        assert!(events[0].target_digest.is_none());
        Ok(())
    }

    #[test]
    fn transport_authentication_failure_stops_when_event_fails() {
        let mut gate = FailureWindowGate::new(16, Duration::from_secs(1));
        assert!(matches!(
            report_transport_authentication_failure(
                &FailingSecurityEventSink,
                &mut gate,
                "peer_credentials_unavailable",
            ),
            Err(error) if error.code == ErrorCode::SecurityEventFailure
        ));
        assert_eq!(gate.failures_in_window, 0);
    }

    #[test]
    fn authenticated_protocol_failure_is_bounded_and_identity_scoped() -> Result<(), Box<dyn Error>>
    {
        let sink = RecordingSecurityEventSink {
            events: Mutex::new(Vec::new()),
        };
        let gate = Mutex::new(FailureWindowGate::new(2, Duration::from_millis(100)));
        let requester = AuthenticatedRequester {
            user_id: "user-7".to_owned(),
            agent_id: "agent-3".to_owned(),
        };

        report_authenticated_protocol_failure(&sink, &gate, &requester, "request_schema_invalid")?;
        let events = sink.events.lock().map_err(|_| "event lock")?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, SecurityEventKind::ResourceAbusePattern);
        assert_eq!(events[0].reason_code, "request_schema_invalid");
        assert_eq!(events[0].user_id.as_deref(), Some("user-7"));
        assert_eq!(events[0].agent_id.as_deref(), Some("agent-3"));
        assert!(events[0].request_id.is_none());
        drop(events);
        assert_eq!(gate.lock().map_err(|_| "gate lock")?.failures_in_window, 1);
        Ok(())
    }

    #[test]
    fn authenticated_protocol_failure_stops_when_event_fails() {
        let gate = Mutex::new(FailureWindowGate::new(2, Duration::from_secs(1)));
        let requester = AuthenticatedRequester {
            user_id: "user-7".to_owned(),
            agent_id: "agent-3".to_owned(),
        };
        assert!(matches!(
            report_authenticated_protocol_failure(
                &FailingSecurityEventSink,
                &gate,
                &requester,
                "request_frame_size_invalid",
            ),
            Err(error) if error.code == ErrorCode::SecurityEventFailure
        ));
        assert_eq!(
            gate.lock()
                .map_or(usize::MAX, |state| state.failures_in_window),
            0
        );
    }

    #[test]
    fn socket_accept_failure_emits_secret_free_sandbox_event() -> Result<(), Box<dyn Error>> {
        let sink = RecordingSecurityEventSink {
            events: Mutex::new(Vec::new()),
        };
        emit_socket_accept_failure(&sink)?;
        let events = sink.events.lock().map_err(|_| "event lock")?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, SecurityEventKind::SandboxFailure);
        assert_eq!(events[0].reason_code, "socket_accept_failure");
        assert!(events[0].request_id.is_none());
        assert!(events[0].user_id.is_none());
        assert!(events[0].target_digest.is_none());
        Ok(())
    }

    #[test]
    fn worker_liveness_guard_detects_return_and_unwind() {
        for unwind in [false, true] {
            let healthy = Arc::new(AtomicBool::new(true));
            let active_workers = Arc::new(AtomicUsize::new(1));
            let guard = WorkerLivenessGuard {
                healthy: Arc::clone(&healthy),
                active_workers: Arc::clone(&active_workers),
            };
            if unwind {
                let outcome = std::panic::catch_unwind(move || {
                    let _guard = guard;
                    std::panic::resume_unwind(Box::new("test worker unwind"));
                });
                assert!(outcome.is_err());
            } else {
                drop(guard);
            }
            assert!(!healthy.load(Ordering::Acquire));
            assert_eq!(active_workers.load(Ordering::Acquire), 0);
            assert!(!worker_pool_is_healthy(
                healthy.load(Ordering::Acquire),
                active_workers.load(Ordering::Acquire),
                1,
            ));
        }
    }

    #[test]
    fn worker_pool_health_requires_exact_configured_count() {
        assert!(worker_pool_is_healthy(true, 4, 4));
        assert!(!worker_pool_is_healthy(true, 3, 4));
        assert!(!worker_pool_is_healthy(true, 5, 4));
        assert!(!worker_pool_is_healthy(false, 4, 4));
    }

    #[test]
    fn worker_pool_failure_emits_secret_free_sandbox_event() -> Result<(), Box<dyn Error>> {
        let sink = RecordingSecurityEventSink {
            events: Mutex::new(Vec::new()),
        };
        emit_worker_pool_failure(&sink)?;
        let events = sink.events.lock().map_err(|_| "event lock")?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, SecurityEventKind::SandboxFailure);
        assert_eq!(events[0].reason_code, "connection_worker_lost");
        assert!(events[0].request_id.is_none());
        assert!(events[0].user_id.is_none());
        assert!(events[0].target_digest.is_none());
        Ok(())
    }

    #[test]
    fn replay_ledger_limits_are_required_and_strict() -> Result<(), Box<dyn Error>> {
        let valid = br#"{"maximum_entries":1000000,"retention_after_expiration_seconds":86400}"#;
        let decoded = decode_strict::<ReplayLedgerConfig>(valid)?;
        assert_eq!(decoded.maximum_entries, 1_000_000);
        assert_eq!(decoded.retention_after_expiration_seconds, 86_400);

        let missing_retention = br#"{"maximum_entries":1000000}"#;
        assert!(decode_strict::<ReplayLedgerConfig>(missing_retention).is_err());
        let bypass = br#"{"maximum_entries":1000000,"retention_after_expiration_seconds":86400,"bypass":true}"#;
        assert!(decode_strict::<ReplayLedgerConfig>(bypass).is_err());
        Ok(())
    }

    #[test]
    fn runtime_privilege_profile_is_required_and_strict() -> Result<(), Box<dyn Error>> {
        let valid = br#"{"expected_user_id":1001,"expected_group_id":1001,"allowed_supplementary_group_ids":[1001,2001]}"#;
        let decoded = decode_strict::<RuntimePrivilegeProfileConfig>(valid)?;
        assert_eq!(decoded.expected_user_id, 1001);
        assert_eq!(decoded.expected_group_id, 1001);
        assert_eq!(
            decoded.allowed_supplementary_group_ids,
            std::collections::BTreeSet::from([1001, 2001])
        );

        let missing_group = br#"{"expected_user_id":1001,"allowed_supplementary_group_ids":[]}"#;
        assert!(decode_strict::<RuntimePrivilegeProfileConfig>(missing_group).is_err());
        let bypass = br#"{"expected_user_id":1001,"expected_group_id":1001,"allowed_supplementary_group_ids":[],"ignore_capabilities":true}"#;
        assert!(decode_strict::<RuntimePrivilegeProfileConfig>(bypass).is_err());
        Ok(())
    }

    #[test]
    fn platform_peer_must_be_distinct_and_maps_one_principal() -> Result<(), Box<dyn Error>> {
        let broker_uid = process::geteuid().as_raw();
        assert!(
            validate_platform_peers(&[PlatformPeerConfig {
                uid: broker_uid,
                user_id: "user".to_owned(),
                agent_id: "agent".to_owned(),
            }])
            .is_err()
        );
        let candidate = if broker_uid == 1 { 2 } else { 1 };
        let peers = validate_platform_peers(&[PlatformPeerConfig {
            uid: candidate,
            user_id: "user".to_owned(),
            agent_id: "agent".to_owned(),
        }])?;
        assert_eq!(
            peers.get(&candidate),
            Some(&AuthenticatedRequester {
                user_id: "user".to_owned(),
                agent_id: "agent".to_owned(),
            })
        );
        Ok(())
    }
}
