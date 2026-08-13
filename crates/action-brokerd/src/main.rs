use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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
const MINIMUM_TRANSPORT_TIMEOUT_MILLISECONDS: u64 = 100;
const MAXIMUM_TRANSPORT_TIMEOUT_MILLISECONDS: u64 = 30_000;

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
}

struct ConnectionWorkerPool {
    sender: SyncSender<ConnectionJob>,
    _workers: Vec<thread::JoinHandle<()>>,
}

impl ConnectionWorkerPool {
    fn new(
        broker: Arc<ActionBroker>,
        limits: &TransportLimitsWireConfig,
    ) -> Result<Self, BrokerError> {
        let (sender, receiver) = mpsc::sync_channel(limits.maximum_open_connections);
        let receiver = Arc::new(Mutex::new(receiver));
        let read_timeout = Duration::from_millis(limits.read_timeout_milliseconds);
        let write_timeout = Duration::from_millis(limits.write_timeout_milliseconds);
        let mut workers = Vec::with_capacity(limits.worker_threads);
        for worker_index in 0..limits.worker_threads {
            let broker = Arc::clone(&broker);
            let receiver = Arc::clone(&receiver);
            let worker = thread::Builder::new()
                .name(format!("action-broker-connection-{worker_index}"))
                .spawn(move || {
                    connection_worker(receiver, broker, read_timeout, write_timeout);
                })
                .map_err(|_| {
                    BrokerError::new(ErrorCode::Internal, "connection worker could not start")
                })?;
            workers.push(worker);
        }
        Ok(Self {
            sender,
            _workers: workers,
        })
    }

    fn try_submit(&self, job: ConnectionJob) -> Result<(), TrySendError<ConnectionJob>> {
        self.sender.try_send(job)
    }
}

fn connection_worker(
    receiver: Arc<Mutex<Receiver<ConnectionJob>>>,
    broker: Arc<ActionBroker>,
    read_timeout: Duration,
    write_timeout: Duration,
) {
    loop {
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
        } = job;
        let _connection_permit = connection_permit;
        let _ = handle_connection(
            Arc::clone(&broker),
            authenticated_requester,
            stream,
            read_timeout,
            write_timeout,
        );
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
    let worker_pool = ConnectionWorkerPool::new(Arc::clone(&broker), &config.transport_limits)?;
    let listener = bind_socket(&config.socket_path, config.socket_group_id)?;
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            continue;
        };
        let Some(peer_uid) = peer_uid(&stream) else {
            continue;
        };
        let Some(authenticated_requester) = peer_principals.get(&peer_uid).cloned() else {
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
    Err(BrokerError::new(
        ErrorCode::Internal,
        "Unix socket accept loop ended",
    ))
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
    authenticated_requester: AuthenticatedRequester,
    mut stream: UnixStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), BrokerError> {
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|_| transport_error("socket read timeout setup failed"))?;
    stream
        .set_write_timeout(Some(write_timeout))
        .map_err(|_| transport_error("socket write timeout setup failed"))?;
    let frame = read_frame(&mut stream)?;
    let request: ActionRequest = decode_strict(&frame)?;
    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let response = broker.execute(request, &authenticated_requester, &worker_cancellation);
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
    write_response(&mut stream, &response)
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, BrokerError> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| transport_error("request frame prefix is incomplete"))?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| transport_error("request frame length is invalid"))?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(transport_error(
            "request frame size is outside the safe bound",
        ));
    }
    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .map_err(|_| transport_error("request frame is incomplete"))?;
    Ok(frame)
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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct RecordingSecurityEventSink {
        events: Mutex<Vec<SecurityEvent>>,
    }

    impl SecurityEventSink for RecordingSecurityEventSink {
        fn emit(&self, event: &SecurityEvent) -> Result<(), BrokerError> {
            self.events
                .lock()
                .map_err(|_| BrokerError::new(ErrorCode::Internal, "test event lock failed"))?
                .push(event.clone());
            Ok(())
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
        assert!(read_frame(&mut frame).is_err());
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
        assert!(read_frame(&mut frame).is_err());
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
        let valid = br#"{"maximum_open_connections":32,"maximum_open_connections_per_peer":8,"worker_threads":8,"read_timeout_milliseconds":5000,"write_timeout_milliseconds":5000}"#;
        let decoded = decode_strict::<TransportLimitsWireConfig>(valid)?;
        validate_transport_limits(&decoded)?;

        let missing_per_peer = br#"{"maximum_open_connections":32,"worker_threads":8,"read_timeout_milliseconds":5000,"write_timeout_milliseconds":5000}"#;
        assert!(decode_strict::<TransportLimitsWireConfig>(missing_per_peer).is_err());
        let bypass = br#"{"maximum_open_connections":32,"maximum_open_connections_per_peer":8,"worker_threads":8,"read_timeout_milliseconds":5000,"write_timeout_milliseconds":5000,"unbounded":true}"#;
        assert!(decode_strict::<TransportLimitsWireConfig>(bypass).is_err());

        assert!(validate_transport_limits(&transport_limits(0, 0, 0)).is_err());
        assert!(validate_transport_limits(&transport_limits(129, 8, 8)).is_err());
        assert!(validate_transport_limits(&transport_limits(8, 9, 8)).is_err());
        assert!(validate_transport_limits(&transport_limits(8, 8, 9)).is_err());
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
