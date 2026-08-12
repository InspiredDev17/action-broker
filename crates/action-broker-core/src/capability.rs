//! Typed capability contracts and their fail-closed policy metadata.
//!
//! There is deliberately no generic shell or "execute anything" variant in
//! this module. Every executable operation has a typed input and a bounded
//! output contract.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The complete set of capabilities understood by this protocol version.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "PascalCase")]
pub enum CapabilityKind {
    ReadFile,
    WriteFile,
    CreateFile,
    MoveFile,
    DeleteFile,
    ListDirectory,
    ExecuteApprovedCommand,
    GitRead,
    GitWrite,
    #[serde(rename = "HTTPRequest")]
    HttpRequest,
    BrowserAction,
    ProcessInspect,
    ServiceInspect,
    ServiceControl,
    ContainerAction,
    NodeAction,
}

/// Deterministic risk classes used by policy and approval decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskClass {
    ReadOnly,
    LowRiskWrite,
    ReversibleChange,
    PrivilegedChange,
    Destructive,
    ExternalSideEffect,
}

/// Stable permission names evaluated by the Personal AI Platform.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    FilesystemRead,
    FilesystemWrite,
    FilesystemDelete,
    CommandExecuteApproved,
    GitRead,
    GitWrite,
    NetworkHttp,
    BrowserControl,
    ProcessInspect,
    ServiceInspect,
    ServiceControl,
    ContainerControl,
    NodeControl,
}

/// Signed approval strengths the broker recognizes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalType {
    ExplicitUser,
    ElevatedUser,
    Administrator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    /// Permission and deterministic policy are sufficient. This is reserved
    /// for bounded inspection operations.
    PolicyOnly,
    /// A short-lived signed token is mandatory.
    SignedToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalPolicy {
    pub requirement: ApprovalRequirement,
    pub accepted_types: Vec<ApprovalType>,
    pub maximum_ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccess {
    None,
    Read,
    Write,
    Delete,
    RepositoryRead,
    RepositoryWrite,
    ControlledWorkingDirectory,
}

/// Filesystem policy shape. Concrete roots are supplied by trusted broker
/// configuration, never by the action request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::struct_excessive_bools)]
pub struct FilesystemScope {
    pub access: FilesystemAccess,
    pub roots_from_broker_policy: bool,
    pub follow_symlinks: bool,
    pub allow_special_files: bool,
    pub allow_secret_paths: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAccess {
    None,
    PolicyFilteredHttp,
    PolicyFilteredBrowser,
    NodeControlPlane,
}

/// Network policy shape. Destination allowlists and resolved-address checks
/// come from trusted broker configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::struct_excessive_bools)]
pub struct NetworkScope {
    pub access: NetworkAccess,
    pub destination_policy_required: bool,
    pub redirects_revalidated: bool,
    pub dns_answers_revalidated: bool,
    pub localhost_allowed: bool,
    pub private_networks_allowed: bool,
    pub metadata_endpoints_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TimeoutPolicy {
    pub default_milliseconds: u64,
    pub maximum_milliseconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceLimits {
    pub maximum_input_bytes: u64,
    pub maximum_output_bytes: u64,
    pub maximum_memory_bytes: u64,
    pub maximum_processes: u32,
    pub maximum_open_files: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::struct_excessive_bools)]
pub struct AuditBehavior {
    pub record_start_and_finish: bool,
    pub hash_validated_arguments: bool,
    pub hash_output: bool,
    pub record_changed_files: bool,
    pub record_network_destinations: bool,
    pub redact_secrets: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    NotReversible,
    AtomicReplacementWithPrechangeDigest,
    BackupMetadataAndAtomicRename,
    GitHistory,
    RuntimeDependent,
}

/// Complete declarative metadata for a typed capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityDescriptor {
    pub kind: CapabilityKind,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    pub permission_required: Permission,
    pub approval_policy: ApprovalPolicy,
    pub filesystem_scope: FilesystemScope,
    pub network_scope: NetworkScope,
    pub timeout: TimeoutPolicy,
    pub resource_limits: ResourceLimits,
    pub audit_behavior: AuditBehavior,
    pub reversibility: Reversibility,
    pub risk_class: RiskClass,
}

/// A path resolved beneath a broker-configured root. `root_id` is a stable
/// policy identifier, never a request-controlled absolute directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootedPath {
    pub root_id: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadFileInput {
    pub path: RootedPath,
    pub maximum_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReadFileOutput {
    pub path: RootedPath,
    pub content_base64: String,
    pub bytes_read: u64,
    pub sha256: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteFileInput {
    pub path: RootedPath,
    pub content_base64: String,
    pub expected_prechange_sha256: Option<String>,
    pub create_if_missing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateFileInput {
    pub path: RootedPath,
    pub content_base64: String,
    pub fail_if_exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileMutationOutput {
    pub path: RootedPath,
    pub previous_sha256: Option<String>,
    pub current_sha256: String,
    pub bytes_written: u64,
    pub backup_reference: Option<String>,
    pub used_atomic_rename: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveFileInput {
    pub source: RootedPath,
    pub destination: RootedPath,
    pub replace_existing: bool,
    pub expected_source_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MoveFileOutput {
    pub source: RootedPath,
    pub destination: RootedPath,
    pub moved_sha256: String,
    pub replaced_sha256: Option<String>,
    pub replaced_backup_reference: Option<String>,
    pub used_atomic_rename: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteFileInput {
    pub path: RootedPath,
    pub expected_sha256: Option<String>,
    /// Recursive deletion is intentionally not part of this capability.
    pub require_regular_file: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeleteFileOutput {
    pub path: RootedPath,
    pub previous_sha256: String,
    pub backup_reference: Option<String>,
    pub removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListDirectoryInput {
    pub path: RootedPath,
    pub maximum_entries: u32,
    pub include_hidden: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DirectoryEntry {
    pub name: String,
    pub kind: DirectoryEntryKind,
    pub byte_len: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ListDirectoryOutput {
    pub path: RootedPath,
    pub entries: Vec<DirectoryEntry>,
    pub truncated: bool,
}

/// Executes one broker-policy-approved executable directly, without a shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecuteApprovedCommandInput {
    /// Identifier resolved through the broker's trusted executable registry.
    /// It is not an executable path and cannot select an arbitrary program.
    pub program_id: String,
    pub arguments: Vec<String>,
    pub working_directory: RootedPath,
    /// Only explicitly named variables may be passed. The host environment is
    /// never inherited by this contract.
    pub environment: BTreeMap<String, String>,
    pub timeout_milliseconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecuteApprovedCommandOutput {
    pub exit_code: Option<i32>,
    pub stdout_base64: String,
    pub stderr_base64: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum GitReadOperation {
    Status,
    Diff { revision: Option<String> },
    Log { maximum_entries: u32 },
    Show { object_id: String },
    ResolveRevision { revision: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitReadInput {
    pub repository_path: RootedPath,
    pub operation: GitReadOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GitReadOutput {
    pub repository_path: RootedPath,
    pub text_base64: String,
    pub truncated: bool,
    pub resolved_object_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum GitWriteOperation {
    AddPaths { paths: Vec<String> },
    Commit { message: String },
    CreateBranch { name: String, start_point: String },
    ApplyPatch { patch_base64: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitWriteInput {
    pub repository_path: RootedPath,
    pub operation: GitWriteOperation,
    pub expected_head: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GitWriteOutput {
    pub repository_path: RootedPath,
    pub previous_head: Option<String>,
    pub current_head: Option<String>,
    pub changed_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestInput {
    pub method: HttpMethod,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body_base64: Option<String>,
    pub maximum_response_bytes: u64,
    pub timeout_milliseconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HttpRequestOutput {
    pub final_url: String,
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
    pub body_base64: String,
    pub truncated: bool,
    pub contacted_destinations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum BrowserOperation {
    Navigate { url: String },
    Click { selector: String },
    TypeText { selector: String, text: String },
    ReadText { selector: String },
    Screenshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserActionInput {
    pub browser_session_id: String,
    pub operation: BrowserOperation,
    pub timeout_milliseconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserActionOutput {
    pub browser_session_id: String,
    pub current_url: Option<String>,
    pub text: Option<String>,
    pub screenshot_base64: Option<String>,
    pub contacted_destinations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ProcessInspectOperation {
    List { maximum_entries: u32 },
    InspectPid { pid: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessInspectInput {
    pub operation: ProcessInspectOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessInformation {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub executable: String,
    pub arguments_redacted: Vec<String>,
    pub user_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessInspectOutput {
    pub processes: Vec<ProcessInformation>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceInspectInput {
    pub service_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceInspectOutput {
    pub service_name: String,
    pub state: String,
    pub substate: Option<String>,
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceControlOperation {
    Start,
    Stop,
    Restart,
    Reload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceControlInput {
    pub service_name: String,
    pub operation: ServiceControlOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceControlOutput {
    pub service_name: String,
    pub previous_state: String,
    pub current_state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRuntime {
    Docker,
    Podman,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContainerOperation {
    Inspect,
    Start,
    Stop,
    Restart,
    Pause,
    Unpause,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContainerActionInput {
    pub runtime: ContainerRuntime,
    pub container_id: String,
    pub operation: ContainerOperation,
    pub timeout_milliseconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ContainerActionOutput {
    pub container_id: String,
    pub previous_state: Option<String>,
    pub current_state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeOperation {
    InspectStatus,
    Drain,
    Resume,
    RestartRuntime,
}

/// `NodeAction` controls the broker runtime on an enrolled node. It does not
/// carry a nested arbitrary action; remote action execution instead uses the
/// normal typed capability with [`crate::model::ExecutionTarget::Node`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeActionInput {
    pub node_id: String,
    pub operation: NodeOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NodeActionOutput {
    pub node_id: String,
    pub previous_state: Option<String>,
    pub current_state: String,
}

/// A request can contain exactly one typed capability invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "capability", content = "arguments", rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub enum CapabilityAction {
    ReadFile(ReadFileInput),
    WriteFile(WriteFileInput),
    CreateFile(CreateFileInput),
    MoveFile(MoveFileInput),
    DeleteFile(DeleteFileInput),
    ListDirectory(ListDirectoryInput),
    ExecuteApprovedCommand(ExecuteApprovedCommandInput),
    GitRead(GitReadInput),
    GitWrite(GitWriteInput),
    #[serde(rename = "HTTPRequest")]
    HttpRequest(HttpRequestInput),
    BrowserAction(BrowserActionInput),
    ProcessInspect(ProcessInspectInput),
    ServiceInspect(ServiceInspectInput),
    ServiceControl(ServiceControlInput),
    ContainerAction(ContainerActionInput),
    NodeAction(NodeActionInput),
}

/// Typed result envelope. Executors must return the variant corresponding to
/// the request capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "capability", content = "result", rename_all = "PascalCase")]
pub enum CapabilityOutput {
    ReadFile(ReadFileOutput),
    WriteFile(FileMutationOutput),
    CreateFile(FileMutationOutput),
    MoveFile(MoveFileOutput),
    DeleteFile(DeleteFileOutput),
    ListDirectory(ListDirectoryOutput),
    ExecuteApprovedCommand(ExecuteApprovedCommandOutput),
    GitRead(GitReadOutput),
    GitWrite(GitWriteOutput),
    #[serde(rename = "HTTPRequest")]
    HttpRequest(HttpRequestOutput),
    BrowserAction(BrowserActionOutput),
    ProcessInspect(ProcessInspectOutput),
    ServiceInspect(ServiceInspectOutput),
    ServiceControl(ServiceControlOutput),
    ContainerAction(ContainerActionOutput),
    NodeAction(NodeActionOutput),
}

impl CapabilityAction {
    #[must_use]
    pub const fn kind(&self) -> CapabilityKind {
        match self {
            Self::ReadFile(_) => CapabilityKind::ReadFile,
            Self::WriteFile(_) => CapabilityKind::WriteFile,
            Self::CreateFile(_) => CapabilityKind::CreateFile,
            Self::MoveFile(_) => CapabilityKind::MoveFile,
            Self::DeleteFile(_) => CapabilityKind::DeleteFile,
            Self::ListDirectory(_) => CapabilityKind::ListDirectory,
            Self::ExecuteApprovedCommand(_) => CapabilityKind::ExecuteApprovedCommand,
            Self::GitRead(_) => CapabilityKind::GitRead,
            Self::GitWrite(_) => CapabilityKind::GitWrite,
            Self::HttpRequest(_) => CapabilityKind::HttpRequest,
            Self::BrowserAction(_) => CapabilityKind::BrowserAction,
            Self::ProcessInspect(_) => CapabilityKind::ProcessInspect,
            Self::ServiceInspect(_) => CapabilityKind::ServiceInspect,
            Self::ServiceControl(_) => CapabilityKind::ServiceControl,
            Self::ContainerAction(_) => CapabilityKind::ContainerAction,
            Self::NodeAction(_) => CapabilityKind::NodeAction,
        }
    }

    #[must_use]
    pub fn descriptor(&self) -> CapabilityDescriptor {
        self.kind().descriptor()
    }
}

impl CapabilityOutput {
    #[must_use]
    pub const fn kind(&self) -> CapabilityKind {
        match self {
            Self::ReadFile(_) => CapabilityKind::ReadFile,
            Self::WriteFile(_) => CapabilityKind::WriteFile,
            Self::CreateFile(_) => CapabilityKind::CreateFile,
            Self::MoveFile(_) => CapabilityKind::MoveFile,
            Self::DeleteFile(_) => CapabilityKind::DeleteFile,
            Self::ListDirectory(_) => CapabilityKind::ListDirectory,
            Self::ExecuteApprovedCommand(_) => CapabilityKind::ExecuteApprovedCommand,
            Self::GitRead(_) => CapabilityKind::GitRead,
            Self::GitWrite(_) => CapabilityKind::GitWrite,
            Self::HttpRequest(_) => CapabilityKind::HttpRequest,
            Self::BrowserAction(_) => CapabilityKind::BrowserAction,
            Self::ProcessInspect(_) => CapabilityKind::ProcessInspect,
            Self::ServiceInspect(_) => CapabilityKind::ServiceInspect,
            Self::ServiceControl(_) => CapabilityKind::ServiceControl,
            Self::ContainerAction(_) => CapabilityKind::ContainerAction,
            Self::NodeAction(_) => CapabilityKind::NodeAction,
        }
    }
}

impl CapabilityKind {
    /// Returns generated JSON Schemas together with every policy declaration
    /// required for this capability.
    #[must_use]
    pub fn descriptor(self) -> CapabilityDescriptor {
        let common = descriptor_policy(self);
        CapabilityDescriptor {
            kind: self,
            input_schema: input_schema(self),
            output_schema: output_schema(self),
            permission_required: common.permission,
            approval_policy: common.approval,
            filesystem_scope: common.filesystem,
            network_scope: common.network,
            timeout: common.timeout,
            resource_limits: common.resources,
            audit_behavior: common.audit,
            reversibility: common.reversibility,
            risk_class: common.risk,
        }
    }
}

struct DescriptorPolicy {
    permission: Permission,
    approval: ApprovalPolicy,
    filesystem: FilesystemScope,
    network: NetworkScope,
    timeout: TimeoutPolicy,
    resources: ResourceLimits,
    audit: AuditBehavior,
    reversibility: Reversibility,
    risk: RiskClass,
}

fn approval(requirement: ApprovalRequirement, types: &[ApprovalType]) -> ApprovalPolicy {
    ApprovalPolicy {
        requirement,
        accepted_types: types.to_vec(),
        maximum_ttl_seconds: 300,
    }
}

const fn filesystem(access: FilesystemAccess) -> FilesystemScope {
    FilesystemScope {
        access,
        roots_from_broker_policy: !matches!(access, FilesystemAccess::None),
        follow_symlinks: false,
        allow_special_files: false,
        allow_secret_paths: false,
    }
}

const fn network(access: NetworkAccess) -> NetworkScope {
    let has_network = !matches!(access, NetworkAccess::None);
    NetworkScope {
        access,
        destination_policy_required: has_network,
        redirects_revalidated: matches!(
            access,
            NetworkAccess::PolicyFilteredHttp | NetworkAccess::PolicyFilteredBrowser
        ),
        dns_answers_revalidated: has_network,
        localhost_allowed: false,
        private_networks_allowed: false,
        metadata_endpoints_allowed: false,
    }
}

const fn timeout(default_milliseconds: u64, maximum_milliseconds: u64) -> TimeoutPolicy {
    TimeoutPolicy {
        default_milliseconds,
        maximum_milliseconds,
    }
}

const fn resources(processes: u32, output: u64) -> ResourceLimits {
    ResourceLimits {
        maximum_input_bytes: 1024 * 1024,
        maximum_output_bytes: if output > 512 * 1024 {
            512 * 1024
        } else {
            output
        },
        maximum_memory_bytes: 256 * 1024 * 1024,
        maximum_processes: processes,
        maximum_open_files: 64,
    }
}

const fn audit(changed_files: bool, network_destinations: bool) -> AuditBehavior {
    AuditBehavior {
        record_start_and_finish: true,
        hash_validated_arguments: true,
        hash_output: true,
        record_changed_files: changed_files,
        record_network_destinations: network_destinations,
        redact_secrets: true,
    }
}

#[allow(clippy::too_many_lines)]
fn descriptor_policy(kind: CapabilityKind) -> DescriptorPolicy {
    use ApprovalRequirement::{PolicyOnly, SignedToken};
    use ApprovalType::{Administrator, ElevatedUser, ExplicitUser};

    match kind {
        CapabilityKind::ReadFile => DescriptorPolicy {
            permission: Permission::FilesystemRead,
            approval: approval(PolicyOnly, &[]),
            filesystem: filesystem(FilesystemAccess::Read),
            network: network(NetworkAccess::None),
            timeout: timeout(2_000, 10_000),
            resources: resources(1, 8 * 1024 * 1024),
            audit: audit(false, false),
            reversibility: Reversibility::NotReversible,
            risk: RiskClass::ReadOnly,
        },
        CapabilityKind::WriteFile => DescriptorPolicy {
            permission: Permission::FilesystemWrite,
            approval: approval(SignedToken, &[ExplicitUser, ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::Write),
            network: network(NetworkAccess::None),
            timeout: timeout(5_000, 30_000),
            resources: resources(1, 1024 * 1024),
            audit: audit(true, false),
            reversibility: Reversibility::AtomicReplacementWithPrechangeDigest,
            risk: RiskClass::ReversibleChange,
        },
        CapabilityKind::CreateFile => DescriptorPolicy {
            permission: Permission::FilesystemWrite,
            approval: approval(SignedToken, &[ExplicitUser, ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::Write),
            network: network(NetworkAccess::None),
            timeout: timeout(5_000, 30_000),
            resources: resources(1, 1024 * 1024),
            audit: audit(true, false),
            reversibility: Reversibility::BackupMetadataAndAtomicRename,
            risk: RiskClass::LowRiskWrite,
        },
        CapabilityKind::MoveFile => DescriptorPolicy {
            permission: Permission::FilesystemWrite,
            approval: approval(SignedToken, &[ExplicitUser, ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::Write),
            network: network(NetworkAccess::None),
            timeout: timeout(5_000, 30_000),
            resources: resources(1, 1024 * 1024),
            audit: audit(true, false),
            reversibility: Reversibility::BackupMetadataAndAtomicRename,
            risk: RiskClass::ReversibleChange,
        },
        CapabilityKind::DeleteFile => DescriptorPolicy {
            permission: Permission::FilesystemDelete,
            approval: approval(SignedToken, &[ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::Delete),
            network: network(NetworkAccess::None),
            timeout: timeout(5_000, 30_000),
            resources: resources(1, 1024 * 1024),
            audit: audit(true, false),
            reversibility: Reversibility::RuntimeDependent,
            risk: RiskClass::Destructive,
        },
        CapabilityKind::ListDirectory => DescriptorPolicy {
            permission: Permission::FilesystemRead,
            approval: approval(PolicyOnly, &[]),
            filesystem: filesystem(FilesystemAccess::Read),
            network: network(NetworkAccess::None),
            timeout: timeout(2_000, 10_000),
            resources: resources(1, 1024 * 1024),
            audit: audit(false, false),
            reversibility: Reversibility::NotReversible,
            risk: RiskClass::ReadOnly,
        },
        CapabilityKind::ExecuteApprovedCommand => DescriptorPolicy {
            permission: Permission::CommandExecuteApproved,
            approval: approval(SignedToken, &[ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::ControlledWorkingDirectory),
            network: network(NetworkAccess::None),
            timeout: timeout(10_000, 120_000),
            resources: resources(16, 4 * 1024 * 1024),
            audit: audit(true, false),
            reversibility: Reversibility::RuntimeDependent,
            risk: RiskClass::PrivilegedChange,
        },
        CapabilityKind::GitRead => DescriptorPolicy {
            permission: Permission::GitRead,
            approval: approval(PolicyOnly, &[]),
            filesystem: filesystem(FilesystemAccess::RepositoryRead),
            network: network(NetworkAccess::None),
            timeout: timeout(10_000, 10_000),
            resources: resources(4, 4 * 1024 * 1024),
            audit: audit(false, false),
            reversibility: Reversibility::NotReversible,
            risk: RiskClass::ReadOnly,
        },
        CapabilityKind::GitWrite => DescriptorPolicy {
            permission: Permission::GitWrite,
            approval: approval(SignedToken, &[ExplicitUser, ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::RepositoryWrite),
            network: network(NetworkAccess::None),
            timeout: timeout(10_000, 60_000),
            resources: resources(8, 4 * 1024 * 1024),
            audit: audit(true, false),
            reversibility: Reversibility::GitHistory,
            risk: RiskClass::ReversibleChange,
        },
        CapabilityKind::HttpRequest => DescriptorPolicy {
            permission: Permission::NetworkHttp,
            approval: approval(SignedToken, &[ExplicitUser, ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::None),
            network: network(NetworkAccess::PolicyFilteredHttp),
            timeout: timeout(10_000, 60_000),
            resources: resources(1, 8 * 1024 * 1024),
            audit: audit(false, true),
            reversibility: Reversibility::NotReversible,
            risk: RiskClass::ExternalSideEffect,
        },
        CapabilityKind::BrowserAction => DescriptorPolicy {
            permission: Permission::BrowserControl,
            approval: approval(SignedToken, &[ExplicitUser, ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::None),
            network: network(NetworkAccess::PolicyFilteredBrowser),
            timeout: timeout(15_000, 120_000),
            resources: resources(8, 8 * 1024 * 1024),
            audit: audit(false, true),
            reversibility: Reversibility::NotReversible,
            risk: RiskClass::ExternalSideEffect,
        },
        CapabilityKind::ProcessInspect => DescriptorPolicy {
            permission: Permission::ProcessInspect,
            approval: approval(PolicyOnly, &[]),
            filesystem: filesystem(FilesystemAccess::None),
            network: network(NetworkAccess::None),
            timeout: timeout(2_000, 10_000),
            resources: resources(1, 2 * 1024 * 1024),
            audit: audit(false, false),
            reversibility: Reversibility::NotReversible,
            risk: RiskClass::ReadOnly,
        },
        CapabilityKind::ServiceInspect => DescriptorPolicy {
            permission: Permission::ServiceInspect,
            approval: approval(PolicyOnly, &[]),
            filesystem: filesystem(FilesystemAccess::None),
            network: network(NetworkAccess::None),
            timeout: timeout(5_000, 15_000),
            resources: resources(1, 1024 * 1024),
            audit: audit(false, false),
            reversibility: Reversibility::NotReversible,
            risk: RiskClass::ReadOnly,
        },
        CapabilityKind::ServiceControl => DescriptorPolicy {
            permission: Permission::ServiceControl,
            approval: approval(SignedToken, &[ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::None),
            network: network(NetworkAccess::None),
            timeout: timeout(20_000, 120_000),
            resources: resources(4, 2 * 1024 * 1024),
            audit: audit(false, false),
            reversibility: Reversibility::RuntimeDependent,
            risk: RiskClass::PrivilegedChange,
        },
        CapabilityKind::ContainerAction => DescriptorPolicy {
            permission: Permission::ContainerControl,
            approval: approval(SignedToken, &[ElevatedUser, Administrator]),
            filesystem: filesystem(FilesystemAccess::None),
            network: network(NetworkAccess::None),
            timeout: timeout(20_000, 120_000),
            resources: resources(4, 2 * 1024 * 1024),
            audit: audit(false, false),
            reversibility: Reversibility::RuntimeDependent,
            risk: RiskClass::PrivilegedChange,
        },
        CapabilityKind::NodeAction => DescriptorPolicy {
            permission: Permission::NodeControl,
            approval: approval(SignedToken, &[Administrator]),
            filesystem: filesystem(FilesystemAccess::None),
            network: network(NetworkAccess::NodeControlPlane),
            timeout: timeout(30_000, 180_000),
            resources: resources(2, 2 * 1024 * 1024),
            audit: audit(false, true),
            reversibility: Reversibility::RuntimeDependent,
            risk: RiskClass::PrivilegedChange,
        },
    }
}

fn schema_for<T: JsonSchema>() -> serde_json::Value {
    match serde_json::to_value(schemars::schema_for!(T)) {
        Ok(schema) => schema,
        Err(error) => {
            // Schema generation is deterministic for derived in-memory types.
            // A serialization failure is represented in-band so callers never
            // get an incomplete descriptor or a process panic.
            serde_json::json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "not": {},
                "x-action-broker-schema-error": error.to_string(),
            })
        }
    }
}

fn input_schema(kind: CapabilityKind) -> serde_json::Value {
    match kind {
        CapabilityKind::ReadFile => schema_for::<ReadFileInput>(),
        CapabilityKind::WriteFile => schema_for::<WriteFileInput>(),
        CapabilityKind::CreateFile => schema_for::<CreateFileInput>(),
        CapabilityKind::MoveFile => schema_for::<MoveFileInput>(),
        CapabilityKind::DeleteFile => schema_for::<DeleteFileInput>(),
        CapabilityKind::ListDirectory => schema_for::<ListDirectoryInput>(),
        CapabilityKind::ExecuteApprovedCommand => schema_for::<ExecuteApprovedCommandInput>(),
        CapabilityKind::GitRead => schema_for::<GitReadInput>(),
        CapabilityKind::GitWrite => schema_for::<GitWriteInput>(),
        CapabilityKind::HttpRequest => schema_for::<HttpRequestInput>(),
        CapabilityKind::BrowserAction => schema_for::<BrowserActionInput>(),
        CapabilityKind::ProcessInspect => schema_for::<ProcessInspectInput>(),
        CapabilityKind::ServiceInspect => schema_for::<ServiceInspectInput>(),
        CapabilityKind::ServiceControl => schema_for::<ServiceControlInput>(),
        CapabilityKind::ContainerAction => schema_for::<ContainerActionInput>(),
        CapabilityKind::NodeAction => schema_for::<NodeActionInput>(),
    }
}

fn output_schema(kind: CapabilityKind) -> serde_json::Value {
    match kind {
        CapabilityKind::ReadFile => schema_for::<ReadFileOutput>(),
        CapabilityKind::WriteFile | CapabilityKind::CreateFile => {
            schema_for::<FileMutationOutput>()
        }
        CapabilityKind::MoveFile => schema_for::<MoveFileOutput>(),
        CapabilityKind::DeleteFile => schema_for::<DeleteFileOutput>(),
        CapabilityKind::ListDirectory => schema_for::<ListDirectoryOutput>(),
        CapabilityKind::ExecuteApprovedCommand => schema_for::<ExecuteApprovedCommandOutput>(),
        CapabilityKind::GitRead => schema_for::<GitReadOutput>(),
        CapabilityKind::GitWrite => schema_for::<GitWriteOutput>(),
        CapabilityKind::HttpRequest => schema_for::<HttpRequestOutput>(),
        CapabilityKind::BrowserAction => schema_for::<BrowserActionOutput>(),
        CapabilityKind::ProcessInspect => schema_for::<ProcessInspectOutput>(),
        CapabilityKind::ServiceInspect => schema_for::<ServiceInspectOutput>(),
        CapabilityKind::ServiceControl => schema_for::<ServiceControlOutput>(),
        CapabilityKind::ContainerAction => schema_for::<ContainerActionOutput>(),
        CapabilityKind::NodeAction => schema_for::<NodeActionOutput>(),
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalRequirement, CapabilityKind, RiskClass};

    #[test]
    fn every_capability_has_nonempty_schemas_and_policy() {
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

        for kind in kinds {
            let descriptor = kind.descriptor();
            assert!(descriptor.input_schema.is_object());
            assert!(descriptor.output_schema.is_object());
            assert!(descriptor.timeout.default_milliseconds > 0);
            assert!(
                descriptor.timeout.maximum_milliseconds >= descriptor.timeout.default_milliseconds
            );
            assert!(descriptor.audit_behavior.redact_secrets);
            assert!(!descriptor.filesystem_scope.follow_symlinks);
            assert!(!descriptor.network_scope.metadata_endpoints_allowed);

            if !matches!(descriptor.risk_class, RiskClass::ReadOnly) {
                assert_eq!(
                    descriptor.approval_policy.requirement,
                    ApprovalRequirement::SignedToken
                );
                assert!(!descriptor.approval_policy.accepted_types.is_empty());
            }
        }
    }
}
