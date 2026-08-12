package actionbroker

import "encoding/json"

// ProtocolVersion is the only Action Broker wire version supported by this
// client module.
const ProtocolVersion uint16 = 1

// CapabilityKind is a closed, typed capability name. It intentionally has no
// shell, eval, or generic execution value.
type CapabilityKind string

const (
	CapabilityReadFile               CapabilityKind = "ReadFile"
	CapabilityWriteFile              CapabilityKind = "WriteFile"
	CapabilityCreateFile             CapabilityKind = "CreateFile"
	CapabilityMoveFile               CapabilityKind = "MoveFile"
	CapabilityDeleteFile             CapabilityKind = "DeleteFile"
	CapabilityListDirectory          CapabilityKind = "ListDirectory"
	CapabilityExecuteApprovedCommand CapabilityKind = "ExecuteApprovedCommand"
	CapabilityGitRead                CapabilityKind = "GitRead"
	CapabilityGitWrite               CapabilityKind = "GitWrite"
	CapabilityHTTPRequest            CapabilityKind = "HTTPRequest"
	CapabilityBrowserAction          CapabilityKind = "BrowserAction"
	CapabilityProcessInspect         CapabilityKind = "ProcessInspect"
	CapabilityServiceInspect         CapabilityKind = "ServiceInspect"
	CapabilityServiceControl         CapabilityKind = "ServiceControl"
	CapabilityContainerAction        CapabilityKind = "ContainerAction"
	CapabilityNodeAction             CapabilityKind = "NodeAction"
)

var allCapabilities = [...]CapabilityKind{
	CapabilityReadFile,
	CapabilityWriteFile,
	CapabilityCreateFile,
	CapabilityMoveFile,
	CapabilityDeleteFile,
	CapabilityListDirectory,
	CapabilityExecuteApprovedCommand,
	CapabilityGitRead,
	CapabilityGitWrite,
	CapabilityHTTPRequest,
	CapabilityBrowserAction,
	CapabilityProcessInspect,
	CapabilityServiceInspect,
	CapabilityServiceControl,
	CapabilityContainerAction,
	CapabilityNodeAction,
}

// AllCapabilities returns a copy of the protocol's complete capability set.
func AllCapabilities() []CapabilityKind {
	result := make([]CapabilityKind, len(allCapabilities))
	copy(result, allCapabilities[:])
	return result
}

func (kind CapabilityKind) valid() bool {
	for _, candidate := range allCapabilities {
		if kind == candidate {
			return true
		}
	}
	return false
}

// RiskClass is the broker's deterministic minimum consequence class.
type RiskClass string

const (
	RiskReadOnly           RiskClass = "READ_ONLY"
	RiskLowRiskWrite       RiskClass = "LOW_RISK_WRITE"
	RiskReversibleChange   RiskClass = "REVERSIBLE_CHANGE"
	RiskPrivilegedChange   RiskClass = "PRIVILEGED_CHANGE"
	RiskDestructive        RiskClass = "DESTRUCTIVE"
	RiskExternalSideEffect RiskClass = "EXTERNAL_SIDE_EFFECT"
)

// Permission is a stable permission evaluated by the platform and broker.
type Permission string

const (
	PermissionFilesystemRead   Permission = "filesystem_read"
	PermissionFilesystemWrite  Permission = "filesystem_write"
	PermissionFilesystemDelete Permission = "filesystem_delete"
	PermissionCommandExecute   Permission = "command_execute_approved"
	PermissionGitRead          Permission = "git_read"
	PermissionGitWrite         Permission = "git_write"
	PermissionNetworkHTTP      Permission = "network_http"
	PermissionBrowserControl   Permission = "browser_control"
	PermissionProcessInspect   Permission = "process_inspect"
	PermissionServiceInspect   Permission = "service_inspect"
	PermissionServiceControl   Permission = "service_control"
	PermissionContainerControl Permission = "container_control"
	PermissionNodeControl      Permission = "node_control"
)

// ApprovalType is a signed approval strength recognized by the broker.
type ApprovalType string

const (
	ApprovalExplicitUser  ApprovalType = "EXPLICIT_USER"
	ApprovalElevatedUser  ApprovalType = "ELEVATED_USER"
	ApprovalAdministrator ApprovalType = "ADMINISTRATOR"
)

// ApprovalRequirement states whether deterministic policy alone may authorize
// a request or whether a signed short-lived token is mandatory.
type ApprovalRequirement string

const (
	ApprovalPolicyOnly  ApprovalRequirement = "policy_only"
	ApprovalSignedToken ApprovalRequirement = "signed_token"
)

// ApprovalPolicy mirrors the broker-owned approval policy declaration. Clients
// may inspect it, but cannot submit or weaken it in an ActionRequest.
type ApprovalPolicy struct {
	Requirement       ApprovalRequirement `json:"requirement"`
	AcceptedTypes     []ApprovalType      `json:"accepted_types"`
	MaximumTTLSeconds uint64              `json:"maximum_ttl_seconds"`
}

type FilesystemAccess string

const (
	FilesystemAccessNone                       FilesystemAccess = "none"
	FilesystemAccessRead                       FilesystemAccess = "read"
	FilesystemAccessWrite                      FilesystemAccess = "write"
	FilesystemAccessDelete                     FilesystemAccess = "delete"
	FilesystemAccessRepositoryRead             FilesystemAccess = "repository_read"
	FilesystemAccessRepositoryWrite            FilesystemAccess = "repository_write"
	FilesystemAccessControlledWorkingDirectory FilesystemAccess = "controlled_working_directory"
)

type FilesystemScope struct {
	Access                FilesystemAccess `json:"access"`
	RootsFromBrokerPolicy bool             `json:"roots_from_broker_policy"`
	FollowSymlinks        bool             `json:"follow_symlinks"`
	AllowSpecialFiles     bool             `json:"allow_special_files"`
	AllowSecretPaths      bool             `json:"allow_secret_paths"`
}

type NetworkAccess string

const (
	NetworkAccessNone                  NetworkAccess = "none"
	NetworkAccessPolicyFilteredHTTP    NetworkAccess = "policy_filtered_http"
	NetworkAccessPolicyFilteredBrowser NetworkAccess = "policy_filtered_browser"
	NetworkAccessNodeControlPlane      NetworkAccess = "node_control_plane"
)

type NetworkScope struct {
	Access                    NetworkAccess `json:"access"`
	DestinationPolicyRequired bool          `json:"destination_policy_required"`
	RedirectsRevalidated      bool          `json:"redirects_revalidated"`
	DNSAnswersRevalidated     bool          `json:"dns_answers_revalidated"`
	LocalhostAllowed          bool          `json:"localhost_allowed"`
	PrivateNetworksAllowed    bool          `json:"private_networks_allowed"`
	MetadataEndpointsAllowed  bool          `json:"metadata_endpoints_allowed"`
}

type TimeoutPolicy struct {
	DefaultMilliseconds uint64 `json:"default_milliseconds"`
	MaximumMilliseconds uint64 `json:"maximum_milliseconds"`
}

type ResourceLimits struct {
	MaximumInputBytes  uint64 `json:"maximum_input_bytes"`
	MaximumOutputBytes uint64 `json:"maximum_output_bytes"`
	MaximumMemoryBytes uint64 `json:"maximum_memory_bytes"`
	MaximumProcesses   uint32 `json:"maximum_processes"`
	MaximumOpenFiles   uint32 `json:"maximum_open_files"`
}

type AuditBehavior struct {
	RecordStartAndFinish      bool `json:"record_start_and_finish"`
	HashValidatedArguments    bool `json:"hash_validated_arguments"`
	HashOutput                bool `json:"hash_output"`
	RecordChangedFiles        bool `json:"record_changed_files"`
	RecordNetworkDestinations bool `json:"record_network_destinations"`
	RedactSecrets             bool `json:"redact_secrets"`
}

// Reversibility describes what recovery evidence a capability can support. It
// is not a promise that a particular invocation can be rolled back.
type Reversibility string

const (
	ReversibilityNotReversible                 Reversibility = "not_reversible"
	ReversibilityAtomicWithPrechangeDigest     Reversibility = "atomic_replacement_with_prechange_digest"
	ReversibilityBackupMetadataAndAtomicRename Reversibility = "backup_metadata_and_atomic_rename"
	ReversibilityGitHistory                    Reversibility = "git_history"
	ReversibilityRuntimeDependent              Reversibility = "runtime_dependent"
)

// CapabilityMetadata summarizes the protocol's baseline policy declaration.
// It is informational client metadata only. The broker's current configuration
// remains authoritative and may strengthen every value.
type CapabilityMetadata struct {
	Permission    Permission
	Risk          RiskClass
	Approval      ApprovalPolicy
	Reversibility Reversibility
}

// CapabilityDescriptor is the complete declarative broker metadata shape.
// InputSchema and OutputSchema are JSON Schema documents generated by Rust.
type CapabilityDescriptor struct {
	Kind               CapabilityKind  `json:"kind"`
	InputSchema        json.RawMessage `json:"input_schema"`
	OutputSchema       json.RawMessage `json:"output_schema"`
	PermissionRequired Permission      `json:"permission_required"`
	ApprovalPolicy     ApprovalPolicy  `json:"approval_policy"`
	FilesystemScope    FilesystemScope `json:"filesystem_scope"`
	NetworkScope       NetworkScope    `json:"network_scope"`
	Timeout            TimeoutPolicy   `json:"timeout"`
	ResourceLimits     ResourceLimits  `json:"resource_limits"`
	AuditBehavior      AuditBehavior   `json:"audit_behavior"`
	Reversibility      Reversibility   `json:"reversibility"`
	RiskClass          RiskClass       `json:"risk_class"`
}

// Metadata returns the protocol baseline for a known capability.
func Metadata(kind CapabilityKind) (CapabilityMetadata, bool) {
	explicit := []ApprovalType{ApprovalExplicitUser, ApprovalElevatedUser, ApprovalAdministrator}
	elevated := []ApprovalType{ApprovalElevatedUser, ApprovalAdministrator}
	administrator := []ApprovalType{ApprovalAdministrator}
	policyOnly := func(permission Permission) CapabilityMetadata {
		return CapabilityMetadata{
			Permission: permission,
			Risk:       RiskReadOnly,
			Approval: ApprovalPolicy{
				Requirement:       ApprovalPolicyOnly,
				AcceptedTypes:     []ApprovalType{},
				MaximumTTLSeconds: 300,
			},
			Reversibility: ReversibilityNotReversible,
		}
	}
	signed := func(permission Permission, risk RiskClass, approvals []ApprovalType, reversibility Reversibility) CapabilityMetadata {
		return CapabilityMetadata{
			Permission: permission,
			Risk:       risk,
			Approval: ApprovalPolicy{
				Requirement:       ApprovalSignedToken,
				AcceptedTypes:     append([]ApprovalType(nil), approvals...),
				MaximumTTLSeconds: 300,
			},
			Reversibility: reversibility,
		}
	}

	switch kind {
	case CapabilityReadFile, CapabilityListDirectory:
		return policyOnly(PermissionFilesystemRead), true
	case CapabilityWriteFile:
		return signed(PermissionFilesystemWrite, RiskReversibleChange, explicit, ReversibilityAtomicWithPrechangeDigest), true
	case CapabilityCreateFile:
		return signed(PermissionFilesystemWrite, RiskLowRiskWrite, explicit, ReversibilityBackupMetadataAndAtomicRename), true
	case CapabilityMoveFile:
		return signed(PermissionFilesystemWrite, RiskReversibleChange, explicit, ReversibilityBackupMetadataAndAtomicRename), true
	case CapabilityDeleteFile:
		return signed(PermissionFilesystemDelete, RiskDestructive, elevated, ReversibilityRuntimeDependent), true
	case CapabilityExecuteApprovedCommand:
		return signed(PermissionCommandExecute, RiskPrivilegedChange, elevated, ReversibilityRuntimeDependent), true
	case CapabilityGitRead:
		return policyOnly(PermissionGitRead), true
	case CapabilityGitWrite:
		return signed(PermissionGitWrite, RiskReversibleChange, explicit, ReversibilityGitHistory), true
	case CapabilityHTTPRequest:
		return signed(PermissionNetworkHTTP, RiskExternalSideEffect, explicit, ReversibilityNotReversible), true
	case CapabilityBrowserAction:
		return signed(PermissionBrowserControl, RiskExternalSideEffect, explicit, ReversibilityNotReversible), true
	case CapabilityProcessInspect:
		return policyOnly(PermissionProcessInspect), true
	case CapabilityServiceInspect:
		return policyOnly(PermissionServiceInspect), true
	case CapabilityServiceControl:
		return signed(PermissionServiceControl, RiskPrivilegedChange, elevated, ReversibilityRuntimeDependent), true
	case CapabilityContainerAction:
		return signed(PermissionContainerControl, RiskPrivilegedChange, elevated, ReversibilityRuntimeDependent), true
	case CapabilityNodeAction:
		return signed(PermissionNodeControl, RiskPrivilegedChange, administrator, ReversibilityRuntimeDependent), true
	default:
		return CapabilityMetadata{}, false
	}
}
