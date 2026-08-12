package actionbroker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// RootedPath is resolved beneath a broker-configured root. RootID is a stable
// policy identifier; RelativePath never selects an ambient absolute root.
type RootedPath struct {
	RootID       string `json:"root_id"`
	RelativePath string `json:"relative_path"`
}

type ReadFileInput struct {
	Path         RootedPath `json:"path"`
	MaximumBytes uint64     `json:"maximum_bytes"`
}

type ReadFileOutput struct {
	Path          RootedPath `json:"path"`
	ContentBase64 string     `json:"content_base64"`
	BytesRead     uint64     `json:"bytes_read"`
	SHA256        string     `json:"sha256"`
	Truncated     bool       `json:"truncated"`
}

type WriteFileInput struct {
	Path                    RootedPath `json:"path"`
	ContentBase64           string     `json:"content_base64"`
	ExpectedPrechangeSHA256 *string    `json:"expected_prechange_sha256"`
	CreateIfMissing         bool       `json:"create_if_missing"`
}

type CreateFileInput struct {
	Path          RootedPath `json:"path"`
	ContentBase64 string     `json:"content_base64"`
	FailIfExists  bool       `json:"fail_if_exists"`
}

type FileMutationOutput struct {
	Path             RootedPath `json:"path"`
	PreviousSHA256   *string    `json:"previous_sha256"`
	CurrentSHA256    string     `json:"current_sha256"`
	BytesWritten     uint64     `json:"bytes_written"`
	BackupReference  *string    `json:"backup_reference"`
	UsedAtomicRename bool       `json:"used_atomic_rename"`
}

type MoveFileInput struct {
	Source               RootedPath `json:"source"`
	Destination          RootedPath `json:"destination"`
	ReplaceExisting      bool       `json:"replace_existing"`
	ExpectedSourceSHA256 *string    `json:"expected_source_sha256"`
}

type MoveFileOutput struct {
	Source                  RootedPath `json:"source"`
	Destination             RootedPath `json:"destination"`
	MovedSHA256             string     `json:"moved_sha256"`
	ReplacedSHA256          *string    `json:"replaced_sha256"`
	ReplacedBackupReference *string    `json:"replaced_backup_reference"`
	UsedAtomicRename        bool       `json:"used_atomic_rename"`
}

type DeleteFileInput struct {
	Path               RootedPath `json:"path"`
	ExpectedSHA256     *string    `json:"expected_sha256"`
	RequireRegularFile bool       `json:"require_regular_file"`
}

type DeleteFileOutput struct {
	Path            RootedPath `json:"path"`
	PreviousSHA256  string     `json:"previous_sha256"`
	BackupReference *string    `json:"backup_reference"`
	Removed         bool       `json:"removed"`
}

type ListDirectoryInput struct {
	Path           RootedPath `json:"path"`
	MaximumEntries uint32     `json:"maximum_entries"`
	IncludeHidden  bool       `json:"include_hidden"`
}

type DirectoryEntryKind string

const (
	DirectoryEntryFile      DirectoryEntryKind = "file"
	DirectoryEntryDirectory DirectoryEntryKind = "directory"
	DirectoryEntrySymlink   DirectoryEntryKind = "symlink"
	DirectoryEntryOther     DirectoryEntryKind = "other"
)

type DirectoryEntry struct {
	Name    string             `json:"name"`
	Kind    DirectoryEntryKind `json:"kind"`
	ByteLen *uint64            `json:"byte_len"`
}

type ListDirectoryOutput struct {
	Path      RootedPath       `json:"path"`
	Entries   []DirectoryEntry `json:"entries"`
	Truncated bool             `json:"truncated"`
}

// ExecuteApprovedCommandInput selects a broker-configured program. Program is
// not a shell command. Arguments are passed directly and Environment is the
// complete requested environment, subject to the broker's explicit allowlist.
type ExecuteApprovedCommandInput struct {
	ProgramID           string            `json:"program_id"`
	Arguments           []string          `json:"arguments"`
	WorkingDirectory    RootedPath        `json:"working_directory"`
	Environment         map[string]string `json:"environment"`
	TimeoutMilliseconds *uint64           `json:"timeout_milliseconds"`
}

type ExecuteApprovedCommandOutput struct {
	ExitCode        *int32 `json:"exit_code"`
	StdoutBase64    string `json:"stdout_base64"`
	StderrBase64    string `json:"stderr_base64"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	TimedOut        bool   `json:"timed_out"`
}

type GitReadOperationKind string

const (
	GitReadStatus          GitReadOperationKind = "status"
	GitReadDiff            GitReadOperationKind = "diff"
	GitReadLog             GitReadOperationKind = "log"
	GitReadShow            GitReadOperationKind = "show"
	GitReadResolveRevision GitReadOperationKind = "resolve_revision"
)

// GitReadOperation is closed: create it using the constructors below.
type GitReadOperation struct {
	kind           GitReadOperationKind
	revision       *string
	maximumEntries uint32
	objectID       string
}

func NewGitStatusOperation() GitReadOperation {
	return GitReadOperation{kind: GitReadStatus}
}

func NewGitDiffOperation(revision *string) GitReadOperation {
	if revision != nil {
		copyOfRevision := *revision
		revision = &copyOfRevision
	}
	return GitReadOperation{kind: GitReadDiff, revision: revision}
}

func NewGitLogOperation(maximumEntries uint32) GitReadOperation {
	return GitReadOperation{kind: GitReadLog, maximumEntries: maximumEntries}
}

func NewGitShowOperation(objectID string) GitReadOperation {
	return GitReadOperation{kind: GitReadShow, objectID: objectID}
}

func NewGitResolveRevisionOperation(revision string) GitReadOperation {
	return GitReadOperation{kind: GitReadResolveRevision, revision: &revision}
}

func (operation GitReadOperation) Kind() GitReadOperationKind { return operation.kind }

func (operation GitReadOperation) MarshalJSON() ([]byte, error) {
	switch operation.kind {
	case GitReadStatus:
		return json.Marshal(struct {
			Operation GitReadOperationKind `json:"operation"`
		}{operation.kind})
	case GitReadDiff:
		return json.Marshal(struct {
			Operation GitReadOperationKind `json:"operation"`
			Revision  *string              `json:"revision"`
		}{operation.kind, operation.revision})
	case GitReadLog:
		return json.Marshal(struct {
			Operation      GitReadOperationKind `json:"operation"`
			MaximumEntries uint32               `json:"maximum_entries"`
		}{operation.kind, operation.maximumEntries})
	case GitReadShow:
		return json.Marshal(struct {
			Operation GitReadOperationKind `json:"operation"`
			ObjectID  string               `json:"object_id"`
		}{operation.kind, operation.objectID})
	case GitReadResolveRevision:
		if operation.revision == nil {
			return nil, fmt.Errorf("resolve_revision requires a revision")
		}
		return json.Marshal(struct {
			Operation GitReadOperationKind `json:"operation"`
			Revision  string               `json:"revision"`
		}{operation.kind, *operation.revision})
	default:
		return nil, fmt.Errorf("unknown Git read operation %q", operation.kind)
	}
}

func (operation *GitReadOperation) UnmarshalJSON(data []byte) error {
	if err := requireTaggedOperationFields(data, map[string][]string{
		string(GitReadStatus):          {},
		string(GitReadDiff):            {},
		string(GitReadLog):             {"maximum_entries"},
		string(GitReadShow):            {"object_id"},
		string(GitReadResolveRevision): {"revision"},
	}); err != nil {
		return err
	}
	var tag struct {
		Operation GitReadOperationKind `json:"operation"`
	}
	if err := decodeStrict(data, &tag); err != nil {
		// The tag pass must tolerate variant fields; decode it non-strictly.
		if err := json.Unmarshal(data, &tag); err != nil {
			return err
		}
	}
	switch tag.Operation {
	case GitReadStatus:
		var value struct {
			Operation GitReadOperationKind `json:"operation"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewGitStatusOperation()
	case GitReadDiff:
		var value struct {
			Operation GitReadOperationKind `json:"operation"`
			Revision  *string              `json:"revision"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewGitDiffOperation(value.Revision)
	case GitReadLog:
		var value struct {
			Operation      GitReadOperationKind `json:"operation"`
			MaximumEntries uint32               `json:"maximum_entries"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewGitLogOperation(value.MaximumEntries)
	case GitReadShow:
		var value struct {
			Operation GitReadOperationKind `json:"operation"`
			ObjectID  string               `json:"object_id"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewGitShowOperation(value.ObjectID)
	case GitReadResolveRevision:
		var value struct {
			Operation GitReadOperationKind `json:"operation"`
			Revision  string               `json:"revision"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewGitResolveRevisionOperation(value.Revision)
	default:
		return fmt.Errorf("unknown Git read operation %q", tag.Operation)
	}
	return nil
}

type GitReadInput struct {
	RepositoryPath RootedPath       `json:"repository_path"`
	Operation      GitReadOperation `json:"operation"`
}

type GitReadOutput struct {
	RepositoryPath   RootedPath `json:"repository_path"`
	TextBase64       string     `json:"text_base64"`
	Truncated        bool       `json:"truncated"`
	ResolvedObjectID *string    `json:"resolved_object_id"`
}

type GitWriteOperationKind string

const (
	GitWriteAddPaths     GitWriteOperationKind = "add_paths"
	GitWriteCommit       GitWriteOperationKind = "commit"
	GitWriteCreateBranch GitWriteOperationKind = "create_branch"
	GitWriteApplyPatch   GitWriteOperationKind = "apply_patch"
)

type GitWriteOperation struct {
	kind        GitWriteOperationKind
	paths       []string
	message     string
	name        string
	startPoint  string
	patchBase64 string
}

func NewGitAddPathsOperation(paths []string) GitWriteOperation {
	if paths == nil {
		paths = []string{}
	}
	return GitWriteOperation{kind: GitWriteAddPaths, paths: append([]string(nil), paths...)}
}

func NewGitCommitOperation(message string) GitWriteOperation {
	return GitWriteOperation{kind: GitWriteCommit, message: message}
}

func NewGitCreateBranchOperation(name, startPoint string) GitWriteOperation {
	return GitWriteOperation{kind: GitWriteCreateBranch, name: name, startPoint: startPoint}
}

func NewGitApplyPatchOperation(patchBase64 string) GitWriteOperation {
	return GitWriteOperation{kind: GitWriteApplyPatch, patchBase64: patchBase64}
}

func (operation GitWriteOperation) Kind() GitWriteOperationKind { return operation.kind }

func (operation GitWriteOperation) MarshalJSON() ([]byte, error) {
	switch operation.kind {
	case GitWriteAddPaths:
		return json.Marshal(struct {
			Operation GitWriteOperationKind `json:"operation"`
			Paths     []string              `json:"paths"`
		}{operation.kind, operation.paths})
	case GitWriteCommit:
		return json.Marshal(struct {
			Operation GitWriteOperationKind `json:"operation"`
			Message   string                `json:"message"`
		}{operation.kind, operation.message})
	case GitWriteCreateBranch:
		return json.Marshal(struct {
			Operation  GitWriteOperationKind `json:"operation"`
			Name       string                `json:"name"`
			StartPoint string                `json:"start_point"`
		}{operation.kind, operation.name, operation.startPoint})
	case GitWriteApplyPatch:
		return json.Marshal(struct {
			Operation   GitWriteOperationKind `json:"operation"`
			PatchBase64 string                `json:"patch_base64"`
		}{operation.kind, operation.patchBase64})
	default:
		return nil, fmt.Errorf("unknown Git write operation %q", operation.kind)
	}
}

func (operation *GitWriteOperation) UnmarshalJSON(data []byte) error {
	if err := requireTaggedOperationFields(data, map[string][]string{
		string(GitWriteAddPaths):     {"paths"},
		string(GitWriteCommit):       {"message"},
		string(GitWriteCreateBranch): {"name", "start_point"},
		string(GitWriteApplyPatch):   {"patch_base64"},
	}); err != nil {
		return err
	}
	var tag struct {
		Operation GitWriteOperationKind `json:"operation"`
	}
	if err := json.Unmarshal(data, &tag); err != nil {
		return err
	}
	switch tag.Operation {
	case GitWriteAddPaths:
		var value struct {
			Operation GitWriteOperationKind `json:"operation"`
			Paths     []string              `json:"paths"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewGitAddPathsOperation(value.Paths)
	case GitWriteCommit:
		var value struct {
			Operation GitWriteOperationKind `json:"operation"`
			Message   string                `json:"message"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewGitCommitOperation(value.Message)
	case GitWriteCreateBranch:
		var value struct {
			Operation  GitWriteOperationKind `json:"operation"`
			Name       string                `json:"name"`
			StartPoint string                `json:"start_point"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewGitCreateBranchOperation(value.Name, value.StartPoint)
	case GitWriteApplyPatch:
		var value struct {
			Operation   GitWriteOperationKind `json:"operation"`
			PatchBase64 string                `json:"patch_base64"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewGitApplyPatchOperation(value.PatchBase64)
	default:
		return fmt.Errorf("unknown Git write operation %q", tag.Operation)
	}
	return nil
}

type GitWriteInput struct {
	RepositoryPath RootedPath        `json:"repository_path"`
	Operation      GitWriteOperation `json:"operation"`
	ExpectedHead   *string           `json:"expected_head"`
}

type GitWriteOutput struct {
	RepositoryPath RootedPath `json:"repository_path"`
	PreviousHead   *string    `json:"previous_head"`
	CurrentHead    *string    `json:"current_head"`
	ChangedPaths   []string   `json:"changed_paths"`
}

type HTTPMethod string

const (
	HTTPGet    HTTPMethod = "GET"
	HTTPHead   HTTPMethod = "HEAD"
	HTTPPost   HTTPMethod = "POST"
	HTTPPut    HTTPMethod = "PUT"
	HTTPPatch  HTTPMethod = "PATCH"
	HTTPDelete HTTPMethod = "DELETE"
)

type HTTPRequestInput struct {
	Method               HTTPMethod        `json:"method"`
	URL                  string            `json:"url"`
	Headers              map[string]string `json:"headers"`
	BodyBase64           *string           `json:"body_base64"`
	MaximumResponseBytes uint64            `json:"maximum_response_bytes"`
	TimeoutMilliseconds  *uint64           `json:"timeout_milliseconds"`
}

type HTTPRequestOutput struct {
	FinalURL              string            `json:"final_url"`
	StatusCode            uint16            `json:"status_code"`
	Headers               map[string]string `json:"headers"`
	BodyBase64            string            `json:"body_base64"`
	Truncated             bool              `json:"truncated"`
	ContactedDestinations []string          `json:"contacted_destinations"`
}

type BrowserOperationKind string

const (
	BrowserNavigate   BrowserOperationKind = "navigate"
	BrowserClick      BrowserOperationKind = "click"
	BrowserTypeText   BrowserOperationKind = "type_text"
	BrowserReadText   BrowserOperationKind = "read_text"
	BrowserScreenshot BrowserOperationKind = "screenshot"
)

type BrowserOperation struct {
	kind     BrowserOperationKind
	url      string
	selector string
	text     string
}

func NewBrowserNavigateOperation(url string) BrowserOperation {
	return BrowserOperation{kind: BrowserNavigate, url: url}
}

func NewBrowserClickOperation(selector string) BrowserOperation {
	return BrowserOperation{kind: BrowserClick, selector: selector}
}

func NewBrowserTypeTextOperation(selector, text string) BrowserOperation {
	return BrowserOperation{kind: BrowserTypeText, selector: selector, text: text}
}

func NewBrowserReadTextOperation(selector string) BrowserOperation {
	return BrowserOperation{kind: BrowserReadText, selector: selector}
}

func NewBrowserScreenshotOperation() BrowserOperation {
	return BrowserOperation{kind: BrowserScreenshot}
}

func (operation BrowserOperation) Kind() BrowserOperationKind { return operation.kind }

func (operation BrowserOperation) MarshalJSON() ([]byte, error) {
	switch operation.kind {
	case BrowserNavigate:
		return json.Marshal(struct {
			Operation BrowserOperationKind `json:"operation"`
			URL       string               `json:"url"`
		}{operation.kind, operation.url})
	case BrowserClick, BrowserReadText:
		return json.Marshal(struct {
			Operation BrowserOperationKind `json:"operation"`
			Selector  string               `json:"selector"`
		}{operation.kind, operation.selector})
	case BrowserTypeText:
		return json.Marshal(struct {
			Operation BrowserOperationKind `json:"operation"`
			Selector  string               `json:"selector"`
			Text      string               `json:"text"`
		}{operation.kind, operation.selector, operation.text})
	case BrowserScreenshot:
		return json.Marshal(struct {
			Operation BrowserOperationKind `json:"operation"`
		}{operation.kind})
	default:
		return nil, fmt.Errorf("unknown browser operation %q", operation.kind)
	}
}

func (operation *BrowserOperation) UnmarshalJSON(data []byte) error {
	if err := requireTaggedOperationFields(data, map[string][]string{
		string(BrowserNavigate):   {"url"},
		string(BrowserClick):      {"selector"},
		string(BrowserTypeText):   {"selector", "text"},
		string(BrowserReadText):   {"selector"},
		string(BrowserScreenshot): {},
	}); err != nil {
		return err
	}
	var tag struct {
		Operation BrowserOperationKind `json:"operation"`
	}
	if err := json.Unmarshal(data, &tag); err != nil {
		return err
	}
	switch tag.Operation {
	case BrowserNavigate:
		var value struct {
			Operation BrowserOperationKind `json:"operation"`
			URL       string               `json:"url"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewBrowserNavigateOperation(value.URL)
	case BrowserClick, BrowserReadText:
		var value struct {
			Operation BrowserOperationKind `json:"operation"`
			Selector  string               `json:"selector"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		if tag.Operation == BrowserClick {
			*operation = NewBrowserClickOperation(value.Selector)
		} else {
			*operation = NewBrowserReadTextOperation(value.Selector)
		}
	case BrowserTypeText:
		var value struct {
			Operation BrowserOperationKind `json:"operation"`
			Selector  string               `json:"selector"`
			Text      string               `json:"text"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewBrowserTypeTextOperation(value.Selector, value.Text)
	case BrowserScreenshot:
		var value struct {
			Operation BrowserOperationKind `json:"operation"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewBrowserScreenshotOperation()
	default:
		return fmt.Errorf("unknown browser operation %q", tag.Operation)
	}
	return nil
}

type BrowserActionInput struct {
	BrowserSessionID    string           `json:"browser_session_id"`
	Operation           BrowserOperation `json:"operation"`
	TimeoutMilliseconds *uint64          `json:"timeout_milliseconds"`
}

type BrowserActionOutput struct {
	BrowserSessionID      string   `json:"browser_session_id"`
	CurrentURL            *string  `json:"current_url"`
	Text                  *string  `json:"text"`
	ScreenshotBase64      *string  `json:"screenshot_base64"`
	ContactedDestinations []string `json:"contacted_destinations"`
}

type ProcessInspectOperationKind string

const (
	ProcessInspectList       ProcessInspectOperationKind = "list"
	ProcessInspectInspectPID ProcessInspectOperationKind = "inspect_pid"
)

type ProcessInspectOperation struct {
	kind           ProcessInspectOperationKind
	maximumEntries uint32
	pid            uint32
}

func NewProcessListOperation(maximumEntries uint32) ProcessInspectOperation {
	return ProcessInspectOperation{kind: ProcessInspectList, maximumEntries: maximumEntries}
}

func NewProcessInspectPIDOperation(pid uint32) ProcessInspectOperation {
	return ProcessInspectOperation{kind: ProcessInspectInspectPID, pid: pid}
}

func (operation ProcessInspectOperation) Kind() ProcessInspectOperationKind { return operation.kind }

func (operation ProcessInspectOperation) MarshalJSON() ([]byte, error) {
	switch operation.kind {
	case ProcessInspectList:
		return json.Marshal(struct {
			Operation      ProcessInspectOperationKind `json:"operation"`
			MaximumEntries uint32                      `json:"maximum_entries"`
		}{operation.kind, operation.maximumEntries})
	case ProcessInspectInspectPID:
		return json.Marshal(struct {
			Operation ProcessInspectOperationKind `json:"operation"`
			PID       uint32                      `json:"pid"`
		}{operation.kind, operation.pid})
	default:
		return nil, fmt.Errorf("unknown process inspect operation %q", operation.kind)
	}
}

func (operation *ProcessInspectOperation) UnmarshalJSON(data []byte) error {
	if err := requireTaggedOperationFields(data, map[string][]string{
		string(ProcessInspectList):       {"maximum_entries"},
		string(ProcessInspectInspectPID): {"pid"},
	}); err != nil {
		return err
	}
	var tag struct {
		Operation ProcessInspectOperationKind `json:"operation"`
	}
	if err := json.Unmarshal(data, &tag); err != nil {
		return err
	}
	switch tag.Operation {
	case ProcessInspectList:
		var value struct {
			Operation      ProcessInspectOperationKind `json:"operation"`
			MaximumEntries uint32                      `json:"maximum_entries"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewProcessListOperation(value.MaximumEntries)
	case ProcessInspectInspectPID:
		var value struct {
			Operation ProcessInspectOperationKind `json:"operation"`
			PID       uint32                      `json:"pid"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*operation = NewProcessInspectPIDOperation(value.PID)
	default:
		return fmt.Errorf("unknown process inspect operation %q", tag.Operation)
	}
	return nil
}

type ProcessInspectInput struct {
	Operation ProcessInspectOperation `json:"operation"`
}

type ProcessInformation struct {
	PID               uint32   `json:"pid"`
	ParentPID         *uint32  `json:"parent_pid"`
	Executable        string   `json:"executable"`
	ArgumentsRedacted []string `json:"arguments_redacted"`
	UserID            *uint32  `json:"user_id"`
}

type ProcessInspectOutput struct {
	Processes []ProcessInformation `json:"processes"`
	Truncated bool                 `json:"truncated"`
}

type ServiceInspectInput struct {
	ServiceName string `json:"service_name"`
}

type ServiceInspectOutput struct {
	ServiceName string  `json:"service_name"`
	State       string  `json:"state"`
	Substate    *string `json:"substate"`
	ProcessID   *uint32 `json:"process_id"`
}

type ServiceControlOperation string

const (
	ServiceStart   ServiceControlOperation = "start"
	ServiceStop    ServiceControlOperation = "stop"
	ServiceRestart ServiceControlOperation = "restart"
	ServiceReload  ServiceControlOperation = "reload"
)

type ServiceControlInput struct {
	ServiceName string                  `json:"service_name"`
	Operation   ServiceControlOperation `json:"operation"`
}

type ServiceControlOutput struct {
	ServiceName   string `json:"service_name"`
	PreviousState string `json:"previous_state"`
	CurrentState  string `json:"current_state"`
}

type ContainerRuntime string

const (
	ContainerDocker ContainerRuntime = "docker"
	ContainerPodman ContainerRuntime = "podman"
)

type ContainerOperation string

const (
	ContainerInspect ContainerOperation = "inspect"
	ContainerStart   ContainerOperation = "start"
	ContainerStop    ContainerOperation = "stop"
	ContainerRestart ContainerOperation = "restart"
	ContainerPause   ContainerOperation = "pause"
	ContainerUnpause ContainerOperation = "unpause"
)

type ContainerActionInput struct {
	Runtime             ContainerRuntime   `json:"runtime"`
	ContainerID         string             `json:"container_id"`
	Operation           ContainerOperation `json:"operation"`
	TimeoutMilliseconds *uint64            `json:"timeout_milliseconds"`
}

type ContainerActionOutput struct {
	ContainerID   string  `json:"container_id"`
	PreviousState *string `json:"previous_state"`
	CurrentState  string  `json:"current_state"`
}

type NodeOperation string

const (
	NodeInspectStatus  NodeOperation = "inspect_status"
	NodeDrain          NodeOperation = "drain"
	NodeResume         NodeOperation = "resume"
	NodeRestartRuntime NodeOperation = "restart_runtime"
)

type NodeActionInput struct {
	NodeID    string        `json:"node_id"`
	Operation NodeOperation `json:"operation"`
}

type NodeActionOutput struct {
	NodeID        string  `json:"node_id"`
	PreviousState *string `json:"previous_state"`
	CurrentState  string  `json:"current_state"`
}

// CapabilityAction is a closed tagged union. Its value can only be created by
// a typed constructor or by decoding a known protocol variant.
type CapabilityAction struct {
	capability CapabilityKind
	arguments  any
}

func NewReadFileAction(input ReadFileInput) CapabilityAction {
	return newAction(CapabilityReadFile, input)
}
func NewWriteFileAction(input WriteFileInput) CapabilityAction {
	return newAction(CapabilityWriteFile, input)
}
func NewCreateFileAction(input CreateFileInput) CapabilityAction {
	return newAction(CapabilityCreateFile, input)
}
func NewMoveFileAction(input MoveFileInput) CapabilityAction {
	return newAction(CapabilityMoveFile, input)
}
func NewDeleteFileAction(input DeleteFileInput) CapabilityAction {
	return newAction(CapabilityDeleteFile, input)
}
func NewListDirectoryAction(input ListDirectoryInput) CapabilityAction {
	return newAction(CapabilityListDirectory, input)
}
func NewExecuteApprovedCommandAction(input ExecuteApprovedCommandInput) CapabilityAction {
	if input.Arguments == nil {
		input.Arguments = []string{}
	} else {
		input.Arguments = append([]string(nil), input.Arguments...)
	}
	if input.Environment == nil {
		input.Environment = map[string]string{}
	} else {
		input.Environment = cloneStringMap(input.Environment)
	}
	return newAction(CapabilityExecuteApprovedCommand, input)
}
func NewGitReadAction(input GitReadInput) CapabilityAction {
	return newAction(CapabilityGitRead, input)
}
func NewGitWriteAction(input GitWriteInput) CapabilityAction {
	return newAction(CapabilityGitWrite, input)
}
func NewHTTPRequestAction(input HTTPRequestInput) CapabilityAction {
	if input.Headers == nil {
		input.Headers = map[string]string{}
	} else {
		input.Headers = cloneStringMap(input.Headers)
	}
	if input.BodyBase64 != nil {
		body := *input.BodyBase64
		input.BodyBase64 = &body
	}
	return newAction(CapabilityHTTPRequest, input)
}
func NewBrowserAction(input BrowserActionInput) CapabilityAction {
	return newAction(CapabilityBrowserAction, input)
}
func NewProcessInspectAction(input ProcessInspectInput) CapabilityAction {
	return newAction(CapabilityProcessInspect, input)
}
func NewServiceInspectAction(input ServiceInspectInput) CapabilityAction {
	return newAction(CapabilityServiceInspect, input)
}
func NewServiceControlAction(input ServiceControlInput) CapabilityAction {
	return newAction(CapabilityServiceControl, input)
}
func NewContainerAction(input ContainerActionInput) CapabilityAction {
	return newAction(CapabilityContainerAction, input)
}
func NewNodeAction(input NodeActionInput) CapabilityAction {
	return newAction(CapabilityNodeAction, input)
}

func newAction(capability CapabilityKind, arguments any) CapabilityAction {
	return CapabilityAction{capability: capability, arguments: cloneCapabilityArguments(arguments)}
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (action CapabilityAction) Capability() CapabilityKind { return action.capability }

// Arguments returns a detached capability-specific input value. Its concrete
// type is the type accepted by the constructor used to create the action.
func (action CapabilityAction) Arguments() any { return cloneCapabilityArguments(action.arguments) }

func cloneCapabilityArguments(arguments any) any {
	switch value := arguments.(type) {
	case ExecuteApprovedCommandInput:
		value.Arguments = append([]string(nil), value.Arguments...)
		value.Environment = cloneStringMap(value.Environment)
		if value.TimeoutMilliseconds != nil {
			timeout := *value.TimeoutMilliseconds
			value.TimeoutMilliseconds = &timeout
		}
		return value
	case HTTPRequestInput:
		value.Headers = cloneStringMap(value.Headers)
		if value.BodyBase64 != nil {
			body := *value.BodyBase64
			value.BodyBase64 = &body
		}
		if value.TimeoutMilliseconds != nil {
			timeout := *value.TimeoutMilliseconds
			value.TimeoutMilliseconds = &timeout
		}
		return value
	case GitWriteInput:
		if value.Operation.kind == GitWriteAddPaths {
			value.Operation.paths = append([]string(nil), value.Operation.paths...)
		}
		if value.ExpectedHead != nil {
			head := *value.ExpectedHead
			value.ExpectedHead = &head
		}
		return value
	case GitReadInput:
		if value.Operation.revision != nil {
			revision := *value.Operation.revision
			value.Operation.revision = &revision
		}
		return value
	case WriteFileInput:
		if value.ExpectedPrechangeSHA256 != nil {
			digest := *value.ExpectedPrechangeSHA256
			value.ExpectedPrechangeSHA256 = &digest
		}
		return value
	case MoveFileInput:
		if value.ExpectedSourceSHA256 != nil {
			digest := *value.ExpectedSourceSHA256
			value.ExpectedSourceSHA256 = &digest
		}
		return value
	case DeleteFileInput:
		if value.ExpectedSHA256 != nil {
			digest := *value.ExpectedSHA256
			value.ExpectedSHA256 = &digest
		}
		return value
	case BrowserActionInput:
		if value.TimeoutMilliseconds != nil {
			timeout := *value.TimeoutMilliseconds
			value.TimeoutMilliseconds = &timeout
		}
		return value
	case ContainerActionInput:
		if value.TimeoutMilliseconds != nil {
			timeout := *value.TimeoutMilliseconds
			value.TimeoutMilliseconds = &timeout
		}
		return value
	default:
		return value
	}
}

func (action CapabilityAction) MarshalJSON() ([]byte, error) {
	if err := action.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Capability CapabilityKind `json:"capability"`
		Arguments  any            `json:"arguments"`
	}{action.capability, action.arguments})
}

func (action *CapabilityAction) UnmarshalJSON(data []byte) error {
	var envelope struct {
		Capability *CapabilityKind `json:"capability"`
		Arguments  json.RawMessage `json:"arguments"`
	}
	if err := decodeStrict(data, &envelope); err != nil {
		return err
	}
	if envelope.Capability == nil || envelope.Arguments == nil || bytes.Equal(bytes.TrimSpace(envelope.Arguments), []byte("null")) {
		return fmt.Errorf("capability action is missing a required field")
	}
	arguments, err := decodeCapabilityArguments(*envelope.Capability, envelope.Arguments)
	if err != nil {
		return err
	}
	action.capability = *envelope.Capability
	action.arguments = arguments
	return action.validate()
}

func (action CapabilityAction) validate() error {
	if !action.capability.valid() {
		return fmt.Errorf("unknown capability %q", action.capability)
	}
	if !argumentTypeMatches(action.capability, action.arguments) {
		return fmt.Errorf("arguments do not match capability %q", action.capability)
	}
	return validateCapabilityArguments(action.capability, action.arguments)
}

func decodeCapabilityArguments(kind CapabilityKind, raw json.RawMessage) (any, error) {
	if err := requireCapabilityArgumentFields(kind, raw); err != nil {
		return nil, err
	}
	var destination any
	switch kind {
	case CapabilityReadFile:
		destination = &ReadFileInput{}
	case CapabilityWriteFile:
		destination = &WriteFileInput{}
	case CapabilityCreateFile:
		destination = &CreateFileInput{}
	case CapabilityMoveFile:
		destination = &MoveFileInput{}
	case CapabilityDeleteFile:
		destination = &DeleteFileInput{}
	case CapabilityListDirectory:
		destination = &ListDirectoryInput{}
	case CapabilityExecuteApprovedCommand:
		destination = &ExecuteApprovedCommandInput{}
	case CapabilityGitRead:
		destination = &GitReadInput{}
	case CapabilityGitWrite:
		destination = &GitWriteInput{}
	case CapabilityHTTPRequest:
		destination = &HTTPRequestInput{}
	case CapabilityBrowserAction:
		destination = &BrowserActionInput{}
	case CapabilityProcessInspect:
		destination = &ProcessInspectInput{}
	case CapabilityServiceInspect:
		destination = &ServiceInspectInput{}
	case CapabilityServiceControl:
		destination = &ServiceControlInput{}
	case CapabilityContainerAction:
		destination = &ContainerActionInput{}
	case CapabilityNodeAction:
		destination = &NodeActionInput{}
	default:
		return nil, fmt.Errorf("unknown capability %q", kind)
	}
	if err := decodeStrict(raw, destination); err != nil {
		return nil, err
	}
	return dereferenceCapabilityValue(destination), nil
}

func requireCapabilityArgumentFields(kind CapabilityKind, raw json.RawMessage) error {
	required := map[CapabilityKind][]string{
		CapabilityReadFile:               {"path", "maximum_bytes"},
		CapabilityWriteFile:              {"path", "content_base64", "create_if_missing"},
		CapabilityCreateFile:             {"path", "content_base64", "fail_if_exists"},
		CapabilityMoveFile:               {"source", "destination", "replace_existing"},
		CapabilityDeleteFile:             {"path", "require_regular_file"},
		CapabilityListDirectory:          {"path", "maximum_entries", "include_hidden"},
		CapabilityExecuteApprovedCommand: {"program_id", "arguments", "working_directory", "environment"},
		CapabilityGitRead:                {"repository_path", "operation"},
		CapabilityGitWrite:               {"repository_path", "operation"},
		CapabilityHTTPRequest:            {"method", "url", "headers", "maximum_response_bytes"},
		CapabilityBrowserAction:          {"browser_session_id", "operation"},
		CapabilityProcessInspect:         {"operation"},
		CapabilityServiceInspect:         {"service_name"},
		CapabilityServiceControl:         {"service_name", "operation"},
		CapabilityContainerAction:        {"runtime", "container_id", "operation"},
		CapabilityNodeAction:             {"node_id", "operation"},
	}[kind]
	if required == nil {
		return fmt.Errorf("unknown capability %q", kind)
	}
	fields, err := requireNonNullObjectFields(raw, required...)
	if err != nil {
		return fmt.Errorf("invalid %s arguments: %w", kind, err)
	}
	rootedFields := map[CapabilityKind][]string{
		CapabilityReadFile:               {"path"},
		CapabilityWriteFile:              {"path"},
		CapabilityCreateFile:             {"path"},
		CapabilityMoveFile:               {"source", "destination"},
		CapabilityDeleteFile:             {"path"},
		CapabilityListDirectory:          {"path"},
		CapabilityExecuteApprovedCommand: {"working_directory"},
		CapabilityGitRead:                {"repository_path"},
		CapabilityGitWrite:               {"repository_path"},
	}[kind]
	for _, field := range rootedFields {
		if _, err := requireNonNullObjectFields(fields[field], "root_id", "relative_path"); err != nil {
			return fmt.Errorf("invalid %s arguments field %q: %w", kind, field, err)
		}
	}
	return nil
}

func requireTaggedOperationFields(data []byte, requiredByOperation map[string][]string) error {
	fields, err := requireNonNullObjectFields(data, "operation")
	if err != nil {
		return err
	}
	var operation string
	if err := decodeStrict(fields["operation"], &operation); err != nil {
		return fmt.Errorf("operation tag must be a string: %w", err)
	}
	required, ok := requiredByOperation[operation]
	if !ok {
		return fmt.Errorf("unknown operation %q", operation)
	}
	for _, name := range required {
		value, exists := fields[name]
		if !exists {
			return fmt.Errorf("operation %q is missing required field %q", operation, name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("operation %q field %q cannot be null", operation, name)
		}
	}
	return nil
}

func requireNonNullObjectFields(data []byte, required ...string) (map[string]json.RawMessage, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, fmt.Errorf("object cannot be null")
	}
	var fields map[string]json.RawMessage
	if err := decodeStrict(data, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, fmt.Errorf("value must be an object")
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok {
			return nil, fmt.Errorf("missing required field %q", name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("required field %q cannot be null", name)
		}
	}
	return fields, nil
}

func dereferenceCapabilityValue(value any) any {
	switch value := value.(type) {
	case *ReadFileInput:
		return *value
	case *WriteFileInput:
		return *value
	case *CreateFileInput:
		return *value
	case *MoveFileInput:
		return *value
	case *DeleteFileInput:
		return *value
	case *ListDirectoryInput:
		return *value
	case *ExecuteApprovedCommandInput:
		return *value
	case *GitReadInput:
		return *value
	case *GitWriteInput:
		return *value
	case *HTTPRequestInput:
		return *value
	case *BrowserActionInput:
		return *value
	case *ProcessInspectInput:
		return *value
	case *ServiceInspectInput:
		return *value
	case *ServiceControlInput:
		return *value
	case *ContainerActionInput:
		return *value
	case *NodeActionInput:
		return *value
	default:
		return nil
	}
}

func argumentTypeMatches(kind CapabilityKind, arguments any) bool {
	switch kind {
	case CapabilityReadFile:
		_, ok := arguments.(ReadFileInput)
		return ok
	case CapabilityWriteFile:
		_, ok := arguments.(WriteFileInput)
		return ok
	case CapabilityCreateFile:
		_, ok := arguments.(CreateFileInput)
		return ok
	case CapabilityMoveFile:
		_, ok := arguments.(MoveFileInput)
		return ok
	case CapabilityDeleteFile:
		_, ok := arguments.(DeleteFileInput)
		return ok
	case CapabilityListDirectory:
		_, ok := arguments.(ListDirectoryInput)
		return ok
	case CapabilityExecuteApprovedCommand:
		_, ok := arguments.(ExecuteApprovedCommandInput)
		return ok
	case CapabilityGitRead:
		_, ok := arguments.(GitReadInput)
		return ok
	case CapabilityGitWrite:
		_, ok := arguments.(GitWriteInput)
		return ok
	case CapabilityHTTPRequest:
		_, ok := arguments.(HTTPRequestInput)
		return ok
	case CapabilityBrowserAction:
		_, ok := arguments.(BrowserActionInput)
		return ok
	case CapabilityProcessInspect:
		_, ok := arguments.(ProcessInspectInput)
		return ok
	case CapabilityServiceInspect:
		_, ok := arguments.(ServiceInspectInput)
		return ok
	case CapabilityServiceControl:
		_, ok := arguments.(ServiceControlInput)
		return ok
	case CapabilityContainerAction:
		_, ok := arguments.(ContainerActionInput)
		return ok
	case CapabilityNodeAction:
		_, ok := arguments.(NodeActionInput)
		return ok
	default:
		return false
	}
}

func decodeStrict(data []byte, destination any) error {
	if err := rejectDuplicateObjectKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("more than one JSON value")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func rejectDuplicateObjectKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walkValue func() error
	walkValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("JSON object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = struct{}{}
				if err := walkValue(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim('}') {
				return fmt.Errorf("JSON object was not terminated")
			}
		case '[':
			for decoder.More() {
				if err := walkValue(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim(']') {
				return fmt.Errorf("JSON array was not terminated")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
		return nil
	}
	if err := walkValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("more than one JSON value")
		}
		return err
	}
	return nil
}
