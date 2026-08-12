package actionbroker

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CapabilityOutput is the response's closed tagged result union.
type CapabilityOutput struct {
	capability CapabilityKind
	result     any
}

func NewReadFileOutput(result ReadFileOutput) CapabilityOutput {
	return newOutput(CapabilityReadFile, result)
}
func NewWriteFileOutput(result FileMutationOutput) CapabilityOutput {
	return newOutput(CapabilityWriteFile, result)
}
func NewCreateFileOutput(result FileMutationOutput) CapabilityOutput {
	return newOutput(CapabilityCreateFile, result)
}
func NewMoveFileOutput(result MoveFileOutput) CapabilityOutput {
	return newOutput(CapabilityMoveFile, result)
}
func NewDeleteFileOutput(result DeleteFileOutput) CapabilityOutput {
	return newOutput(CapabilityDeleteFile, result)
}
func NewListDirectoryOutput(result ListDirectoryOutput) CapabilityOutput {
	return newOutput(CapabilityListDirectory, result)
}
func NewExecuteApprovedCommandOutput(result ExecuteApprovedCommandOutput) CapabilityOutput {
	return newOutput(CapabilityExecuteApprovedCommand, result)
}
func NewGitReadOutput(result GitReadOutput) CapabilityOutput {
	return newOutput(CapabilityGitRead, result)
}
func NewGitWriteOutput(result GitWriteOutput) CapabilityOutput {
	return newOutput(CapabilityGitWrite, result)
}
func NewHTTPRequestOutput(result HTTPRequestOutput) CapabilityOutput {
	return newOutput(CapabilityHTTPRequest, result)
}
func NewBrowserActionOutput(result BrowserActionOutput) CapabilityOutput {
	return newOutput(CapabilityBrowserAction, result)
}
func NewProcessInspectOutput(result ProcessInspectOutput) CapabilityOutput {
	return newOutput(CapabilityProcessInspect, result)
}
func NewServiceInspectOutput(result ServiceInspectOutput) CapabilityOutput {
	return newOutput(CapabilityServiceInspect, result)
}
func NewServiceControlOutput(result ServiceControlOutput) CapabilityOutput {
	return newOutput(CapabilityServiceControl, result)
}
func NewContainerActionOutput(result ContainerActionOutput) CapabilityOutput {
	return newOutput(CapabilityContainerAction, result)
}
func NewNodeActionOutput(result NodeActionOutput) CapabilityOutput {
	return newOutput(CapabilityNodeAction, result)
}

func newOutput(capability CapabilityKind, result any) CapabilityOutput {
	return CapabilityOutput{capability: capability, result: result}
}

func (output CapabilityOutput) Capability() CapabilityKind { return output.capability }

// Result returns the typed result payload. Callers switch on Capability or use
// a type assertion against the corresponding output struct.
func (output CapabilityOutput) Result() any { return output.result }

func (output CapabilityOutput) MarshalJSON() ([]byte, error) {
	if !output.capability.valid() || !outputTypeMatches(output.capability, output.result) {
		return nil, fmt.Errorf("result does not match capability %q", output.capability)
	}
	return json.Marshal(struct {
		Capability CapabilityKind `json:"capability"`
		Result     any            `json:"result"`
	}{output.capability, output.result})
}

func (output *CapabilityOutput) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("capability output cannot be null")
	}
	var envelope struct {
		Capability *CapabilityKind `json:"capability"`
		Result     json.RawMessage `json:"result"`
	}
	if err := decodeStrict(data, &envelope); err != nil {
		return err
	}
	if envelope.Capability == nil || envelope.Result == nil || bytes.Equal(bytes.TrimSpace(envelope.Result), []byte("null")) {
		return fmt.Errorf("capability output is missing a required field")
	}
	result, err := decodeCapabilityResult(*envelope.Capability, envelope.Result)
	if err != nil {
		return err
	}
	output.capability = *envelope.Capability
	output.result = result
	return nil
}

func decodeCapabilityResult(kind CapabilityKind, raw json.RawMessage) (any, error) {
	if err := requireResultFields(kind, raw); err != nil {
		return nil, err
	}
	var destination any
	switch kind {
	case CapabilityReadFile:
		destination = &ReadFileOutput{}
	case CapabilityWriteFile, CapabilityCreateFile:
		destination = &FileMutationOutput{}
	case CapabilityMoveFile:
		destination = &MoveFileOutput{}
	case CapabilityDeleteFile:
		destination = &DeleteFileOutput{}
	case CapabilityListDirectory:
		destination = &ListDirectoryOutput{}
	case CapabilityExecuteApprovedCommand:
		destination = &ExecuteApprovedCommandOutput{}
	case CapabilityGitRead:
		destination = &GitReadOutput{}
	case CapabilityGitWrite:
		destination = &GitWriteOutput{}
	case CapabilityHTTPRequest:
		destination = &HTTPRequestOutput{}
	case CapabilityBrowserAction:
		destination = &BrowserActionOutput{}
	case CapabilityProcessInspect:
		destination = &ProcessInspectOutput{}
	case CapabilityServiceInspect:
		destination = &ServiceInspectOutput{}
	case CapabilityServiceControl:
		destination = &ServiceControlOutput{}
	case CapabilityContainerAction:
		destination = &ContainerActionOutput{}
	case CapabilityNodeAction:
		destination = &NodeActionOutput{}
	default:
		return nil, fmt.Errorf("unknown capability %q", kind)
	}
	if err := decodeStrict(raw, destination); err != nil {
		return nil, err
	}
	result := dereferenceOutputValue(destination)
	if err := validateCapabilityResult(kind, result); err != nil {
		return nil, err
	}
	return result, nil
}

func requireResultFields(kind CapabilityKind, raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := decodeStrict(raw, &fields); err != nil {
		return err
	}
	required := map[CapabilityKind][]string{
		CapabilityReadFile:               {"path", "content_base64", "bytes_read", "sha256", "truncated"},
		CapabilityWriteFile:              {"path", "previous_sha256", "current_sha256", "bytes_written", "backup_reference", "used_atomic_rename"},
		CapabilityCreateFile:             {"path", "previous_sha256", "current_sha256", "bytes_written", "backup_reference", "used_atomic_rename"},
		CapabilityMoveFile:               {"source", "destination", "moved_sha256", "replaced_sha256", "used_atomic_rename"},
		CapabilityDeleteFile:             {"path", "previous_sha256", "backup_reference", "removed"},
		CapabilityListDirectory:          {"path", "entries", "truncated"},
		CapabilityExecuteApprovedCommand: {"exit_code", "stdout_base64", "stderr_base64", "stdout_truncated", "stderr_truncated", "timed_out"},
		CapabilityGitRead:                {"repository_path", "text_base64", "truncated", "resolved_object_id"},
		CapabilityGitWrite:               {"repository_path", "previous_head", "current_head", "changed_paths"},
		CapabilityHTTPRequest:            {"final_url", "status_code", "headers", "body_base64", "truncated", "contacted_destinations"},
		CapabilityBrowserAction:          {"browser_session_id", "current_url", "text", "screenshot_base64", "contacted_destinations"},
		CapabilityProcessInspect:         {"processes", "truncated"},
		CapabilityServiceInspect:         {"service_name", "state", "substate", "process_id"},
		CapabilityServiceControl:         {"service_name", "previous_state", "current_state"},
		CapabilityContainerAction:        {"container_id", "previous_state", "current_state"},
		CapabilityNodeAction:             {"node_id", "previous_state", "current_state"},
	}[kind]
	if required == nil {
		return fmt.Errorf("unknown capability %q", kind)
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok {
			return fmt.Errorf("capability result is missing required field %q", name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !nullableResultField(kind, name) {
			return fmt.Errorf("capability result field %q cannot be null", name)
		}
	}
	return nil
}

func nullableResultField(kind CapabilityKind, name string) bool {
	switch name {
	case "previous_sha256", "backup_reference", "replaced_sha256", "replaced_backup_reference", "exit_code", "resolved_object_id", "previous_head", "current_head", "current_url", "text", "screenshot_base64", "substate", "process_id":
		return true
	case "previous_state":
		return kind == CapabilityContainerAction || kind == CapabilityNodeAction
	default:
		return false
	}
}

func dereferenceOutputValue(value any) any {
	switch value := value.(type) {
	case *ReadFileOutput:
		return *value
	case *FileMutationOutput:
		return *value
	case *MoveFileOutput:
		return *value
	case *DeleteFileOutput:
		return *value
	case *ListDirectoryOutput:
		return *value
	case *ExecuteApprovedCommandOutput:
		return *value
	case *GitReadOutput:
		return *value
	case *GitWriteOutput:
		return *value
	case *HTTPRequestOutput:
		return *value
	case *BrowserActionOutput:
		return *value
	case *ProcessInspectOutput:
		return *value
	case *ServiceInspectOutput:
		return *value
	case *ServiceControlOutput:
		return *value
	case *ContainerActionOutput:
		return *value
	case *NodeActionOutput:
		return *value
	default:
		return nil
	}
}

func outputTypeMatches(kind CapabilityKind, result any) bool {
	switch kind {
	case CapabilityReadFile:
		_, ok := result.(ReadFileOutput)
		return ok
	case CapabilityWriteFile, CapabilityCreateFile:
		_, ok := result.(FileMutationOutput)
		return ok
	case CapabilityMoveFile:
		_, ok := result.(MoveFileOutput)
		return ok
	case CapabilityDeleteFile:
		_, ok := result.(DeleteFileOutput)
		return ok
	case CapabilityListDirectory:
		_, ok := result.(ListDirectoryOutput)
		return ok
	case CapabilityExecuteApprovedCommand:
		_, ok := result.(ExecuteApprovedCommandOutput)
		return ok
	case CapabilityGitRead:
		_, ok := result.(GitReadOutput)
		return ok
	case CapabilityGitWrite:
		_, ok := result.(GitWriteOutput)
		return ok
	case CapabilityHTTPRequest:
		_, ok := result.(HTTPRequestOutput)
		return ok
	case CapabilityBrowserAction:
		_, ok := result.(BrowserActionOutput)
		return ok
	case CapabilityProcessInspect:
		_, ok := result.(ProcessInspectOutput)
		return ok
	case CapabilityServiceInspect:
		_, ok := result.(ServiceInspectOutput)
		return ok
	case CapabilityServiceControl:
		_, ok := result.(ServiceControlOutput)
		return ok
	case CapabilityContainerAction:
		_, ok := result.(ContainerActionOutput)
		return ok
	case CapabilityNodeAction:
		_, ok := result.(NodeActionOutput)
		return ok
	default:
		return false
	}
}
