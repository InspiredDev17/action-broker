package actionbroker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestEveryCapabilityActionRoundTripsWithExactTag(t *testing.T) {
	root := RootedPath{RootID: "workspace", RelativePath: "item"}
	timeout := uint64(1000)
	actions := []CapabilityAction{
		NewReadFileAction(ReadFileInput{Path: root, MaximumBytes: 1}),
		NewWriteFileAction(WriteFileInput{Path: root, ContentBase64: "eA=="}),
		NewCreateFileAction(CreateFileInput{Path: root, ContentBase64: "eA==", FailIfExists: true}),
		NewMoveFileAction(MoveFileInput{Source: root, Destination: RootedPath{RootID: "workspace", RelativePath: "other"}}),
		NewDeleteFileAction(DeleteFileInput{Path: root, RequireRegularFile: true}),
		NewListDirectoryAction(ListDirectoryInput{Path: root, MaximumEntries: 10}),
		NewExecuteApprovedCommandAction(ExecuteApprovedCommandInput{
			ProgramID:        "git.readonly",
			Arguments:        []string{"status"},
			WorkingDirectory: root,
			Environment:      map[string]string{},
		}),
		NewGitReadAction(GitReadInput{RepositoryPath: root, Operation: NewGitStatusOperation()}),
		NewGitWriteAction(GitWriteInput{RepositoryPath: root, Operation: NewGitCommitOperation("message")}),
		NewHTTPRequestAction(HTTPRequestInput{
			Method:               HTTPGet,
			URL:                  "https://example.test/",
			Headers:              map[string]string{},
			MaximumResponseBytes: 1024,
		}),
		NewBrowserAction(BrowserActionInput{
			BrowserSessionID: "session-1",
			Operation:        NewBrowserScreenshotOperation(),
		}),
		NewProcessInspectAction(ProcessInspectInput{Operation: NewProcessListOperation(10)}),
		NewServiceInspectAction(ServiceInspectInput{ServiceName: "service"}),
		NewServiceControlAction(ServiceControlInput{ServiceName: "service", Operation: ServiceRestart}),
		NewContainerAction(ContainerActionInput{
			Runtime:             ContainerDocker,
			ContainerID:         "container",
			Operation:           ContainerInspect,
			TimeoutMilliseconds: &timeout,
		}),
		NewNodeAction(NodeActionInput{NodeID: "node-1", Operation: NodeInspectStatus}),
	}
	if len(actions) != len(AllCapabilities()) {
		t.Fatalf("test action inventory has %d entries; capability inventory has %d", len(actions), len(AllCapabilities()))
	}
	for _, action := range actions {
		t.Run(string(action.Capability()), func(t *testing.T) {
			encoded, err := json.Marshal(action)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !strings.Contains(string(encoded), `"capability":"`+string(action.Capability())+`"`) {
				t.Fatalf("missing exact capability tag in %s", encoded)
			}
			var decoded CapabilityAction
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if decoded.Capability() != action.Capability() || !reflect.DeepEqual(decoded.Arguments(), action.Arguments()) {
				t.Fatalf("round-trip mismatch\n got: %#v\nwant: %#v", decoded.Arguments(), action.Arguments())
			}
		})
	}
}

func TestOperationTaggedUnionsRoundTrip(t *testing.T) {
	revision := "main"
	operations := []any{
		NewGitStatusOperation(),
		NewGitDiffOperation(nil),
		NewGitDiffOperation(&revision),
		NewGitLogOperation(10),
		NewGitShowOperation("deadbeef"),
		NewGitResolveRevisionOperation("HEAD"),
		NewGitAddPathsOperation([]string{"one", "two"}),
		NewGitCommitOperation("message"),
		NewGitCreateBranchOperation("branch", "main"),
		NewGitApplyPatchOperation("cGF0Y2g="),
		NewBrowserNavigateOperation("https://example.test/"),
		NewBrowserClickOperation("#button"),
		NewBrowserTypeTextOperation("#input", "text"),
		NewBrowserReadTextOperation("main"),
		NewBrowserScreenshotOperation(),
		NewProcessListOperation(10),
		NewProcessInspectPIDOperation(42),
	}
	for index, operation := range operations {
		encoded, err := json.Marshal(operation)
		if err != nil {
			t.Fatalf("operation %d marshal: %v", index, err)
		}
		var destination any
		switch operation.(type) {
		case GitReadOperation:
			destination = &GitReadOperation{}
		case GitWriteOperation:
			destination = &GitWriteOperation{}
		case BrowserOperation:
			destination = &BrowserOperation{}
		case ProcessInspectOperation:
			destination = &ProcessInspectOperation{}
		default:
			t.Fatalf("operation %d has unexpected type %T", index, operation)
		}
		if err := json.Unmarshal(encoded, destination); err != nil {
			t.Fatalf("operation %d unmarshal %s: %v", index, encoded, err)
		}
		if !reflect.DeepEqual(reflect.ValueOf(destination).Elem().Interface(), operation) {
			t.Fatalf("operation %d round-trip mismatch: got %#v want %#v", index, destination, operation)
		}
	}
}

func TestCapabilityActionRejectsUnknownAndDuplicateFields(t *testing.T) {
	tests := []string{
		`{"capability":"ReadFile","arguments":{"path":{"root_id":"workspace","relative_path":"file"},"maximum_bytes":1,"extra":true}}`,
		`{"capability":"ReadFile","capability":"DeleteFile","arguments":{"path":{"root_id":"workspace","relative_path":"file"},"maximum_bytes":1}}`,
		`{"capability":"RunAnything","arguments":{}}`,
	}
	for _, input := range tests {
		var action CapabilityAction
		if err := json.Unmarshal([]byte(input), &action); err == nil {
			t.Fatalf("expected rejection for %s", input)
		}
	}
}

func TestEveryCapabilityInputRejectsMissingAndNullRequiredFields(t *testing.T) {
	tests := []struct {
		capability CapabilityKind
		arguments  string
		required   []string
	}{
		{CapabilityReadFile, `{"path":{"root_id":"workspace","relative_path":"file"},"maximum_bytes":1}`, []string{"path", "maximum_bytes"}},
		{CapabilityWriteFile, `{"path":{"root_id":"workspace","relative_path":"file"},"content_base64":"","expected_prechange_sha256":null,"create_if_missing":false}`, []string{"path", "content_base64", "create_if_missing"}},
		{CapabilityCreateFile, `{"path":{"root_id":"workspace","relative_path":"file"},"content_base64":"","fail_if_exists":false}`, []string{"path", "content_base64", "fail_if_exists"}},
		{CapabilityMoveFile, `{"source":{"root_id":"workspace","relative_path":"from"},"destination":{"root_id":"workspace","relative_path":"to"},"replace_existing":false,"expected_source_sha256":null}`, []string{"source", "destination", "replace_existing"}},
		{CapabilityDeleteFile, `{"path":{"root_id":"workspace","relative_path":"file"},"expected_sha256":null,"require_regular_file":false}`, []string{"path", "require_regular_file"}},
		{CapabilityListDirectory, `{"path":{"root_id":"workspace","relative_path":"."},"maximum_entries":1,"include_hidden":false}`, []string{"path", "maximum_entries", "include_hidden"}},
		{CapabilityExecuteApprovedCommand, `{"program_id":"git.readonly","arguments":[],"working_directory":{"root_id":"workspace","relative_path":"."},"environment":{},"timeout_milliseconds":null}`, []string{"program_id", "arguments", "working_directory", "environment"}},
		{CapabilityGitRead, `{"repository_path":{"root_id":"workspace","relative_path":"repo"},"operation":{"operation":"status"}}`, []string{"repository_path", "operation"}},
		{CapabilityGitWrite, `{"repository_path":{"root_id":"workspace","relative_path":"repo"},"operation":{"operation":"commit","message":"message"},"expected_head":null}`, []string{"repository_path", "operation"}},
		{CapabilityHTTPRequest, `{"method":"GET","url":"https://example.test/","headers":{},"body_base64":null,"maximum_response_bytes":1,"timeout_milliseconds":null}`, []string{"method", "url", "headers", "maximum_response_bytes"}},
		{CapabilityBrowserAction, `{"browser_session_id":"session-1","operation":{"operation":"screenshot"},"timeout_milliseconds":null}`, []string{"browser_session_id", "operation"}},
		{CapabilityProcessInspect, `{"operation":{"operation":"list","maximum_entries":1}}`, []string{"operation"}},
		{CapabilityServiceInspect, `{"service_name":"service"}`, []string{"service_name"}},
		{CapabilityServiceControl, `{"service_name":"service","operation":"stop"}`, []string{"service_name", "operation"}},
		{CapabilityContainerAction, `{"runtime":"docker","container_id":"container","operation":"inspect","timeout_milliseconds":null}`, []string{"runtime", "container_id", "operation"}},
		{CapabilityNodeAction, `{"node_id":"node-1","operation":"inspect_status"}`, []string{"node_id", "operation"}},
	}
	if len(tests) != len(AllCapabilities()) {
		t.Fatalf("input fixture inventory has %d entries; capability inventory has %d", len(tests), len(AllCapabilities()))
	}
	for _, test := range tests {
		t.Run(string(test.capability), func(t *testing.T) {
			var arguments map[string]any
			if err := json.Unmarshal([]byte(test.arguments), &arguments); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if err := decodeActionMap(test.capability, arguments); err != nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
			for _, field := range test.required {
				t.Run("missing_"+field, func(t *testing.T) {
					mutated := cloneAnyMap(arguments)
					delete(mutated, field)
					if err := decodeActionMap(test.capability, mutated); err == nil {
						t.Fatalf("missing required field %q was accepted", field)
					}
				})
				t.Run("null_"+field, func(t *testing.T) {
					mutated := cloneAnyMap(arguments)
					mutated[field] = nil
					if err := decodeActionMap(test.capability, mutated); err == nil {
						t.Fatalf("null required field %q was accepted", field)
					}
				})
			}
		})
	}
}

func TestRootedPathAndOperationVariantsRejectMissingAndNullFields(t *testing.T) {
	rootedPathMutations := []string{
		`{"relative_path":"file"}`,
		`{"root_id":null,"relative_path":"file"}`,
		`{"root_id":"workspace"}`,
		`{"root_id":"workspace","relative_path":null}`,
	}
	for _, path := range rootedPathMutations {
		input := `{"capability":"ReadFile","arguments":{"path":` + path + `,"maximum_bytes":1}}`
		var action CapabilityAction
		if err := json.Unmarshal([]byte(input), &action); err == nil {
			t.Fatalf("invalid rooted path was accepted: %s", path)
		}
	}

	operations := []struct {
		name   string
		valid  string
		fields []string
		decode func([]byte) error
	}{
		{"git_log", `{"operation":"log","maximum_entries":1}`, []string{"operation", "maximum_entries"}, decodeGitReadOperation},
		{"git_show", `{"operation":"show","object_id":"deadbeef"}`, []string{"operation", "object_id"}, decodeGitReadOperation},
		{"git_resolve", `{"operation":"resolve_revision","revision":"HEAD"}`, []string{"operation", "revision"}, decodeGitReadOperation},
		{"git_add", `{"operation":"add_paths","paths":[]}`, []string{"operation", "paths"}, decodeGitWriteOperation},
		{"git_commit", `{"operation":"commit","message":"message"}`, []string{"operation", "message"}, decodeGitWriteOperation},
		{"git_branch", `{"operation":"create_branch","name":"branch","start_point":"main"}`, []string{"operation", "name", "start_point"}, decodeGitWriteOperation},
		{"git_patch", `{"operation":"apply_patch","patch_base64":""}`, []string{"operation", "patch_base64"}, decodeGitWriteOperation},
		{"browser_navigate", `{"operation":"navigate","url":"https://example.test/"}`, []string{"operation", "url"}, decodeBrowserOperation},
		{"browser_click", `{"operation":"click","selector":"#button"}`, []string{"operation", "selector"}, decodeBrowserOperation},
		{"browser_type", `{"operation":"type_text","selector":"#input","text":"value"}`, []string{"operation", "selector", "text"}, decodeBrowserOperation},
		{"browser_read", `{"operation":"read_text","selector":"main"}`, []string{"operation", "selector"}, decodeBrowserOperation},
		{"process_list", `{"operation":"list","maximum_entries":1}`, []string{"operation", "maximum_entries"}, decodeProcessOperation},
		{"process_pid", `{"operation":"inspect_pid","pid":1}`, []string{"operation", "pid"}, decodeProcessOperation},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal([]byte(operation.valid), &value); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if err := operation.decode([]byte(operation.valid)); err != nil {
				t.Fatalf("valid operation rejected: %v", err)
			}
			for _, field := range operation.fields {
				missing := cloneAnyMap(value)
				delete(missing, field)
				encoded, _ := json.Marshal(missing)
				if err := operation.decode(encoded); err == nil {
					t.Errorf("missing field %q was accepted", field)
				}
				nullValue := cloneAnyMap(value)
				nullValue[field] = nil
				encoded, _ = json.Marshal(nullValue)
				if err := operation.decode(encoded); err == nil {
					t.Errorf("null field %q was accepted", field)
				}
			}
		})
	}

	var diff GitReadOperation
	if err := json.Unmarshal([]byte(`{"operation":"diff"}`), &diff); err != nil {
		t.Fatalf("optional Git diff revision omission was rejected: %v", err)
	}
}

func decodeActionMap(capability CapabilityKind, arguments map[string]any) error {
	encoded, err := json.Marshal(map[string]any{"capability": capability, "arguments": arguments})
	if err != nil {
		return err
	}
	var action CapabilityAction
	return json.Unmarshal(encoded, &action)
}

func cloneAnyMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func decodeGitReadOperation(data []byte) error {
	var value GitReadOperation
	return json.Unmarshal(data, &value)
}

func decodeGitWriteOperation(data []byte) error {
	var value GitWriteOperation
	return json.Unmarshal(data, &value)
}

func decodeBrowserOperation(data []byte) error {
	var value BrowserOperation
	return json.Unmarshal(data, &value)
}

func decodeProcessOperation(data []byte) error {
	var value ProcessInspectOperation
	return json.Unmarshal(data, &value)
}

func TestCapabilityOutputRejectsMissingAndNullRequiredFields(t *testing.T) {
	valid := `{"capability":"ExecuteApprovedCommand","result":{"exit_code":null,"stdout_base64":"","stderr_base64":"","stdout_truncated":false,"stderr_truncated":false,"timed_out":false}}`
	var output CapabilityOutput
	if err := json.Unmarshal([]byte(valid), &output); err != nil {
		t.Fatalf("valid output rejected: %v", err)
	}
	invalid := []string{
		`{"capability":"ExecuteApprovedCommand","result":{}}`,
		`{"capability":"ExecuteApprovedCommand","result":{"exit_code":null,"stdout_base64":null,"stderr_base64":"","stdout_truncated":false,"stderr_truncated":false,"timed_out":false}}`,
		`{"capability":"ProcessInspect","result":{"truncated":false}}`,
		`{"capability":"ReadFile","result":null}`,
	}
	for _, encoded := range invalid {
		if err := json.Unmarshal([]byte(encoded), &output); err == nil {
			t.Fatalf("expected required-field rejection for %s", encoded)
		}
	}
}

func TestMetadataCoversEveryCapabilityAndRequiresSignedApprovalForWrites(t *testing.T) {
	for _, capability := range AllCapabilities() {
		metadata, ok := Metadata(capability)
		if !ok || metadata.Permission == "" || metadata.Risk == "" || metadata.Approval.Requirement == "" {
			t.Fatalf("incomplete metadata for %s: %#v", capability, metadata)
		}
		if metadata.Risk != RiskReadOnly {
			if metadata.Approval.Requirement != ApprovalSignedToken || len(metadata.Approval.AcceptedTypes) == 0 {
				t.Fatalf("non-read-only capability lacks signed approval baseline: %s %#v", capability, metadata)
			}
		}
	}
}
