package actionbroker

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type RequesterIdentity struct {
	UserID  string `json:"user_id"`
	AgentID string `json:"agent_id"`
	TaskID  string `json:"task_id"`
}

type TargetType string

const (
	TargetLocal TargetType = "local"
	TargetNode  TargetType = "node"
)

// ExecutionTarget is included in approval binding. NodeID must be empty for a
// local target and non-empty for a node target.
type ExecutionTarget struct {
	Type   TargetType `json:"type"`
	NodeID string     `json:"node_id,omitempty"`
}

func (target ExecutionTarget) MarshalJSON() ([]byte, error) {
	if err := target.validate(); err != nil {
		return nil, err
	}
	switch target.Type {
	case TargetLocal:
		return json.Marshal(struct {
			Type TargetType `json:"type"`
		}{Type: TargetLocal})
	case TargetNode:
		return json.Marshal(struct {
			Type   TargetType `json:"type"`
			NodeID string     `json:"node_id"`
		}{Type: TargetNode, NodeID: target.NodeID})
	default:
		return nil, fmt.Errorf("unknown target type %q", target.Type)
	}
}

func (target *ExecutionTarget) UnmarshalJSON(data []byte) error {
	var tag struct {
		Type TargetType `json:"type"`
	}
	if err := json.Unmarshal(data, &tag); err != nil {
		return err
	}
	switch tag.Type {
	case TargetLocal:
		var value struct {
			Type TargetType `json:"type"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		*target = LocalTarget()
	case TargetNode:
		var value struct {
			Type   TargetType `json:"type"`
			NodeID *string    `json:"node_id"`
		}
		if err := decodeStrict(data, &value); err != nil {
			return err
		}
		if value.NodeID == nil {
			return fmt.Errorf("node target requires node_id")
		}
		*target = NodeTarget(*value.NodeID)
	default:
		return fmt.Errorf("unknown target type %q", tag.Type)
	}
	return target.validate()
}

func LocalTarget() ExecutionTarget { return ExecutionTarget{Type: TargetLocal} }

func NodeTarget(nodeID string) ExecutionTarget {
	return ExecutionTarget{Type: TargetNode, NodeID: nodeID}
}

func (target ExecutionTarget) validate() error {
	switch target.Type {
	case TargetLocal:
		if target.NodeID != "" {
			return fmt.Errorf("local target cannot contain a node ID")
		}
	case TargetNode:
		if strings.TrimSpace(target.NodeID) == "" {
			return fmt.Errorf("node target requires a node ID")
		}
	default:
		return fmt.Errorf("unknown target type %q", target.Type)
	}
	return nil
}

// ActionRequest is the complete versioned request envelope. A nil
// ApprovalToken is encoded as JSON null and is only valid when broker policy
// authorizes the capability without one.
type ActionRequest struct {
	ProtocolVersion uint16            `json:"protocol_version"`
	RequestID       string            `json:"request_id"`
	Requester       RequesterIdentity `json:"requester"`
	Target          ExecutionTarget   `json:"target"`
	Action          CapabilityAction  `json:"action"`
	ApprovalToken   *string           `json:"approval_token"`
}

func (request ActionRequest) validate() error {
	if request.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", request.ProtocolVersion)
	}
	if !validUUID(request.RequestID) {
		return fmt.Errorf("request ID is not a canonical UUID")
	}
	if strings.TrimSpace(request.Requester.UserID) == "" ||
		strings.TrimSpace(request.Requester.AgentID) == "" ||
		strings.TrimSpace(request.Requester.TaskID) == "" {
		return fmt.Errorf("requester user, agent, and task IDs are required")
	}
	if err := request.Target.validate(); err != nil {
		return err
	}
	if err := request.Action.validate(); err != nil {
		return err
	}
	if request.ApprovalToken != nil && *request.ApprovalToken == "" {
		return fmt.Errorf("approval token cannot be empty")
	}
	return nil
}

type ActionStatus string

const (
	StatusSucceeded ActionStatus = "succeeded"
	StatusFailed    ActionStatus = "failed"
	StatusCancelled ActionStatus = "cancelled"
	StatusTimedOut  ActionStatus = "timed_out"
	StatusRejected  ActionStatus = "rejected"
)

func (status ActionStatus) valid() bool {
	switch status {
	case StatusSucceeded, StatusFailed, StatusCancelled, StatusTimedOut, StatusRejected:
		return true
	default:
		return false
	}
}

type ActionErrorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (response *ActionErrorResponse) UnmarshalJSON(data []byte) error {
	var value struct {
		Code      *string `json:"code"`
		Message   *string `json:"message"`
		Retryable *bool   `json:"retryable"`
	}
	if err := decodeStrict(data, &value); err != nil {
		return err
	}
	if value.Code == nil || value.Message == nil || value.Retryable == nil {
		return fmt.Errorf("error response is missing a required field")
	}
	response.Code = *value.Code
	response.Message = *value.Message
	response.Retryable = *value.Retryable
	return nil
}

type ActionResponse struct {
	ProtocolVersion            uint16               `json:"protocol_version"`
	RequestID                  string               `json:"request_id"`
	Target                     ExecutionTarget      `json:"target"`
	Capability                 CapabilityKind       `json:"capability"`
	Status                     ActionStatus         `json:"status"`
	Output                     *CapabilityOutput    `json:"output"`
	Error                      *ActionErrorResponse `json:"error"`
	StartedAtUnixMilliseconds  int64                `json:"started_at_unix_milliseconds"`
	FinishedAtUnixMilliseconds int64                `json:"finished_at_unix_milliseconds"`
	OutputSHA256               *string              `json:"output_sha256"`
}

func (response *ActionResponse) UnmarshalJSON(data []byte) error {
	*response = ActionResponse{}
	type decodedResponse struct {
		ProtocolVersion            *uint16          `json:"protocol_version"`
		RequestID                  *string          `json:"request_id"`
		Target                     *ExecutionTarget `json:"target"`
		Capability                 *CapabilityKind  `json:"capability"`
		Status                     *ActionStatus    `json:"status"`
		Output                     json.RawMessage  `json:"output"`
		Error                      json.RawMessage  `json:"error"`
		StartedAtUnixMilliseconds  *int64           `json:"started_at_unix_milliseconds"`
		FinishedAtUnixMilliseconds *int64           `json:"finished_at_unix_milliseconds"`
		OutputSHA256               json.RawMessage  `json:"output_sha256"`
	}
	var value decodedResponse
	if err := decodeStrict(data, &value); err != nil {
		return err
	}
	if value.ProtocolVersion == nil || value.RequestID == nil || value.Target == nil ||
		value.Capability == nil || value.Status == nil || value.Output == nil || value.Error == nil ||
		value.StartedAtUnixMilliseconds == nil || value.FinishedAtUnixMilliseconds == nil || value.OutputSHA256 == nil {
		return fmt.Errorf("action response is missing a required field")
	}
	response.ProtocolVersion = *value.ProtocolVersion
	response.RequestID = *value.RequestID
	response.Target = *value.Target
	response.Capability = *value.Capability
	response.Status = *value.Status
	response.StartedAtUnixMilliseconds = *value.StartedAtUnixMilliseconds
	response.FinishedAtUnixMilliseconds = *value.FinishedAtUnixMilliseconds
	if !bytes.Equal(value.Output, []byte("null")) {
		var output CapabilityOutput
		if err := decodeStrict(value.Output, &output); err != nil {
			return fmt.Errorf("invalid capability output: %w", err)
		}
		response.Output = &output
	}
	if !bytes.Equal(value.Error, []byte("null")) {
		var actionError ActionErrorResponse
		if err := decodeStrict(value.Error, &actionError); err != nil {
			return fmt.Errorf("invalid action error: %w", err)
		}
		response.Error = &actionError
	}
	if !bytes.Equal(value.OutputSHA256, []byte("null")) {
		var digest string
		if err := decodeStrict(value.OutputSHA256, &digest); err != nil {
			return fmt.Errorf("invalid output digest: %w", err)
		}
		response.OutputSHA256 = &digest
	}
	return nil
}

func (response *ActionResponse) validateFor(request ActionRequest) error {
	if response.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("response has unsupported protocol version %d", response.ProtocolVersion)
	}
	if response.RequestID != request.RequestID {
		return fmt.Errorf("response request ID does not match request")
	}
	if response.Target != request.Target {
		return fmt.Errorf("response target does not match request")
	}
	if response.Capability != request.Action.Capability() {
		return fmt.Errorf("response capability does not match request")
	}
	if !response.Status.valid() {
		return fmt.Errorf("response has unknown status %q", response.Status)
	}
	if response.StartedAtUnixMilliseconds < 0 ||
		response.FinishedAtUnixMilliseconds < response.StartedAtUnixMilliseconds {
		return fmt.Errorf("response timestamps are invalid")
	}
	if response.OutputSHA256 != nil && !validLowerHex(*response.OutputSHA256, 32) {
		return fmt.Errorf("response output digest is not lowercase SHA-256")
	}
	if response.Status == StatusSucceeded {
		if response.Output == nil {
			return fmt.Errorf("successful response has no typed output")
		}
		if response.Error != nil {
			return fmt.Errorf("successful response contains an error")
		}
	} else {
		if response.Output != nil {
			return fmt.Errorf("unsuccessful response contains output")
		}
		if response.Error == nil || strings.TrimSpace(response.Error.Code) == "" {
			return fmt.Errorf("unsuccessful response has no structured error")
		}
	}
	if response.Output != nil && response.Output.Capability() != response.Capability {
		return fmt.Errorf("typed output capability does not match response")
	}
	return nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:36]
	if compact != strings.ToLower(compact) {
		return false
	}
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16
}

func validLowerHex(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}
