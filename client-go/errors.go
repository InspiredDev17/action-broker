package actionbroker

import (
	"errors"
	"fmt"
)

// ErrorCode identifies a stable class of client-side failure.
type ErrorCode string

const (
	ErrorInvalidConfiguration ErrorCode = "invalid_configuration"
	ErrorInvalidRequest       ErrorCode = "invalid_request"
	ErrorMarshalRequest       ErrorCode = "marshal_request"
	ErrorEndpointSecurity     ErrorCode = "endpoint_security"
	ErrorDial                 ErrorCode = "dial"
	ErrorWrite                ErrorCode = "write"
	ErrorRead                 ErrorCode = "read"
	ErrorTruncatedFrame       ErrorCode = "truncated_frame"
	ErrorFrameTooLarge        ErrorCode = "frame_too_large"
	ErrorMalformedResponse    ErrorCode = "malformed_response"
	ErrorMismatchedResponse   ErrorCode = "mismatched_response"
	ErrorOutcomeUnknown       ErrorCode = "outcome_unknown"
	ErrorBrokerRejected       ErrorCode = "broker_rejected"
)

// ClientError is returned for transport, framing, validation, and broker
// failures. Message is deliberately stable and does not include request data.
// The underlying error is available through errors.Is and errors.As.
type ClientError struct {
	Code      ErrorCode
	Operation string
	Message   string
	Cause     error
}

func (e *ClientError) Error() string {
	if e == nil {
		return "action broker: <nil>"
	}
	if e.Operation == "" {
		return fmt.Sprintf("action broker: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("action broker: %s: %s: %s", e.Operation, e.Code, e.Message)
}

// Unwrap exposes the underlying system or context error without adding it to
// the rendered error, where it might disclose a local path.
func (e *ClientError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is reports equality by ErrorCode when target is a ClientError with a code.
func (e *ClientError) Is(target error) bool {
	var other *ClientError
	return errors.As(target, &other) && other.Code != "" && e.Code == other.Code
}

// FrameError provides safe frame-bound diagnostics without retaining payload
// bytes.
type FrameError struct {
	Direction string
	Size      uint32
	Maximum   uint32
}

// BrokerError represents a well-formed unsuccessful response. Response remains
// available from Execute so callers can inspect timestamps and status without
// parsing this error string.
type BrokerError struct {
	RequestID string
	Status    ActionStatus
	Code      string
	Message   string
	Retryable bool
}

// Is lets callers classify any well-formed broker rejection with
// errors.Is(err, &ClientError{Code: ErrorBrokerRejected}).
func (e *BrokerError) Is(target error) bool {
	var other *ClientError
	return errors.As(target, &other) && other.Code == ErrorBrokerRejected
}

// OutcomeUnknownError means the request frame was fully delivered but the
// client could not receive a broker-confirmed outcome. The action may still be
// running or may have completed; callers must reconcile by RequestID and must
// not blindly retry a consequential action.
type OutcomeUnknownError struct {
	RequestID string
	Cause     error
}

func (e *OutcomeUnknownError) Error() string {
	return "action broker: outcome_unknown: request was delivered but no broker-confirmed outcome was received"
}

func (e *OutcomeUnknownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *BrokerError) Error() string {
	if e == nil {
		return "action broker: rejected action"
	}
	return fmt.Sprintf("action broker: %s: %s", e.Status, e.Code)
}

func (e *FrameError) Error() string {
	if e == nil {
		return "action broker: invalid frame"
	}
	return fmt.Sprintf("action broker: %s frame is %d bytes; maximum is %d", e.Direction, e.Size, e.Maximum)
}

func clientError(code ErrorCode, operation, message string, cause error) error {
	return &ClientError{
		Code:      code,
		Operation: operation,
		Message:   message,
		Cause:     cause,
	}
}
