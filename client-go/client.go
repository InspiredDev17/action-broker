package actionbroker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

const defaultTransportTimeout = 3 * time.Minute

// Client executes one typed request per Unix-domain-socket connection. Client
// is safe for concurrent use.
type Client struct {
	socketPath             string
	expectedBrokerUID      uint32
	transportTimeout       time.Duration
	dialer                 net.Dialer
	allowSameUIDForTesting bool
}

// Option configures a Client.
type Option func(*Client) error

// WithTransportTimeout bounds the complete dial/write/read exchange. It is
// independent of the capability's broker-enforced execution timeout.
func WithTransportTimeout(timeout time.Duration) Option {
	return func(client *Client) error {
		if timeout <= 0 {
			return clientError(ErrorInvalidConfiguration, "new_client", "transport timeout must be positive", nil)
		}
		client.transportTimeout = timeout
		return nil
	}
}

// NewClient creates a local Unix-socket client. The path must be absolute and
// expectedBrokerUID must identify the distinct unprivileged broker service
// account; the Platform and broker are never allowed to share a UID.
func NewClient(socketPath string, expectedBrokerUID uint32, options ...Option) (*Client, error) {
	if strings.TrimSpace(socketPath) == "" || socketPath[0] != '/' || strings.IndexByte(socketPath, 0) >= 0 {
		return nil, clientError(ErrorInvalidConfiguration, "new_client", "socket path must be a non-empty absolute path without NUL bytes", nil)
	}
	client := &Client{
		socketPath:        socketPath,
		expectedBrokerUID: expectedBrokerUID,
		transportTimeout:  defaultTransportTimeout,
	}
	for _, option := range options {
		if option == nil {
			return nil, clientError(ErrorInvalidConfiguration, "new_client", "client option cannot be nil", nil)
		}
		if err := option(client); err != nil {
			return nil, err
		}
	}
	if expectedBrokerUID == 0 {
		return nil, clientError(ErrorInvalidConfiguration, "new_client", "broker UID must be unprivileged", nil)
	}
	if expectedBrokerUID == uint32(os.Geteuid()) && !client.allowSameUIDForTesting {
		return nil, clientError(ErrorInvalidConfiguration, "new_client", "broker UID must be distinct from the platform UID", nil)
	}
	return client, nil
}

// Execute sends one typed request and waits for its correlated typed response.
// It never invokes a shell and never retries: retries could duplicate external
// side effects or consume a fresh approval decision.
func (client *Client) Execute(ctx context.Context, request ActionRequest) (*ActionResponse, error) {
	if client == nil || client.transportTimeout <= 0 || client.socketPath == "" {
		return nil, clientError(ErrorInvalidConfiguration, "execute", "client is not initialized", nil)
	}
	if ctx == nil {
		return nil, clientError(ErrorInvalidRequest, "execute", "context cannot be nil", nil)
	}
	if err := request.validate(); err != nil {
		return nil, clientError(ErrorInvalidRequest, "validate_request", "request did not pass client-side structural validation", err)
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, clientError(ErrorMarshalRequest, "marshal_request", "could not encode typed request", err)
	}
	if uint64(len(payload)) > uint64(MaxFrameSize) {
		frameErr := &FrameError{Direction: "request", Size: boundedUint32(len(payload)), Maximum: MaxFrameSize}
		return nil, clientError(ErrorFrameTooLarge, "marshal_request", "request frame exceeds the protocol limit", frameErr)
	}

	operationContext, cancel := context.WithTimeout(ctx, client.transportTimeout)
	defer cancel()
	endpointIdentity, err := inspectSocketEndpoint(client.socketPath, client.expectedBrokerUID)
	if err != nil {
		return nil, clientError(ErrorEndpointSecurity, "inspect_endpoint", "broker socket did not pass local identity checks", err)
	}
	connection, err := client.dialer.DialContext(operationContext, "unix", client.socketPath)
	if err != nil {
		return nil, classifyOperationError(operationContext, ErrorDial, "dial", "could not connect to broker", err)
	}
	defer connection.Close()
	if err := confirmSocketEndpoint(client.socketPath, client.expectedBrokerUID, endpointIdentity); err != nil {
		return nil, clientError(ErrorEndpointSecurity, "confirm_endpoint", "broker socket identity changed while connecting", err)
	}

	if deadline, ok := operationContext.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, clientError(ErrorDial, "set_deadline", "could not apply transport deadline", err)
		}
	}
	watchComplete := make(chan struct{})
	go func() {
		select {
		case <-operationContext.Done():
			_ = connection.SetDeadline(time.Now())
		case <-watchComplete:
		}
	}()
	defer close(watchComplete)

	if err := writeFrame(connection, payload); err != nil {
		var uncertain *frameDeliveryUncertainError
		if errors.As(err, &uncertain) {
			return nil, clientError(ErrorOutcomeUnknown, "write_request", "complete request frame may have been delivered without a confirmed outcome", &OutcomeUnknownError{
				RequestID: request.RequestID,
				Cause:     uncertain,
			})
		}
		return nil, classifyOperationError(operationContext, ErrorWrite, "write_request", "could not send complete request", err)
	}
	responsePayload, err := readFrame(connection)
	if err != nil {
		cause := err
		if operationContext.Err() != nil {
			cause = operationContext.Err()
		}
		return nil, clientError(ErrorOutcomeUnknown, "read_response", "request was delivered but no broker-confirmed outcome was received", &OutcomeUnknownError{
			RequestID: request.RequestID,
			Cause:     cause,
		})
	}

	var response ActionResponse
	if err := decodeStrict(responsePayload, &response); err != nil {
		return nil, clientError(ErrorOutcomeUnknown, "decode_response", "request was delivered but the broker outcome was malformed", &OutcomeUnknownError{
			RequestID: request.RequestID,
			Cause:     err,
		})
	}
	if err := response.validateFor(request); err != nil {
		return nil, clientError(ErrorOutcomeUnknown, "validate_response", "request was delivered but the broker outcome did not match it", &OutcomeUnknownError{
			RequestID: request.RequestID,
			Cause:     err,
		})
	}
	if response.Status != StatusSucceeded {
		brokerError := &BrokerError{
			RequestID: response.RequestID,
			Status:    response.Status,
			Code:      response.Error.Code,
			Message:   response.Error.Message,
			Retryable: response.Error.Retryable,
		}
		return &response, brokerError
	}
	return &response, nil
}

func classifyOperationError(ctx context.Context, fallback ErrorCode, operation, message string, cause error) error {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return clientError(fallback, operation, "operation was cancelled before confirmed delivery", context.Canceled)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return clientError(fallback, operation, "operation deadline was exceeded before confirmed delivery", context.DeadlineExceeded)
	default:
		var structured *ClientError
		if errors.As(cause, &structured) {
			return cause
		}
		return clientError(fallback, operation, message, cause)
	}
}
