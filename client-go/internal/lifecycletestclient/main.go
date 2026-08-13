// Command lifecycletestclient is an internal Linux service-lifecycle probe.
// It is not an approval service and cannot bypass broker policy.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	actionbroker "github.com/InspiredDev17/action-broker/client-go"
)

const requestID = "018f47d2-60d2-7af0-bc35-2a1f7f5a6d01"

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "lifecycletestclient: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "read", "probe mode: read, execute-and-expect-approval-expired, execute-and-expect-approval-invalid, execute-and-expect-cancel, execute-and-expect-replay, or hold-incomplete-frame")
	socketPath := flag.String("socket", "", "absolute broker Unix-socket path")
	brokerUID := flag.Uint64("broker-uid", 0, "expected unprivileged broker UID")
	rootID := flag.String("root-id", "lifecycle", "broker filesystem root ID")
	relativePath := flag.String("relative-path", "probe.txt", "root-relative probe path")
	expectedContent := flag.String("expected-content", "", "exact expected read result")
	markerPath := flag.String("marker", "", "hold-mode readiness marker")
	requestPath := flag.String("request", "", "signed typed request JSON path")
	timeout := flag.Duration("timeout", 5*time.Second, "complete probe timeout")
	flag.Parse()

	if *mode == "normalize-request" {
		return normalizeRequest(*requestPath, os.Stdout)
	}
	if *socketPath == "" || *brokerUID == 0 || *brokerUID > uint64(^uint32(0)) || *timeout <= 0 {
		return errors.New("socket, a uint32 nonzero broker UID, and a positive timeout are required")
	}

	switch *mode {
	case "read":
		return readProbe(*socketPath, uint32(*brokerUID), *rootID, *relativePath, *expectedContent, *timeout)
	case "execute-and-expect-approval-expired":
		return executeAndExpectBrokerError(*socketPath, uint32(*brokerUID), *requestPath, *timeout, actionbroker.StatusRejected, "approval_expired")
	case "execute-and-expect-approval-invalid":
		return executeAndExpectBrokerError(*socketPath, uint32(*brokerUID), *requestPath, *timeout, actionbroker.StatusRejected, "approval_invalid")
	case "execute-and-expect-cancel":
		return executeAndExpectBrokerError(*socketPath, uint32(*brokerUID), *requestPath, *timeout, actionbroker.StatusCancelled, "cancelled")
	case "execute-and-expect-replay":
		return executeAndExpectBrokerError(*socketPath, uint32(*brokerUID), *requestPath, *timeout, actionbroker.StatusRejected, "approval_replayed")
	case "hold-incomplete-frame":
		return holdIncompleteFrame(*socketPath, *markerPath, *timeout)
	default:
		return fmt.Errorf("unsupported mode %q", *mode)
	}
}

func executeAndExpectBrokerError(
	socketPath string,
	brokerUID uint32,
	requestPath string,
	timeout time.Duration,
	expectedStatus actionbroker.ActionStatus,
	expectedCode string,
) error {
	request, err := readRequest(requestPath)
	if err != nil {
		return err
	}
	client, err := actionbroker.NewClient(
		socketPath,
		brokerUID,
		actionbroker.WithTransportTimeout(timeout),
	)
	if err != nil {
		return fmt.Errorf("construct client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	response, executeErr := client.Execute(ctx, request)
	if executeErr == nil {
		return fmt.Errorf(
			"request unexpectedly succeeded: status=%s output=%#v",
			response.Status,
			response.Output.Result(),
		)
	}
	var brokerError *actionbroker.BrokerError
	if !errors.As(executeErr, &brokerError) || response == nil ||
		brokerError.Status != expectedStatus || brokerError.Code != expectedCode {
		return fmt.Errorf(
			"request did not return broker-confirmed %s/%s: %w",
			expectedStatus,
			expectedCode,
			executeErr,
		)
	}
	return nil
}

func normalizeRequest(requestPath string, destination io.Writer) error {
	request, err := readRequest(requestPath)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(destination)
	if err := encoder.Encode(request); err != nil {
		return fmt.Errorf("encode normalized request: %w", err)
	}
	return nil
}

func readRequest(requestPath string) (actionbroker.ActionRequest, error) {
	var request actionbroker.ActionRequest
	if requestPath == "" {
		return request, errors.New("request path is required")
	}
	requestFile, err := os.Open(requestPath)
	if err != nil {
		return request, fmt.Errorf("open signed request: %w", err)
	}
	defer requestFile.Close()
	decoder := json.NewDecoder(io.LimitReader(requestFile, int64(actionbroker.MaxFrameSize)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, fmt.Errorf("decode signed request: %w", err)
	}
	if err := requireJSONEnd(decoder); err != nil {
		return request, err
	}
	return request, nil
}

func requireJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode signed request trailing data: %w", err)
	}
	return errors.New("signed request contains multiple JSON values")
}

func readProbe(socketPath string, brokerUID uint32, rootID, relativePath, expectedContent string, timeout time.Duration) error {
	client, err := actionbroker.NewClient(
		socketPath,
		brokerUID,
		actionbroker.WithTransportTimeout(timeout),
	)
	if err != nil {
		return fmt.Errorf("construct client: %w", err)
	}
	request := actionbroker.ActionRequest{
		ProtocolVersion: actionbroker.ProtocolVersion,
		RequestID:       requestID,
		Requester: actionbroker.RequesterIdentity{
			UserID:  "lifecycle-user",
			AgentID: "lifecycle-agent",
			TaskID:  "lifecycle-readiness",
		},
		Target: actionbroker.LocalTarget(),
		Action: actionbroker.NewReadFileAction(actionbroker.ReadFileInput{
			Path: actionbroker.RootedPath{
				RootID:       rootID,
				RelativePath: relativePath,
			},
			MaximumBytes: 4096,
		}),
		ApprovalToken: nil,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	response, err := client.Execute(ctx, request)
	if err != nil {
		return fmt.Errorf("execute typed read: %w", err)
	}
	if response.Output == nil {
		return errors.New("broker returned no typed output")
	}
	result, ok := response.Output.Result().(actionbroker.ReadFileOutput)
	if !ok {
		return errors.New("broker returned the wrong typed output")
	}
	content, err := base64.StdEncoding.DecodeString(result.ContentBase64)
	if err != nil {
		return fmt.Errorf("decode broker content: %w", err)
	}
	if string(content) != expectedContent {
		return errors.New("broker content did not match the lifecycle fixture")
	}
	return nil
}

func holdIncompleteFrame(socketPath, markerPath string, timeout time.Duration) error {
	if markerPath == "" {
		return errors.New("hold mode requires a marker path")
	}
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial broker: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set connection deadline: %w", err)
	}
	// Announce a bounded payload but intentionally send no payload bytes. This
	// occupies a real daemon worker in its framed-read path until shutdown or
	// the configured read deadline; it never constructs an action request.
	if _, err := connection.Write([]byte{0, 0, 16, 0}); err != nil {
		return fmt.Errorf("write incomplete frame prefix: %w", err)
	}
	if err := os.WriteFile(markerPath, []byte("connected\n"), 0o600); err != nil {
		return fmt.Errorf("write readiness marker: %w", err)
	}
	var byte [1]byte
	_, err = connection.Read(byte[:])
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("broker unexpectedly returned bytes for an incomplete frame")
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return errors.New("broker did not close the incomplete frame before the probe deadline")
	}
	// Linux may report connection reset instead of EOF when the daemon closes
	// a socket with unread bytes. Both outcomes prove that the peer was closed.
	return nil
}
