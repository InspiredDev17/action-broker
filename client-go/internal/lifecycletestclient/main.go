// Command lifecycletestclient is an internal Linux service-lifecycle probe.
// It is not an approval service and cannot bypass broker policy.
package main

import (
	"context"
	"encoding/base64"
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
	mode := flag.String("mode", "read", "probe mode: read or hold-incomplete-frame")
	socketPath := flag.String("socket", "", "absolute broker Unix-socket path")
	brokerUID := flag.Uint64("broker-uid", 0, "expected unprivileged broker UID")
	rootID := flag.String("root-id", "lifecycle", "broker filesystem root ID")
	relativePath := flag.String("relative-path", "probe.txt", "root-relative probe path")
	expectedContent := flag.String("expected-content", "", "exact expected read result")
	markerPath := flag.String("marker", "", "hold-mode readiness marker")
	timeout := flag.Duration("timeout", 5*time.Second, "complete probe timeout")
	flag.Parse()

	if *socketPath == "" || *brokerUID == 0 || *brokerUID > uint64(^uint32(0)) || *timeout <= 0 {
		return errors.New("socket, a uint32 nonzero broker UID, and a positive timeout are required")
	}

	switch *mode {
	case "read":
		return readProbe(*socketPath, uint32(*brokerUID), *rootID, *relativePath, *expectedContent, *timeout)
	case "hold-incomplete-frame":
		return holdIncompleteFrame(*socketPath, *markerPath, *timeout)
	default:
		return fmt.Errorf("unsupported mode %q", *mode)
	}
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
