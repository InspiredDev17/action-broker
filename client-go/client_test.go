package actionbroker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testRequestID = "018f47d2-60d2-7af0-bc35-2a1f7f5a6d01"

func allowSameUIDBrokerForTest(client *Client) error {
	client.allowSameUIDForTesting = true
	return nil
}

func newTestClient(t *testing.T, socketPath string, options ...Option) *Client {
	t.Helper()
	options = append(options, allowSameUIDBrokerForTest)
	client, err := NewClient(socketPath, uint32(os.Geteuid()), options...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestNewClientRejectsSharedPlatformAndBrokerUID(t *testing.T) {
	_, err := NewClient("/tmp/action-broker.sock", uint32(os.Geteuid()))
	requireClientCode(t, err, ErrorInvalidConfiguration)
}

func TestExecuteSuccessfulUnixSocketRoundTrip(t *testing.T) {
	listener, socketPath := testUnixListener(t)
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		payload, err := readFrame(connection)
		if err != nil {
			serverDone <- err
			return
		}
		var received ActionRequest
		if err := decodeStrict(payload, &received); err != nil {
			serverDone <- err
			return
		}
		if received.Action.Capability() != CapabilityReadFile {
			serverDone <- fmt.Errorf("received capability %q", received.Action.Capability())
			return
		}
		arguments, ok := received.Action.Arguments().(ReadFileInput)
		if !ok || arguments.Path != (RootedPath{RootID: "workspace", RelativePath: "report.txt"}) || arguments.MaximumBytes != 4096 {
			serverDone <- fmt.Errorf("received unexpected arguments: %#v", received.Action.Arguments())
			return
		}

		output := NewReadFileOutput(ReadFileOutput{
			Path:          arguments.Path,
			ContentBase64: "b2s=",
			BytesRead:     2,
			SHA256:        strings.Repeat("a", 64),
			Truncated:     false,
		})
		response := ActionResponse{
			ProtocolVersion:            ProtocolVersion,
			RequestID:                  received.RequestID,
			Target:                     received.Target,
			Capability:                 received.Action.Capability(),
			Status:                     StatusSucceeded,
			Output:                     &output,
			Error:                      nil,
			StartedAtUnixMilliseconds:  100,
			FinishedAtUnixMilliseconds: 101,
			OutputSHA256:               nil,
		}
		encoded, err := json.Marshal(response)
		if err == nil {
			err = writeFrame(connection, encoded)
		}
		serverDone <- err
	}()

	client := newTestClient(t, socketPath)
	response, err := client.Execute(context.Background(), readRequest(testRequestID))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
	if response.Status != StatusSucceeded || response.Output == nil {
		t.Fatalf("unexpected response: %#v", response)
	}
	result, ok := response.Output.Result().(ReadFileOutput)
	if !ok || result.ContentBase64 != "b2s=" {
		t.Fatalf("unexpected typed output: %#v", response.Output.Result())
	}
}

func TestExecuteRejectsOversizedRequestBeforeDial(t *testing.T) {
	client := newTestClient(t, "/tmp/action-broker-not-listening.sock")
	request := readRequest(testRequestID)
	request.Action = NewReadFileAction(ReadFileInput{
		Path: RootedPath{
			RootID:       "workspace",
			RelativePath: strings.Repeat("x", int(MaxFrameSize)),
		},
		MaximumBytes: 1,
	})
	_, err := client.Execute(context.Background(), request)
	requireClientCode(t, err, ErrorFrameTooLarge)
	var frameError *FrameError
	if !errors.As(err, &frameError) || frameError.Direction != "request" {
		t.Fatalf("expected request FrameError, got %T %v", err, err)
	}
}

func TestExecuteRejectsOversizedResponseFrame(t *testing.T) {
	listener, socketPath := testUnixListener(t)
	serverDone := serveOne(t, listener, func(connection net.Conn) error {
		if _, err := readFrame(connection); err != nil {
			return err
		}
		header := [4]byte{}
		binary.BigEndian.PutUint32(header[:], MaxFrameSize+1)
		return writeAll(connection, header[:])
	})

	client := newTestClient(t, socketPath)
	_, err := client.Execute(context.Background(), readRequest(testRequestID))
	requireClientCode(t, err, ErrorOutcomeUnknown)
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestExecuteRejectsTruncatedResponse(t *testing.T) {
	tests := []struct {
		name    string
		respond func(net.Conn) error
	}{
		{
			name: "header",
			respond: func(connection net.Conn) error {
				return writeAll(connection, []byte{0, 0})
			},
		},
		{
			name: "payload",
			respond: func(connection net.Conn) error {
				header := [4]byte{}
				binary.BigEndian.PutUint32(header[:], 100)
				if err := writeAll(connection, header[:]); err != nil {
					return err
				}
				return writeAll(connection, []byte(`{"partial":true}`))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, socketPath := testUnixListener(t)
			serverDone := serveOne(t, listener, func(connection net.Conn) error {
				if _, err := readFrame(connection); err != nil {
					return err
				}
				return test.respond(connection)
			})
			client := newTestClient(t, socketPath)
			_, err := client.Execute(context.Background(), readRequest(testRequestID))
			requireClientCode(t, err, ErrorOutcomeUnknown)
			if err := <-serverDone; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}

func TestExecuteCancellationInterruptsBlockedRead(t *testing.T) {
	listener, socketPath := testUnixListener(t)
	requestReceived := make(chan struct{})
	serverDone := serveOne(t, listener, func(connection net.Conn) error {
		if _, err := readFrame(connection); err != nil {
			return err
		}
		close(requestReceived)
		buffer := make([]byte, 1)
		_, err := connection.Read(buffer)
		return err
	})

	client := newTestClient(t, socketPath, WithTransportTimeout(2*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.Execute(ctx, readRequest(testRequestID))
		result <- err
	}()
	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}
	cancel()
	select {
	case err := <-result:
		requireClientCode(t, err, ErrorOutcomeUnknown)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled cause, got %v", err)
		}
		var outcomeUnknown *OutcomeUnknownError
		if !errors.As(err, &outcomeUnknown) || outcomeUnknown.RequestID != testRequestID {
			t.Fatalf("expected correlated unknown outcome, got %T %v", err, err)
		}
	case <-time.After(time.Second):
		t.Fatal("Execute did not return after cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server connection did not close after cancellation")
	}
}

func TestClientConcurrentExecution(t *testing.T) {
	const count = 24
	listener, socketPath := testUnixListener(t)
	serverDone := make(chan error, 1)
	go func() {
		var workers sync.WaitGroup
		errorsFromWorkers := make(chan error, count)
		for range count {
			connection, err := listener.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				payload, err := readFrame(connection)
				if err != nil {
					errorsFromWorkers <- err
					return
				}
				var request ActionRequest
				if err := decodeStrict(payload, &request); err != nil {
					errorsFromWorkers <- err
					return
				}
				output := NewReadFileOutput(ReadFileOutput{
					Path:          request.Action.Arguments().(ReadFileInput).Path,
					ContentBase64: "",
					SHA256:        strings.Repeat("0", 64),
				})
				response := ActionResponse{
					ProtocolVersion:            ProtocolVersion,
					RequestID:                  request.RequestID,
					Target:                     request.Target,
					Capability:                 CapabilityReadFile,
					Status:                     StatusSucceeded,
					Output:                     &output,
					StartedAtUnixMilliseconds:  1,
					FinishedAtUnixMilliseconds: 2,
				}
				encoded, err := json.Marshal(response)
				if err == nil {
					err = writeFrame(connection, encoded)
				}
				if err != nil {
					errorsFromWorkers <- err
				}
			}()
		}
		workers.Wait()
		close(errorsFromWorkers)
		for err := range errorsFromWorkers {
			if err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	client := newTestClient(t, socketPath)
	errorsFromClients := make(chan error, count)
	var clients sync.WaitGroup
	for index := range count {
		clients.Add(1)
		go func() {
			defer clients.Done()
			requestID := fmt.Sprintf("018f47d2-60d2-7af0-bc35-%012x", index+1)
			response, err := client.Execute(context.Background(), readRequest(requestID))
			if err == nil && response.RequestID != requestID {
				err = fmt.Errorf("response correlated to %s, want %s", response.RequestID, requestID)
			}
			errorsFromClients <- err
		}()
	}
	clients.Wait()
	close(errorsFromClients)
	for err := range errorsFromClients {
		if err != nil {
			t.Errorf("concurrent Execute: %v", err)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestRequestWireShapeUsesClosedTags(t *testing.T) {
	request := readRequest(testRequestID)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"protocol_version":1,"request_id":"018f47d2-60d2-7af0-bc35-2a1f7f5a6d01","requester":{"user_id":"user-1","agent_id":"agent-1","task_id":"task-1"},"target":{"type":"local"},"action":{"capability":"ReadFile","arguments":{"path":{"root_id":"workspace","relative_path":"report.txt"},"maximum_bytes":4096}},"approval_token":null}`
	if string(encoded) != want {
		t.Fatalf("wire shape mismatch\n got: %s\nwant: %s", encoded, want)
	}
}

func readRequest(requestID string) ActionRequest {
	return ActionRequest{
		ProtocolVersion: ProtocolVersion,
		RequestID:       requestID,
		Requester: RequesterIdentity{
			UserID:  "user-1",
			AgentID: "agent-1",
			TaskID:  "task-1",
		},
		Target: LocalTarget(),
		Action: NewReadFileAction(ReadFileInput{
			Path: RootedPath{
				RootID:       "workspace",
				RelativePath: "report.txt",
			},
			MaximumBytes: 4096,
		}),
	}
}

func testUnixListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	temporaryRoot, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	directory, err := os.MkdirTemp(temporaryRoot, "action-broker-go-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "broker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		t.Fatalf("Chmod socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, socketPath
}

func serveOne(t *testing.T, listener net.Listener, handler func(net.Conn) error) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		done <- handler(connection)
	}()
	return done
}

func requireClientCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", code)
	}
	var clientError *ClientError
	if !errors.As(err, &clientError) || clientError.Code != code {
		t.Fatalf("expected %s ClientError, got %T %v", code, err, err)
	}
}
