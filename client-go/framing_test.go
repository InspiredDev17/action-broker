package actionbroker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestWriteFrameHandlesShortWrites(t *testing.T) {
	writer := &oneByteWriter{}
	if err := writeFrame(writer, []byte("payload")); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if len(writer.data) != 11 || binary.BigEndian.Uint32(writer.data[:4]) != 7 || string(writer.data[4:]) != "payload" {
		t.Fatalf("unexpected frame: %x", writer.data)
	}
}

func TestReadFrameRejectsTruncation(t *testing.T) {
	header := [4]byte{}
	binary.BigEndian.PutUint32(header[:], 5)
	_, err := readFrame(bytes.NewReader(append(header[:], []byte("ab")...)))
	var clientError *ClientError
	if !errors.As(err, &clientError) || clientError.Code != ErrorTruncatedFrame {
		t.Fatalf("expected truncated frame, got %T %v", err, err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF cause, got %v", err)
	}
}

func TestWriteFrameClassifiesFullPayloadWriteWithErrorAsUnknownDelivery(t *testing.T) {
	writer := &payloadCompletionErrorWriter{}
	err := writeFrame(writer, []byte("payload"))
	var clientError *ClientError
	if !errors.As(err, &clientError) || clientError.Code != ErrorOutcomeUnknown {
		t.Fatalf("expected unknown outcome, got %T %v", err, err)
	}
	var uncertain *frameDeliveryUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("expected uncertain-delivery cause, got %T %v", err, err)
	}
}

type oneByteWriter struct {
	data []byte
}

type payloadCompletionErrorWriter struct {
	writes int
}

func (writer *payloadCompletionErrorWriter) Write(payload []byte) (int, error) {
	writer.writes++
	if writer.writes == 1 {
		return len(payload), nil
	}
	return len(payload), io.ErrClosedPipe
}

func (writer *oneByteWriter) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	writer.data = append(writer.data, payload[0])
	return 1, nil
}
