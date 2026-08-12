package actionbroker

import (
	"encoding/binary"
	"errors"
	"io"
)

// MaxFrameSize is the maximum request or response JSON payload accepted by the
// local protocol.
const MaxFrameSize uint32 = 1 << 20

func writeFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return clientError(ErrorInvalidRequest, "write_frame", "empty request frame", nil)
	}
	if uint64(len(payload)) > uint64(MaxFrameSize) {
		frameErr := &FrameError{
			Direction: "request",
			Size:      boundedUint32(len(payload)),
			Maximum:   MaxFrameSize,
		}
		return clientError(ErrorFrameTooLarge, "write_frame", "request frame exceeds the protocol limit", frameErr)
	}

	header := [4]byte{}
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return clientError(ErrorWrite, "write_frame", "could not write request header", err)
	}
	if err := writeAll(writer, payload); err != nil {
		var progress *writeProgressError
		if errors.As(err, &progress) && progress.written == progress.expected {
			return clientError(ErrorOutcomeUnknown, "write_frame", "complete request payload may have been delivered", &frameDeliveryUncertainError{cause: err})
		}
		return clientError(ErrorWrite, "write_frame", "could not write complete request payload", err)
	}
	return nil
}

func readFrame(reader io.Reader) ([]byte, error) {
	header := [4]byte{}
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, classifyTruncatedRead("response header", err)
	}

	length := binary.BigEndian.Uint32(header[:])
	if length == 0 {
		return nil, clientError(ErrorMalformedResponse, "read_frame", "response frame is empty", nil)
	}
	if length > MaxFrameSize {
		frameErr := &FrameError{
			Direction: "response",
			Size:      length,
			Maximum:   MaxFrameSize,
		}
		return nil, clientError(ErrorFrameTooLarge, "read_frame", "response frame exceeds the protocol limit", frameErr)
	}

	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, classifyTruncatedRead("response payload", err)
	}
	return payload, nil
}

func classifyTruncatedRead(part string, err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return clientError(ErrorTruncatedFrame, "read_frame", part+" was truncated", err)
	}
	return clientError(ErrorRead, "read_frame", "could not read "+part, err)
}

func writeAll(writer io.Writer, payload []byte) error {
	expected := len(payload)
	writtenTotal := 0
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if written < 0 || written > len(payload) {
			return &writeProgressError{written: writtenTotal, expected: expected, cause: io.ErrShortWrite}
		}
		writtenTotal += written
		payload = payload[written:]
		if err != nil {
			return &writeProgressError{written: writtenTotal, expected: expected, cause: err}
		}
		if written == 0 {
			return &writeProgressError{written: writtenTotal, expected: expected, cause: io.ErrShortWrite}
		}
	}
	return nil
}

type writeProgressError struct {
	written  int
	expected int
	cause    error
}

func (e *writeProgressError) Error() string { return "framed write did not report clean completion" }

func (e *writeProgressError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type frameDeliveryUncertainError struct {
	cause error
}

func (e *frameDeliveryUncertainError) Error() string {
	return "complete request frame may have been delivered"
}

func (e *frameDeliveryUncertainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func boundedUint32(size int) uint32 {
	if uint64(size) > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(size)
}
