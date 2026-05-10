package control

import (
	"bufio"
	"bytes"
	"errors"
	"testing"

	"github.com/acidghost/fcp/internal/protocol"
)

func TestReadWriteMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, protocol.Ping{}); err != nil {
		t.Fatal(err)
	}
	msg, err := ReadMessage(bufio.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.(protocol.Ping); !ok {
		t.Fatalf("decoded %T, want protocol.Ping", msg)
	}
}

func TestReadMessageEOF(t *testing.T) {
	_, err := ReadMessage(bufio.NewReader(bytes.NewReader(nil)))
	if !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("error = %v, want ErrConnectionClosed", err)
	}
}

func TestReadMessageRejectsOversizedLine(t *testing.T) {
	payload := bytes.Repeat([]byte{'a'}, MaxMessageSize+1)
	payload = append(payload, '\n')
	_, err := ReadMessage(bufio.NewReader(bytes.NewReader(payload)))
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("error = %v, want ErrMessageTooLarge", err)
	}
}
