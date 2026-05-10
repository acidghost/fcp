package protocol

import (
	"strings"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	name := "node"
	pid := uint32(1234)
	messages := []Message{
		Register{ContainerID: "abc123", Hostname: "dev", AuthToken: strings.Repeat("a", 64)},
		RegisterAck{Success: true},
		Forward{Port: 8080, Protocol: ProtocolTCP, ProcessName: &name, PID: &pid},
		ForwardAck{Port: 8080, Success: true, HostPort: 8081},
		Unforward{Port: 8080},
		ConnectRequest{Port: 8080, ConnID: "conn-1"},
		ConnectReady{ConnID: "conn-1"},
		ConnectFailed{ConnID: "conn-1", Error: "refused"},
		OpenURL{URL: "http://localhost:8080/callback"},
		OpenURLAck{Success: true},
		Ping{},
		Pong{},
		ListRequest{},
		ListResponse{Forwards: []ForwardInfo{{ContainerID: "abc123", Hostname: "dev", Port: 8080, HostPort: 8081, Protocol: ProtocolTCP, ProcessName: &name, PID: &pid, Since: "1"}}, SocketForwards: []SocketForwardInfo{}},
		SocketForward{SocketID: "sock-1", HostPath: "/tmp/a.sock", ContainerPath: "/tmp/a.sock"},
		SocketUnforward{SocketID: "sock-1"},
		SocketConnectRequest{SocketID: "sock-1", ConnID: "conn-2"},
		Shutdown{AuthToken: strings.Repeat("b", 64)},
	}
	for _, msg := range messages {
		jsonText, err := SerializeMessage(msg)
		if err != nil {
			t.Fatalf("SerializeMessage(%T): %v", msg, err)
		}
		decoded, err := DeserializeMessage(jsonText)
		if err != nil {
			t.Fatalf("DeserializeMessage(%s): %v", jsonText, err)
		}
		if decoded.messageType() != msg.messageType() {
			t.Fatalf("decoded type %s, want %s", decoded.messageType(), msg.messageType())
		}
	}
}

func TestTaggedPingFormat(t *testing.T) {
	jsonText, err := SerializeMessage(Ping{})
	if err != nil {
		t.Fatal(err)
	}
	if jsonText != `{"type":"Ping"}` {
		t.Fatalf("unexpected ping JSON: %s", jsonText)
	}
}

func TestDeserializeRejectsUnknownFieldsAndBadPorts(t *testing.T) {
	cases := []string{
		`{"type":"Unknown"}`,
		`{"type":"Forward","port":8080,"protocol":"Tcp","process_name":null,"pid":null,"extra":"bad"}`,
		`{"type":"Forward","port":-1,"protocol":"Tcp","process_name":null,"pid":null}`,
		`{"type":"Forward","port":70000,"protocol":"Tcp","process_name":null,"pid":null}`,
	}
	for _, tc := range cases {
		if _, err := DeserializeMessage(tc); err == nil {
			t.Fatalf("DeserializeMessage(%s) succeeded, want error", tc)
		}
	}
}

func TestValidateOpenURL(t *testing.T) {
	valid := []string{"http://localhost:8080/path", "https://example.com/callback", "HTTP://example.com"}
	for _, raw := range valid {
		if err := ValidateOpenURL(raw); err != nil {
			t.Fatalf("ValidateOpenURL(%q): %v", raw, err)
		}
	}
	invalid := []string{"", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "http://example.com/\nInjected"}
	for _, raw := range invalid {
		if err := ValidateOpenURL(raw); err == nil {
			t.Fatalf("ValidateOpenURL(%q) succeeded, want error", raw)
		}
	}
}
