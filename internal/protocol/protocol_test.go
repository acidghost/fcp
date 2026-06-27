package protocol

import (
	"encoding/json"
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
		UnforwardAck{Port: 8080, Success: true},
		ConnectRequest{Port: 8080, ConnID: "conn-1"},
		ConnectReady{ConnID: "conn-1", Proof: strings.Repeat("c", 64)},
		ConnectFailed{ConnID: "conn-1", Error: "refused"},
		OpenURL{URL: "http://localhost:8080/callback"},
		OpenURLAck{Success: true},
		Ping{},
		Pong{},
		ListRequest{},
		ListResponse{Success: true, Forwards: []ForwardInfo{{ContainerID: "abc123", Hostname: "dev", Port: 8080, HostPort: 8081, Protocol: ProtocolTCP, ProcessName: &name, PID: &pid, Since: "1"}}, SocketForwards: []SocketForwardInfo{}},
		SocketForward{SocketID: "sock-1", HostPath: "/tmp/a.sock", ContainerPath: "/tmp/a.sock"},
		SocketUnforward{SocketID: "sock-1"},
		SocketConnectRequest{SocketID: "sock-1", ConnID: "conn-2"},
		Shutdown{AuthToken: strings.Repeat("b", 64)},
		ShutdownAck{Success: true},
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

func TestStandaloneAuthFieldsRoundTrip(t *testing.T) {
	token := strings.Repeat("a", 64)
	messages := []Message{
		ListRequest{AuthToken: token},
		OpenURL{URL: "http://localhost:3000", AuthToken: token},
		Unforward{Port: 3000, AuthToken: token},
	}
	for _, msg := range messages {
		jsonText, err := SerializeMessage(msg)
		if err != nil {
			t.Fatalf("SerializeMessage(%T): %v", msg, err)
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(jsonText), &raw); err != nil {
			t.Fatal(err)
		}
		if raw["auth_token"] != token {
			t.Fatalf("%T auth_token = %v, want token in %s", msg, raw["auth_token"], jsonText)
		}
		decoded, err := DeserializeMessage(jsonText)
		if err != nil {
			t.Fatalf("DeserializeMessage(%s): %v", jsonText, err)
		}
		switch got := decoded.(type) {
		case ListRequest:
			if got.AuthToken != token {
				t.Fatalf("ListRequest auth token = %q", got.AuthToken)
			}
		case OpenURL:
			if got.AuthToken != token {
				t.Fatalf("OpenURL auth token = %q", got.AuthToken)
			}
		case Unforward:
			if got.AuthToken != token {
				t.Fatalf("Unforward auth token = %q", got.AuthToken)
			}
		default:
			t.Fatalf("decoded type = %T", decoded)
		}
	}
}

func TestEmptyAuthFieldsOmitted(t *testing.T) {
	messages := []Message{
		ListRequest{},
		OpenURL{URL: "http://localhost:3000"},
		Unforward{Port: 3000},
	}
	for _, msg := range messages {
		jsonText, err := SerializeMessage(msg)
		if err != nil {
			t.Fatalf("SerializeMessage(%T): %v", msg, err)
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(jsonText), &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw["auth_token"]; ok {
			t.Fatalf("%T serialized empty auth_token in %s", msg, jsonText)
		}
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
