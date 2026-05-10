package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	MaxURLLength        = 2048
	MaxSocketPathLength = 4096

	TypeRegister             = "Register"
	TypeRegisterAck          = "RegisterAck"
	TypeForward              = "Forward"
	TypeForwardAck           = "ForwardAck"
	TypeUnforward            = "Unforward"
	TypeConnectRequest       = "ConnectRequest"
	TypeConnectReady         = "ConnectReady"
	TypeConnectFailed        = "ConnectFailed"
	TypeOpenURL              = "OpenUrl"
	TypeOpenURLAck           = "OpenUrlAck"
	TypePing                 = "Ping"
	TypePong                 = "Pong"
	TypeListRequest          = "ListRequest"
	TypeListResponse         = "ListResponse"
	TypeSocketForward        = "SocketForward"
	TypeSocketUnforward      = "SocketUnforward"
	TypeSocketConnectRequest = "SocketConnectRequest"
	TypeShutdown             = "Shutdown"
)

type Protocol string

const ProtocolTCP Protocol = "Tcp"

type Message interface {
	messageType() string
}

type Register struct {
	ContainerID string
	Hostname    string
	AuthToken   string
}

func (Register) messageType() string { return TypeRegister }

type RegisterAck struct {
	Success bool
}

func (RegisterAck) messageType() string { return TypeRegisterAck }

type Forward struct {
	Port        uint16
	Protocol    Protocol
	ProcessName *string
	PID         *uint32
}

func (Forward) messageType() string { return TypeForward }

type ForwardAck struct {
	Port     uint16
	Success  bool
	HostPort uint16
}

func (ForwardAck) messageType() string { return TypeForwardAck }

type Unforward struct {
	Port uint16
}

func (Unforward) messageType() string { return TypeUnforward }

type ConnectRequest struct {
	Port   uint16
	ConnID string
}

func (ConnectRequest) messageType() string { return TypeConnectRequest }

type ConnectReady struct {
	ConnID string
}

func (ConnectReady) messageType() string { return TypeConnectReady }

type ConnectFailed struct {
	ConnID string
	Error  string
}

func (ConnectFailed) messageType() string { return TypeConnectFailed }

type OpenURL struct {
	URL string
}

func (OpenURL) messageType() string { return TypeOpenURL }

type OpenURLAck struct {
	Success bool
}

func (OpenURLAck) messageType() string { return TypeOpenURLAck }

type Ping struct{}

func (Ping) messageType() string { return TypePing }

type Pong struct{}

func (Pong) messageType() string { return TypePong }

type ListRequest struct{}

func (ListRequest) messageType() string { return TypeListRequest }

type ForwardInfo struct {
	ContainerID string   `json:"container_id"`
	Hostname    string   `json:"hostname"`
	Port        uint16   `json:"port"`
	HostPort    uint16   `json:"host_port"`
	Protocol    Protocol `json:"protocol"`
	ProcessName *string  `json:"process_name"`
	PID         *uint32  `json:"pid"`
	Since       string   `json:"since"`
}

type SocketForwardInfo struct {
	SocketID      string `json:"socket_id"`
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
}

type ListResponse struct {
	Forwards       []ForwardInfo       `json:"forwards"`
	SocketForwards []SocketForwardInfo `json:"socket_forwards"`
}

func (ListResponse) messageType() string { return TypeListResponse }

type SocketForward struct {
	SocketID      string
	HostPath      string
	ContainerPath string
}

func (SocketForward) messageType() string { return TypeSocketForward }

type SocketUnforward struct {
	SocketID string
}

func (SocketUnforward) messageType() string { return TypeSocketUnforward }

type SocketConnectRequest struct {
	SocketID string
	ConnID   string
}

func (SocketConnectRequest) messageType() string { return TypeSocketConnectRequest }

type Shutdown struct {
	AuthToken string
}

func (Shutdown) messageType() string { return TypeShutdown }

var ErrInvalidURL = errors.New("invalid URL")

func ValidateOpenURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("%w: URL is empty", ErrInvalidURL)
	}
	if len(rawURL) > MaxURLLength {
		return fmt.Errorf("%w: URL too long: %d chars exceeds %d char limit", ErrInvalidURL, len(rawURL), MaxURLLength)
	}
	for _, r := range rawURL {
		if r >= 0 && r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: URL contains ASCII control characters", ErrInvalidURL)
		}
	}
	lower := strings.ToLower(rawURL)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return fmt.Errorf("%w: only http:// and https:// URLs are allowed", ErrInvalidURL)
	}
	return nil
}

func MarshalMessage(msg Message) ([]byte, error) {
	switch m := msg.(type) {
	case Register:
		//nolint:gosec // auth_token is part of the on-wire protocol, not a hardcoded secret.
		return json.Marshal(struct {
			Type        string `json:"type"`
			ContainerID string `json:"container_id"`
			Hostname    string `json:"hostname"`
			AuthToken   string `json:"auth_token"`
		}{TypeRegister, m.ContainerID, m.Hostname, m.AuthToken})
	case *Register:
		return MarshalMessage(*m)
	case RegisterAck:
		return json.Marshal(struct {
			Type    string `json:"type"`
			Success bool   `json:"success"`
		}{TypeRegisterAck, m.Success})
	case *RegisterAck:
		return MarshalMessage(*m)
	case Forward:
		return json.Marshal(struct {
			Type        string   `json:"type"`
			Port        uint16   `json:"port"`
			Protocol    Protocol `json:"protocol"`
			ProcessName *string  `json:"process_name"`
			PID         *uint32  `json:"pid"`
		}{TypeForward, m.Port, m.Protocol, m.ProcessName, m.PID})
	case *Forward:
		return MarshalMessage(*m)
	case ForwardAck:
		return json.Marshal(struct {
			Type     string `json:"type"`
			Port     uint16 `json:"port"`
			Success  bool   `json:"success"`
			HostPort uint16 `json:"host_port"`
		}{TypeForwardAck, m.Port, m.Success, m.HostPort})
	case *ForwardAck:
		return MarshalMessage(*m)
	case Unforward:
		return json.Marshal(struct {
			Type string `json:"type"`
			Port uint16 `json:"port"`
		}{TypeUnforward, m.Port})
	case *Unforward:
		return MarshalMessage(*m)
	case ConnectRequest:
		return json.Marshal(struct {
			Type   string `json:"type"`
			Port   uint16 `json:"port"`
			ConnID string `json:"conn_id"`
		}{TypeConnectRequest, m.Port, m.ConnID})
	case *ConnectRequest:
		return MarshalMessage(*m)
	case ConnectReady:
		return json.Marshal(struct {
			Type   string `json:"type"`
			ConnID string `json:"conn_id"`
		}{TypeConnectReady, m.ConnID})
	case *ConnectReady:
		return MarshalMessage(*m)
	case ConnectFailed:
		return json.Marshal(struct {
			Type   string `json:"type"`
			ConnID string `json:"conn_id"`
			Error  string `json:"error"`
		}{TypeConnectFailed, m.ConnID, m.Error})
	case *ConnectFailed:
		return MarshalMessage(*m)
	case OpenURL:
		return json.Marshal(struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		}{TypeOpenURL, m.URL})
	case *OpenURL:
		return MarshalMessage(*m)
	case OpenURLAck:
		return json.Marshal(struct {
			Type    string `json:"type"`
			Success bool   `json:"success"`
		}{TypeOpenURLAck, m.Success})
	case *OpenURLAck:
		return MarshalMessage(*m)
	case Ping, *Ping:
		return json.Marshal(struct {
			Type string `json:"type"`
		}{TypePing})
	case Pong, *Pong:
		return json.Marshal(struct {
			Type string `json:"type"`
		}{TypePong})
	case ListRequest, *ListRequest:
		return json.Marshal(struct {
			Type string `json:"type"`
		}{TypeListRequest})
	case ListResponse:
		return json.Marshal(struct {
			Type           string              `json:"type"`
			Forwards       []ForwardInfo       `json:"forwards"`
			SocketForwards []SocketForwardInfo `json:"socket_forwards"`
		}{TypeListResponse, nonNilForwards(m.Forwards), nonNilSocketForwards(m.SocketForwards)})
	case *ListResponse:
		return MarshalMessage(*m)
	case SocketForward:
		return json.Marshal(struct {
			Type          string `json:"type"`
			SocketID      string `json:"socket_id"`
			HostPath      string `json:"host_path"`
			ContainerPath string `json:"container_path"`
		}{TypeSocketForward, m.SocketID, m.HostPath, m.ContainerPath})
	case *SocketForward:
		return MarshalMessage(*m)
	case SocketUnforward:
		return json.Marshal(struct {
			Type     string `json:"type"`
			SocketID string `json:"socket_id"`
		}{TypeSocketUnforward, m.SocketID})
	case *SocketUnforward:
		return MarshalMessage(*m)
	case SocketConnectRequest:
		return json.Marshal(struct {
			Type     string `json:"type"`
			SocketID string `json:"socket_id"`
			ConnID   string `json:"conn_id"`
		}{TypeSocketConnectRequest, m.SocketID, m.ConnID})
	case *SocketConnectRequest:
		return MarshalMessage(*m)
	case Shutdown:
		//nolint:gosec // auth_token is part of the on-wire protocol, not a hardcoded secret.
		return json.Marshal(struct {
			Type      string `json:"type"`
			AuthToken string `json:"auth_token"`
		}{TypeShutdown, m.AuthToken})
	case *Shutdown:
		return MarshalMessage(*m)
	default:
		return nil, fmt.Errorf("unknown protocol message type %T", msg)
	}
}

func UnmarshalMessage(data []byte) (Message, error) {
	var header struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, err
	}

	switch header.Type {
	case TypeRegister:
		var wire struct {
			Type        string `json:"type"`
			ContainerID string `json:"container_id"`
			Hostname    string `json:"hostname"`
			AuthToken   string `json:"auth_token"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return Register{ContainerID: wire.ContainerID, Hostname: wire.Hostname, AuthToken: wire.AuthToken}, nil
	case TypeRegisterAck:
		var wire struct {
			Type    string `json:"type"`
			Success bool   `json:"success"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return RegisterAck{Success: wire.Success}, nil
	case TypeForward:
		var wire struct {
			Type        string   `json:"type"`
			Port        uint16   `json:"port"`
			Protocol    Protocol `json:"protocol"`
			ProcessName *string  `json:"process_name"`
			PID         *uint32  `json:"pid"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		if wire.Protocol != ProtocolTCP {
			return nil, fmt.Errorf("unsupported protocol %q", wire.Protocol)
		}
		return Forward{Port: wire.Port, Protocol: wire.Protocol, ProcessName: wire.ProcessName, PID: wire.PID}, nil
	case TypeForwardAck:
		var wire struct {
			Type     string `json:"type"`
			Port     uint16 `json:"port"`
			Success  bool   `json:"success"`
			HostPort uint16 `json:"host_port"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return ForwardAck{Port: wire.Port, Success: wire.Success, HostPort: wire.HostPort}, nil
	case TypeUnforward:
		var wire struct {
			Type string `json:"type"`
			Port uint16 `json:"port"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return Unforward{Port: wire.Port}, nil
	case TypeConnectRequest:
		var wire struct {
			Type   string `json:"type"`
			Port   uint16 `json:"port"`
			ConnID string `json:"conn_id"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return ConnectRequest{Port: wire.Port, ConnID: wire.ConnID}, nil
	case TypeConnectReady:
		var wire struct {
			Type   string `json:"type"`
			ConnID string `json:"conn_id"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return ConnectReady{ConnID: wire.ConnID}, nil
	case TypeConnectFailed:
		var wire struct {
			Type   string `json:"type"`
			ConnID string `json:"conn_id"`
			Error  string `json:"error"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return ConnectFailed{ConnID: wire.ConnID, Error: wire.Error}, nil
	case TypeOpenURL:
		var wire struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return OpenURL{URL: wire.URL}, nil
	case TypeOpenURLAck:
		var wire struct {
			Type    string `json:"type"`
			Success bool   `json:"success"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return OpenURLAck{Success: wire.Success}, nil
	case TypePing:
		if err := decodeStrict(data, &struct {
			Type string `json:"type"`
		}{}); err != nil {
			return nil, err
		}
		return Ping{}, nil
	case TypePong:
		if err := decodeStrict(data, &struct {
			Type string `json:"type"`
		}{}); err != nil {
			return nil, err
		}
		return Pong{}, nil
	case TypeListRequest:
		if err := decodeStrict(data, &struct {
			Type string `json:"type"`
		}{}); err != nil {
			return nil, err
		}
		return ListRequest{}, nil
	case TypeListResponse:
		var wire struct {
			Type           string              `json:"type"`
			Forwards       []ForwardInfo       `json:"forwards"`
			SocketForwards []SocketForwardInfo `json:"socket_forwards"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return ListResponse{Forwards: nonNilForwards(wire.Forwards), SocketForwards: nonNilSocketForwards(wire.SocketForwards)}, nil
	case TypeSocketForward:
		var wire struct {
			Type          string `json:"type"`
			SocketID      string `json:"socket_id"`
			HostPath      string `json:"host_path"`
			ContainerPath string `json:"container_path"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return SocketForward{SocketID: wire.SocketID, HostPath: wire.HostPath, ContainerPath: wire.ContainerPath}, nil
	case TypeSocketUnforward:
		var wire struct {
			Type     string `json:"type"`
			SocketID string `json:"socket_id"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return SocketUnforward{SocketID: wire.SocketID}, nil
	case TypeSocketConnectRequest:
		var wire struct {
			Type     string `json:"type"`
			SocketID string `json:"socket_id"`
			ConnID   string `json:"conn_id"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return SocketConnectRequest{SocketID: wire.SocketID, ConnID: wire.ConnID}, nil
	case TypeShutdown:
		var wire struct {
			Type      string `json:"type"`
			AuthToken string `json:"auth_token"`
		}
		if err := decodeStrict(data, &wire); err != nil {
			return nil, err
		}
		return Shutdown{AuthToken: wire.AuthToken}, nil
	default:
		return nil, fmt.Errorf("unknown message type %q", header.Type)
	}
}

func SerializeMessage(msg Message) (string, error) {
	data, err := MarshalMessage(msg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func DeserializeMessage(text string) (Message, error) {
	return UnmarshalMessage([]byte(text))
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values in message")
		}
		return err
	}
	return nil
}

func nonNilForwards(in []ForwardInfo) []ForwardInfo {
	if in == nil {
		return []ForwardInfo{}
	}
	return in
}

func nonNilSocketForwards(in []SocketForwardInfo) []SocketForwardInfo {
	if in == nil {
		return []SocketForwardInfo{}
	}
	return in
}
