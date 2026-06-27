package container

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/acidghost/fcp/internal/control"
	"github.com/acidghost/fcp/internal/log"
	"github.com/acidghost/fcp/internal/protocol"
)

const maxUnixSocketPath = 108

type MirrorSocket struct {
	SocketID      string
	ContainerPath string
	Listener      net.Listener
	Stop          chan struct{}
}

type RelayMessage struct {
	Msg protocol.Message
	Ack chan struct{}
}

func CreateMirrorSocket(socketID, containerPath string) (*MirrorSocket, error) {
	log.Debug("creating mirror socket", "socketID", socketID, "path", containerPath)
	if !filepath.IsAbs(containerPath) {
		return nil, fmt.Errorf("container socket path is not absolute: %s", containerPath)
	}
	if len(containerPath) > maxUnixSocketPath {
		return nil, fmt.Errorf("container socket path too long: %d > %d", len(containerPath), maxUnixSocketPath)
	}
	if err := os.MkdirAll(filepath.Dir(containerPath), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(containerPath)
	ln, err := net.Listen("unix", containerPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(containerPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return &MirrorSocket{SocketID: socketID, ContainerPath: containerPath, Listener: ln, Stop: make(chan struct{})}, nil
}

func RemoveMirrorSocket(m *MirrorSocket) {
	if m == nil {
		return
	}
	log.Debug("removing mirror socket", "socketID", m.SocketID, "path", m.ContainerPath)
	_ = m.Listener.Close()
	_ = os.Remove(m.ContainerPath)
	_ = os.Remove(filepath.Dir(m.ContainerPath))
}

func RunMirrorAcceptLoop(m *MirrorSocket, relay chan<- RelayMessage, dataAddr net.Addr, authToken string) {
	log.Info("mirror socket accept loop started", "socketID", m.SocketID, "path", m.ContainerPath)
	for {
		conn, err := m.Listener.Accept()
		if err != nil {
			select {
			case <-m.Stop:
				return
			default:
				return
			}
		}
		go handleMirrorClient(m.SocketID, conn, relay, dataAddr, authToken)
	}
}

func handleMirrorClient(socketID string, unixConn net.Conn, relay chan<- RelayMessage, dataAddr net.Addr, authToken string) {
	defer unixConn.Close()
	log.Debug("handling mirror client", "socketID", socketID)
	connID := newConnID()
	ack := make(chan struct{})
	select {
	case relay <- RelayMessage{Msg: protocol.SocketConnectRequest{SocketID: socketID, ConnID: connID}, Ack: ack}:
	case <-time.After(5 * time.Second):
		return
	}
	select {
	case <-ack:
	case <-time.After(5 * time.Second):
		return
	}
	dataConn, err := net.DialTimeout(dataAddr.Network(), dataAddr.String(), 5*time.Second)
	if err != nil {
		return
	}
	defer dataConn.Close()
	ready, err := connectReady(connID, authToken)
	if err != nil {
		return
	}
	if err := control.WriteMessage(dataConn, ready); err != nil {
		return
	}
	_ = copyBoth(unixConn, dataConn)
}

func copyBoth(a, b net.Conn) error {
	type result struct{ err error }
	ab := make(chan result, 1)
	ba := make(chan result, 1)
	go func() {
		_, err := io.Copy(b, a)
		closeWrite(b)
		ab <- result{err: err}
	}()
	go func() {
		_, err := io.Copy(a, b)
		closeWrite(a)
		ba <- result{err: err}
	}()
	r1 := <-ab
	r2 := <-ba
	if r1.err != nil && !benignCopyErr(r1.err) {
		return r1.err
	}
	if r2.err != nil && !benignCopyErr(r2.err) {
		return r2.err
	}
	return nil
}

func closeWrite(conn net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

func benignCopyErr(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset")
}
