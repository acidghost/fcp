package host

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/acidghost/fcp/internal/auth"
	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/control"
	"github.com/acidghost/fcp/internal/protocol"
)

func TestAuthOK(t *testing.T) {
	token := strings.Repeat("a", auth.TokenHexLength)
	daemon := &Daemon{cfg: Config{AuthToken: token}}
	if !daemon.authOK(strings.ToUpper(token)) {
		t.Fatal("authOK rejected equivalent uppercase token")
	}
	if daemon.authOK(strings.Repeat("b", auth.TokenHexLength)) {
		t.Fatal("authOK accepted wrong token")
	}
	if daemon.authOK("not-a-token") {
		t.Fatal("authOK accepted malformed token")
	}

	noAuthDaemon := &Daemon{cfg: Config{NoAuth: true}}
	if !noAuthDaemon.authOK("") {
		t.Fatal("authOK rejected empty token in no-auth mode")
	}
}

func TestTopLevelRequestsRequireAuth(t *testing.T) {
	token := strings.Repeat("a", auth.TokenHexLength)
	d := newTestDaemon(token)

	msg := sendOneShot(t, d, protocol.ListRequest{})
	listResp, ok := msg.(protocol.ListResponse)
	if !ok || listResp.Success || listResp.Error != "unauthorized" {
		t.Fatalf("unauthorized ListRequest response = %#v", msg)
	}

	msg = sendOneShot(t, d, protocol.ListRequest{AuthToken: token})
	listResp, ok = msg.(protocol.ListResponse)
	if !ok || !listResp.Success {
		t.Fatalf("authorized ListRequest response = %#v", msg)
	}

	msg = sendOneShot(t, d, protocol.OpenURL{URL: "http://localhost:3000"})
	openAck, ok := msg.(protocol.OpenURLAck)
	if !ok || openAck.Success || openAck.Error != "unauthorized" {
		t.Fatalf("unauthorized OpenURL response = %#v", msg)
	}

	msg = sendOneShot(t, d, protocol.Unforward{Port: 3000})
	unforwardAck, ok := msg.(protocol.UnforwardAck)
	if !ok || unforwardAck.Success || unforwardAck.Error != "unauthorized" {
		t.Fatalf("unauthorized Unforward response = %#v", msg)
	}

	msg = sendOneShot(t, d, protocol.Unforward{Port: 3000, AuthToken: token})
	unforwardAck, ok = msg.(protocol.UnforwardAck)
	if !ok || unforwardAck.Success || unforwardAck.Error != "" {
		t.Fatalf("authorized missing Unforward response = %#v", msg)
	}

	msg = sendOneShot(t, d, protocol.Shutdown{AuthToken: strings.Repeat("b", auth.TokenHexLength)})
	shutdownAck, ok := msg.(protocol.ShutdownAck)
	if !ok || shutdownAck.Success || shutdownAck.Error != "unauthorized" {
		t.Fatalf("unauthorized Shutdown response = %#v", msg)
	}
}

func TestShutdownAckSuccessClosesShutdown(t *testing.T) {
	token := strings.Repeat("a", auth.TokenHexLength)
	d := newTestDaemon(token)
	msg := sendOneShot(t, d, protocol.Shutdown{AuthToken: token})
	ack, ok := msg.(protocol.ShutdownAck)
	if !ok || !ack.Success {
		t.Fatalf("shutdown response = %#v", msg)
	}
	select {
	case <-d.shutdown:
	case <-time.After(time.Second):
		t.Fatal("shutdown channel was not closed")
	}
}

func TestDataHandshakeRequiresProof(t *testing.T) {
	token := strings.Repeat("a", auth.TokenHexLength)
	d := newTestDaemon(token)
	if dataHandshakeResolved(t, d, protocol.ConnectReady{ConnID: "conn-1", Proof: strings.Repeat("b", auth.TokenHexLength)}) {
		t.Fatal("invalid data handshake proof resolved pending connection")
	}
	proof, err := auth.DataHandshakeProof(token, "conn-2")
	if err != nil {
		t.Fatal(err)
	}
	if !dataHandshakeResolved(t, d, protocol.ConnectReady{ConnID: "conn-2", Proof: proof}) {
		t.Fatal("valid data handshake proof did not resolve pending connection")
	}
}

func TestDataHandshakeAllowsMissingProofInNoAuthMode(t *testing.T) {
	d := newTestDaemon("")
	d.cfg.NoAuth = true
	if !dataHandshakeResolved(t, d, protocol.ConnectReady{ConnID: "conn-1"}) {
		t.Fatal("no-auth data handshake without proof did not resolve pending connection")
	}
}

func TestRunRejectsUnsafeNoAuthNonLoopbackBind(t *testing.T) {
	err := Run(context.Background(), Config{ControlPort: 1, DataPort: 2, BindAddr: net.ParseIP("0.0.0.0"), NoAuth: true})
	if err == nil || !strings.Contains(err.Error(), "refusing --no-auth") {
		t.Fatalf("Run() err = %v, want unsafe no-auth refusal", err)
	}
}

func TestHostReverseProxyPipeline(t *testing.T) {
	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if isListenSandboxError(err) {
			t.Skipf("network sandbox does not permit listening sockets: %v", err)
		}
		t.Fatal(err)
	}
	defer echoLn.Close()
	containerPort := uint16(echoLn.Addr().(*net.TCPAddr).Port) //nolint:gosec // TCPAddr.Port is always in 0..65535.
	go runEchoServer(echoLn)

	controlPort := freePort(t)
	dataPort := freePort(t)
	ctx := t.Context()
	controlReady := make(chan net.Addr, 1)
	dataReady := make(chan net.Addr, 1)
	go func() {
		err := Run(ctx, Config{ControlPort: controlPort, DataPort: dataPort, BindAddr: net.ParseIP("127.0.0.1"), NoAuth: true, ControlReady: controlReady, DataReady: dataReady})
		if err != nil {
			t.Errorf("host Run: %v", err)
		}
	}()
	<-controlReady
	<-dataReady

	ctrl, err := control.DialTCP(net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(controlPort)}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	if err := ctrl.Send(protocol.Register{ContainerID: "test-container", Hostname: "test", AuthToken: ""}); err != nil {
		t.Fatal(err)
	}
	msg, err := ctrl.Recv()
	if err != nil {
		t.Fatal(err)
	}
	ack, ok := msg.(protocol.RegisterAck)
	if !ok || !ack.Success {
		t.Fatalf("register response = %#v", msg)
	}
	if err := ctrl.Send(protocol.Forward{Port: containerPort, Protocol: protocol.ProtocolTCP}); err != nil {
		t.Fatal(err)
	}
	msg, err = ctrl.Recv()
	if err != nil {
		t.Fatal(err)
	}
	fwdAck, ok := msg.(protocol.ForwardAck)
	if !ok || !fwdAck.Success || fwdAck.HostPort == 0 {
		t.Fatalf("forward response = %#v", msg)
	}
	go fakeContainerControlLoop(t, ctrl, dataPort)

	client, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(fwdAck.HostPort))), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want hello", string(buf))
	}
}

func newTestDaemon(token string) *Daemon {
	return &Daemon{
		cfg:           Config{AuthToken: token},
		browser:       NewBrowserOpener(""),
		shutdown:      make(chan struct{}),
		containers:    map[string]*containerState{},
		usedHostPorts: map[uint16]string{},
		pending:       map[string]chan dataStream{},
		earlyData:     map[string]dataStream{},
		sockets:       map[string]SocketInfo{},
	}
}

func sendOneShot(t *testing.T, d *Daemon, msg protocol.Message) protocol.Message {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go d.handleControl(control.NewConnection(server))
	conn := control.NewConnection(client)
	if err := conn.Send(msg); err != nil {
		t.Fatal(err)
	}
	resp, err := conn.Recv()
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func dataHandshakeResolved(t *testing.T, d *Daemon, ready protocol.ConnectReady) bool {
	t.Helper()
	ch, ok := d.registerPending(ready.ConnID)
	if !ok {
		t.Fatal("registerPending failed")
	}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		d.handleDataConnection(server)
		close(done)
	}()
	if err := control.WriteMessage(client, ready); err != nil {
		t.Fatal(err)
	}
	select {
	case ds := <-ch:
		_ = ds.conn.Close()
		_ = client.Close()
		<-done
		return true
	case <-time.After(100 * time.Millisecond):
		_ = client.Close()
		d.cancelPending(ready.ConnID)
		<-done
		return false
	}
}

func TestHostUnixSocketEarlyDataPipeline(t *testing.T) {
	tmp := t.TempDir()
	socketPath := filepath.Join(tmp, "host.sock")
	echoLn, err := net.Listen("unix", socketPath)
	if err != nil {
		if isListenSandboxError(err) {
			t.Skipf("network sandbox does not permit unix sockets: %v", err)
		}
		t.Skipf("unix sockets unavailable in this sandbox: %v", err)
	}
	defer echoLn.Close()
	go runEchoServer(echoLn)

	controlPort := freePort(t)
	dataPort := freePort(t)
	ctx := t.Context()
	controlReady := make(chan net.Addr, 1)
	dataReady := make(chan net.Addr, 1)
	go func() {
		err := Run(ctx, Config{
			ControlPort:  controlPort,
			DataPort:     dataPort,
			BindAddr:     net.ParseIP("127.0.0.1"),
			NoAuth:       true,
			ControlReady: controlReady,
			DataReady:    dataReady,
			SocketForwarding: config.SocketForwardingConfig{
				Enabled:             true,
				WatchPaths:          []string{socketPath},
				ContainerPathPrefix: filepath.Join(tmp, "mirrors"),
				ScanIntervalMillis:  10,
				MaxSocketForwards:   4,
			},
		})
		if err != nil {
			t.Errorf("host Run: %v", err)
		}
	}()
	<-controlReady
	<-dataReady

	ctrl, err := control.DialTCP(net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(controlPort)}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	if err := ctrl.Send(protocol.Register{ContainerID: "test-container", Hostname: "test", AuthToken: ""}); err != nil {
		t.Fatal(err)
	}
	msg := recvControlMessage(t, ctrl, time.Second)
	ack, ok := msg.(protocol.RegisterAck)
	if !ok || !ack.Success {
		t.Fatalf("register response = %#v", msg)
	}
	msg = recvControlMessage(t, ctrl, time.Second)
	socketForward, ok := msg.(protocol.SocketForward)
	if !ok {
		t.Fatalf("socket forward = %#v", msg)
	}
	if socketForward.HostPath != socketPath {
		t.Fatalf("host socket path = %q, want %q", socketForward.HostPath, socketPath)
	}

	data, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(dataPort))), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	connID := "conn-early"
	if err := control.WriteMessage(data, protocol.ConnectReady{ConnID: connID}); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Send(protocol.SocketConnectRequest{SocketID: socketForward.SocketID, ConnID: connID}); err != nil {
		t.Fatal(err)
	}
	if err := data.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(data, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want hello", string(buf))
	}
}

func fakeContainerControlLoop(t *testing.T, ctrl *control.Connection, dataPort uint16) {
	t.Helper()
	for {
		msg, err := ctrl.Recv()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case protocol.Ping:
			_ = ctrl.Send(protocol.Pong{})
		case protocol.ConnectRequest:
			go fakeContainerData(t, m, dataPort)
		}
	}
}

func fakeContainerData(t *testing.T, req protocol.ConnectRequest, dataPort uint16) {
	t.Helper()
	local, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(req.Port))), time.Second)
	if err != nil {
		t.Errorf("dial local: %v", err)
		return
	}
	defer local.Close()
	data, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(dataPort))), time.Second)
	if err != nil {
		t.Errorf("dial data: %v", err)
		return
	}
	defer data.Close()
	if err := control.WriteMessage(data, protocol.ConnectReady{ConnID: req.ConnID}); err != nil {
		t.Errorf("write ConnectReady: %v", err)
		return
	}
	_ = bridge(local, data, nil)
}

func runEchoServer(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}(conn)
	}
}

func recvControlMessage(t *testing.T, ctrl *control.Connection, timeout time.Duration) protocol.Message {
	t.Helper()
	type result struct {
		msg protocol.Message
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, err := ctrl.Recv()
		ch <- result{msg: msg, err: err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatal(res.err)
		}
		return res.msg
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for control message")
		return nil
	}
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if isListenSandboxError(err) {
			t.Skipf("network sandbox does not permit listening sockets: %v", err)
		}
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // TCPAddr.Port is always in 0..65535.
}

func isListenSandboxError(err error) bool {
	return strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied")
}
