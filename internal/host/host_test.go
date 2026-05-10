package host

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/acidghost/fcp/internal/control"
	"github.com/acidghost/fcp/internal/protocol"
)

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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
