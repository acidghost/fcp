package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/control"
	"github.com/acidghost/fcp/internal/log"
	"github.com/acidghost/fcp/internal/protocol"
)

const (
	maxContainers           = 64
	maxForwardsPerContainer = 128
	maxPendingConnections   = 1024
	connectTimeout          = 10 * time.Second
	dataHandshakeTimeout    = 10 * time.Second
	firstMessageTimeout     = 30 * time.Second
	heartbeatInterval       = 30 * time.Second
	maxMissedPongs          = 3
)

type Config struct {
	ControlPort      uint16
	DataPort         uint16
	BindAddr         net.IP
	NoDockerDetect   bool
	ExitOnIdle       bool
	BrowserCommand   string
	AuthToken        string
	NoAuth           bool
	SocketForwarding config.SocketForwardingConfig
	ControlReady     chan<- net.Addr
	DataReady        chan<- net.Addr
}

type Daemon struct {
	cfg       Config
	browser   *BrowserOpener
	shutdown  chan struct{}
	stopOnce  sync.Once
	stateMu   sync.Mutex
	pendingMu sync.Mutex

	containers    map[string]*containerState
	usedHostPorts map[uint16]string
	pending       map[string]chan dataStream
	sockets       map[string]SocketInfo
}

type containerState struct {
	registrationID uint64
	hostname       string
	forwards       map[uint16]*forwardState
	conn           *control.Connection
	writeMu        sync.Mutex
	missedPongs    int
}

type forwardState struct {
	containerPort uint16
	hostPort      uint16
	processName   *string
	pid           *uint32
	since         string
	listener      net.Listener
	closed        chan struct{}
	tracker       *connectionTracker
}

type connectionTracker struct {
	mu      sync.Mutex
	active  int
	zeroCh  chan struct{}
	forceCh chan struct{}
}

type clientConnection struct {
	stream        net.Conn
	containerID   string
	containerPort uint16
	hostPort      uint16
}

type dataStream struct {
	conn     net.Conn
	buffered []byte
}

var nextRegistrationID atomic.Uint64

func DefaultConfig() Config {
	return Config{ControlPort: config.DefaultControlPort, DataPort: config.DefaultDataPort}
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.ControlPort == 0 {
		cfg.ControlPort = config.DefaultControlPort
	}
	if cfg.DataPort == 0 {
		cfg.DataPort = config.DefaultDataPort
	}
	bindAddr := ResolveBindAddr(cfg)
	log.Info("host daemon starting", "controlPort", cfg.ControlPort, "dataPort", cfg.DataPort, "bindAddr", bindAddr, "exitOnIdle", cfg.ExitOnIdle, "noAuth", cfg.NoAuth, "socketForwarding", cfg.SocketForwarding.Enabled)
	controlLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: bindAddr, Port: int(cfg.ControlPort)})
	if err != nil {
		log.Error("failed to bind control port", "port", cfg.ControlPort, "err", err)
		return fmt.Errorf("bind control port %d: %w", cfg.ControlPort, err)
	}
	defer func() { _ = controlLn.Close() }()
	log.Info("control listener bound", "addr", controlLn.Addr())
	if cfg.ControlReady != nil {
		cfg.ControlReady <- controlLn.Addr()
	}
	dataLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: bindAddr, Port: int(cfg.DataPort)})
	if err != nil {
		log.Error("failed to bind data port", "port", cfg.DataPort, "err", err)
		return fmt.Errorf("bind data port %d: %w", cfg.DataPort, err)
	}
	defer func() { _ = dataLn.Close() }()
	log.Info("data listener bound", "addr", dataLn.Addr())
	if cfg.DataReady != nil {
		cfg.DataReady <- dataLn.Addr()
	}

	d := &Daemon{
		cfg:           cfg,
		browser:       NewBrowserOpener(cfg.BrowserCommand),
		shutdown:      make(chan struct{}),
		containers:    map[string]*containerState{},
		usedHostPorts: map[uint16]string{},
		pending:       map[string]chan dataStream{},
		sockets:       map[string]SocketInfo{},
	}

	go d.acceptControl(controlLn)
	go d.acceptData(dataLn)
	if cfg.SocketForwarding.Enabled && len(cfg.SocketForwarding.WatchPaths) > 0 {
		log.Info("socket forwarding enabled", "watchPaths", cfg.SocketForwarding.WatchPaths, "scanInterval", cfg.SocketForwarding.ScanIntervalMillis)
		go d.runSocketScanner(ctx)
	}

	select {
	case <-ctx.Done():
		log.Info("host daemon shutting down (context cancelled)")
	case <-d.shutdown:
		log.Info("host daemon shutting down (shutdown requested)")
	}
	_ = controlLn.Close()
	_ = dataLn.Close()
	d.cleanupAll()
	log.Info("host daemon stopped")
	return nil
}

func ResolveBindAddr(cfg Config) net.IP {
	if cfg.BindAddr != nil {
		log.Debug("bind address from config", "addr", cfg.BindAddr)
		return cfg.BindAddr
	}
	if cfg.NoDockerDetect {
		log.Debug("docker detection disabled, binding to 127.0.0.1")
		return net.ParseIP("127.0.0.1")
	}
	if detectDocker() {
		log.Info("docker detected, binding to 0.0.0.0")
		return net.ParseIP("0.0.0.0")
	}
	log.Debug("no docker detected, binding to 127.0.0.1")
	return net.ParseIP("127.0.0.1")
}

func detectDocker() bool {
	//nolint:gosec // constant executable and no shell; used only as a best-effort Docker availability probe.
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func (d *Daemon) acceptControl(ln *net.TCPListener) {
	log.Debug("accepting control connections")
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go d.handleControl(control.NewConnection(conn))
	}
}

func (d *Daemon) acceptData(ln *net.TCPListener) {
	log.Debug("accepting data connections")
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go d.handleDataConnection(conn)
	}
}

func (d *Daemon) handleControl(conn *control.Connection) {
	defer conn.Close()
	log.Debug("new control connection", "remote", conn.RemoteAddr().String())
	msgCh := make(chan protocol.Message, 1)
	errCh := make(chan error, 1)
	go func() {
		msg, err := conn.Recv()
		if err != nil {
			errCh <- err
			return
		}
		msgCh <- msg
	}()

	var first protocol.Message
	select {
	case first = <-msgCh:
	case <-time.After(firstMessageTimeout):
		return
	case <-errCh:
		return
	}

	switch m := first.(type) {
	case protocol.Register:
		log.Info("register request received", "containerID", m.ContainerID, "hostname", m.Hostname)
		d.handleRegister(conn, m)
	case protocol.ListRequest:
		log.Debug("list request received")
		d.sendListResponse(conn)
	case protocol.Ping:
		log.Debug("ping received")
		_ = conn.Send(protocol.Pong{})
	case protocol.Unforward:
		log.Info("global unforward request", "port", m.Port)
		d.unforwardGlobal(m.Port)
	case protocol.OpenURL:
		log.Info("open URL request", "url", m.URL)
		success := d.browser.Open(m.URL) == nil
		_ = conn.Send(protocol.OpenURLAck{Success: success})
	case protocol.Shutdown:
		log.Info("shutdown request received")
		if d.authOK(m.AuthToken) {
			d.requestShutdown()
		} else {
			log.Warn("shutdown request with invalid auth token")
		}
	default:
		log.Warn("unexpected first control message", "type", fmt.Sprintf("%T", first))
	}
}

func (d *Daemon) handleRegister(conn *control.Connection, msg protocol.Register) {
	if !validIdentifier(msg.ContainerID) || !validIdentifier(msg.Hostname) || !d.authOK(msg.AuthToken) {
		log.Warn("registration rejected", "containerID", msg.ContainerID, "hostname", msg.Hostname)
		_ = conn.Send(protocol.RegisterAck{Success: false})
		return
	}

	d.stateMu.Lock()
	if _, ok := d.containers[msg.ContainerID]; !ok && len(d.containers) >= maxContainers {
		d.stateMu.Unlock()
		log.Warn("max containers reached, rejecting registration", "containerID", msg.ContainerID, "max", maxContainers)
		_ = conn.Send(protocol.RegisterAck{Success: false})
		return
	}
	old := d.containers[msg.ContainerID]
	delete(d.containers, msg.ContainerID)
	d.stateMu.Unlock()
	if old != nil {
		log.Info("replacing existing container registration", "containerID", msg.ContainerID)
		d.cleanupContainerState(msg.ContainerID, old)
	}

	_ = conn.Send(protocol.RegisterAck{Success: true})

	regID := nextRegistrationID.Add(1)
	state := &containerState{registrationID: regID, hostname: msg.Hostname, forwards: map[uint16]*forwardState{}, conn: conn}
	d.stateMu.Lock()
	d.containers[msg.ContainerID] = state
	log.Info("container registered", "containerID", msg.ContainerID, "hostname", msg.Hostname, "registrationID", regID)
	existingSockets := make([]SocketInfo, 0, len(d.sockets))
	for _, info := range d.sockets {
		existingSockets = append(existingSockets, info)
	}
	d.stateMu.Unlock()

	for _, info := range existingSockets {
		_ = safeSend(state, protocol.SocketForward{SocketID: info.SocketID, HostPath: info.HostPath, ContainerPath: info.ContainerPath})
	}

	d.handleContainerMessages(msg.ContainerID, state)
	log.Info("container disconnected", "containerID", msg.ContainerID)
	if d.cleanupContainer(msg.ContainerID, state.registrationID) && d.cfg.ExitOnIdle {
		d.stateMu.Lock()
		empty := len(d.containers) == 0
		d.stateMu.Unlock()
		if empty {
			log.Info("all containers disconnected, requesting shutdown (exit-on-idle)")
			d.requestShutdown()
		}
	}
}

func (d *Daemon) handleContainerMessages(containerID string, state *containerState) {
	log.Debug("listening for container messages", "containerID", containerID)
	for {
		msg, err := state.conn.Recv()
		if err != nil {
			log.Warn("container connection read error", "containerID", containerID, "err", err)
			return
		}
		d.dispatchContainerMessage(containerID, state, msg)
	}
}

func (d *Daemon) dispatchContainerMessage(containerID string, state *containerState, msg protocol.Message) {
	log.Debug("dispatching container message", "containerID", containerID, "type", fmt.Sprintf("%T", msg))
	switch m := msg.(type) {
	case protocol.Forward:
		log.Info("forward request", "container", containerID, "port", m.Port, "protocol", m.Protocol)
		hostPort, err := d.forward(containerID, state, m)
		if err != nil {
			log.Error("forward failed", "container", containerID, "port", m.Port, "err", err)
			_ = safeSend(state, protocol.ForwardAck{Port: m.Port, Success: false})
			return
		}
		log.Info("forward established", "container", containerID, "containerPort", m.Port, "hostPort", hostPort)
		d.browser.AddPortMapping(m.Port, hostPort)
		_ = safeSend(state, protocol.ForwardAck{Port: m.Port, Success: true, HostPort: hostPort})
	case protocol.Unforward:
		log.Info("unforward request", "container", containerID, "port", m.Port)
		d.unforward(containerID, m.Port)
		d.browser.RemovePortMapping(m.Port)
	case protocol.ConnectFailed:
		log.Debug("connect failed", "container", containerID, "connID", m.ConnID, "error", m.Error)
		d.cancelPending(m.ConnID)
	case protocol.OpenURL:
		log.Info("open URL request from container", "container", containerID, "url", m.URL)
		success := d.browser.Open(m.URL) == nil
		_ = safeSend(state, protocol.OpenURLAck{Success: success})
	case protocol.Ping:
		_ = safeSend(state, protocol.Pong{})
	case protocol.Pong:
		state.missedPongs = 0
	case protocol.SocketConnectRequest:
		d.handleSocketConnectRequest(state, m)
	default:
	}
}

func (d *Daemon) forward(containerID string, state *containerState, msg protocol.Forward) (uint16, error) {
	if msg.Protocol != protocol.ProtocolTCP {
		return 0, fmt.Errorf("unsupported protocol %q", msg.Protocol)
	}

	d.stateMu.Lock()
	old := state.forwards[msg.Port]
	if old == nil && len(state.forwards) >= maxForwardsPerContainer {
		d.stateMu.Unlock()
		return 0, fmt.Errorf("too many forwards")
	}
	if old != nil {
		delete(state.forwards, msg.Port)
		delete(d.usedHostPorts, old.hostPort)
	}
	preferred := msg.Port
	d.stateMu.Unlock()
	if old != nil {
		closeForward(old)
	}

	var ln net.Listener
	var hostPort uint16
	var err error
	tried := 0
	for candidate := preferred; tried < 65535; candidate = nextPort(candidate) {
		d.stateMu.Lock()
		_, used := d.usedHostPorts[candidate]
		if !used {
			d.usedHostPorts[candidate] = containerID
		}
		d.stateMu.Unlock()
		if used {
			tried++
			continue
		}
		ln, err = bindLoopback(candidate)
		if err == nil {
			//nolint:gosec // TCPAddr.Port is assigned by the kernel and is always in 0..65535.
			hostPort = uint16(ln.Addr().(*net.TCPAddr).Port)
			break
		}
		d.stateMu.Lock()
		delete(d.usedHostPorts, candidate)
		d.stateMu.Unlock()
		tried++
	}
	if ln == nil {
		log.Error("no available host port for forward", "containerPort", msg.Port, "err", err)
		return 0, fmt.Errorf("no available host port: %w", err)
	}

	fwd := &forwardState{containerPort: msg.Port, hostPort: hostPort, processName: msg.ProcessName, pid: msg.PID, since: fmt.Sprint(time.Now().Unix()), listener: ln, closed: make(chan struct{}), tracker: newConnectionTracker()}
	d.stateMu.Lock()
	if current := d.containers[containerID]; current != state {
		d.stateMu.Unlock()
		closeForward(fwd)
		return 0, fmt.Errorf("container disconnected during forward setup")
	}
	state.forwards[msg.Port] = fwd
	if hostPort != preferred {
		delete(d.usedHostPorts, preferred)
		d.usedHostPorts[hostPort] = containerID
	}
	d.stateMu.Unlock()
	go d.acceptForward(containerID, fwd)
	return hostPort, nil
}

func nextPort(port uint16) uint16 {
	next := port + 1
	if next < 1024 {
		next = 1024
	}
	return next
}

func bindLoopback(port uint16) (net.Listener, error) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)})
	if err == nil {
		return ln, nil
	}
	if strings.Contains(err.Error(), "address already in use") {
		return nil, err
	}
	return net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1"), Port: int(port)})
}

func (d *Daemon) acceptForward(containerID string, fwd *forwardState) {
	defer close(fwd.closed)
	for {
		conn, err := fwd.listener.Accept()
		if err != nil {
			return
		}
		go d.handleClient(clientConnection{stream: conn, containerID: containerID, containerPort: fwd.containerPort, hostPort: fwd.hostPort})
	}
}

func (d *Daemon) handleClient(client clientConnection) {
	defer client.stream.Close()
	log.Debug("handling client connection", "containerID", client.containerID, "containerPort", client.containerPort, "hostPort", client.hostPort, "remote", client.stream.RemoteAddr().String())
	d.stateMu.Lock()
	state := d.containers[client.containerID]
	var tracker *connectionTracker
	if state != nil {
		if fwd := state.forwards[client.containerPort]; fwd != nil && fwd.hostPort == client.hostPort {
			tracker = fwd.tracker
		}
	}
	d.stateMu.Unlock()
	if state == nil || tracker == nil {
		log.Warn("client connection dropped, container/tracker not found", "containerID", client.containerID, "port", client.containerPort)
		return
	}
	tracker.inc()
	defer tracker.dec()

	connID := newConnID()
	dataCh, ok := d.registerPending(connID)
	if !ok {
		return
	}
	if err := safeSend(state, protocol.ConnectRequest{Port: client.containerPort, ConnID: connID}); err != nil {
		d.cancelPending(connID)
		return
	}
	done := make(chan struct{})
	go func() {
		select {
		case ds, ok := <-dataCh:
			if ok {
				_ = bridge(client.stream, ds.conn, ds.buffered)
			}
		case <-time.After(connectTimeout):
			d.cancelPending(connID)
		case <-tracker.forceCh:
		}
		close(done)
	}()
	<-done
}

func (d *Daemon) handleDataConnection(conn net.Conn) {
	log.Debug("new data connection", "remote", conn.RemoteAddr().String())
	_ = conn.SetReadDeadline(time.Now().Add(dataHandshakeTimeout))
	reader := bufio.NewReader(conn)
	msg, err := control.ReadMessage(reader)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return
	}
	ready, ok := msg.(protocol.ConnectReady)
	if !ok || len(ready.ConnID) > 128 {
		log.Warn("invalid data handshake", "type", fmt.Sprintf("%T", msg))
		_ = conn.Close()
		return
	}
	log.Debug("data handshake received", "connID", ready.ConnID)
	buffered := make([]byte, reader.Buffered())
	if len(buffered) > 0 {
		if _, err := io.ReadFull(reader, buffered); err != nil {
			_ = conn.Close()
			return
		}
	}
	if !d.resolvePending(ready.ConnID, dataStream{conn: conn, buffered: buffered}) {
		return
	}
}

func (d *Daemon) registerPending(connID string) (<-chan dataStream, bool) {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()
	if len(d.pending) >= maxPendingConnections {
		return nil, false
	}
	ch := make(chan dataStream, 1)
	d.pending[connID] = ch
	return ch, true
}

func (d *Daemon) resolvePending(connID string, ds dataStream) bool {
	d.pendingMu.Lock()
	ch := d.pending[connID]
	delete(d.pending, connID)
	d.pendingMu.Unlock()
	if ch == nil {
		_ = ds.conn.Close()
		return false
	}
	ch <- ds
	return true
}

func (d *Daemon) cancelPending(connID string) {
	d.pendingMu.Lock()
	ch := d.pending[connID]
	delete(d.pending, connID)
	d.pendingMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (d *Daemon) unforward(containerID string, port uint16) {
	log.Debug("unforwarding port", "container", containerID, "port", port)
	d.stateMu.Lock()
	state := d.containers[containerID]
	var fwd *forwardState
	if state != nil {
		fwd = state.forwards[port]
		delete(state.forwards, port)
	}
	if fwd != nil {
		delete(d.usedHostPorts, fwd.hostPort)
	}
	d.stateMu.Unlock()
	if fwd != nil {
		closeForward(fwd)
	}
}

func (d *Daemon) unforwardGlobal(port uint16) {
	d.stateMu.Lock()
	var owner string
	var fwd *forwardState
	for cid, state := range d.containers {
		if candidate := state.forwards[port]; candidate != nil {
			owner = cid
			fwd = candidate
			delete(state.forwards, port)
			break
		}
	}
	if fwd != nil {
		delete(d.usedHostPorts, fwd.hostPort)
	}
	d.stateMu.Unlock()
	if fwd != nil {
		d.browser.RemovePortMapping(port)
		log.Info("unforwarded", "container", owner, "port", port)
		closeForward(fwd)
	}
}

func (d *Daemon) sendListResponse(conn *control.Connection) {
	log.Debug("sending list response")
	d.stateMu.Lock()
	forwards := make([]protocol.ForwardInfo, 0)
	for cid, state := range d.containers {
		for port, fwd := range state.forwards {
			forwards = append(forwards, protocol.ForwardInfo{ContainerID: cid, Hostname: state.hostname, Port: port, HostPort: fwd.hostPort, Protocol: protocol.ProtocolTCP, ProcessName: fwd.processName, PID: fwd.pid, Since: fwd.since})
		}
	}
	sockets := make([]protocol.SocketForwardInfo, 0, len(d.sockets))
	for _, info := range d.sockets {
		sockets = append(sockets, protocol.SocketForwardInfo{SocketID: info.SocketID, HostPath: info.HostPath, ContainerPath: info.ContainerPath})
	}
	d.stateMu.Unlock()
	sort.Slice(forwards, func(i, j int) bool { return forwards[i].HostPort < forwards[j].HostPort })
	_ = conn.Send(protocol.ListResponse{Forwards: forwards, SocketForwards: sockets})
}

func (d *Daemon) handleSocketConnectRequest(state *containerState, req protocol.SocketConnectRequest) {
	log.Debug("socket connect request", "socketID", req.SocketID, "connID", req.ConnID)
	if !validIdentifier(req.SocketID) || !validIdentifier(req.ConnID) {
		log.Warn("invalid socket connect request identifiers", "socketID", req.SocketID, "connID", req.ConnID)
		return
	}
	d.stateMu.Lock()
	info, ok := d.sockets[req.SocketID]
	d.stateMu.Unlock()
	if !ok {
		_ = safeSend(state, protocol.ConnectFailed{ConnID: req.ConnID, Error: "unknown socket_id"})
		return
	}
	dataCh, ok := d.registerPending(req.ConnID)
	if !ok {
		return
	}
	unixConn, err := net.DialTimeout("unix", info.HostPath, 5*time.Second)
	if err != nil {
		log.Warn("failed to dial unix socket", "path", info.HostPath, "err", err)
		d.cancelPending(req.ConnID)
		_ = safeSend(state, protocol.ConnectFailed{ConnID: req.ConnID, Error: err.Error()})
		return
	}
	go func() {
		select {
		case ds, ok := <-dataCh:
			if ok {
				_ = bridge(unixConn, ds.conn, ds.buffered)
			}
		case <-time.After(connectTimeout):
			d.cancelPending(req.ConnID)
		}
		_ = unixConn.Close()
	}()
}

func (d *Daemon) runSocketScanner(ctx context.Context) {
	sf := d.cfg.SocketForwarding
	log.Info("socket scanner starting", "watchPaths", sf.WatchPaths, "interval", sf.ScanIntervalMillis)
	interval := time.Duration(sf.ScanIntervalMillis) * time.Millisecond //nolint:gosec // CLI/env value is bounded operationally; excessively large intervals are harmless.
	if interval <= 0 {
		interval = time.Duration(config.DefaultSocketScanMillis) * time.Millisecond
	}
	scanner := NewSocketScanner(sf.WatchPaths, sf.ContainerPathPrefix, sf.MaxSocketForwards)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.shutdown:
			return
		case <-ticker.C:
			found, removed := scanner.Scan()
			if len(found) > 0 || len(removed) > 0 {
				log.Info("socket scan results", "found", len(found), "removed", len(removed))
			}
			d.broadcastSocketChanges(found, removed)
		}
	}
}

func (d *Daemon) broadcastSocketChanges(found, removed []SocketInfo) {
	if len(found) == 0 && len(removed) == 0 {
		return
	}
	log.Debug("broadcasting socket changes", "found", len(found), "removed", len(removed))
	d.stateMu.Lock()
	states := make([]*containerState, 0, len(d.containers))
	for _, state := range d.containers {
		states = append(states, state)
	}
	for _, info := range found {
		d.sockets[info.SocketID] = info
	}
	for _, info := range removed {
		delete(d.sockets, info.SocketID)
	}
	d.stateMu.Unlock()
	for _, info := range found {
		for _, state := range states {
			_ = safeSend(state, protocol.SocketForward{SocketID: info.SocketID, HostPath: info.HostPath, ContainerPath: info.ContainerPath})
		}
	}
	for _, info := range removed {
		for _, state := range states {
			_ = safeSend(state, protocol.SocketUnforward{SocketID: info.SocketID})
		}
	}
}

func (d *Daemon) cleanupContainer(containerID string, regID uint64) bool {
	d.stateMu.Lock()
	state := d.containers[containerID]
	if state == nil || state.registrationID != regID {
		d.stateMu.Unlock()
		return false
	}
	delete(d.containers, containerID)
	d.stateMu.Unlock()
	d.cleanupContainerState(containerID, state)
	return true
}

func (d *Daemon) cleanupContainerState(_ string, state *containerState) {
	log.Debug("cleaning up container state")
	for port, fwd := range state.forwards {
		d.browser.RemovePortMapping(port)
		d.stateMu.Lock()
		delete(d.usedHostPorts, fwd.hostPort)
		d.stateMu.Unlock()
		closeForward(fwd)
	}
}

func (d *Daemon) cleanupAll() {
	log.Info("cleaning up all daemon state")
	d.stateMu.Lock()
	states := make([]*containerState, 0, len(d.containers))
	for _, state := range d.containers {
		states = append(states, state)
	}
	d.containers = map[string]*containerState{}
	d.usedHostPorts = map[uint16]string{}
	d.stateMu.Unlock()
	for _, state := range states {
		d.cleanupContainerState("", state)
	}
}

func (d *Daemon) authOK(token string) bool {
	return d.cfg.NoAuth || (d.cfg.AuthToken != "" && token == d.cfg.AuthToken)
}

func (d *Daemon) requestShutdown() {
	log.Info("shutdown requested")
	d.stopOnce.Do(func() { close(d.shutdown) })
}

func safeSend(state *containerState, msg protocol.Message) error {
	state.writeMu.Lock()
	defer state.writeMu.Unlock()
	return state.conn.Send(msg)
}

func closeForward(fwd *forwardState) {
	_ = fwd.listener.Close()
	select {
	case <-fwd.closed:
	case <-time.After(2 * time.Second):
	}
	fwd.tracker.force()
}

func newConnectionTracker() *connectionTracker {
	return &connectionTracker{zeroCh: make(chan struct{}), forceCh: make(chan struct{})}
}

func (t *connectionTracker) inc() {
	t.mu.Lock()
	t.active++
	t.mu.Unlock()
}

func (t *connectionTracker) dec() {
	t.mu.Lock()
	if t.active > 0 {
		t.active--
	}
	if t.active == 0 {
		select {
		case <-t.zeroCh:
		default:
			close(t.zeroCh)
		}
	}
	t.mu.Unlock()
}

func (t *connectionTracker) force() {
	select {
	case <-t.forceCh:
	default:
		close(t.forceCh)
	}
}

func bridge(a, b net.Conn, bBuffered []byte) error {
	if len(bBuffered) > 0 {
		if _, err := a.Write(bBuffered); err != nil {
			return err
		}
	}
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
	if r1.err != nil && !benignNetErr(r1.err) {
		return r1.err
	}
	if r2.err != nil && !benignNetErr(r2.err) {
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

func benignNetErr(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset")
}

func validIdentifier(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func newConnID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprint(time.Now().UnixNano())
	}
	var out bytes.Buffer
	out.WriteString(hex.EncodeToString(buf[:4]))
	out.WriteByte('-')
	out.WriteString(hex.EncodeToString(buf[4:6]))
	out.WriteByte('-')
	out.WriteString(hex.EncodeToString(buf[6:8]))
	out.WriteByte('-')
	out.WriteString(hex.EncodeToString(buf[8:10]))
	out.WriteByte('-')
	out.WriteString(hex.EncodeToString(buf[10:]))
	return out.String()
}
