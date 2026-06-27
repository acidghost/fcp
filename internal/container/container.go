package container

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/acidghost/fcp/internal/auth"
	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/control"
	"github.com/acidghost/fcp/internal/log"
	"github.com/acidghost/fcp/internal/protocol"
)

type DaemonConfig = config.Config

func Run(ctx context.Context, cfg DaemonConfig, authToken string) error {
	host, err := ResolveHostAddr(cfg)
	if err != nil {
		log.Error("failed to resolve host address", "err", err)
		return err
	}
	log.Info("container daemon starting", "host", host, "controlPort", cfg.ControlPort, "dataPort", cfg.DataPort)
	controlAddr := &net.TCPAddr{IP: net.ParseIP(host), Port: int(cfg.ControlPort)}
	dataAddr := &net.TCPAddr{IP: net.ParseIP(host), Port: int(cfg.DataPort)}
	exclude := map[uint16]struct{}{cfg.ControlPort: {}, cfg.DataPort: {}}
	for _, port := range cfg.ExcludePorts {
		exclude[port] = struct{}{}
	}
	filter := NewPortFilter(cfg.ExcludePorts, cfg.IncludePorts)
	interval := max(
		//nolint:gosec // CLI/env value is bounded operationally; excessively large intervals are harmless.
		time.Duration(cfg.ScanIntervalMillis)*time.Millisecond, 100*time.Millisecond)
	backoff := 100 * time.Millisecond
	forwarded := map[uint16]ListeningPort{}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		log.Info("connecting to host daemon", "addr", controlAddr.String())
		conn, err := control.DialTCP(*controlAddr, 5*time.Second)
		if err != nil {
			log.Warn("connection to host daemon failed, retrying", "addr", controlAddr.String(), "backoff", backoff, "err", err)
			if waitContext(ctx, backoff) {
				return nil
			}
			backoff = minDuration(backoff*2, 5*time.Second)
			continue
		}
		if err := register(conn, authToken); err != nil {
			log.Error("registration failed", "err", err)
			_ = conn.Close()
			return err
		}
		log.Info("registered with host daemon")
		backoff = 100 * time.Millisecond
		outcomeForwarded := runSession(ctx, conn, dataAddr, interval, exclude, filter, forwarded, authToken)
		forwarded = outcomeForwarded
		_ = conn.Close()
		log.Warn("session ended, reconnecting", "backoff", backoff)
		if waitContext(ctx, backoff) {
			return nil
		}
		backoff = minDuration(backoff*2, 5*time.Second)
	}
}

func ResolveHostAddr(cfg DaemonConfig) (string, error) {
	if strings.TrimSpace(cfg.HostAddr) != "" {
		resolved := resolveHostString(cfg.HostAddr)
		if net.ParseIP(resolved) == nil {
			log.Error("could not resolve explicit host address", "host", cfg.HostAddr)
			return "", fmt.Errorf("could not resolve explicit host address %q", cfg.HostAddr)
		}
		log.Debug("host address resolved from config", "host", resolved)
		return resolved, nil
	}
	if ips, err := net.LookupIP("host.docker.internal"); err == nil && len(ips) > 0 {
		log.Debug("host address resolved via host.docker.internal", "ip", ips[0])
		return ips[0].String(), nil
	}
	if ip := gatewayIP(); ip != "" {
		log.Debug("host address resolved via gateway IP", "ip", ip)
		return ip, nil
	}
	log.Error("could not resolve host address by any method")
	return "", fmt.Errorf("could not resolve host address; set --host-addr or FCP_HOST")
}

func resolveHostString(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		return ips[0].String()
	}
	return host
}

func gatewayIP() string {
	//nolint:gosec // constant executable and arguments; no shell.
	cmd := exec.Command("ip", "route")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "default" && fields[1] == "via" {
			return fields[2]
		}
	}
	return ""
}

func register(conn *control.Connection, authToken string) error {
	id := containerID()
	if err := conn.Send(protocol.Register{ContainerID: id, Hostname: id, AuthToken: authToken}); err != nil {
		return err
	}
	msg, err := conn.Recv()
	if err != nil {
		return err
	}
	ack, ok := msg.(protocol.RegisterAck)
	if !ok || !ack.Success {
		log.Error("registration rejected by host daemon")
		return fmt.Errorf("registration rejected by host daemon")
	}
	log.Debug("registration acknowledged by host daemon", "id", id)
	return nil
}

func runSession(ctx context.Context, conn *control.Connection, dataAddr net.Addr, scanInterval time.Duration, exclude map[uint16]struct{}, filter PortFilter, initial map[uint16]ListeningPort, authToken string) map[uint16]ListeningPort {
	forwarded := make(map[uint16]ListeningPort, len(initial))
	for port, lp := range initial {
		forwarded[port] = lp
		_ = conn.Send(protocol.Forward{Port: port, Protocol: protocol.ProtocolTCP, ProcessName: lp.ProcessName, PID: lp.PID})
	}
	relay := make(chan RelayMessage, 64)
	mirrorSockets := map[string]*MirrorSocket{}
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()
	defer cleanupMirrors(mirrorSockets)

	msgCh := make(chan protocol.Message, 1)
	errCh := make(chan error, 1)
	readNext := func() {
		go func() {
			msg, err := conn.Recv()
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- msg
		}()
	}
	readNext()
	for {
		select {
		case <-ctx.Done():
			for port := range forwarded {
				_ = conn.Send(protocol.Unforward{Port: port})
			}
			return forwarded
		case <-ticker.C:
			current, err := ScanListeningPorts("/proc", exclude)
			if err != nil {
				log.Warn("port scan failed", "err", err)
				continue
			}
			current = filter.Filter(current)
			currentMap := map[uint16]ListeningPort{}
			for _, lp := range current {
				currentMap[lp.Port] = lp
				if _, ok := forwarded[lp.Port]; !ok {
					log.Info("new port detected, forwarding", "port", lp.Port, "process", lp.ProcessName)
					_ = conn.Send(protocol.Forward{Port: lp.Port, Protocol: protocol.ProtocolTCP, ProcessName: lp.ProcessName, PID: lp.PID})
					forwarded[lp.Port] = lp
				}
			}
			for port := range forwarded {
				if _, ok := currentMap[port]; !ok {
					log.Info("port no longer listening, unforwarding", "port", port)
					_ = conn.Send(protocol.Unforward{Port: port})
					delete(forwarded, port)
				}
			}
		case msg := <-msgCh:
			log.Debug("received control message", "type", fmt.Sprintf("%T", msg))
			switch m := msg.(type) {
			case protocol.ConnectRequest:
				go handleConnectRequest(m.Port, m.ConnID, dataAddr, relay, authToken)
			case protocol.Ping:
				_ = conn.Send(protocol.Pong{})
			case protocol.ForwardAck:
				if !m.Success {
					delete(forwarded, m.Port)
				}
			case protocol.SocketForward:
				mirror, err := CreateMirrorSocket(m.SocketID, m.ContainerPath)
				if err == nil {
					mirrorSockets[m.SocketID] = mirror
					go RunMirrorAcceptLoop(mirror, relay, dataAddr, authToken)
				} else {
					log.Error("create mirror socket failed", "path", m.ContainerPath, "err", err)
				}
			case protocol.SocketUnforward:
				if mirror := mirrorSockets[m.SocketID]; mirror != nil {
					close(mirror.Stop)
					RemoveMirrorSocket(mirror)
					delete(mirrorSockets, m.SocketID)
				}
			}
			readNext()
		case relayMsg := <-relay:
			if err := conn.Send(relayMsg.Msg); err == nil && relayMsg.Ack != nil {
				close(relayMsg.Ack)
			}
		case <-errCh:
			log.Warn("control connection lost")
			return forwarded
		}
	}
}

func handleConnectRequest(port uint16, connID string, dataAddr net.Addr, relay chan<- RelayMessage, authToken string) {
	log.Debug("handling connect request", "port", port, "connID", connID)
	localConn, err := dialLocalPort(port)
	if err != nil {
		log.Warn("failed to dial local port", "port", port, "err", err)
		relayConnectFailed(relay, connID, err)
		return
	}
	defer localConn.Close()
	dataConn, err := net.DialTimeout(dataAddr.Network(), dataAddr.String(), 5*time.Second)
	if err != nil {
		log.Warn("failed to connect to data port", "addr", dataAddr.String(), "err", err)
		relayConnectFailed(relay, connID, err)
		return
	}
	defer dataConn.Close()
	ready, err := connectReady(connID, authToken)
	if err != nil {
		log.Warn("failed to create data handshake proof", "connID", connID, "err", err)
		relayConnectFailed(relay, connID, err)
		return
	}
	if err := control.WriteMessage(dataConn, ready); err != nil {
		log.Warn("failed to send ConnectReady", "connID", connID, "err", err)
		relayConnectFailed(relay, connID, err)
		return
	}
	log.Debug("connection bridge established", "connID", connID, "port", port)
	_ = copyBoth(localConn, dataConn)
}

func dialLocalPort(port uint16) (net.Conn, error) {
	ipv4 := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
	conn, err := net.DialTimeout("tcp4", ipv4.String(), 5*time.Second)
	if err == nil {
		return conn, nil
	}
	ipv6 := &net.TCPAddr{IP: net.ParseIP("::1"), Port: int(port)}
	conn6, err6 := net.DialTimeout("tcp6", ipv6.String(), 5*time.Second)
	if err6 == nil {
		return conn6, nil
	}
	return nil, fmt.Errorf("IPv4: %v; IPv6: %w", err, err6)
}

func relayConnectFailed(relay chan<- RelayMessage, connID string, err error) {
	select {
	case relay <- RelayMessage{Msg: protocol.ConnectFailed{ConnID: connID, Error: err.Error()}}:
	case <-time.After(time.Second):
	}
}

func connectReady(connID, authToken string) (protocol.ConnectReady, error) {
	if strings.TrimSpace(authToken) == "" {
		return protocol.ConnectReady{ConnID: connID}, nil
	}
	proof, err := auth.DataHandshakeProof(authToken, connID)
	if err != nil {
		return protocol.ConnectReady{}, err
	}
	return protocol.ConnectReady{ConnID: connID, Proof: proof}, nil
}

func cleanupMirrors(mirrors map[string]*MirrorSocket) {
	for _, mirror := range mirrors {
		close(mirror.Stop)
		RemoveMirrorSocket(mirror)
	}
}

func containerID() string {
	if data, err := os.ReadFile("/etc/hostname"); err == nil { //nolint:gosec // fixed container hostname path.
		if id := strings.TrimSpace(string(data)); id != "" {
			return sanitizeIdentifier(id)
		}
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return sanitizeIdentifier(hostname)
	}
	return "unknown"
}

func sanitizeIdentifier(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func newConnID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprint(time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:4]) + "-" + hex.EncodeToString(buf[4:6]) + "-" + hex.EncodeToString(buf[6:8]) + "-" + hex.EncodeToString(buf[8:10]) + "-" + hex.EncodeToString(buf[10:])
}

func waitContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-t.C:
		return false
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
