package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/acidghost/fcp/internal/log"
)

const (
	DefaultControlPort          uint16 = 19285
	DefaultDataPort             uint16 = 19286
	DefaultScanIntervalMillis   uint64 = 1000
	DefaultSocketScanMillis     uint64 = 2000
	DefaultMaxSocketForwards           = 16
	DefaultConnectTimeoutMillis        = 10_000
)

type SocketForwardingConfig struct {
	Enabled             bool
	WatchPaths          []string
	ContainerPathPrefix string
	ScanIntervalMillis  uint64
	MaxSocketForwards   int
}

type Config struct {
	ControlPort        uint16
	DataPort           uint16
	HostAddr           string
	ScanIntervalMillis uint64
	ExcludePorts       []uint16
	IncludePorts       []uint16
	NoAuth             bool
	SocketForwarding   SocketForwardingConfig
}

func Default() Config {
	return Config{
		ControlPort:        DefaultControlPort,
		DataPort:           DefaultDataPort,
		ScanIntervalMillis: DefaultScanIntervalMillis,
		SocketForwarding: SocketForwardingConfig{
			ScanIntervalMillis: DefaultSocketScanMillis,
			MaxSocketForwards:  DefaultMaxSocketForwards,
		},
	}
}

func FromEnv() (Config, error) {
	cfg := Default()
	if host := os.Getenv("FCP_HOST"); host != "" {
		log.Debug("config: FCP_HOST set from env", "host", host)
		cfg.HostAddr = host
	}
	if value := os.Getenv("FCP_HOST_PORT"); value != "" {
		port, err := ParsePort(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid host port %q: %w", value, err)
		}
		cfg.ControlPort = port
	}
	if value := os.Getenv("FCP_DATA_PORT"); value != "" {
		port, err := ParsePort(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid data port %q: %w", value, err)
		}
		cfg.DataPort = port
	}
	if value := os.Getenv("FCP_SCAN_INTERVAL_MS"); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return cfg, fmt.Errorf("invalid scan interval %q: %w", value, err)
		}
		cfg.ScanIntervalMillis = parsed
	}
	log.Debug("config loaded from env", "host", cfg.HostAddr, "controlPort", cfg.ControlPort, "dataPort", cfg.DataPort, "scanInterval", cfg.ScanIntervalMillis)
	return cfg, nil
}

func ParsePort(value string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("port must be in 1-65535")
	}
	return uint16(n), nil
}

func ParsePortList(value string) ([]uint16, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	ports := make([]uint16, 0, len(parts))
	for _, part := range parts {
		port, err := ParsePort(part)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func ResolveCLIHost(explicit string) net.IP {
	for _, candidate := range []string{explicit, os.Getenv("FCP_HOST"), "host.docker.internal", "127.0.0.1"} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if ip := net.ParseIP(candidate); ip != nil {
			log.Debug("resolved CLI host", "candidate", candidate, "ip", ip)
			return ip
		}
		ips, err := net.LookupIP(candidate)
		if err == nil && len(ips) > 0 {
			log.Debug("resolved CLI host via DNS lookup", "candidate", candidate, "ip", ips[0])
			return ips[0]
		}
	}
	log.Debug("CLI host resolution fell back to 127.0.0.1")
	return net.ParseIP("127.0.0.1")
}
