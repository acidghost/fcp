package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/acidghost/fcp/internal/log"
)

type ListeningPort struct {
	Port        uint16
	ProcessName *string
	PID         *uint32
}

func ParseProcNetTCP(content string) []struct {
	Port  uint16
	Inode uint64
} {
	lines := strings.Split(content, "\n")
	out := make([]struct {
		Port  uint16
		Inode uint64
	}, 0)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		}
		idx := strings.LastIndex(fields[1], ":")
		if idx < 0 {
			continue
		}
		port64, err := strconv.ParseUint(fields[1][idx+1:], 16, 16)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, struct {
			Port  uint16
			Inode uint64
		}{Port: uint16(port64), Inode: inode})
	}
	return out
}

func ScanListeningPorts(procPath string, exclude map[uint16]struct{}) ([]ListeningPort, error) {
	tcpContent, tcpErr := os.ReadFile(filepath.Join(procPath, "net", "tcp"))    //nolint:gosec // procPath is controlled by caller/test fixture.
	tcp6Content, tcp6Err := os.ReadFile(filepath.Join(procPath, "net", "tcp6")) //nolint:gosec // procPath is controlled by caller/test fixture.
	if tcpErr != nil && tcp6Err != nil {
		return nil, fmt.Errorf("read proc net tcp: %w", tcpErr)
	}
	seen := map[uint16]struct{}{}
	ports := make([]ListeningPort, 0)
	log.Debug("scanning listening ports", "procPath", procPath)
	for _, content := range [][]byte{tcpContent, tcp6Content} {
		if len(content) == 0 {
			continue
		}
		for _, item := range ParseProcNetTCP(string(content)) {
			if _, skip := exclude[item.Port]; skip {
				continue
			}
			if _, ok := seen[item.Port]; ok {
				continue
			}
			seen[item.Port] = struct{}{}
			name, pid := resolveProcessForInode(procPath, item.Inode)
			ports = append(ports, ListeningPort{Port: item.Port, ProcessName: name, PID: pid})
		}
	}
	log.Debug("port scan complete", "count", len(ports))
	return ports, nil
}

func resolveProcessForInode(procPath string, inode uint64) (*string, *uint32) {
	target := fmt.Sprintf("socket:[%d]", inode)
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return nil, nil
	}
	for _, entry := range entries {
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procPath, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name())) //nolint:gosec // /proc fd symlink target lookup.
			if err != nil || link != target {
				continue
			}
			nameData, err := os.ReadFile(filepath.Join(procPath, entry.Name(), "comm")) //nolint:gosec // /proc process comm lookup.
			if err != nil {
				pid := uint32(pid64)
				return nil, &pid
			}
			name := strings.TrimSpace(string(nameData))
			pid := uint32(pid64)
			if name == "" {
				return nil, &pid
			}
			return &name, &pid
		}
	}
	return nil, nil
}

type PortFilter struct {
	exclude map[uint16]struct{}
	include map[uint16]struct{}
}

func NewPortFilter(excludePorts, includePorts []uint16) PortFilter {
	filter := PortFilter{exclude: map[uint16]struct{}{}, include: map[uint16]struct{}{}}
	for _, port := range excludePorts {
		filter.exclude[port] = struct{}{}
	}
	for _, port := range includePorts {
		filter.include[port] = struct{}{}
	}
	return filter
}

func (f PortFilter) ShouldForward(port ListeningPort) bool {
	if _, ok := f.exclude[port.Port]; ok {
		return false
	}
	if len(f.include) > 0 {
		_, ok := f.include[port.Port]
		return ok
	}
	return true
}

func (f PortFilter) Filter(ports []ListeningPort) []ListeningPort {
	out := make([]ListeningPort, 0, len(ports))
	for _, port := range ports {
		if f.ShouldForward(port) {
			out = append(out, port)
		}
	}
	return out
}
