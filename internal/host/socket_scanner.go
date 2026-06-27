package host

import (
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/acidghost/fcp/internal/log"
)

const maxUnixSocketPath = 108

type SocketInfo struct {
	SocketID      string
	HostPath      string
	ContainerPath string
	DiscoveredAt  time.Time
}

type SocketScanner struct {
	watchPaths          []string
	containerPathPrefix string
	known               map[string]SocketInfo
	maxForwards         int
}

func NewSocketScanner(watchPaths []string, containerPathPrefix string, maxForwards int) *SocketScanner {
	if maxForwards <= 0 {
		maxForwards = 16
	}
	return &SocketScanner{watchPaths: watchPaths, containerPathPrefix: containerPathPrefix, known: map[string]SocketInfo{}, maxForwards: maxForwards}
}

func (s *SocketScanner) Scan() ([]SocketInfo, []SocketInfo) {
	log.Debug("socket scanner running", "watchPaths", s.watchPaths)
	current := map[string]struct{}{}
	for _, pattern := range s.watchPaths {
		matches, err := glob(pattern)
		if err != nil {
			log.Warn("invalid socket glob", "pattern", pattern, "err", err)
			continue
		}
		for _, path := range matches {
			if len(path) > maxUnixSocketPath || !IsUnixSocket(path) {
				continue
			}
			current[path] = struct{}{}
		}
	}

	removed := make([]SocketInfo, 0)
	for path, info := range s.known {
		if _, ok := current[path]; !ok {
			removed = append(removed, info)
			delete(s.known, path)
		}
	}

	found := make([]SocketInfo, 0)
	for path := range current {
		if _, ok := s.known[path]; ok {
			continue
		}
		if len(s.known) >= s.maxForwards {
			log.Warn("socket forward limit reached; ignoring", "path", path)
			break
		}
		info := SocketInfo{SocketID: randomID(), HostPath: path, ContainerPath: s.containerPath(path), DiscoveredAt: time.Now()}
		s.known[path] = info
		found = append(found, info)
	}
	for _, info := range found {
		log.Debug("new socket discovered", "socketID", info.SocketID, "hostPath", info.HostPath, "containerPath", info.ContainerPath)
		if isSensitiveHostSocket(info.HostPath) {
			log.Warn("forwarding sensitive host socket grants high-impact host capabilities", "hostPath", info.HostPath, "containerPath", info.ContainerPath)
		}
	}
	for _, info := range removed {
		log.Debug("socket removed", "socketID", info.SocketID, "hostPath", info.HostPath)
	}
	return found, removed
}

func (s *SocketScanner) Known() []SocketInfo {
	out := make([]SocketInfo, 0, len(s.known))
	for _, info := range s.known {
		out = append(out, info)
	}
	return out
}

func (s *SocketScanner) containerPath(hostPath string) string {
	if s.containerPathPrefix == "" {
		return hostPath
	}
	return filepath.Join(s.containerPathPrefix, filepath.Base(hostPath))
}

func IsUnixSocket(path string) bool {
	info, err := os.Lstat(path) //nolint:gosec // Socket watch paths are explicit user configuration.
	if err != nil {
		return false
	}
	return info.Mode()&fs.ModeSocket != 0
}

func glob(pattern string) ([]string, error) {
	if !strings.Contains(pattern, "**") {
		return filepath.Glob(pattern)
	}
	root := globRoot(pattern)
	matches := make([]string, 0)
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ok, matchErr := pathMatchesDoubleStar(pattern, path)
		if matchErr != nil {
			return matchErr
		}
		if ok {
			matches = append(matches, path)
		}
		return nil
	})
	return matches, walkErr
}

func globRoot(pattern string) string {
	idx := strings.Index(pattern, "**")
	prefix := pattern[:idx]
	if meta := strings.IndexAny(prefix, "*?["); meta >= 0 {
		prefix = prefix[:meta]
	}
	if prefix == "" {
		if filepath.IsAbs(pattern) {
			return string(filepath.Separator)
		}
		return "."
	}
	if strings.HasSuffix(prefix, string(filepath.Separator)) {
		return filepath.Clean(prefix)
	}
	return filepath.Dir(filepath.Clean(prefix))
}

func pathMatchesDoubleStar(pattern, path string) (bool, error) {
	return matchPathParts(splitPath(pattern), splitPath(path))
}

func splitPath(path string) []string {
	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) {
		cleaned = strings.TrimPrefix(cleaned, string(filepath.Separator))
	}
	if cleaned == "." || cleaned == "" {
		return nil
	}
	return strings.Split(cleaned, string(filepath.Separator))
}

func matchPathParts(patternParts, pathParts []string) (bool, error) {
	if len(patternParts) == 0 {
		return len(pathParts) == 0, nil
	}
	if patternParts[0] == "**" {
		for i := 0; i <= len(pathParts); i++ {
			ok, err := matchPathParts(patternParts[1:], pathParts[i:])
			if err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	}
	if len(pathParts) == 0 {
		return false, nil
	}
	ok, err := filepath.Match(patternParts[0], pathParts[0])
	if err != nil || !ok {
		return ok, err
	}
	return matchPathParts(patternParts[1:], pathParts[1:])
}

func randomID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "sock-unknown"
	}
	return "sock-" + hex.EncodeToString(buf)
}

func isSensitiveHostSocket(path string) bool {
	cleaned := filepath.Clean(path)
	base := filepath.Base(cleaned)
	if base == "docker.sock" {
		return true
	}
	for _, marker := range []string{
		"containerd.sock",
		"containerd-shim",
		"podman.sock",
		"colima",
		"lima",
		"buildkit",
	} {
		if strings.Contains(cleaned, marker) {
			return true
		}
	}
	return false
}
