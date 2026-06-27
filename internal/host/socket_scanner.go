package host

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/acidghost/fcp/internal/config"
	"github.com/acidghost/fcp/internal/log"
)

const maxUnixSocketPath = 108

var errSocketScanBudgetExceeded = errors.New("socket scan budget exceeded")

type SocketInfo struct {
	SocketID      string
	HostPath      string
	ContainerPath string
	DiscoveredAt  time.Time
}

type SocketScanner struct {
	watchPaths          []string
	rules               []config.SocketForwardRule
	containerPathPrefix string
	known               map[string]SocketInfo
	maxForwards         int
	scanBudget          time.Duration
	allowSensitive      bool
	allowRecursiveGlobs bool
}

func NewSocketScanner(watchPaths []string, containerPathPrefix string, maxForwards int) *SocketScanner {
	return newSocketScanner(config.SocketForwardingConfig{
		WatchPaths:               watchPaths,
		ContainerPathPrefix:      containerPathPrefix,
		MaxSocketForwards:        maxForwards,
		ScanBudgetMillis:         config.DefaultSocketScanBudgetMillis,
		AllowRecursiveSocketGlob: true,
	})
}

func NewSocketScannerFromConfig(sf config.SocketForwardingConfig) *SocketScanner {
	return newSocketScanner(sf)
}

func newSocketScanner(sf config.SocketForwardingConfig) *SocketScanner {
	maxForwards := sf.MaxSocketForwards
	if maxForwards <= 0 {
		maxForwards = config.DefaultMaxSocketForwards
	}
	budget := time.Duration(sf.ScanBudgetMillis) * time.Millisecond //nolint:gosec // Operational scan budget; overly large values are not security-sensitive.
	if budget <= 0 {
		budget = time.Duration(config.DefaultSocketScanBudgetMillis) * time.Millisecond
	}
	return &SocketScanner{
		watchPaths:          dedupeStrings(sf.WatchPaths),
		rules:               sf.Rules,
		containerPathPrefix: sf.ContainerPathPrefix,
		known:               map[string]SocketInfo{},
		maxForwards:         maxForwards,
		scanBudget:          budget,
		allowSensitive:      sf.AllowSensitiveSockets,
		allowRecursiveGlobs: sf.AllowRecursiveSocketGlob,
	}
}

func (s *SocketScanner) Scan() ([]SocketInfo, []SocketInfo) {
	log.Debug("socket scanner running", "watchPaths", s.watchPaths)
	deadline := time.Now().Add(s.scanBudget)
	current := map[string]SocketInfo{}
	containerPaths := map[string]string{}

	for _, rule := range s.rules {
		hostPath := filepath.Clean(rule.HostPath)
		containerPath := filepath.Clean(rule.ContainerPath)
		if !IsUnixSocket(hostPath) {
			continue
		}
		if !s.allowSensitive && (rule.Sensitive || isSensitiveHostSocket(hostPath)) {
			log.Warn("skipping sensitive host socket; pass --allow-sensitive-sockets to forward it", "hostPath", hostPath, "containerPath", containerPath)
			continue
		}
		if existingHost, ok := containerPaths[containerPath]; ok && existingHost != hostPath {
			log.Warn("skipping socket rule with duplicate container path", "hostPath", hostPath, "containerPath", containerPath, "existingHostPath", existingHost)
			continue
		}
		containerPaths[containerPath] = hostPath
		current[hostPath] = SocketInfo{HostPath: hostPath, ContainerPath: containerPath}
	}

	for _, pattern := range s.watchPaths {
		if strings.Contains(pattern, "**") && !s.allowRecursiveGlobs {
			log.Warn("skipping recursive socket glob; pass --allow-recursive-socket-globs to enable it", "pattern", pattern)
			continue
		}
		matches, err := glob(pattern, deadline)
		if err != nil {
			log.Warn("socket glob failed", "pattern", pattern, "err", err)
			continue
		}
		for _, path := range matches {
			if len(path) > maxUnixSocketPath || !IsUnixSocket(path) {
				continue
			}
			if !s.allowSensitive && isSensitiveHostSocket(path) {
				log.Warn("skipping sensitive host socket; pass --allow-sensitive-sockets to forward it", "hostPath", path)
				continue
			}
			containerPath := s.containerPath(path)
			if len(containerPath) > maxUnixSocketPath {
				log.Warn("derived container socket path is too long; skipping", "hostPath", path, "containerPath", containerPath)
				continue
			}
			if existingHost, ok := containerPaths[containerPath]; ok && existingHost != path {
				log.Warn("skipping socket with duplicate container path", "hostPath", path, "containerPath", containerPath, "existingHostPath", existingHost)
				continue
			}
			containerPaths[containerPath] = path
			current[path] = SocketInfo{HostPath: path, ContainerPath: containerPath}
		}
	}

	removed := make([]SocketInfo, 0)
	knownPaths := sortedSocketInfoKeys(s.known)
	for _, path := range knownPaths {
		info := s.known[path]
		if _, ok := current[path]; !ok {
			removed = append(removed, info)
			delete(s.known, path)
		}
	}

	found := make([]SocketInfo, 0)
	currentPaths := sortedSocketInfoKeys(current)
	for _, path := range currentPaths {
		candidate := current[path]
		if existing, ok := s.known[path]; ok {
			existing.ContainerPath = candidate.ContainerPath
			s.known[path] = existing
			continue
		}
		if len(s.known) >= s.maxForwards {
			log.Warn("socket forward limit reached; ignoring", "path", path)
			break
		}
		info := SocketInfo{SocketID: randomID(), HostPath: path, ContainerPath: candidate.ContainerPath, DiscoveredAt: time.Now()}
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
	for _, path := range sortedSocketInfoKeys(s.known) {
		info := s.known[path]
		out = append(out, info)
	}
	return out
}

func (s *SocketScanner) containerPath(hostPath string) string {
	name := filepath.Base(hostPath) + "-" + shortPathHash(hostPath)
	if s.containerPathPrefix == "" {
		return filepath.Join(filepath.Dir(hostPath), name)
	}
	return filepath.Join(s.containerPathPrefix, name)
}

func IsUnixSocket(path string) bool {
	info, err := os.Lstat(path) //nolint:gosec // Socket watch paths are explicit user configuration.
	if err != nil {
		return false
	}
	return info.Mode()&fs.ModeSocket != 0
}

func glob(pattern string, deadline time.Time) ([]string, error) {
	if !strings.Contains(pattern, "**") {
		matches, err := filepath.Glob(pattern)
		sort.Strings(matches)
		return matches, err
	}
	root := globRoot(pattern)
	matches := make([]string, 0)
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if time.Now().After(deadline) {
			return errSocketScanBudgetExceeded
		}
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
	sort.Strings(matches)
	return matches, walkErr
}

func globRoot(pattern string) string {
	prefix, _, _ := strings.Cut(pattern, "**")
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

func shortPathHash(path string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return hex.EncodeToString(sum[:])[:8]
}

func isSensitiveHostSocket(path string) bool {
	cleaned := strings.ToLower(filepath.Clean(path))
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

func ValidateSocketForwardingConfig(sf config.SocketForwardingConfig) error {
	if !sf.Enabled {
		return nil
	}
	containerPaths := map[string]string{}
	for _, rule := range sf.Rules {
		hostPath := filepath.Clean(strings.TrimSpace(rule.HostPath))
		containerPath := filepath.Clean(strings.TrimSpace(rule.ContainerPath))
		if hostPath == "." || !filepath.IsAbs(hostPath) {
			return fmt.Errorf("socket forward host path must be absolute: %q", rule.HostPath)
		}
		if containerPath == "." || !filepath.IsAbs(containerPath) {
			return fmt.Errorf("socket forward container path must be absolute: %q", rule.ContainerPath)
		}
		if len(containerPath) > maxUnixSocketPath {
			return fmt.Errorf("socket forward container path too long: %d > %d", len(containerPath), maxUnixSocketPath)
		}
		if !sf.AllowSensitiveSockets && (rule.Sensitive || isSensitiveHostSocket(hostPath)) {
			return fmt.Errorf("refusing to forward sensitive host socket %s without --allow-sensitive-sockets", hostPath)
		}
		if existing, ok := containerPaths[containerPath]; ok && existing != hostPath {
			return fmt.Errorf("socket forwards %s and %s use the same container path %s", existing, hostPath, containerPath)
		}
		containerPaths[containerPath] = hostPath
	}
	for _, pattern := range sf.WatchPaths {
		if strings.Contains(pattern, "**") {
			if !sf.AllowRecursiveSocketGlob {
				return fmt.Errorf("recursive socket glob %q requires --allow-recursive-socket-globs", pattern)
			}
			if isBroadRecursiveGlob(pattern) {
				log.Warn("recursive socket glob may discover privileged host sockets; prefer exact --socket-forward rules", "pattern", pattern)
			}
		}
	}
	return nil
}

func isBroadRecursiveGlob(pattern string) bool {
	root := filepath.Clean(globRoot(pattern))
	return root == string(filepath.Separator) || root == "/run" || root == "/var" || root == "/tmp"
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedSocketInfoKeys(values map[string]SocketInfo) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
