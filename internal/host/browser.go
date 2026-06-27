package host

import (
	"fmt"
	"maps"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/acidghost/fcp/internal/log"
	"github.com/acidghost/fcp/internal/protocol"
)

const browserRateLimitPerSecond = 5

type BrowserOpener struct {
	mu          sync.Mutex
	portMap     map[uint16]uint16
	recentOpens []time.Time
	command     string
}

func NewBrowserOpener(command string) *BrowserOpener {
	return &BrowserOpener{portMap: map[uint16]uint16{}, command: command}
}

func (b *BrowserOpener) AddPortMapping(containerPort, hostPort uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.portMap[containerPort] = hostPort
}

func (b *BrowserOpener) RemovePortMapping(containerPort uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.portMap, containerPort)
}

func (b *BrowserOpener) Open(rawURL string) error {
	if err := protocol.ValidateOpenURL(rawURL); err != nil {
		return err
	}
	b.mu.Lock()
	now := time.Now()
	kept := b.recentOpens[:0]
	for _, t := range b.recentOpens {
		if now.Sub(t) < time.Second {
			kept = append(kept, t)
		}
	}
	b.recentOpens = kept
	if len(b.recentOpens) >= browserRateLimitPerSecond {
		b.mu.Unlock()
		return fmt.Errorf("browser open rate limited")
	}
	b.recentOpens = append(b.recentOpens, now)
	portMap := make(map[uint16]uint16, len(b.portMap))
	maps.Copy(portMap, b.portMap)
	command := b.command
	b.mu.Unlock()

	rewritten := RewriteURL(rawURL, portMap)
	log.Debug("opening URL in browser", "original", rawURL, "rewritten", rewritten, "command", command)
	if command == "" {
		if runtime.GOOS == "darwin" {
			command = "open"
		} else {
			command = "xdg-open"
		}
	}
	//nolint:gosec // command is an explicit executable name/path and URL is passed as one argument, not through a shell.
	cmd := exec.Command(command, rewritten)
	if err := cmd.Run(); err != nil {
		log.Warn("browser open failed", "command", command, "err", err)
		return err
	}
	log.Debug("browser opened successfully", "url", rewritten)
	return nil
}

func RewriteURL(rawURL string, portMap map[uint16]uint16) string {
	if len(portMap) == 0 {
		return rawURL
	}
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd < 0 {
		return rawURL
	}
	schemeEnd += len("://")
	rest := rawURL[schemeEnd:]
	lowerRest := strings.ToLower(rest)
	for _, hostPrefix := range []string{"localhost:", "127.0.0.1:", "[::1]:"} {
		if !strings.HasPrefix(lowerRest, hostPrefix) {
			continue
		}
		afterHost := rest[len(hostPrefix):]
		digits := takeDigits(afterHost)
		if digits == "" {
			return rawURL
		}
		port64, err := strconv.ParseUint(digits, 10, 16)
		if err != nil {
			return rawURL
		}
		if hostPort, ok := portMap[uint16(port64)]; ok {
			return rawURL[:schemeEnd+len(hostPrefix)] + strconv.Itoa(int(hostPort)) + afterHost[len(digits):]
		}
		return rawURL
	}
	return rawURL
}

func takeDigits(s string) string {
	idx := 0
	for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
		idx++
	}
	return s[:idx]
}
