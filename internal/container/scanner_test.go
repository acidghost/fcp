package container

import (
	"os"
	"path/filepath"
	"testing"
)

const procNetTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:4B59 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 100 0 0 10 0
   2: 0100007F:C3A8 AC110002:01BB 01 00000000:00000000 02:0000009C 00000000  1000        0 34567 2 0000000000000000 20 4 30 10 -1
   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 45678 1 0000000000000000 100 0 0 10 0
`

const procNetTCP6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:23F1 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 56789 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNetTCP(t *testing.T) {
	items := ParseProcNetTCP(procNetTCPFixture)
	ports := make([]uint16, 0, len(items))
	for _, item := range items {
		ports = append(ports, item.Port)
	}
	want := []uint16{8080, 19289, 80}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports = %v, want %v", ports, want)
		}
	}
}

func TestScanListeningPortsDeduplicatesAndExcludes(t *testing.T) {
	tmp := t.TempDir()
	netDir := filepath.Join(tmp, "net")
	if err := os.MkdirAll(netDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(procNetTCPFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(procNetTCP6Fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	ports, err := ScanListeningPorts(tmp, map[uint16]struct{}{80: {}})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]uint16, 0, len(ports))
	for _, lp := range ports {
		got = append(got, lp.Port)
	}
	want := []uint16{8080, 19289, 9201}
	if len(got) != len(want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ports = %v, want %v", got, want)
		}
	}
}
