package host

import "testing"

func TestRewriteURL(t *testing.T) {
	portMap := map[uint16]uint16{3000: 3001, 8080: 9090}
	cases := map[string]string{
		"http://localhost:3000/callback":     "http://localhost:3001/callback",
		"http://127.0.0.1:8080/api":          "http://127.0.0.1:9090/api",
		"https://[::1]:3000/path?q=1#frag":   "https://[::1]:3001/path?q=1#frag",
		"http://localhost:4000/unchanged":    "http://localhost:4000/unchanged",
		"http://example.com:3000/unchanged":  "http://example.com:3000/unchanged",
		"http://localhost/path-without-port": "http://localhost/path-without-port",
	}
	for in, want := range cases {
		if got := RewriteURL(in, portMap); got != want {
			t.Fatalf("RewriteURL(%q) = %q, want %q", in, got, want)
		}
	}
}
