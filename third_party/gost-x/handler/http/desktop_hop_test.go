package http

import (
	"net/http"
	"testing"
)

func TestDesktopHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Add("Connection", "keep-alive, X-Private")
	h.Add("Connection", "X-Other")
	h.Set("X-Private", "must not escape")
	h.Set("X-Other", "must not escape")
	h.Set("Proxy-Authorization", "Basic test")
	h.Set("Keep-Alive", "timeout=10")
	h.Set("X-End-To-End", "keep")
	stripDesktopHopHeaders(h, true)
	for _, key := range []string{"Connection", "X-Private", "X-Other", "Proxy-Authorization", "Keep-Alive"} {
		if h.Get(key) != "" {
			t.Errorf("hop header forwarded: %s", key)
		}
	}
	if h.Get("X-End-To-End") != "keep" {
		t.Fatal("end-to-end header lost")
	}
}
func TestDesktopHopHeadersPreservesWebSocketAndTrailers(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Private, Upgrade")
	h.Set("Upgrade", "websocket")
	h.Set("X-Private", "must not escape")
	h.Set("Te", "gzip, trailers")
	stripDesktopHopHeaders(h, true)
	if h.Get("Connection") != "Upgrade" || h.Get("Upgrade") != "websocket" || h.Get("X-Private") != "" || h.Get("Te") != "trailers" {
		t.Fatalf("incorrect upgrade headers: %v", h)
	}
	stripDesktopHopHeaders(h, false)
	if h.Get("Connection") != "" || h.Get("Upgrade") != "" {
		t.Fatal("unexpected non-upgrade response header")
	}
}
