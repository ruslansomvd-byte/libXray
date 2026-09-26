package xray

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// The tunnel that is up must be measurable. Before this the app had nothing to
// ask while connected and fell back to a TCP handshake against the node's
// address, which answers even for a proxy that carries nothing.
func TestPingLiveMeasuresThroughTheRunningInstance(t *testing.T) {
	var heads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			heads.Add(1)
		}
	}))
	defer server.Close()

	config := `{
	  "log": {"loglevel": "none"},
	  "outbounds": [
	    {"protocol": "freedom", "tag": "live-ok"},
	    {"protocol": "blackhole", "tag": "live-dead"}
	  ]
	}`
	if err := RunXray(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = StopXray() })

	results, err := PingLive([]string{"live-ok", "live-dead"}, 2, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d", len(results))
	}
	if !results[0].Success || results[0].Tag != "live-ok" {
		t.Fatalf("working outbound was not measured: %+v", results[0])
	}
	if results[1].Success || results[1].Error == "" {
		t.Fatalf("blackhole reported as reachable: %+v", results[1])
	}
	// Two per working outbound, by design; the blackhole answers neither.
	if heads.Load() != 2 {
		t.Fatalf("HEAD requests = %d, want 2", heads.Load())
	}
}

func TestPingLiveRefusesWithoutARunningInstance(t *testing.T) {
	// Saying so plainly matters: the caller falls back to showing the last
	// known numbers, and a silent empty answer would look like "all dead".
	if _, err := PingLive([]string{"anything"}, 2, "http://127.0.0.1:1/"); err == nil {
		t.Fatal("expected a refusal with no instance running")
	}
}
