package xray

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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

// A node that does not answer must cost one timeout, not two.
//
// The two-request measurement briefly retried after a failure, which doubled
// what every dead node cost; with a subscription full of them the locations
// list took minutes and looked frozen.
func TestPingLiveFailsOnceNotTwice(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := `{"log":{"loglevel":"none"},"outbounds":[{"protocol":"blackhole","tag":"dead"}]}`
	if err := RunXray(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = StopXray() })

	results, err := PingLive([]string{"dead"}, 1, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Success {
		t.Fatalf("a blackhole reported success: %+v", results[0])
	}
	if attempts.Load() != 0 {
		t.Fatalf("the blackhole let %d request(s) through", attempts.Load())
	}
}

// A probe URL that answers with a redirect must be measured as that answer,
// not followed. `http://1.1.1.1/` replies to HEAD with a 301 to its own https
// address, and following it hung every probe until the timeout -- which the
// owner saw as pings that were far too large, with half the locations blank.
func TestPingLiveDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
			return
		}
		// Where a followed redirect would land: slow enough to be obvious.
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := `{"log":{"loglevel":"none"},"outbounds":[{"protocol":"freedom","tag":"direct-out"}]}`
	if err := RunXray(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = StopXray() })

	started := time.Now()
	results, err := PingLive([]string{"direct-out"}, 5, server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Success {
		t.Fatalf("a 301 was treated as a failure: %+v", results[0])
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the redirect was followed: %v", elapsed)
	}
	// Two requests, both to "/" -- the measurement, not the redirect target.
	if hits.Load() != 2 {
		t.Fatalf("requests = %d, want 2", hits.Load())
	}
}
