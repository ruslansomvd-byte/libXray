package xray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/xtls/libxray/nodep"
	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

// PingLiveResult is one outbound's measurement, in the order the tags were
// given.
type PingLiveResult struct {
	Tag     string
	Success bool
	Delay   int64
	Error   string
}

// PingLive measures outbounds of the tunnel that is already running.
//
// PingBatch cannot help here: it stands up its own isolated instance and
// refuses to run while a managed one exists, so with the tunnel up the app
// had nothing to measure with and fell back to a TCP handshake against the
// node's address -- which answers even when the proxy behind it carries
// nothing, and which, with a tun interface up, is carried through the tunnel
// itself and so reports the tunnel's latency for every node alike. That is
// the "sometimes wrong" the owner sees.
//
// This dials through the live instance with the outbound forced, exactly as
// the balancer's own observatory does. It costs one connection at a time and
// no second core, which matters: the iOS extension is killed past ~50 MB.
func PingLive(tags []string, timeout int, targetURL string) ([]PingLiveResult, error) {
	if len(tags) == 0 {
		return nil, errors.New("ping live: no outbound tags")
	}
	if timeout <= 0 {
		return nil, errors.New("ping live: timeout must be greater than zero")
	}
	parsed, err := url.ParseRequestURI(targetURL)
	if err != nil || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("ping live: URL must be an absolute HTTP or HTTPS URL")
	}

	coreServerMu.Lock()
	server := coreServer
	coreServerMu.Unlock()
	if server == nil || !server.IsRunning() {
		return nil, errors.New("ping live: no running instance")
	}

	results := make([]PingLiveResult, len(tags))
	// Serial on purpose. Measuring every outbound at once is what put the iOS
	// extension at its memory ceiling once already (burstObservatory), and
	// concurrent probes also compete for the same uplink and inflate each
	// other's numbers.
	for i, tag := range tags {
		results[i] = probeLiveOutbound(server, tag, timeout, targetURL)
	}
	return results, nil
}

func probeLiveOutbound(
	server *core.Instance,
	outboundTag string,
	timeout int,
	targetURL string,
) PingLiveResult {
	httpTimeout := time.Second * time.Duration(timeout)
	transport := &http.Transport{
		// On, for the same reason as in PingBatch: the second of the two
		// requests PingHTTPRequest sends is the one that measures latency
		// rather than handshake cost.
		DisableKeepAlives: false,
		MaxIdleConns:      1,
		IdleConnTimeout:   httpTimeout,
		DialContext: func(
			ctx context.Context,
			network string,
			address string,
		) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, fmt.Errorf("unsupported ping network %q", network)
			}
			destination, err := xrayNet.ParseDestination("tcp:" + address)
			if err != nil {
				return nil, err
			}
			ctx = session.SetForcedOutboundTagToContext(ctx, outboundTag)
			return core.Dial(ctx, server, destination)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: httpTimeout}
	delay, err := nodep.PingHTTPRequest(client, targetURL, timeout)
	if err != nil {
		return PingLiveResult{Tag: outboundTag, Delay: delay, Error: err.Error()}
	}
	return PingLiveResult{Tag: outboundTag, Success: true, Delay: delay}
}
