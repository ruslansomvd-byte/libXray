package nodep

import (
	"io"
	"math"
	"net/http"
	"net/url"
	"time"
)

const (
	PingDelayTimeout int64 = 11000
	PingDelayError   int64 = 10000
)

// get the delay of some outbound.
// timeout means how long the http request will be cancelled if no response, in units of seconds.
// url means the website we use to test speed. "https://www.google.com" is a good choice for most cases.
// proxy means the local http/socks5 proxy, like "socks5://[::1]:1080". If proxy is empty, it means no proxy.
func MeasureDelay(timeout int, url string, proxy string) (int64, error) {
	httpTimeout := time.Second * time.Duration(timeout)
	c, err := CoreHTTPClient(httpTimeout, proxy)
	if err != nil {
		return PingDelayError, err
	}
	delay, err := PingHTTPRequest(c, url, timeout)
	if err != nil {
		return delay, err
	}

	return delay, nil
}

func CoreHTTPClient(timeout time.Duration, proxy string) (*http.Client, error) {
	tr := &http.Transport{
		DisableKeepAlives: true,
	}

	if len(proxy) > 0 {
		tr.Proxy = func(r *http.Request) (*url.URL, error) {
			return url.Parse(proxy)
		}
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	return c, nil
}

// PingHTTPRequest measures a proxy by carrying two HEAD requests through it
// and keeping the better one.
//
// One request measures the wrong thing. It pays for the whole setup -- TCP,
// TLS, and for reality or xhttp a good deal more -- and that cost swamps the
// latency it is supposed to report: the same node measured twice in a row can
// differ by hundreds of milliseconds, and a nearby node with an expensive
// handshake ranks below a distant one with a cheap one. Happ, which the owner
// trusts to report this correctly, sends two requests over one session and
// takes the best; its own settings screen explains why ("the second request
// measures pure connection speed via an already established TLS connection").
// This does the same, which is also why the caller must leave keep-alives on.
func PingHTTPRequest(c *http.Client, url string, timeout int) (int64, error) {
	best := int64(-1)
	var lastErr error
	var lastDelay int64 = PingDelayError
	for range 2 {
		delay, err := pingHTTPOnce(c, url, timeout)
		if err != nil {
			lastErr = err
			lastDelay = delay
			// A failed first attempt is worth a second one (a proxy that has
			// just come up, a lost SYN); two failures are an answer.
			continue
		}
		if best < 0 || delay < best {
			best = delay
		}
	}
	if best < 0 {
		return lastDelay, lastErr
	}
	return best, nil
}

func pingHTTPOnce(c *http.Client, url string, timeout int) (int64, error) {
	start := time.Now()
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return PingDelayError, err
	}
	response, err := c.Do(req)
	delay := time.Since(start).Milliseconds()
	if err != nil {
		precision := delay - int64(timeout)*1000
		if math.Abs(float64(precision)) < 50 {
			return PingDelayTimeout, err
		}
		return PingDelayError, err
	}
	// Drained, not just closed: an unread body keeps the connection out of the
	// idle pool, and the second request would then pay for a new one -- which
	// is the entire measurement.
	io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	response.Body.Close()
	return delay, nil
}
