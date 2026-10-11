package awg

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// countingNetwork считает обращения к DNS и запоминает, куда звонили.
type countingNetwork struct {
	mu      sync.Mutex
	lookups int
	answer  []string
	dialed  []string
	failTo  string
}

func (n *countingNetwork) LookupHost(ctx context.Context, host string) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lookups++
	return n.answer, nil
}

func (n *countingNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, address)
	fail := address == n.failTo
	n.mu.Unlock()
	if fail {
		return nil, errors.New("отказ")
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func (n *countingNetwork) ListenPacket(bool) (net.PacketConn, error) {
	return nil, errors.New("нет")
}

func TestDNSCacheSecondConnectionSkipsLookup(t *testing.T) {
	inner := &countingNetwork{answer: []string{"104.16.1.1"}}
	c := newCachedNetwork(inner)

	for i := 0; i < 3; i++ {
		conn, err := c.DialContext(context.Background(), "tcp", "cp.cloudflare.com:80")
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	if inner.lookups != 1 {
		t.Fatalf("три соединения — %d запросов DNS, ждал 1", inner.lookups)
	}
	if inner.dialed[0] != "104.16.1.1:80" {
		t.Fatalf("соединение не по адресу из DNS: %s", inner.dialed[0])
	}
}

func TestDNSCacheExpires(t *testing.T) {
	inner := &countingNetwork{answer: []string{"104.16.1.1"}}
	c := newCachedNetwork(inner)
	now := time.Now()
	c.now = func() time.Time { return now }

	_, _ = c.LookupHost(context.Background(), "x.ru")
	now = now.Add(dnsTTL + time.Second)
	_, _ = c.LookupHost(context.Background(), "x.ru")

	if inner.lookups != 2 {
		t.Fatalf("после срока ответ должен запрашиваться заново, запросов %d", inner.lookups)
	}
}

func TestDNSCacheFailedDialForgetsName(t *testing.T) {
	inner := &countingNetwork{answer: []string{"104.16.1.1"}, failTo: "104.16.1.1:443"}
	c := newCachedNetwork(inner)

	if _, err := c.DialContext(context.Background(), "tcp", "site.com:443"); err == nil {
		t.Fatal("отказ должен дойти до вызывающего")
	}
	inner.failTo = ""
	_, _ = c.DialContext(context.Background(), "tcp", "site.com:443")

	if inner.lookups != 2 {
		t.Fatalf("после неудачи имя должно спрашиваться заново, запросов %d", inner.lookups)
	}
}

func TestDNSCachePrefersIPv4AndPassesIPsThrough(t *testing.T) {
	inner := &countingNetwork{answer: []string{"2606:4700::1", "104.16.1.1"}}
	c := newCachedNetwork(inner)

	_, _ = c.DialContext(context.Background(), "tcp", "site.com:443")
	_, _ = c.DialContext(context.Background(), "tcp", "8.8.8.8:53")

	if inner.dialed[0] != "104.16.1.1:443" {
		t.Fatalf("ждал IPv4, ушло на %s", inner.dialed[0])
	}
	if inner.dialed[1] != "8.8.8.8:53" || inner.lookups != 1 {
		t.Fatalf("адрес-IP не должен трогать DNS: %v, запросов %d", inner.dialed, inner.lookups)
	}
}
