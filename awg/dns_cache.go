package awg

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// dnsTTL — сколько держать ответ. Стек амнезии не отдаёт TTL записей, так
// что срок свой: короткий, чтобы смена адреса у сайта не ломала его надолго,
// и достаточный, чтобы страница с десятком соединений не платила за DNS
// десять раз.
const dnsTTL = 2 * time.Minute

// cachedNetwork кэширует разрешение имён поверх Network.
//
// Зачем: Xray отдаёт в socks имя сайта, и без кэша каждое новое соединение
// сначала ходило за DNS через туннель — лишний RTT. Замер 11.10: HTTP-проба
// через амнезию ≈ 3 RTT, из них один — DNS.
type cachedNetwork struct {
	inner Network
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]dnsEntry
}

type dnsEntry struct {
	names   []string
	expires time.Time
}

// WithDNSCache — то же, что использует StartUserspace; наружу для замеров.
func WithDNSCache(inner Network) Network { return newCachedNetwork(inner) }

func newCachedNetwork(inner Network) *cachedNetwork {
	return &cachedNetwork{inner: inner, now: time.Now, entries: map[string]dnsEntry{}}
}

func (c *cachedNetwork) LookupHost(ctx context.Context, host string) ([]string, error) {
	c.mu.Lock()
	e, ok := c.entries[host]
	c.mu.Unlock()
	if ok && c.now().Before(e.expires) {
		return e.names, nil
	}
	names, err := c.inner.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.entries[host] = dnsEntry{names: names, expires: c.now().Add(dnsTTL)}
	c.mu.Unlock()
	return names, nil
}

func (c *cachedNetwork) forget(host string) {
	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}

// DialContext разрешает имя через кэш и соединяется по адресу. Неудачное
// соединение выбрасывает имя из кэша: адрес мог смениться, и следующая
// попытка должна спросить DNS заново, а не биться в старый.
func (c *cachedNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return c.inner.DialContext(ctx, network, address)
	}
	names, err := c.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	ip, err := preferIPv4(names)
	if err != nil {
		return nil, err
	}
	conn, err := c.inner.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	if err != nil {
		c.forget(host)
		return nil, err
	}
	return conn, nil
}

func (c *cachedNetwork) ListenPacket(ipv6 bool) (net.PacketConn, error) {
	return c.inner.ListenPacket(ipv6)
}
