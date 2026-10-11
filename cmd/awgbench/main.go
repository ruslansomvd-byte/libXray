// Замер амнезии по слоям: где именно теряется время и скорость.
//
//	сырой туннель   — ICMP через амнезию (только RTT до сервера и дальше);
//	стек напрямую   — HTTP-проба через сетевой стек амнезии, как в awglive;
//	через socks     — та же проба через наш socks5 поверх того же стека.
//
// Разница между вторым и третьим — цена socks, между первым и вторым —
// цена TCP+HTTP (два RTT на новое соединение).
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/xtls/libxray/awg"
	"github.com/xtls/libxray/awg/netstack"
	"golang.org/x/net/proxy"
)

const probe = "http://cp.cloudflare.com/generate_204"
const big = "https://speed.cloudflare.com/__down?bytes=20000000"

func main() {
	raw, err := os.ReadFile(os.Args[1])
	must(err)
	p, err := awg.ParseConf(string(raw))
	must(err)

	var addrs, dns []netip.Addr
	for _, a := range p.Addresses {
		pr, _ := netip.ParsePrefix(a)
		addrs = append(addrs, pr.Addr())
	}
	for _, d := range p.DNS {
		if ip, err := netip.ParseAddr(d); err == nil {
			dns = append(dns, ip)
		}
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, dns, p.MTU)
	must(err)
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	must(dev.IpcSet(p.UAPI))
	must(dev.Up())
	defer dev.Close()

	start := time.Now()
	for !handshaken(dev) {
		if time.Since(start) > 30*time.Second {
			fmt.Println("рукопожатия нет за 30 с")
			os.Exit(1)
		}
		// Рукопожатие само не начнётся, пока не пойдёт трафик.
		go func() {
			c, err := tnet.DialContext(context.Background(), "tcp", "1.1.1.1:80")
			if err == nil {
				c.Close()
			}
		}()
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Printf("рукопожатие: %d мс\n", time.Since(start).Milliseconds())

	// 1. ICMP через туннель.
	var icmp []time.Duration
	for i := 0; i < 6; i++ {
		if d, err := pingThrough(tnet, "1.1.1.1"); err == nil {
			icmp = append(icmp, d)
		}
		time.Sleep(300 * time.Millisecond)
	}
	report("ICMP 1.1.1.1 через туннель", icmp)

	// 2. HTTP напрямую через стек.
	direct := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext:       tnet.DialContext,
		DisableKeepAlives: true,
	}}
	report("HTTP-проба, стек напрямую", probeN(direct, 6))

	// 3. HTTP через наш socks.
	s, err := awg.ServeSocks(awg.WithDNSCache(socksNetwork{tnet}))
	must(err)
	defer s.Close()
	sd, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", s.Port()), nil, proxy.Direct)
	must(err)
	viaSocks := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext:       sd.(proxy.ContextDialer).DialContext,
		DisableKeepAlives: true,
	}}
	report("HTTP-проба, через socks", probeN(viaSocks, 6))

	// 4. Скорость.
	speed("загрузка 20 МБ, стек напрямую", direct)
	speed("загрузка 20 МБ, через socks", viaSocks)
}

type socksNetwork struct{ t *netstack.Net }

func (n socksNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.t.DialContext(ctx, network, address)
}
func (n socksNetwork) ListenPacket(bool) (net.PacketConn, error) { return nil, fmt.Errorf("нет") }
func (n socksNetwork) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.t.LookupContextHost(ctx, host)
}

func handshaken(dev *device.Device) bool {
	st, _ := dev.IpcGet()
	for _, l := range strings.Split(st, "\n") {
		if strings.HasPrefix(l, "last_handshake_time_sec=") && l != "last_handshake_time_sec=0" {
			return true
		}
	}
	return false
}

func pingThrough(tnet *netstack.Net, host string) (time.Duration, error) {
	dst := netip.MustParseAddr(host)
	c, err := tnet.DialPingAddr(netip.Addr{}, dst)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	// Эхо-запрос ICMP: тип 8, код 0, контрольная сумма считается ниже.
	msg := []byte{8, 0, 0, 0, 0, 1, 0, 1, 'p', 'i', 'n', 'g'}
	cs := checksum(msg)
	msg[2], msg[3] = byte(cs>>8), byte(cs)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t := time.Now()
	if _, err := c.Write(msg); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	if _, err := c.Read(buf); err != nil {
		return 0, err
	}
	return time.Since(t), nil
}

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func probeN(c *http.Client, n int) []time.Duration {
	var out []time.Duration
	for i := 0; i < n; i++ {
		t := time.Now()
		resp, err := c.Get(probe)
		if err != nil {
			fmt.Println("  проба:", err)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		out = append(out, time.Since(t))
		time.Sleep(300 * time.Millisecond)
	}
	return out
}

func speed(name string, c *http.Client) {
	c2 := *c
	c2.Timeout = 120 * time.Second
	t := time.Now()
	resp, err := c2.Get(big)
	if err != nil {
		fmt.Println(name+":", err)
		return
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sec := time.Since(t).Seconds()
	fmt.Printf("%-34s %.1f Мбит/с (%d байт за %.1f с)\n", name+":", float64(n)*8/sec/1e6, n, sec)
}

func report(name string, ds []time.Duration) {
	if len(ds) == 0 {
		fmt.Printf("%-34s нет ответов\n", name+":")
		return
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	var ms []string
	for _, d := range ds {
		ms = append(ms, fmt.Sprint(d.Milliseconds()))
	}
	fmt.Printf("%-34s медиана %d мс  [%s]\n", name+":", ds[len(ds)/2].Milliseconds(), strings.Join(ms, " "))
}

func must(err error) {
	if err != nil {
		fmt.Println("ОШИБКА:", err)
		os.Exit(1)
	}
}
