// Замер DNS через стек амнезии после рукопожатия: какой из этапов теряет 5 с.
package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/xtls/libxray/awg"
	"github.com/xtls/libxray/awg/netstack"
)

func main() {
	raw, _ := os.ReadFile(os.Args[1])
	p, _ := awg.ParseConf(string(raw))
	var addrs, dns []netip.Addr
	for _, a := range p.Addresses {
		pr, _ := netip.ParsePrefix(a)
		addrs = append(addrs, pr.Addr())
	}
	for _, d := range p.DNS {
		dns = append(dns, netip.MustParseAddr(d))
	}
	tunDev, tnet, _ := netstack.CreateNetTUN(addrs, dns, p.MTU)
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	_ = dev.IpcSet(p.UAPI)
	_ = dev.Up()
	t0 := time.Now()
	for {
		st, _ := dev.IpcGet()
		if !strings.Contains(st, "last_handshake_time_sec=0\n") && strings.Contains(st, "last_handshake_time_sec=") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Printf("рукопожатие %d мс\n", time.Since(t0).Milliseconds())

	// UDP напрямую к 1.1.1.1:53 — сам ли DNS-пакет теряется
	c, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("1.1.1.1:53"))
	if err == nil {
		q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0, 0, 1, 0, 1}
		t := time.Now()
		_, _ = c.Write(q)
		_ = c.SetReadDeadline(time.Now().Add(6 * time.Second))
		b := make([]byte, 512)
		n, err := c.Read(b)
		fmt.Printf("ПЕРВЫЙ сырой UDP к 1.1.1.1:53 %d мс, %d байт, %v\n", time.Since(t).Milliseconds(), n, err)
	}
	// UDP напрямую к 1.1.1.1:53 — сам ли DNS-пакет теряется
	c, err = tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("1.1.1.1:53"))
	if err == nil {
		q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0, 0, 1, 0, 1}
		t := time.Now()
		_, _ = c.Write(q)
		_ = c.SetReadDeadline(time.Now().Add(6 * time.Second))
		b := make([]byte, 512)
		n, err := c.Read(b)
		fmt.Printf("второй сырой UDP к 1.1.1.1:53 %d мс, %d байт, %v\n", time.Since(t).Milliseconds(), n, err)
	}
	for _, host := range []string{"cp.cloudflare.com", "cp.cloudflare.com", "example.com"} {
		t := time.Now()
		ips, err := tnet.LookupContextHost(context.Background(), host)
		fmt.Printf("LookupHost %-18s %5d мс  %v %v\n", host, time.Since(t).Milliseconds(), ips, err)
	}
	_ = net.IPv4len
	dev.Close()
}
