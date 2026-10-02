// Живая проверка: поднять AmneziaWG из настоящего ключа панели целиком в
// юзерспейсе (netstack, без root и без tun) и сходить наружу.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/xtls/libxray/awg"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	must(err)

	p, err := awg.ParseConf(string(raw))
	must(err)
	fmt.Println("разобрано:", p.Addresses, p.DNS, "MTU", p.MTU)

	var addrs []netip.Addr
	for _, a := range p.Addresses {
		ip, err := netip.ParsePrefix(a)
		must(err)
		addrs = append(addrs, ip.Addr())
	}
	var dns []netip.Addr
	for _, d := range p.DNS {
		if ip, err := netip.ParseAddr(d); err == nil {
			dns = append(dns, ip)
		}
	}

	tunDev, tnet, err := netstack.CreateNetTUN(addrs, dns, p.MTU)
	must(err)

	logger := device.NewLogger(device.LogLevelError, "awg ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	must(dev.IpcSet(p.UAPI))
	must(dev.Up())
	fmt.Println("движок поднят, жду рукопожатие")

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := dev.IpcGet()
		if h := field(st, "last_handshake_time_sec"); h != "" && h != "0" {
			fmt.Println("РУКОПОЖАТИЕ ЕСТЬ")
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	st, _ := dev.IpcGet()
	if h := field(st, "last_handshake_time_sec"); h == "" || h == "0" {
		fmt.Println("рукопожатия нет за 20 с")
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tnet.DialContext(ctx, network, addr)
			},
		},
	}
	resp, err := client.Get("http://ifconfig.me/ip")
	must(err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println("выходной адрес:", strings.TrimSpace(string(body)))

	st, _ = dev.IpcGet()
	fmt.Println("передано/принято:", field(st, "tx_bytes"), "/", field(st, "rx_bytes"))
	dev.Close()
}

func field(ipc, key string) string {
	for _, l := range strings.Split(ipc, "\n") {
		if strings.HasPrefix(l, key+"=") {
			return strings.TrimPrefix(l, key+"=")
		}
	}
	return ""
}

func must(err error) {
	if err != nil {
		fmt.Println("ОШИБКА:", err)
		os.Exit(1)
	}
}
