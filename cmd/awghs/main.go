// Замер рукопожатия AmneziaWG с подробным журналом движка: сколько попыток
// и через какие паузы проходит, пока сервер не ответит.
package main

import (
	"context"
	"fmt"
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
	raw, _ := os.ReadFile(os.Args[1])
	p, err := awg.ParseConf(string(raw))
	if err != nil {
		panic(err)
	}
	var addrs []netip.Addr
	for _, a := range p.Addresses {
		pr, _ := netip.ParsePrefix(a)
		addrs = append(addrs, pr.Addr())
	}
	t0 := time.Now()
	logf := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if strings.Contains(msg, "andshake") || strings.Contains(msg, "eceiv") || strings.Contains(msg, "ending") || strings.Contains(msg, "ookie") {
			fmt.Printf("%6d мс  %s\n", time.Since(t0).Milliseconds(), msg)
		}
	}
	tunDev, tnet, _ := netstack.CreateNetTUN(addrs, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, p.MTU)
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), &device.Logger{Verbosef: logf, Errorf: logf})
	if err := dev.IpcSet(p.UAPI); err != nil {
		panic(err)
	}
	_ = dev.Up()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := tnet.DialContext(ctx, "tcp", "1.1.1.1:80")
		if err == nil {
			c.Close()
		}
	}()
	for time.Since(t0) < 20*time.Second {
		st, _ := dev.IpcGet()
		if strings.Contains(st, "last_handshake_time_sec=") && !strings.Contains(st, "last_handshake_time_sec=0\n") {
			fmt.Printf("ИТОГ: рукопожатие за %d мс\n", time.Since(t0).Milliseconds())
			dev.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Println("ИТОГ: нет за 20 с")
}
