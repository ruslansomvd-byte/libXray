package awg

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/xtls/libxray/awg/netstack"
)

// udpAssociate обслуживает UDP ASSOCIATE (RFC 1928, раздел 7).
//
// Клиент — Xray на том же устройстве — шлёт датаграммы с socks-заголовком
// на локальный порт ретранслятора; мы снимаем заголовок и отправляем
// полезную нагрузку через амнезию, ответы заворачиваем обратно. Жизнь
// ассоциации привязана к управляющему TCP-соединению: закрыл его клиент —
// закрылось всё.
func (s *SocksServer) udpAssociate(ctrl net.Conn) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_, _ = ctrl.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	port := relay.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(port))
	if _, err := ctrl.Write(reply); err != nil {
		_ = relay.Close()
		return
	}
	_ = ctrl.SetDeadline(time.Time{})

	a := &association{nw: s.nw, relay: relay, resolved: map[string]netip.Addr{}}
	go a.fromClient()

	// Управляющее соединение молчит до конца ассоциации; EOF — сигнал
	// закрыть всё.
	_, _ = io.Copy(io.Discard, ctrl)
	a.close()
}

type association struct {
	nw    Network
	relay *net.UDPConn

	mu       sync.Mutex
	client   *net.UDPAddr
	v4, v6   net.PacketConn
	resolved map[string]netip.Addr
	closed   bool
}

func (a *association) close() {
	a.mu.Lock()
	a.closed = true
	v4, v6 := a.v4, a.v6
	a.mu.Unlock()
	_ = a.relay.Close()
	if v4 != nil {
		_ = v4.Close()
	}
	if v6 != nil {
		_ = v6.Close()
	}
}

func (a *association) fromClient() {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Чужие отправители не принимаются: первый, кто прислал датаграмму
		// с 127.0.0.1, и есть клиент этой ассоциации.
		if !from.IP.IsLoopback() {
			continue
		}
		a.mu.Lock()
		if a.client == nil {
			a.client = from
		}
		ok := a.client.String() == from.String()
		a.mu.Unlock()
		if !ok {
			continue
		}

		dst, payload, err := parseUDPHeader(buf[:n])
		if err != nil {
			continue
		}
		addr, err := a.resolve(dst)
		if err != nil {
			continue
		}
		pc, err := a.socketFor(addr.Addr().Is6())
		if err != nil {
			continue
		}
		_, _ = pc.WriteTo(payload, net.UDPAddrFromAddrPort(addr))
	}
}

func (a *association) resolve(dst string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
	}

	a.mu.Lock()
	ip, ok := a.resolved[host]
	a.mu.Unlock()
	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		names, err := a.nw.LookupHost(ctx, host)
		cancel()
		if err != nil || len(names) == 0 {
			return netip.AddrPort{}, errors.New("имя не разрешилось")
		}
		ip, err = preferIPv4(names)
		if err != nil {
			return netip.AddrPort{}, err
		}
		a.mu.Lock()
		a.resolved[host] = ip
		a.mu.Unlock()
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
}

// preferIPv4 выбирает IPv4, если он есть. У ключей амнезии адрес обычно
// только IPv4, и пакет на AAAA-адрес молча пропал бы: сокета IPv6 нет.
func preferIPv4(names []string) (netip.Addr, error) {
	var v6 netip.Addr
	for _, n := range names {
		ip, err := netip.ParseAddr(n)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() {
			return ip, nil
		}
		if !v6.IsValid() {
			v6 = ip
		}
	}
	if v6.IsValid() {
		return v6, nil
	}
	return netip.Addr{}, errors.New("имя не разрешилось")
}

func (a *association) socketFor(ipv6 bool) (net.PacketConn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, net.ErrClosed
	}
	cur := &a.v4
	if ipv6 {
		cur = &a.v6
	}
	if *cur != nil {
		return *cur, nil
	}
	pc, err := a.nw.ListenPacket(ipv6)
	if err != nil {
		return nil, err
	}
	*cur = pc
	go a.toClient(pc)
	return pc, nil
}

func (a *association) toClient(pc net.PacketConn) {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		src, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		if client == nil {
			continue
		}
		_, _ = a.relay.WriteToUDP(buildUDPHeader(src, buf[:n]), client)
	}
}

// parseUDPHeader снимает socks-заголовок: RSV(2) FRAG(1) ATYP АДРЕС ПОРТ.
// Фрагменты не поддерживаются (FRAG != 0 отбрасывается) — Xray их не шлёт.
func parseUDPHeader(b []byte) (string, []byte, error) {
	if len(b) < 4 || b[2] != 0 {
		return "", nil, errors.New("плохой заголовок")
	}
	r := &sliceReader{b: b[4:]}
	host, port, err := readAddr(r, b[3])
	if err != nil {
		return "", nil, err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), r.b, nil
}

func buildUDPHeader(src *net.UDPAddr, payload []byte) []byte {
	ip := src.IP.To4()
	atyp := byte(1)
	if ip == nil {
		ip = src.IP.To16()
		atyp = 4
	}
	out := make([]byte, 0, 4+len(ip)+2+len(payload))
	out = append(out, 0, 0, 0, atyp)
	out = append(out, ip...)
	out = binary.BigEndian.AppendUint16(out, uint16(src.Port))
	return append(out, payload...)
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// stackNetwork — сетевой стек амнезии как Network.
type stackNetwork struct {
	tnet  *netstack.Net
	addrs []netip.Addr
}

func (n *stackNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.tnet.DialContext(ctx, network, address)
}

func (n *stackNetwork) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.tnet.LookupContextHost(ctx, host)
}

// ListenPacket привязывает сокет к адресу интерфейса амнезии: без адреса
// стек не знает семейства протокола и сокет не создаёт.
func (n *stackNetwork) ListenPacket(ipv6 bool) (net.PacketConn, error) {
	for _, a := range n.addrs {
		if a.Is6() == ipv6 {
			return n.tnet.ListenUDPAddrPort(netip.AddrPortFrom(a, 0))
		}
	}
	return nil, errors.New("у ключа нет адреса нужного семейства")
}
