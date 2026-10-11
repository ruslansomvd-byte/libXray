package awg

// Амнезия как обычный выход Xray.
//
// Зачем: в режиме туннеля AmneziaWG забирает весь трафик устройства, и
// Xray с его правилами (российские сайты напрямую, балансир, наблюдатель)
// в этот момент не работает вовсе. Поднятая здесь амнезия живёт целиком в
// юзерспейсе (gvisor netstack, без tun и без root), а наружу смотрит
// socks5 на 127.0.0.1. Xray видит её как самый обычный socks-выход: на неё
// действуют все правила маршрутизации, она попадает в балансир, и
// наблюдатель ядра её измеряет — у строки появляется пинг.
//
// Форк Xray с полями амнезии в outbound wireguard не берём сознательно:
// в основной ветке эту поддержку закрыли как «не планируется», и форк
// пришлось бы догонять на каждом обновлении ядра.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/xtls/libxray/awg/netstack"
)

// Network — то, через что socks-сервер ходит наружу. В бою это сетевой
// стек амнезии, в тестах — обычная сеть.
type Network interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// ListenPacket — несвязанный UDP-сокет нужного семейства.
	ListenPacket(ipv6 bool) (net.PacketConn, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// SocksServer — минимальный socks5 без авторизации: CONNECT и UDP ASSOCIATE.
//
// UDP обязателен: правила приложения отправляют в выход и tcp, и udp, а
// в прямом режиме амнезия возит UDP (звонки, игры, QUIC). Выход без UDP
// был бы шагом назад.
//
// Слушает строго 127.0.0.1: на любом другом адресе это открытый прокси в
// туннель для всей локальной сети.
type SocksServer struct {
	nw   Network
	ln   net.Listener
	wg   sync.WaitGroup
	once sync.Once
}

// ServeSocks поднимает socks5 на 127.0.0.1 и свободном порту.
func ServeSocks(nw Network) (*SocksServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &SocksServer{nw: nw, ln: ln}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Port — на каком порту слушает сервер.
func (s *SocksServer) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Close останавливает приём. Уже открытые соединения доживают сами.
func (s *SocksServer) Close() error {
	var err error
	s.once.Do(func() {
		err = s.ln.Close()
		s.wg.Wait()
	})
	return err
}

func (s *SocksServer) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *SocksServer) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	cmd, target, err := socksHandshake(c)
	if err != nil {
		return
	}
	if cmd == cmdUDPAssociate {
		s.udpAssociate(c)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	up, err := s.nw.DialContext(ctx, "tcp", target)
	cancel()
	if err != nil {
		// 0x05 — «соединение отклонено»: Xray поймёт отказ сразу, а не по
		// таймауту, и наблюдатель честно запишет ноду в мёртвые.
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); closeWrite(c); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

const (
	cmdConnect      = 1
	cmdUDPAssociate = 3
)

// socksHandshake читает приветствие и запрос, возвращает команду и адрес.
func socksHandshake(c net.Conn) (byte, string, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return 0, "", err
	}
	if hdr[0] != 5 {
		return 0, "", errors.New("не socks5")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return 0, "", err
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return 0, "", err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return 0, "", err
	}
	if req[0] != 5 {
		return 0, "", errors.New("не socks5")
	}
	if req[1] != cmdConnect && req[1] != cmdUDPAssociate {
		// 0x07 — команда не поддерживается (BIND нам не нужен).
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return 0, "", fmt.Errorf("команда %d не поддерживается", req[1])
	}

	host, port, err := readAddr(c, req[3])
	if err != nil {
		return 0, "", err
	}
	return req[1], net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// readAddr читает адрес socks5 (тип уже прочитан) и порт.
func readAddr(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4([4]byte(b)).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16([16]byte(b)).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, errors.New("неизвестный тип адреса")
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(p), nil
}

// Userspace — амнезия в юзерспейсе с socks5 перед ней.
type Userspace struct {
	dev   *device.Device
	socks *SocksServer
}

// StartUserspace поднимает амнезию из .conf панели без tun и отдаёт socks.
func StartUserspace(confText string) (*Userspace, error) {
	p, err := ParseConf(confText)
	if err != nil {
		return nil, fmt.Errorf("конфигурация не разобрана: %w", err)
	}
	var addrs, dns []netip.Addr
	for _, a := range p.Addresses {
		pr, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, fmt.Errorf("адрес %q: %w", a, err)
		}
		addrs = append(addrs, pr.Addr())
	}
	for _, d := range p.DNS {
		if ip, err := netip.ParseAddr(d); err == nil {
			dns = append(dns, ip)
		}
	}
	mtu := p.MTU
	if mtu <= 0 {
		mtu = 1280
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, fmt.Errorf("сетевой стек: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "[awg] "))
	if err := dev.IpcSet(p.UAPI); err != nil {
		dev.Close()
		return nil, fmt.Errorf("конфигурация не принята ядром: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("не удалось поднять движок: %w", err)
	}
	s, err := ServeSocks(newCachedNetwork(&stackNetwork{tnet: tnet, addrs: addrs}))
	if err != nil {
		dev.Close()
		return nil, err
	}
	return &Userspace{dev: dev, socks: s}, nil
}

// Port — порт socks5 на 127.0.0.1.
func (u *Userspace) Port() int { return u.socks.Port() }

// Stats — счётчики и время последнего рукопожатия.
func (u *Userspace) Stats() Stats {
	raw, err := u.dev.IpcGet()
	if err != nil {
		return Stats{}
	}
	return parseStats(raw)
}

// Close гасит socks и движок.
func (u *Userspace) Close() {
	_ = u.socks.Close()
	u.dev.Close()
}
