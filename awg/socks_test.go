package awg

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// plainNetwork — обычная сеть вместо стека амнезии.
type plainNetwork struct{}

func (plainNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (plainNetwork) ListenPacket(ipv6 bool) (net.PacketConn, error) {
	if ipv6 {
		return net.ListenPacket("udp6", "[::1]:0")
	}
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

func (plainNetwork) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func socksClient(t *testing.T, s *SocksServer) proxy.Dialer {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port())), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSocksConnectByIP(t *testing.T) {
	target := echoServer(t)
	s, err := ServeSocks(plainNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c, err := socksClient(t, s).Dial("tcp", target)
	if err != nil {
		t.Fatalf("CONNECT не прошёл: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("привет\n"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "привет\n" {
		t.Fatalf("эхо не вернулось: %q %v", line, err)
	}
}

func TestSocksConnectByName(t *testing.T) {
	_, port, _ := net.SplitHostPort(echoServer(t))
	s, err := ServeSocks(plainNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Имя должно уйти в dialer как есть: резолвить его обязана амнезия,
	// иначе запрос к DNS ушёл бы мимо туннеля.
	c, err := socksClient(t, s).Dial("tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("CONNECT по имени не прошёл: %v", err)
	}
	c.Close()
}

func TestSocksRefusedTargetFailsFast(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()

	s, err := ServeSocks(plainNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	start := time.Now()
	_, err = socksClient(t, s).Dial("tcp", dead)
	if err == nil {
		t.Fatal("недоступная цель должна дать ошибку")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("отказ пришёл по таймауту, а не сразу: %v", time.Since(start))
	}
}

// associate проходит рукопожатие UDP ASSOCIATE и возвращает управляющее
// соединение и адрес ретранслятора.
func associate(t *testing.T, s *SocksServer) (net.Conn, *net.UDPAddr) {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port())))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("ответа на UDP ASSOCIATE нет: %v", err)
	}
	if reply[1] != 0 {
		t.Fatalf("UDP ASSOCIATE отклонён, код %d", reply[1])
	}
	_ = c.SetDeadline(time.Time{})
	return c, &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}
}

func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func TestSocksUDPRoundTrip(t *testing.T) {
	echo := udpEcho(t)
	s, err := ServeSocks(plainNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctrl, relay := associate(t, s)
	defer ctrl.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// По IP и по имени: имя должна разрешать амнезия, а не система.
	for _, dst := range []string{echo.String(), "localhost:" + strconv.Itoa(echo.Port)} {
		pkt := append(buildUDPHeader(echo, nil)[:0:0], 0, 0, 0)
		host, port, _ := net.SplitHostPort(dst)
		if ip := net.ParseIP(host); ip != nil {
			pkt = append(pkt, 1)
			pkt = append(pkt, ip.To4()...)
		} else {
			pkt = append(pkt, 3, byte(len(host)))
			pkt = append(pkt, host...)
		}
		pn, _ := strconv.Atoi(port)
		pkt = append(pkt, byte(pn>>8), byte(pn))
		pkt = append(pkt, []byte("пакет")...)

		if _, err := client.WriteToUDP(pkt, relay); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 2048)
		n, _, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("%s: ответа нет: %v", dst, err)
		}
		_, payload, err := parseUDPHeader(buf[:n])
		if err != nil || string(payload) != "пакет" {
			t.Fatalf("%s: пришло не то: %q %v", dst, payload, err)
		}
	}
}

func TestSocksUDPClosesWithControlConnection(t *testing.T) {
	s, err := ServeSocks(plainNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctrl, relay := associate(t, s)
	ctrl.Close()

	// Ретранслятор должен закрыться: занять его порт снова становится можно.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pc, err := net.ListenUDP("udp4", relay)
		if err == nil {
			pc.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("ассоциация пережила своё управляющее соединение")
}

func TestSocksRejectsBind(t *testing.T) {
	s, err := ServeSocks(plainNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	greet := make([]byte, 2)
	_, _ = io.ReadFull(c, greet)
	_, _ = c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("ответа на BIND нет: %v", err)
	}
	if reply[1] != 7 {
		t.Fatalf("ждал код 7 (не поддерживается), пришёл %d", reply[1])
	}
}

func TestSocksListensOnLoopbackOnly(t *testing.T) {
	s, err := ServeSocks(plainNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if ip := s.ln.Addr().(*net.TCPAddr).IP; !ip.IsLoopback() {
		t.Fatalf("socks слушает не только 127.0.0.1: %v", ip)
	}
}
