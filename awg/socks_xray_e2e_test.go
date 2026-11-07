package awg

// Сквозная проверка (07.11): настоящее ядро Xray ходит через socks
// амнезии с логином и паролем этого запуска, а без них -- не ходит. Части
// по отдельности проверены в socks_test.go и prepare_test.go; здесь --
// что Xray понимает "users" в socks-выходе и сервер их принимает.

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/net/proxy"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// xrayThrough поднимает Xray: вход socks без пароля на свободном порту,
// выход socks на сервер амнезии с данными логином и паролем.
func xrayThrough(t *testing.T, s *SocksServer, user, pass string) int {
	t.Helper()
	in := freePort(t)
	users := ""
	if user != "" {
		users = fmt.Sprintf(`,"users":[{"user":%q,"pass":%q}]`, user, pass)
	}
	cfg := fmt.Sprintf(`{
	  "log":{"loglevel":"none"},
	  "inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],
	  "outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":%d%s}]}}]
	}`, in, s.Port(), users)
	c, err := core.LoadConfig("json", strings.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.New(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return in
}

func roundTrip(t *testing.T, xrayPort int, target string) error {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(xrayPort)), nil, proxy.Direct)
	if err != nil {
		return err
	}
	c, err := d.Dial("tcp", target)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return err
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != "ping" {
		return fmt.Errorf("эхо вернуло %q", b)
	}
	return nil
}

func TestXrayGoesThroughAuthSocks(t *testing.T) {
	s, err := ServeSocks(plainNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	user, pass := s.Credentials()
	if err := roundTrip(t, xrayThrough(t, s, user, pass), echoServer(t)); err != nil {
		t.Fatalf("Xray с логином и паролем не прошёл: %v", err)
	}
}

func TestXrayWithoutCredentialsIsRefused(t *testing.T) {
	s, err := ServeSocks(plainNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := roundTrip(t, xrayThrough(t, s, "", ""), echoServer(t)); err == nil {
		t.Fatal("Xray без логина и пароля прошёл через socks амнезии")
	}
}
