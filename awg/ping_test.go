package awg

import (
	"testing"
	"time"
)

// Сервер амнезии недоступен -- замер честно не проходит в пределах срока и
// отпускает движок (07.11).
func TestPingOfflineFailsInTimeAndReleases(t *testing.T) {
	t.Cleanup(SocksStopAll)
	start := time.Now()
	_, err := Ping(PingRequest{Conf: offlineConf, URL: "http://cp.cloudflare.com/generate_204", Timeout: 1})
	if err == nil {
		t.Fatal("недоступный сервер «ответил»")
	}
	if time.Since(start) > 6*time.Second {
		t.Fatalf("замер висел %v при сроке 1 с", time.Since(start))
	}
	if SocksRunning() != 0 {
		t.Fatalf("движок не отпущен: %d", SocksRunning())
	}
}

func TestPingEmptyConf(t *testing.T) {
	if _, err := Ping(PingRequest{}); err == nil {
		t.Fatal("пустой ключ принят")
	}
}
