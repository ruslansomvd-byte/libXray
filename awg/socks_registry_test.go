package awg

import "testing"

// Ключ без сети: узел на 127.0.0.1:9, рукопожатия не будет, но движок,
// стек и socks поднимаются — этого достаточно для проверки реестра.
const offlineConf = `[Interface]
Address = 10.8.3.6/32
PrivateKey = qJ8hFzK3vN2mQ5xR7tY9uI0oP1aS2dF4gH6jK8lZ0wE=
MTU = 1280
Jc = 5
Jmin = 10
Jmax = 50

[Peer]
PublicKey = 3xH5kL7mN9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hJ9kM0=
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:9
`

func TestSocksRegistrySameKeyOnce(t *testing.T) {
	t.Cleanup(SocksStopAll)

	a, err := SocksStart(SocksStartRequest{Conf: offlineConf})
	if err != nil {
		t.Fatal(err)
	}
	b, err := SocksStart(SocksStartRequest{Conf: offlineConf})
	if err != nil {
		t.Fatal(err)
	}
	if a.Port != b.Port || SocksRunning() != 1 {
		t.Fatalf("один ключ поднят дважды: порты %d и %d, движков %d", a.Port, b.Port, SocksRunning())
	}
}

func TestSocksRegistryDifferentKeysSeparate(t *testing.T) {
	t.Cleanup(SocksStopAll)

	other := offlineConf[:len(offlineConf)-len("Endpoint = 127.0.0.1:9\n")] + "Endpoint = 127.0.0.1:10\n"
	a, _ := SocksStart(SocksStartRequest{Conf: offlineConf})
	b, err := SocksStart(SocksStartRequest{Conf: other})
	if err != nil {
		t.Fatal(err)
	}
	if a.Port == b.Port || SocksRunning() != 2 {
		t.Fatalf("разные ключи слились: %d / %d, движков %d", a.Port, b.Port, SocksRunning())
	}
}

func TestSocksRegistryStopAllIsIdempotent(t *testing.T) {
	_, _ = SocksStart(SocksStartRequest{Conf: offlineConf})
	SocksStopAll()
	SocksStopAll()
	if SocksRunning() != 0 {
		t.Fatalf("после остановки осталось %d", SocksRunning())
	}
}

func TestSocksRegistryBadKeyFailsWithoutLeak(t *testing.T) {
	t.Cleanup(SocksStopAll)
	if _, err := SocksStart(SocksStartRequest{Conf: "мусор"}); err == nil {
		t.Fatal("мусор вместо ключа должен дать ошибку")
	}
	if SocksRunning() != 0 {
		t.Fatal("неудачный старт оставил запись в реестре")
	}
}
