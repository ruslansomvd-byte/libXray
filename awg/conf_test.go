package awg

import (
	"net"
	"strings"
	"testing"
)

// Проверки не ходят в сеть: имя узла разрешается заглушкой.
func init() {
	resolveHost = func(host string) ([]net.IP, error) {
		switch host {
		case "amnz.sferavip.ru":
			return []net.IP{net.ParseIP("203.0.113.7")}, nil
		case "second.example":
			return []net.IP{net.ParseIP("203.0.113.8")}, nil
		}
		return nil, net.UnknownNetworkError(host)
	}
}

// Настоящий .conf с нашей панели, профиль 3.1. Ключи заменены на
// валидные, но посторонние — всё остальное слово в слово как отдаёт
// панель, включая диапазоны и блоб I1.
const реальныйКонфиг = `[Interface]
Address = 10.8.3.1/32
DNS = 8.8.8.8, 8.8.4.4
PrivateKey = qJ8hFzK3vN2mQ5xR7tY9uI0oP1aS2dF4gH6jK8lZ0wE=
MTU = 1280
Jc = 5
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>
HeaderProtectionKey = iKPbIrN2bYSVLNA3Q0DXYbF3Sm38WVTb62w/T9jDqVw=
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = 3xH5kL7mN9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hJ9kM0=
PresharedKey = 9zA1bC3dE5fG7hJ9kM1nO3pQ5rS7tU9vW1xY3zA5bC7=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = amnz.sferavip.ru:2014
PersistentKeepalive = 25-35
`

func TestParseConfНастоящийКлюч(t *testing.T) {
	p, err := ParseConf(реальныйКонфиг)
	if err != nil {
		t.Fatalf("не разобрался: %v", err)
	}

	// Настройки интерфейса уходят НЕ в ядро, а в туннель.
	if len(p.Addresses) != 1 || p.Addresses[0] != "10.8.3.1/32" {
		t.Errorf("адреса: %v", p.Addresses)
	}
	if len(p.DNS) != 2 || p.DNS[1] != "8.8.4.4" {
		t.Errorf("DNS: %v", p.DNS)
	}
	if p.MTU != 1280 {
		t.Errorf("MTU: %d", p.MTU)
	}
	for _, лишнее := range []string{"address=", "dns=", "mtu="} {
		if strings.Contains(p.UAPI, лишнее) {
			t.Errorf("в UAPI попало лишнее поле %q", лишнее)
		}
	}

	// Поля маскировки 3.1 должны дойти до ядра дословно.
	обязательные := []string{
		"jc=5", "jmin=10", "jmax=50",
		"s1=12", "s2=12", "s3=12", "s4=12",
		"h1=1", "h2=2", "h3=3", "h4=4",
		"i1=<r 2><b 0x858000010001",
		"header_protection_key=88a3db22b3766d84952cd0374340d761b1774a6dfc5954dbeb6c3f4fd8c3a95c",
		"rekey_after_time=100-120",
		"rekey_timeout=3-7",
		"reject_after_time=150-180",
		"keepalive_timeout=5-15",
		"max_handshake_attempts=15-20",
		"random_trailers=true",
		"disable_cookies=true",
		"persistent_keepalive_interval=25-35",
		"endpoint=203.0.113.7:2014",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"replace_peers=true",
	}
	for _, нужно := range обязательные {
		if !strings.Contains(p.UAPI, нужно) {
			t.Errorf("в UAPI нет %q", нужно)
		}
	}

	// Ключи должны быть переведены в шестнадцатеричный вид.
	if !strings.Contains(p.UAPI, "private_key=a89f21173") {
		t.Errorf("приватный ключ не переведён в hex:\n%s", p.UAPI)
	}
	if strings.Contains(p.UAPI, "=qJ8hFzK3") {
		t.Errorf("ключ остался в base64")
	}
}

func TestParseConfОтказы(t *testing.T) {
	cases := map[string]string{
		"пусто":          "",
		"нет пира":       "[Interface]\nPrivateKey = qJ8hFzK3vN2mQ5xR7tY9uI0oP1aS2dF4gH6jK8lZ0wE=\n",
		"нет ключа":      "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = 3xH5kL7mN9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hJ9kM0=\n",
		"ключ не base64": "[Interface]\nPrivateKey = ЭТО-НЕ-КЛЮЧ\n[Peer]\nPublicKey = 3xH5kL7mN9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hJ9kM0=\n",
		"ключ короткий":  "[Interface]\nPrivateKey = YWJj\n[Peer]\nPublicKey = 3xH5kL7mN9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hJ9kM0=\n",
	}
	for имя, conf := range cases {
		t.Run(имя, func(t *testing.T) {
			if _, err := ParseConf(conf); err == nil {
				t.Fatalf("ожидалась ошибка, её нет")
			}
		})
	}
}

func TestParseConfДваПираНеСтираютДругДруга(t *testing.T) {
	conf := реальныйКонфиг + `
[Peer]
PublicKey = 7hJ9kM1nO3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kM5=
AllowedIPs = 10.9.0.0/24
Endpoint = second.example:443
`
	p, err := ParseConf(conf)
	if err != nil {
		t.Fatalf("не разобрался: %v", err)
	}
	if n := strings.Count(p.UAPI, "replace_peers=true"); n != 1 {
		t.Fatalf("replace_peers должен быть один раз, найдено %d", n)
	}
	if n := strings.Count(p.UAPI, "public_key="); n != 2 {
		t.Fatalf("ожидалось два пира, найдено %d", n)
	}
}

// Три поля, на которых живой ключ панели отвергался ядром целиком.
// Каждое проверено против настоящего сервера 03.10.2026: без правок
// IpcSet возвращал -22 и туннель не поднимался вовсе.
func TestParseConfПриводитПоляКВидуЯдра(t *testing.T) {
	p, err := ParseConf(реальныйКонфиг)
	if err != nil {
		t.Fatalf("не разобрался: %v", err)
	}

	// HeaderProtectionKey ядро читает как hex (HeaderCipherKey.FromHex),
	// а панель пишет base64.
	if strings.Contains(p.UAPI, "header_protection_key=iKPb") {
		t.Error("ключ защиты заголовка остался в base64 — ядро такую конфигурацию отвергает целиком")
	}
	if !strings.Contains(p.UAPI, "header_protection_key=88a3db22b3766d84952cd0374340d761b1774a6dfc5954dbeb6c3f4fd8c3a95c") {
		t.Errorf("ключ защиты заголовка не переведён в hex:\n%s", p.UAPI)
	}

	// `on`/`off` панели против strconv.ParseBool ядра.
	for _, плохо := range []string{"random_trailers=on", "disable_cookies=on"} {
		if strings.Contains(p.UAPI, плохо) {
			t.Errorf("%q: ParseBool такого не знает", плохо)
		}
	}

	// Endpoint ядро читает через netip.ParseAddr и имя не разрешает.
	if strings.Contains(p.UAPI, "endpoint=amnz.sferavip.ru") {
		t.Error("в endpoint остался домен — ядро принимает только адрес")
	}
	if !strings.Contains(p.UAPI, "endpoint=203.0.113.7:2014") {
		t.Errorf("имя узла не разрешено в адрес:\n%s", p.UAPI)
	}
}

func TestParseConfНаписаниеДаНет(t *testing.T) {
	for _, c := range []struct{ пишут, ждём string }{
		{"on", "true"}, {"off", "false"},
		{"yes", "true"}, {"no", "false"},
		{"true", "true"}, {"false", "false"},
		{"1", "true"}, {"0", "false"},
		{"On", "true"}, {" OFF ", "false"},
	} {
		conf := strings.Replace(реальныйКонфиг, "RandomTrailers = on", "RandomTrailers = "+c.пишут, 1)
		p, err := ParseConf(conf)
		if err != nil {
			t.Fatalf("%q: %v", c.пишут, err)
		}
		if !strings.Contains(p.UAPI, "random_trailers="+c.ждём) {
			t.Errorf("%q дало не %q", c.пишут, c.ждём)
		}
	}
}

func TestParseConfАдресУзла(t *testing.T) {
	// Готовый адрес не трогаем — лишнего запроса в DNS быть не должно.
	conf := strings.Replace(реальныйКонфиг, "Endpoint = amnz.sferavip.ru:2014", "Endpoint = 198.51.100.9:2014", 1)
	p, err := ParseConf(conf)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(p.UAPI, "endpoint=198.51.100.9:2014") {
		t.Errorf("готовый адрес изменён:\n%s", p.UAPI)
	}

	// Имя, которое не разрешается, — это отказ с понятной причиной, а не
	// конфигурация, на которой туннель молча не поднимется.
	conf = strings.Replace(реальныйКонфиг, "amnz.sferavip.ru:2014", "нет-такого-узла.invalid:2014", 1)
	if _, err := ParseConf(conf); err == nil {
		t.Error("неразрешимое имя принято")
	}

	// Порт обязателен: без него ядро тоже откажет, но уже без объяснения.
	conf = strings.Replace(реальныйКонфиг, "Endpoint = amnz.sferavip.ru:2014", "Endpoint = amnz.sferavip.ru", 1)
	if _, err := ParseConf(conf); err == nil {
		t.Error("адрес без порта принят")
	}
}
