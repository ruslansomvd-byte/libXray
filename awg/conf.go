package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Parsed — то, что получилось из .conf: конфигурация для ядра и
// отдельно настройки самого туннеля.
//
// Разделение не косметическое: Address, DNS и MTU ядро AmneziaWG не
// принимает вовсе — это настройки сетевого интерфейса, их выставляет
// расширение туннеля через NEPacketTunnelNetworkSettings (iOS) или
// VpnService.Builder (Android).
type Parsed struct {
	UAPI      string   `json:"uapi"`
	Addresses []string `json:"addresses"`
	DNS       []string `json:"dns"`
	MTU       int      `json:"mtu"`
}

// Поля раздела [Interface], которые уходят в ядро как есть.
// Имена слева — как их пишет панель, справа — как их ждёт UAPI.
// Проверено по исходнику amneziawg-go v3.1: device/uapi.go.
var ifaceKeys = map[string]string{
	"jc": "jc", "jmin": "jmin", "jmax": "jmax",
	"s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4",
	"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4",
	"i1": "i1", "i2": "i2", "i3": "i3", "i4": "i4", "i5": "i5",
	"headerprotectionkey":    "header_protection_key",
	"contentpaddingaddition": "content_padding_addition",
	"rekeyaftertime":         "rekey_after_time",
	"rekeytimeout":           "rekey_timeout",
	"rejectaftertime":        "reject_after_time",
	"keepalivetimeout":       "keepalive_timeout",
	"maxhandshakeattempts":   "max_handshake_attempts",
	"randomtrailers":         "random_trailers",
	"disablecookies":         "disable_cookies",
	"listenport":             "listen_port",
}

// Поля интерфейса, которые ядро читает как hex, а панель пишет в base64.
// Проверено по device/uapi.go: `HeaderCipherKey.FromHex`.
var ifaceHexKeys = map[string]bool{
	"headerprotectionkey": true,
}

// Поля интерфейса «да/нет». Ядро читает их strconv.ParseBool.
var ifaceBoolKeys = map[string]bool{
	"randomtrailers": true,
	"disablecookies": true,
}

// ParseConf превращает .conf из панели в конфигурацию UAPI.
//
// Значения полей маскировки НЕ разбираются и не проверяются: там и
// числа, и диапазоны вида «100-120», и блобы вида «<r 2><b 0x85...>».
// Ядро умеет их читать само, а любая проверка здесь означала бы, что
// каждую новую версию протокола придётся догонять правкой обёртки.
func ParseConf(conf string) (Parsed, error) {
	var out Parsed
	var b strings.Builder
	section := ""
	peerStarted := false

	for _, rawLine := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		switch section {
		case "interface":
			switch key {
			case "address":
				out.Addresses = splitList(value)
			case "dns":
				out.DNS = splitList(value)
			case "mtu":
				n, err := strconv.Atoi(value)
				if err != nil {
					return out, fmt.Errorf("MTU не число: %q", value)
				}
				out.MTU = n
			case "privatekey":
				h, err := keyToHex(value)
				if err != nil {
					return out, fmt.Errorf("PrivateKey: %w", err)
				}
				fmt.Fprintf(&b, "private_key=%s\n", h)
			default:
				name, known := ifaceKeys[key]
				if !known {
					break
				}
				// Ключи маскировки панель пишет в base64, как и
				// остальные ключи, а UAPI ждёт их в hex — ровно так же,
				// как private_key. Мимо этого места конфигурация с
				// HeaderProtectionKey отвергалась ядром целиком:
				// «failed to set header_protection_key: encoding/hex:
				// invalid byte» (проверено на живом ключе панели).
				// То же самое с «да/нет»: панель пишет `on`/`off`,
				// а ядро читает их через strconv.ParseBool, который
				// такого не знает и отвергает всю конфигурацию.
				if ifaceBoolKeys[key] {
					value = normalizeBool(value)
				}
				if ifaceHexKeys[key] {
					h, err := keyToHex(value)
					if err != nil {
						return out, fmt.Errorf("%s: %w", name, err)
					}
					value = h
				}
				fmt.Fprintf(&b, "%s=%s\n", name, value)
			}
		case "peer":
			switch key {
			case "publickey":
				h, err := keyToHex(value)
				if err != nil {
					return out, fmt.Errorf("PublicKey: %w", err)
				}
				// replace_peers ставится один раз, перед первым пиром:
				// иначе второй пир стёр бы первого.
				if !peerStarted {
					fmt.Fprintf(&b, "replace_peers=true\n")
					peerStarted = true
				}
				fmt.Fprintf(&b, "public_key=%s\n", h)
			case "presharedkey":
				h, err := keyToHex(value)
				if err != nil {
					return out, fmt.Errorf("PresharedKey: %w", err)
				}
				fmt.Fprintf(&b, "preshared_key=%s\n", h)
			case "endpoint":
				ep, err := endpointToIP(value)
				if err != nil {
					return out, fmt.Errorf("Endpoint %q: %w", value, err)
				}
				fmt.Fprintf(&b, "endpoint=%s\n", ep)
			case "persistentkeepalive":
				fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", value)
			case "allowedips":
				// В UAPI каждый диапазон отдельной строкой.
				fmt.Fprintf(&b, "replace_allowed_ips=true\n")
				for _, ip := range splitList(value) {
					fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
				}
			}
		}
	}

	if !strings.Contains(b.String(), "private_key=") {
		return out, fmt.Errorf("в конфигурации нет PrivateKey")
	}
	if !peerStarted {
		return out, fmt.Errorf("в конфигурации нет ни одного пира")
	}
	out.UAPI = b.String()
	return out, nil
}

// keyToHex переводит ключ из base64 (как в .conf) в шестнадцатеричный
// вид (как ждёт UAPI).
func keyToHex(v string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", fmt.Errorf("не разбирается как base64")
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("длина %d байт вместо 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizeBool приводит написание панели к тому, что понимает ядро.
// Нераспознанное остаётся как есть: пусть лучше ядро скажет, что не так,
// чем обёртка тихо подменит смысл.
func normalizeBool(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "yes", "enabled", "true", "1":
		return "true"
	case "off", "no", "disabled", "false", "0":
		return "false"
	}
	return v
}

// resolveHost вынесен переменной, чтобы проверки не ходили в сеть.
var resolveHost = func(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// endpointToIP приводит адрес узла к виду, который принимает UAPI.
//
// Ядро читает endpoint через netip.ParseAddr и имя хоста не разрешает:
// с доменом вся конфигурация отвергается целиком («unexpected character»),
// а панель пишет туда именно домен. Разрешение делается здесь, до того как
// поднят интерфейс, — иначе запрос ушёл бы в ещё не работающий туннель.
//
// IPv4 предпочитается: туннель у нас четвёртой версии, и узел, доступный
// только по IPv6, молча не заработал бы на мобильной сети.
func endpointToIP(value string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("не разбирается как адрес с портом: %w", err)
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, port), nil
	}
	ips, err := resolveHost(host)
	if err != nil {
		return "", fmt.Errorf("имя не разрешается: %w", err)
	}
	var chosen net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			chosen = v4
			break
		}
		if chosen == nil {
			chosen = ip
		}
	}
	if chosen == nil {
		return "", fmt.Errorf("имя не разрешается ни в один адрес")
	}
	return net.JoinHostPort(chosen.String(), port), nil
}
