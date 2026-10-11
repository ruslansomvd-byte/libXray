package libXray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/libxray/awg"
)

// Сквозная проверка: метод доходит от JSON-конверта до движка и обратно.
// Без неё можно собрать ядро, в котором пакет есть, а вызвать его нельзя.
func callInvoke(t *testing.T, method string, payload string) invokeResponse {
	t.Helper()
	req := `{"apiVersion":3,"method":"` + method + `"`
	if payload != "" {
		req += `,"payload":` + payload
	}
	req += `}`
	var resp invokeResponse
	if err := json.Unmarshal([]byte(Invoke(req)), &resp); err != nil {
		t.Fatalf("ответ не разобрался: %v", err)
	}
	return resp
}

func TestAwgМетодыДоходятДоДвижка(t *testing.T) {
	// Состояние до запуска.
	r := callInvoke(t, "awgState", "")
	if !r.Success {
		t.Fatalf("awgState вернул ошибку: %s", r.Err)
	}
	if running, ok := r.Data.(bool); !ok || running {
		t.Fatalf("ожидалось running=false, получено %v", r.Data)
	}

	// Запуск с пустой конфигурацией должен быть отклонён ВНЯТНО.
	r = callInvoke(t, "awgStart", `{"tunFd":7}`)
	if r.Success {
		t.Fatalf("пустая конфигурация принята, чего быть не должно")
	}
	if !strings.Contains(r.Err, "UAPI") {
		t.Fatalf("ошибка должна называть причину, получено: %q", r.Err)
	}

	// Останов незапущенного — молча успешен.
	if r = callInvoke(t, "awgStop", ""); !r.Success {
		t.Fatalf("awgStop вернул ошибку: %s", r.Err)
	}

	// Счётчики доступны и не врут.
	r = callInvoke(t, "awgStats", "")
	if !r.Success {
		t.Fatalf("awgStats вернул ошибку: %s", r.Err)
	}
	m, ok := r.Data.(map[string]any)
	if !ok {
		t.Fatalf("ожидалась структура счётчиков, получено %T", r.Data)
	}
	if m["running"] != false {
		t.Fatalf("движок не запущен, а счётчики говорят %v", m["running"])
	}
}

func TestНеизвестныйМетодНеЛомаетДиспетчер(t *testing.T) {
	r := callInvoke(t, "awgНесуществующий", "")
	if r.Success {
		t.Fatalf("несуществующий метод принят")
	}
}

func TestAwgParseConfЧерезДиспетчер(t *testing.T) {
	conf := "[Interface]\nAddress = 10.8.3.1/32\nDNS = 8.8.8.8\nMTU = 1280\n" +
		"PrivateKey = qJ8hFzK3vN2mQ5xR7tY9uI0oP1aS2dF4gH6jK8lZ0wE=\nJc = 5\n" +
		"[Peer]\nPublicKey = 3xH5kL7mN9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hJ9kM0=\n" +
		"AllowedIPs = 0.0.0.0/0\nEndpoint = amnz.sferavip.ru:2014\n"
	raw, _ := json.Marshal(map[string]string{"conf": conf})
	r := callInvoke(t, "awgParseConf", string(raw))
	if !r.Success {
		t.Fatalf("разбор не прошёл: %s", r.Err)
	}
	m, ok := r.Data.(map[string]any)
	if !ok {
		t.Fatalf("ожидалась структура, получено %T", r.Data)
	}
	if m["mtu"].(float64) != 1280 {
		t.Errorf("MTU: %v", m["mtu"])
	}
	if !strings.Contains(m["uapi"].(string), "jc=5") {
		t.Errorf("поля маскировки не дошли: %v", m["uapi"])
	}
}

func TestAwgSocksЧерезДиспетчер(t *testing.T) {
	conf := "[Interface]\nAddress = 10.8.3.6/32\nMTU = 1280\n" +
		"PrivateKey = qJ8hFzK3vN2mQ5xR7tY9uI0oP1aS2dF4gH6jK8lZ0wE=\nJc = 5\n" +
		"[Peer]\nPublicKey = 3xH5kL7mN9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hJ9kM0=\n" +
		"AllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n"
	raw, _ := json.Marshal(map[string]string{"conf": conf})
	t.Cleanup(func() { callInvoke(t, "awgSocksStopAll", "") })

	r := callInvoke(t, "awgSocksStart", string(raw))
	if !r.Success {
		t.Fatalf("awgSocksStart не прошёл: %s", r.Err)
	}
	m, ok := r.Data.(map[string]any)
	if !ok || m["port"].(float64) <= 0 {
		t.Fatalf("ожидался порт, получено %v", r.Data)
	}

	// Мусор вместо ключа — внятный отказ, а не падение.
	if r = callInvoke(t, "awgSocksStart", `{"conf":"мусор"}`); r.Success {
		t.Fatal("мусор вместо ключа принят")
	}

	if r = callInvoke(t, "awgSocksStopAll", ""); !r.Success {
		t.Fatalf("awgSocksStopAll вернул ошибку: %s", r.Err)
	}
}

func TestRunXrayПоднимаетИГаситАмнезию(t *testing.T) {
	conf := "[Interface]\nAddress = 10.8.3.6/32\nMTU = 1280\n" +
		"PrivateKey = qJ8hFzK3vN2mQ5xR7tY9uI0oP1aS2dF4gH6jK8lZ0wE=\nJc = 5\n" +
		"[Peer]\nPublicKey = 3xH5kL7mN9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hJ9kM0=\n" +
		"AllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n"
	xrayJSON, _ := json.Marshal(map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"outbounds": []any{map[string]any{"tag": "awg-1", "protocol": "socks", "awgConf": conf}},
	})
	payload, _ := json.Marshal(map[string]string{"xrayJson": string(xrayJSON)})
	t.Cleanup(func() { callInvoke(t, "stopXray", ""); awg.SocksStopAll() })

	if r := callInvoke(t, "runXray", string(payload)); !r.Success {
		t.Fatalf("ядро с выходом-амнезией не запустилось: %s", r.Err)
	}
	if awg.SocksRunning() != 1 {
		t.Fatalf("под ядро должна подняться одна амнезия, поднято %d", awg.SocksRunning())
	}
	if r := callInvoke(t, "stopXray", ""); !r.Success {
		t.Fatalf("stopXray: %s", r.Err)
	}
	if awg.SocksRunning() != 0 {
		t.Fatal("ядро остановлено, а амнезия осталась висеть")
	}
}

func TestGoMemStatsЧерезДиспетчер(t *testing.T) {
	r := callInvoke(t, "goMemStats", "")
	if !r.Success {
		t.Fatalf("goMemStats: %s", r.Err)
	}
	m, ok := r.Data.(map[string]any)
	if !ok || m["sysMB"].(float64) <= 0 || m["goroutines"].(float64) < 1 {
		t.Fatalf("ожидались цифры памяти, получено %v", r.Data)
	}
}
