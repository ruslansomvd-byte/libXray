package awg

import (
	"encoding/json"
	"strings"
	"testing"
)

func confJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPrepareLeavesPlainConfigByteForByte(t *testing.T) {
	plain := `{"outbounds":[{"tag":"ger","protocol":"vless"}],  "log":{"loglevel":"none"}}`
	out, release, err := PrepareXrayJSON(plain)
	defer release()
	if err != nil || out != plain {
		t.Fatalf("конфигурация без амнезии изменилась: %q %v", out, err)
	}
	if SocksRunning() != 0 {
		t.Fatal("без пометки поднят движок")
	}
}

func TestPrepareStartsAndRewritesOutbound(t *testing.T) {
	t.Cleanup(SocksStopAll)
	in := confJSON(t, map[string]any{"outbounds": []any{
		map[string]any{"tag": "ger", "protocol": "vless"},
		map[string]any{"tag": "awg-1", "protocol": "socks", ConfKey: offlineConf},
	}})

	out, release, err := PrepareXrayJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if strings.Contains(out, ConfKey) || strings.Contains(out, "PrivateKey") {
		t.Fatal("ключ амнезии остался в конфигурации ядра")
	}
	var root struct {
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Settings struct {
				Servers []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
				} `json:"servers"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(out), &root); err != nil {
		t.Fatal(err)
	}
	ob := root.Outbounds[1]
	if ob.Protocol != "socks" || len(ob.Settings.Servers) != 1 || ob.Settings.Servers[0].Address != "127.0.0.1" || ob.Settings.Servers[0].Port <= 0 {
		t.Fatalf("outbound амнезии собран неверно: %+v", ob)
	}
	if root.Outbounds[0].Protocol != "vless" {
		t.Fatal("соседний outbound испорчен")
	}
}

func TestPrepareRefcountPingDoesNotKillTunnel(t *testing.T) {
	t.Cleanup(SocksStopAll)
	in := confJSON(t, map[string]any{"outbounds": []any{map[string]any{"tag": "a", ConfKey: offlineConf}}})

	_, tunnelRelease, err := PrepareXrayJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	_, pingRelease, err := PrepareXrayJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if SocksRunning() != 1 {
		t.Fatalf("один ключ — один движок, а поднято %d", SocksRunning())
	}
	pingRelease()
	pingRelease() // повторное отпускание ничего не ломает
	if SocksRunning() != 1 {
		t.Fatal("пинг погасил движок, которым пользуется туннель")
	}
	tunnelRelease()
	if SocksRunning() != 0 {
		t.Fatal("последний отпустил, а движок жив")
	}
}

func TestPrepareBadKeyReleasesOthers(t *testing.T) {
	t.Cleanup(SocksStopAll)
	in := confJSON(t, map[string]any{"outbounds": []any{
		map[string]any{"tag": "ok", ConfKey: offlineConf},
		map[string]any{"tag": "bad", ConfKey: "мусор"},
	}})
	if _, _, err := PrepareXrayJSON(in); err == nil {
		t.Fatal("плохой ключ должен дать ошибку")
	}
	if SocksRunning() != 0 {
		t.Fatalf("после ошибки остались поднятые движки: %d", SocksRunning())
	}
}

func TestPrepareWordInTagIsNotAMarker(t *testing.T) {
	in := `{"outbounds":[{"tag":"awgConf-like","protocol":"vless"}]}`
	out, release, err := PrepareXrayJSON(in)
	defer release()
	if err != nil || out != in || SocksRunning() != 0 {
		t.Fatalf("слово в теге приняли за пометку: %q %v", out, err)
	}
}
