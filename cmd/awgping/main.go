// Воспроизведение пинга строки амнезии ровно так, как его зовёт приложение:
// Invoke("pingBatch") с outbound socks + awgConf, таймаут и URL приложения.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	libXray "github.com/xtls/libxray"
)

func main() {
	conf, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	timeout := 3
	if len(os.Args) > 2 {
		fmt.Sscan(os.Args[2], &timeout)
	}
	ob := map[string]any{
		"protocol": "socks",
		"settings": map[string]any{"servers": []any{map[string]any{"address": "amnz.sferavip.ru", "port": 2014}}},
		"awgConf":  string(conf),
		"tag":      "ping-out",
	}
	xj, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{ob}})
	req, _ := json.Marshal(map[string]any{
		"apiVersion": 3, "method": "pingBatch",
		"payload": map[string]any{
			"configs": []any{map[string]any{"xrayJson": string(xj), "outboundTag": "ping-out"}},
			"timeout": timeout, "url": "http://cp.cloudflare.com/generate_204",
		},
	})
	t := time.Now()
	resp := libXray.Invoke(string(req))
	fmt.Printf("за %d мс, таймаут %d с\n%s\n", time.Since(t).Milliseconds(), timeout, resp)
}
