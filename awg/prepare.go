package awg

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ConfKey — пометка в outbound конфигурации Xray: «это амнезия, вот её
// ключ». Приложение пишет outbound как обычный socks с этим полем, а
// libXray перед запуском ядра поднимает амнезию, подставляет порт и
// поле убирает. Так одна точка обслуживает и туннель, и пинг строк, и
// обе платформы сразу.
const ConfKey = "awgConf"

// PrepareXrayJSON поднимает амнезии, помеченные в outbounds, и возвращает
// конфигурацию с настоящими портами.
//
// Конфигурация без пометки возвращается байт в байт: для всех прочих
// профилей ничего не меняется. Функция release отпускает поднятые
// движки; при ошибке они отпускаются сами.
func PrepareXrayJSON(xrayJSON string) (string, func(), error) {
	noop := func() {}
	if !strings.Contains(xrayJSON, ConfKey) {
		return xrayJSON, noop, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(xrayJSON), &root); err != nil {
		return "", noop, fmt.Errorf("конфигурация с амнезией не разобрана: %w", err)
	}
	outbounds, _ := root["outbounds"].([]any)

	var releases []func()
	releaseAll := func() {
		for _, r := range releases {
			r()
		}
	}
	found := 0
	for _, raw := range outbounds {
		ob, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		conf, ok := ob[ConfKey].(string)
		if !ok {
			continue
		}
		delete(ob, ConfKey)
		found++
		port, rel, err := acquire(conf)
		if err != nil {
			releaseAll()
			return "", noop, fmt.Errorf("амнезия для %v не поднялась: %w", ob["tag"], err)
		}
		releases = append(releases, rel)
		ob["protocol"] = "socks"
		ob["settings"] = map[string]any{
			"servers": []any{map[string]any{"address": "127.0.0.1", "port": port}},
		}
	}
	if found == 0 {
		// Слово встретилось, но не как пометка outbound (например, в теге).
		return xrayJSON, noop, nil
	}

	out, err := json.Marshal(root)
	if err != nil {
		releaseAll()
		return "", noop, err
	}
	return string(out), releaseAll, nil
}
