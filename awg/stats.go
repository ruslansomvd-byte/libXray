package awg

import (
	"strconv"
	"strings"
)

// parseStats вытаскивает счётчики из ответа UAPI.
//
// Ответ — плоский список строк «ключ=значение», где поля пира идут
// после его public_key. Нам нужны только три величины, поэтому берём
// последние встреченные: при одном пире это он и есть, а при нескольких
// суммировать байты честнее, чем показывать первый попавшийся.
func parseStats(raw string) Stats {
	st := Stats{Running: true}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "last_handshake_time_sec":
			if n > st.LastHandshake {
				st.LastHandshake = n
			}
		case "rx_bytes":
			st.RxBytes += n
		case "tx_bytes":
			st.TxBytes += n
		}
	}
	return st
}
