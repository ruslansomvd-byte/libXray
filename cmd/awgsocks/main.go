// Живая проверка амнезии как socks-выхода: поднять её из настоящего ключа
// в юзерспейсе, выставить socks5 на 127.0.0.1 и держать, пока не прервут.
// Порт пишется в файл из второго аргумента — его подхватывает стенд с Xray.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/xtls/libxray/awg"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("использование: awgsocks ключ.conf файл-для-порта")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	must(err)

	start := time.Now()
	u, err := awg.StartUserspace(string(raw))
	must(err)
	defer u.Close()
	must(os.WriteFile(os.Args[2], []byte(strconv.Itoa(u.Port())), 0o600))
	fmt.Println("socks5 на 127.0.0.1:", u.Port())

	// Рукопожатие ждём только для журнала: socks работает и до него,
	// первое соединение само его вызовет.
	go func() {
		for i := 0; i < 600; i++ {
			if st := u.Stats(); st.LastHandshake > 0 {
				fmt.Printf("рукопожатие через %d мс после старта\n", time.Since(start).Milliseconds())
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	for {
		select {
		case <-sig:
			return
		case <-tick.C:
			st := u.Stats()
			fmt.Printf("передано %d / принято %d байт\n", st.TxBytes, st.RxBytes)
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("ОШИБКА:", err)
		os.Exit(1)
	}
}
