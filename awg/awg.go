// Package awg поднимает движок AmneziaWG рядом с Xray, внутри той же
// нативной библиотеки.
//
// Схема подсмотрена у INCY 3.6.6: там один Go-пакет экспортирует и Xray,
// и AmneziaWG, туннель при этом остаётся один. Нам это подходит ровно
// потому, что два РАЗНЫХ расширения туннеля мы уже пробовали и
// переключение между ними падало.
//
// Настройки протокола принимаются в формате UAPI — в нём amneziawg-go их
// и ждёт. Поля обфускации (jc, jmin, jmax, s1..s4, h1..h4, i1..i5,
// header_protection_key и прочие) передаются как есть, без разбора:
// ядро само решит, что из этого понимает. Так же поступает принятый
// патч AmneziaWG для Xray — и это правильно, иначе каждую новую версию
// протокола пришлось бы догонять правкой обёртки.
package awg

import (
	"errors"
	"fmt"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// StartRequest — что нужно движку для запуска.
type StartRequest struct {
	// TunFd — файловый описатель туннеля, который даёт система.
	// На iOS его отдаёт расширение NEPacketTunnelProvider, на Android —
	// VpnService. Своего туннеля движок не создаёт.
	TunFd int `json:"tunFd"`
	// MTU туннеля. Ноль — взять у системы.
	MTU int `json:"mtu"`
	// UAPI — конфигурация в формате UAPI: private_key, peer, endpoint,
	// allowed_ip и поля обфускации AmneziaWG.
	UAPI string `json:"uapi"`
	// Conf — то же самое, но в виде .conf, как его отдаёт панель.
	// Если задан, используется он, а UAPI пересчитывается из него.
	// Приложению так проще: оно передаёт ключ ровно в том виде, в каком
	// получило, и ничего не разбирает само.
	Conf string `json:"conf"`
	// Verbose — подробный журнал ядра.
	Verbose bool `json:"verbose"`
}

// Stats — то, что движок знает о себе.
type Stats struct {
	Running       bool  `json:"running"`
	LastHandshake int64 `json:"lastHandshake"`
	RxBytes       int64 `json:"rxBytes"`
	TxBytes       int64 `json:"txBytes"`
}

var (
	mu      sync.Mutex
	current *device.Device
	curTun  tun.Device
)

// Start поднимает движок. Повторный вызов при уже поднятом движке —
// ошибка, а не тихая замена: тихая замена маскирует рассинхронизацию
// состояния между приложением и ядром.
func Start(req StartRequest) error {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		return errors.New("движок AmneziaWG уже запущен")
	}
	if req.Conf != "" {
		parsed, err := ParseConf(req.Conf)
		if err != nil {
			return fmt.Errorf("конфигурация не разобрана: %w", err)
		}
		req.UAPI = parsed.UAPI
		if req.MTU <= 0 {
			req.MTU = parsed.MTU
		}
	}
	if err := validateStart(req); err != nil {
		return err
	}

	// Дублируем описатель: системный мы закрывать не имеем права, его
	// жизненным циклом управляет расширение туннеля.
	dupFd, err := dupTunFd(req.TunFd)
	if err != nil {
		return fmt.Errorf("не удалось продублировать описатель туннеля: %w", err)
	}
	// MTU не задаём: его уже выставила система (iOS --
	// setTunnelNetworkSettings, Android -- VpnService.Builder), а менять его
	// изнутри туннеля запрещено. См. newTunFromFD для каждой платформы.
	tunDev, err := newTunFromFD(dupFd)
	if err != nil {
		return fmt.Errorf("не удалось создать туннель: %w", err)
	}

	level := device.LogLevelError
	if req.Verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, "[awg] ")

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(req.UAPI); err != nil {
		dev.Close()
		return fmt.Errorf("конфигурация не принята ядром: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("не удалось поднять движок: %w", err)
	}

	current, curTun = dev, tunDev
	return nil
}

// Stop останавливает движок. Останов уже остановленного — не ошибка:
// приложение может перестраховаться и вызвать его дважды.
func Stop() error {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return nil
	}
	current.Close()
	current, curTun = nil, nil
	return nil
}

// IsRunning — поднят ли движок.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return current != nil
}

// GetStats отдаёт счётчики. Читаются из того же UAPI, что и настройки.
func GetStats() (Stats, error) {
	mu.Lock()
	dev := current
	mu.Unlock()
	if dev == nil {
		return Stats{}, nil
	}
	raw, err := dev.IpcGet()
	if err != nil {
		return Stats{}, fmt.Errorf("не удалось прочитать состояние: %w", err)
	}
	return parseStats(raw), nil
}

// validateStart проверяет запрос до любых побочных действий.
//
// Вынесено отдельно намеренно: проверять её внутри Start бесполезно —
// там дальше всё равно падает создание туннеля, и тест проходит по
// чужой причине, ничего не проверяя.
func validateStart(req StartRequest) error {
	if req.TunFd <= 0 {
		return errors.New("не передан описатель туннеля (tunFd)")
	}
	if req.UAPI == "" {
		return errors.New("пустая конфигурация UAPI")
	}
	return nil
}
