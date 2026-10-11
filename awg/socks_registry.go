package awg

import (
	"crypto/sha256"
	"sync"
)

// Амнезии в socks-режиме, поднятые в этом процессе, по ключу.
//
// Один и тот же ключ поднимается один раз: повторный старт отдаёт тот же
// порт. Иначе пинг строки и подключение подняли бы два движка на одном
// ключе, и сервер видел бы одного пира с двух мест — сессии бы
// перебивали друг друга.
var (
	socksMu  sync.Mutex
	socksRun = map[[32]byte]*Userspace{}
)

// SocksStartRequest — запуск амнезии как socks-выхода.
type SocksStartRequest struct {
	Conf string `json:"conf"`
}

// SocksStartResponse — где её ждать.
type SocksStartResponse struct {
	Port int `json:"port"`
}

// SocksStart поднимает амнезию для ключа (или отдаёт уже поднятую).
func SocksStart(req SocksStartRequest) (SocksStartResponse, error) {
	id := sha256.Sum256([]byte(req.Conf))
	socksMu.Lock()
	defer socksMu.Unlock()
	if u, ok := socksRun[id]; ok {
		return SocksStartResponse{Port: u.Port()}, nil
	}
	u, err := StartUserspace(req.Conf)
	if err != nil {
		return SocksStartResponse{}, err
	}
	socksRun[id] = u
	return SocksStartResponse{Port: u.Port()}, nil
}

// SocksStopAll гасит все поднятые амнезии. Вызывается при остановке
// туннеля; повторный вызов безопасен.
func SocksStopAll() {
	socksMu.Lock()
	run := socksRun
	socksRun = map[[32]byte]*Userspace{}
	socksMu.Unlock()
	for _, u := range run {
		u.Close()
	}
}

// SocksRunning — сколько амнезий сейчас поднято (для журнала и тестов).
func SocksRunning() int {
	socksMu.Lock()
	defer socksMu.Unlock()
	return len(socksRun)
}
