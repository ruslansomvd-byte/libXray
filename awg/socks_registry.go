package awg

import (
	"crypto/sha256"
	"sync"
)

// Амнезии в socks-режиме, поднятые в этом процессе, по ключу.
//
// Один и тот же ключ поднимается один раз: повторный запрос отдаёт тот же
// порт и прибавляет счётчик. Иначе пинг строки и подключение подняли бы
// два движка на одном ключе, и сервер видел бы одного пира с двух мест —
// сессии бы перебивали друг друга. Гасит движок тот, кто отпустил его
// последним.
var (
	socksMu  sync.Mutex
	socksRun = map[[32]byte]*socksEntry{}
)

type socksEntry struct {
	u    *Userspace
	refs int
}

// SocksStartRequest — запуск амнезии как socks-выхода.
type SocksStartRequest struct {
	Conf string `json:"conf"`
}

// SocksStartResponse — где её ждать и с каким логином и паролем.
type SocksStartResponse struct {
	Port int    `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

// socksAccess -- куда и с чем подключаться к поднятой амнезии.
type socksAccess struct {
	port       int
	user, pass string
}

// acquire поднимает амнезию для ключа (или берёт уже поднятую) и
// возвращает порт и функцию, которая её отпускает. Отпускать можно
// сколько угодно раз — сработает первый.
func acquire(conf string) (socksAccess, func(), error) {
	id := sha256.Sum256([]byte(conf))
	socksMu.Lock()
	defer socksMu.Unlock()
	e, ok := socksRun[id]
	if !ok {
		u, err := StartUserspace(conf)
		if err != nil {
			return socksAccess{}, nil, err
		}
		e = &socksEntry{u: u}
		socksRun[id] = e
	}
	e.refs++
	var once sync.Once
	user, pass := e.u.Credentials()
	return socksAccess{port: e.u.Port(), user: user, pass: pass}, func() { once.Do(func() { release(id, e) }) }, nil
}

func release(id [32]byte, e *socksEntry) {
	socksMu.Lock()
	cur, ok := socksRun[id]
	if !ok || cur != e {
		// Уже погашено через SocksStopAll.
		socksMu.Unlock()
		return
	}
	e.refs--
	last := e.refs <= 0
	if last {
		delete(socksRun, id)
	}
	socksMu.Unlock()
	if last {
		e.u.Close()
	}
}

// SocksStart — то же, что acquire, для прямого вызова из приложения. Ссылка
// держится до SocksStopAll.
func SocksStart(req SocksStartRequest) (SocksStartResponse, error) {
	acc, _, err := acquire(req.Conf)
	if err != nil {
		return SocksStartResponse{}, err
	}
	return SocksStartResponse{Port: acc.port, User: acc.user, Pass: acc.pass}, nil
}

// SocksStopAll гасит все поднятые амнезии, сколько бы ссылок на них ни
// было. Вызывается при остановке туннеля; повторный вызов безопасен.
func SocksStopAll() {
	socksMu.Lock()
	run := socksRun
	socksRun = map[[32]byte]*socksEntry{}
	socksMu.Unlock()
	for _, e := range run {
		e.u.Close()
	}
}

// SocksRunning — сколько амнезий сейчас поднято (для журнала и тестов).
func SocksRunning() int {
	socksMu.Lock()
	defer socksMu.Unlock()
	return len(socksRun)
}
