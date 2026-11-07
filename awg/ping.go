package awg

// Замер строки амнезии без экземпляра Xray (07.11).
//
// На Android приложение и туннель живут в одном процессе, и pingBatch при
// работающем ядре Xray отказывается ("requires an isolated process without a
// managed Xray instance") -- поэтому при включённом VPN строки амнезии на
// Samsung владельца не мерились вовсе. Здесь запрос идёт прямо через
// сетевой стек амнезии (её socks с логином и паролем этого запуска): второго
// ядра Xray нет, и запрет не задевает. Само приложение на Android из
// туннеля исключено, так что замер идёт напрямую до сервера, честно.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/xtls/libxray/nodep"
	"golang.org/x/net/proxy"
)

// PingRequest -- что мерить.
type PingRequest struct {
	Conf    string `json:"conf"`
	URL     string `json:"url"`
	Timeout int    `json:"timeout"`
}

// PingResponse -- задержка в мс.
type PingResponse struct {
	Delay int64 `json:"delay"`
}

// Ping поднимает амнезию (или берёт уже поднятую с тем же ключом), делает
// запрос через неё и отпускает.
func Ping(req PingRequest) (PingResponse, error) {
	if req.Conf == "" {
		return PingResponse{}, errors.New("пустой ключ")
	}
	if req.Timeout <= 0 {
		req.Timeout = 3
	}
	if req.URL == "" {
		req.URL = "http://cp.cloudflare.com/generate_204"
	}
	acc, release, err := acquire(req.Conf)
	if err != nil {
		return PingResponse{}, err
	}
	defer release()

	d, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(acc.port)),
		&proxy.Auth{User: acc.user, Password: acc.pass}, proxy.Direct)
	if err != nil {
		return PingResponse{}, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return PingResponse{}, errors.New("socks без контекста")
	}
	timeout := time.Duration(req.Timeout) * time.Second
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Второй запрос PingHTTPRequest идёт по тому же соединению и
			// меряет задержку, а не рукопожатие.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return cd.DialContext(ctx, network, addr)
			},
			MaxIdleConns:    1,
			IdleConnTimeout: timeout,
		},
	}
	defer client.CloseIdleConnections()
	delay, err := nodep.PingHTTPRequest(client, req.URL, req.Timeout)
	if err != nil {
		return PingResponse{}, err
	}
	return PingResponse{Delay: delay}, nil
}
