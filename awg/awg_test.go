package awg

import "testing"

func TestStartОтказыБезПобочныхЭффектов(t *testing.T) {
	cases := []struct {
		имя string
		req StartRequest
	}{
		{"без описателя туннеля", StartRequest{UAPI: "private_key=00\n"}},
		{"отрицательный описатель", StartRequest{TunFd: -1, UAPI: "private_key=00\n"}},
		{"пустая конфигурация", StartRequest{TunFd: 3}},
	}
	for _, c := range cases {
		t.Run(c.имя, func(t *testing.T) {
			if err := Start(c.req); err == nil {
				t.Fatalf("ожидалась ошибка, её нет")
			}
			// Главное: неудачный запуск НЕ оставляет движок «поднятым».
			if IsRunning() {
				t.Fatalf("после неудачного запуска движок считается работающим")
			}
		})
	}
}

func TestStopБезЗапускаНеОшибка(t *testing.T) {
	if err := Stop(); err != nil {
		t.Fatalf("останов незапущенного должен быть молчаливым, получено: %v", err)
	}
}

func TestStatsБезЗапускаПусто(t *testing.T) {
	st, err := GetStats()
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if st.Running {
		t.Fatalf("движок не запущен, а счётчики говорят обратное")
	}
}

func TestParseStatsСуммируетПиров(t *testing.T) {
	// Ответ UAPI с двумя пирами: байты складываются, рукопожатие берём
	// самое свежее.
	raw := "private_key=aa\n" +
		"public_key=11\nrx_bytes=100\ntx_bytes=10\nlast_handshake_time_sec=1000\n" +
		"public_key=22\nrx_bytes=250\ntx_bytes=25\nlast_handshake_time_sec=2000\n" +
		"errno=0\n"
	st := parseStats(raw)
	if st.RxBytes != 350 {
		t.Errorf("принято: ожидалось 350, получено %d", st.RxBytes)
	}
	if st.TxBytes != 35 {
		t.Errorf("отдано: ожидалось 35, получено %d", st.TxBytes)
	}
	if st.LastHandshake != 2000 {
		t.Errorf("рукопожатие: ожидалось 2000, получено %d", st.LastHandshake)
	}
	if !st.Running {
		t.Errorf("при наличии ответа движок считается работающим")
	}
}

func TestParseStatsМусорНеЛомает(t *testing.T) {
	st := parseStats("это не uapi\n\nrx_bytes=не_число\n=\n")
	if st.RxBytes != 0 || st.TxBytes != 0 {
		t.Fatalf("мусор не должен давать счётчики: %+v", st)
	}
}

func TestValidateStart(t *testing.T) {
	// Здесь проверяется ИМЕННО проверка: ничего больше в ней не
	// происходит, поэтому сломать её незаметно нельзя.
	cases := []struct {
		имя    string
		req    StartRequest
		ошибка bool
	}{
		{"всё на месте", StartRequest{TunFd: 7, UAPI: "private_key=00\n"}, false},
		{"нет описателя", StartRequest{UAPI: "private_key=00\n"}, true},
		{"описатель отрицательный", StartRequest{TunFd: -3, UAPI: "private_key=00\n"}, true},
		{"пустая конфигурация", StartRequest{TunFd: 7}, true},
	}
	for _, c := range cases {
		t.Run(c.имя, func(t *testing.T) {
			err := validateStart(c.req)
			if c.ошибка && err == nil {
				t.Fatalf("ожидалась ошибка, её нет")
			}
			if !c.ошибка && err != nil {
				t.Fatalf("ошибки быть не должно, получено: %v", err)
			}
		})
	}
}
