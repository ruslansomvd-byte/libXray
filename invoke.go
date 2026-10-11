package libXray

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/xtls/libxray/awg"
	"github.com/xtls/libxray/geo"
	"github.com/xtls/libxray/nodep"
	"github.com/xtls/libxray/share"
	"github.com/xtls/libxray/xray"
)

type invokeResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data"`
	Err     string `json:"error"`
}

const (
	maxInvokeJSONSizeMiB = 16
	maxInvokeJSONBytes   = maxInvokeJSONSizeMiB * 1024 * 1024
)

func Invoke(requestJSON string) string {
	if len(requestJSON) > maxInvokeJSONBytes {
		return encodeInvokeResponse(nil, errors.New(invokeJSONSizeLimitMessage("request")))
	}
	var request LibXrayInvokeRequest
	if err := json.Unmarshal([]byte(requestJSON), &request); err != nil {
		return encodeInvokeResponse(nil, err)
	}
	if err := validateAPIVersion(request.APIVersion); err != nil {
		return encodeInvokeResponse(nil, err)
	}

	switch request.Method {
	case LibXrayMethodGetFreePorts:
		return invokeGetFreePorts(request.Payload)
	case LibXrayMethodConvertShareLinksToXrayJson:
		return invokeConvertShareLinksToXrayJson(request.Payload)
	case LibXrayMethodConvertXrayJsonToShareLinks:
		return invokeConvertXrayJsonToShareLinks(request.Payload)
	case LibXrayMethodGenerateAgeKeyPair:
		return invokeGenerateAgeKeyPair(request.Payload)
	case LibXrayMethodCountGeoData:
		return invokeCountGeoData(request.Payload)
	case LibXrayMethodPingBatch:
		return invokePingBatch(request.Payload)
	case LibXrayMethodPingLive:
		return invokePingLive(request.Payload)
	case LibXrayMethodTestXray:
		return invokeTestXray(request.Payload)
	case LibXrayMethodRunXray:
		return invokeRunXray(request.Payload)
	case LibXrayMethodStopXray:
		return invokeStopXray()
	case LibXrayMethodXrayVersion:
		return encodeInvokeResponse(&XrayVersionResponse{Version: xray.XrayVersion()}, nil)
	case LibXrayMethodGetXrayState:
		return encodeInvokeResponse(&GetXrayStateResponse{Running: xray.GetXrayState()}, nil)
	case LibXrayMethodAwgStart:
		return invokeAwgStart(request.Payload)
	case LibXrayMethodAwgStop:
		return invokeAwgStop()
	case LibXrayMethodAwgState:
		return invokeAwgState()
	case LibXrayMethodAwgStats:
		return invokeAwgStats()
	case LibXrayMethodAwgParseConf:
		return invokeAwgParseConf(request.Payload)
	case LibXrayMethodAwgSocksStart:
		return invokeAwgSocksStart(request.Payload)
	case LibXrayMethodGoMemStats:
		return encodeInvokeResponse(goMemStats(), nil)
	case LibXrayMethodAwgSocksStopAll:
		awg.SocksStopAll()
		return encodeInvokeNoDataResponse(nil)
	default:
		return encodeInvokeResponse(nil, errors.New("unknown method"))
	}
}
func validateAPIVersion(version int) error {
	if version == LibXrayAPIVersion {
		return nil
	}
	return errors.New("unsupported apiVersion")
}

func decodePayload[T any](payload json.RawMessage) (T, error) {
	var request T
	if len(payload) == 0 {
		return request, nil
	}
	err := json.Unmarshal(payload, &request)
	return request, err
}

func encodeInvokeResponse(data any, err error) string {
	response := invokeResponse{Data: data}
	if err != nil {
		response.Success = false
		response.Err = err.Error()
	} else {
		response.Success = true
	}
	raw, err := json.Marshal(&response)
	if err != nil {
		return `{"success":false,"data":null,"error":"failed to encode response"}`
	}
	if len(raw) > maxInvokeJSONBytes {
		return encodeInvokeFailure(invokeJSONSizeLimitMessage("response"))
	}
	return string(raw)
}

func invokeJSONSizeLimitMessage(kind string) string {
	return fmt.Sprintf(
		"invoke %s exceeds the %d MiB size limit",
		kind,
		maxInvokeJSONSizeMiB,
	)
}

func encodeInvokeFailure(message string) string {
	raw, err := json.Marshal(&invokeResponse{Err: message})
	if err != nil {
		return `{"success":false,"data":null,"error":"failed to encode response"}`
	}
	return string(raw)
}

func encodeInvokeNoDataResponse(err error) string {
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	return encodeInvokeResponse(struct{}{}, nil)
}

func invokeGetFreePorts(payload json.RawMessage) string {
	request, err := decodePayload[GetFreePortsRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	ports, err := nodep.GetFreePorts(request.Count)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	return encodeInvokeResponse(&GetFreePortsResponse{Ports: ports}, nil)
}

func invokeConvertShareLinksToXrayJson(payload json.RawMessage) string {
	request, err := decodePayload[ConvertShareLinksToXrayJsonRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	secretKey := ""
	if request.Age != nil {
		secretKey = request.Age.SecretKey
	}
	result, err := share.ConvertShareLinksToXrayJson(request.Text, secretKey)
	return encodeInvokeResponse(result, err)
}

func invokeGenerateAgeKeyPair(payload json.RawMessage) string {
	request, err := decodePayload[GenerateAgeKeyPairRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	pair, err := share.GenerateAgeKeyPair(share.AgeKeyType(request.KeyType))
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	return encodeInvokeResponse(&GenerateAgeKeyPairResponse{
		SecretKey: pair.SecretKey,
		PublicKey: pair.PublicKey,
	}, nil)
}

func invokeConvertXrayJsonToShareLinks(payload json.RawMessage) string {
	request, err := decodePayload[ConvertXrayJsonToShareLinksRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	links, err := share.ConvertXrayJsonToShareLinks([]byte(request.XrayJson))
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	return encodeInvokeResponse(&ConvertXrayJsonToShareLinksResponse{Links: links}, nil)
}

func invokeCountGeoData(payload json.RawMessage) string {
	request, err := decodePayload[CountGeoDataRequest](payload)
	if err != nil {
		return encodeInvokeNoDataResponse(err)
	}
	if request.DatDir == "" {
		return encodeInvokeNoDataResponse(errors.New("missing datDir"))
	}
	err = geo.CountGeoData(request.DatDir, request.Name, request.GeoType)
	return encodeInvokeNoDataResponse(err)
}

func invokePingLive(payload json.RawMessage) string {
	request, err := decodePayload[PingLiveRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	results, err := xray.PingLive(request.Tags, request.Timeout, request.URL)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	responseResults := make([]PingLiveItemResponse, len(results))
	for i, result := range results {
		responseResults[i] = PingLiveItemResponse{
			Tag:     result.Tag,
			Success: result.Success,
			Delay:   result.Delay,
			Error:   result.Error,
		}
	}
	return encodeInvokeResponse(PingLiveResponse{Results: responseResults}, nil)
}

func invokePingBatch(payload json.RawMessage) string {
	request, err := decodePayload[PingBatchRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}

	configs := make([]xray.PingBatchItem, len(request.Configs))
	for i, config := range request.Configs {
		// Амнезия поднимается только на время пробы. Если тот же ключ уже
		// держит туннель в этом процессе, берётся его движок, а не второй.
		prepared, release, err := awg.PrepareXrayJSON(config.XrayJson)
		if err != nil {
			prepared = config.XrayJson
		} else {
			defer release()
		}
		configs[i] = xray.PingBatchItem{
			XrayJSON:    prepared,
			OutboundTag: config.OutboundTag,
		}
	}

	results, err := xray.PingBatchWithLocation(
		configs,
		request.Timeout,
		request.URL,
		request.LocationURL,
	)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}

	responseResults := make([]PingBatchItemResponse, len(results))
	for i, result := range results {
		responseResults[i] = PingBatchItemResponse{
			Success:       result.Success,
			Delay:         result.Delay,
			Error:         result.Error,
			LocationJSON:  result.LocationJSON,
			LocationError: result.LocationError,
		}
	}
	return encodeInvokeResponse(&PingBatchResponse{Results: responseResults}, nil)
}

func invokeTestXray(payload json.RawMessage) string {
	request, err := decodePayload[TestXrayRequest](payload)
	if err != nil {
		return encodeInvokeNoDataResponse(err)
	}
	err = xray.TestXray(request.XrayJson)
	return encodeInvokeNoDataResponse(err)
}

// awgRelease отпускает амнезии, поднятые под работающее ядро.
var (
	awgReleaseMu sync.Mutex
	awgRelease   = func() {}
)

func invokeRunXray(payload json.RawMessage) string {
	request, err := decodePayload[RunXrayRequest](payload)
	if err != nil {
		return encodeInvokeNoDataResponse(err)
	}
	// Outbounds с пометкой awgConf становятся socks на поднятую амнезию;
	// конфигурация без пометки проходит как есть.
	prepared, release, err := awg.PrepareXrayJSON(request.XrayJson)
	if err != nil {
		return encodeInvokeNoDataResponse(err)
	}
	if err = xray.RunXray(prepared); err != nil {
		release()
		return encodeInvokeNoDataResponse(err)
	}
	awgReleaseMu.Lock()
	awgRelease = release
	awgReleaseMu.Unlock()
	return encodeInvokeNoDataResponse(nil)
}

func invokeStopXray() string {
	err := xray.StopXray()
	awgReleaseMu.Lock()
	release := awgRelease
	awgRelease = func() {}
	awgReleaseMu.Unlock()
	release()
	return encodeInvokeNoDataResponse(err)
}

// Методы движка AmneziaWG.
//
// Отдельный движок, а не выход Xray: у Xray нет подключаемых протоколов,
// а второе расширение туннеля нам нельзя. Поэтому запускаем его рядом и
// отдаём ему тот же туннель.

func invokeAwgStart(payload json.RawMessage) string {
	request, err := decodePayload[awg.StartRequest](payload)
	if err != nil {
		return encodeInvokeNoDataResponse(err)
	}
	return encodeInvokeNoDataResponse(awg.Start(request))
}

// invokeAwgSocksStart поднимает амнезию в юзерспейсе и отдаёт порт socks5
// на 127.0.0.1, который приложение подставляет в outbound Xray.
func invokeAwgSocksStart(payload json.RawMessage) string {
	request, err := decodePayload[awg.SocksStartRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	resp, err := awg.SocksStart(request)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	return encodeInvokeResponse(&resp, nil)
}

func invokeAwgStop() string {
	return encodeInvokeNoDataResponse(awg.Stop())
}

func invokeAwgState() string {
	return encodeInvokeResponse(awg.IsRunning(), nil)
}

func invokeAwgStats() string {
	stats, err := awg.GetStats()
	if err != nil {
		return encodeInvokeNoDataResponse(err)
	}
	return encodeInvokeResponse(stats, nil)
}

// invokeAwgParseConf разбирает .conf от панели и отдаёт приложению и
// конфигурацию для ядра, и настройки интерфейса.
//
// Нужно до запуска: адреса, DNS и MTU надо выставить расширению
// туннеля, а ядро их не принимает.
func invokeAwgParseConf(payload json.RawMessage) string {
	request, err := decodePayload[struct {
		Conf string `json:"conf"`
	}](payload)
	if err != nil {
		return encodeInvokeNoDataResponse(err)
	}
	parsed, err := awg.ParseConf(request.Conf)
	if err != nil {
		return encodeInvokeNoDataResponse(err)
	}
	return encodeInvokeResponse(parsed, nil)
}

// GoMemStats — сколько памяти держит Go в этом процессе, в мегабайтах.
//
// Расширение iOS умирает у потолка ~50 МБ на весь процесс, а туда входят и
// Go (Xray, амнезия, её стек), и нативная часть (мост пакетов, Swift,
// система). Без разбивки непонятно, что урезать.
type GoMemStats struct {
	HeapInuseMB float64 `json:"heapInuseMB"`
	HeapSysMB   float64 `json:"heapSysMB"`
	StackMB     float64 `json:"stackMB"`
	SysMB       float64 `json:"sysMB"`
	Goroutines  int     `json:"goroutines"`
	NumGC       uint32  `json:"numGC"`
	AwgEngines  int     `json:"awgEngines"`
}

func goMemStats() *GoMemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	mb := func(b uint64) float64 { return float64(b) / (1 << 20) }
	return &GoMemStats{
		HeapInuseMB: mb(m.HeapInuse),
		HeapSysMB:   mb(m.HeapSys),
		StackMB:     mb(m.StackInuse),
		SysMB:       mb(m.Sys),
		Goroutines:  runtime.NumGoroutine(),
		NumGC:       m.NumGC,
		AwgEngines:  awg.SocksRunning(),
	}
}
