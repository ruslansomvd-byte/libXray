// libXray is an Xray wrapper focusing on improving the experience of Xray-core mobile development.
package libXray

import (
	"encoding/json"
)

type LibXrayMethod string

const LibXrayAPIVersion = 3

const (
	LibXrayMethodGetFreePorts                LibXrayMethod = "getFreePorts"
	LibXrayMethodConvertShareLinksToXrayJson LibXrayMethod = "convertShareLinksToXrayJson"
	LibXrayMethodConvertXrayJsonToShareLinks LibXrayMethod = "convertXrayJsonToShareLinks"
	LibXrayMethodGenerateAgeKeyPair          LibXrayMethod = "generateAgeKeyPair"
	LibXrayMethodCountGeoData                LibXrayMethod = "countGeoData"
	LibXrayMethodPingBatch                   LibXrayMethod = "pingBatch"
	LibXrayMethodPingLive                    LibXrayMethod = "pingLive"
	LibXrayMethodTestXray                    LibXrayMethod = "testXray"
	LibXrayMethodRunXray                     LibXrayMethod = "runXray"
	LibXrayMethodStopXray                    LibXrayMethod = "stopXray"
	LibXrayMethodXrayVersion                 LibXrayMethod = "xrayVersion"
	LibXrayMethodGetXrayState                LibXrayMethod = "getXrayState"

	// Движок AmneziaWG. Живёт рядом с Xray в той же библиотеке и делит с
	// ним один туннель: двух расширений туннеля мы намеренно избегаем.
	LibXrayMethodAwgStart     LibXrayMethod = "awgStart"
	LibXrayMethodAwgStop      LibXrayMethod = "awgStop"
	LibXrayMethodAwgState     LibXrayMethod = "awgState"
	LibXrayMethodAwgStats     LibXrayMethod = "awgStats"
	LibXrayMethodAwgParseConf LibXrayMethod = "awgParseConf"
	// Амнезия как socks-выход Xray (см. awg/socks.go).
	LibXrayMethodAwgSocksStart   LibXrayMethod = "awgSocksStart"
	LibXrayMethodAwgSocksStopAll LibXrayMethod = "awgSocksStopAll"
	// Доля Go в памяти процесса — чтобы знать, кто ест память расширения.
	LibXrayMethodGoMemStats LibXrayMethod = "goMemStats"
	// Дополнение маршрутов для Android ниже 13 (нет excludeRoute).
	LibXrayMethodRoutesComplement LibXrayMethod = "routesComplement"
)

type LibXrayInvokeRequest struct {
	APIVersion int             `json:"apiVersion,omitempty"`
	Method     LibXrayMethod   `json:"method,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

type GetFreePortsRequest struct {
	Count int `json:"count,omitempty"`
}

type GetFreePortsResponse struct {
	Ports []int `json:"ports,omitempty"`
}

type AgeDecryptConfig struct {
	SecretKey string `json:"secretKey,omitempty"`
}

type ConvertShareLinksToXrayJsonRequest struct {
	Text string            `json:"text,omitempty"`
	Age  *AgeDecryptConfig `json:"age,omitempty"`
}

type AgeKeyType string

const (
	AgeKeyTypeX25519 AgeKeyType = "x25519"
	AgeKeyTypeHybrid AgeKeyType = "hybrid"
)

type GenerateAgeKeyPairRequest struct {
	KeyType AgeKeyType `json:"keyType,omitempty"`
}

type GenerateAgeKeyPairResponse struct {
	SecretKey string `json:"secretKey,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
}

type ConvertXrayJsonToShareLinksRequest struct {
	XrayJson string `json:"xrayJson,omitempty"`
}

type ConvertXrayJsonToShareLinksResponse struct {
	Links string `json:"links,omitempty"`
}

type CountGeoDataRequest struct {
	Name    string `json:"name,omitempty"`
	GeoType string `json:"geoType,omitempty"`
	DatDir  string `json:"datDir,omitempty"`
}

type PingBatchRequest struct {
	Configs     []PingBatchItemRequest `json:"configs,omitempty"`
	Timeout     int                    `json:"timeout,omitempty"`
	URL         string                 `json:"url,omitempty"`
	LocationURL string                 `json:"locationUrl,omitempty"`
}

type PingBatchItemRequest struct {
	XrayJson    string `json:"xrayJson,omitempty"`
	OutboundTag string `json:"outboundTag,omitempty"`
}

type PingBatchResponse struct {
	Results []PingBatchItemResponse `json:"results,omitempty"`
}

type PingBatchItemResponse struct {
	Success       bool    `json:"success"`
	Delay         int64   `json:"delay"`
	Error         string  `json:"error,omitempty"`
	LocationJSON  *string `json:"locationJson,omitempty"`
	LocationError string  `json:"locationError,omitempty"`
}

// PingLiveRequest measures outbounds of the instance that is already running,
// by tag. See xray.PingLive for why this exists next to PingBatchRequest.
type PingLiveRequest struct {
	Tags    []string `json:"tags,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
	URL     string   `json:"url,omitempty"`
}

type PingLiveResponse struct {
	Results []PingLiveItemResponse `json:"results,omitempty"`
}

type PingLiveItemResponse struct {
	Tag     string `json:"tag,omitempty"`
	Success bool   `json:"success"`
	Delay   int64  `json:"delay"`
	Error   string `json:"error,omitempty"`
}

type RunXrayRequest struct {
	XrayJson string `json:"xrayJson,omitempty"`
}

type TestXrayRequest struct {
	XrayJson string `json:"xrayJson,omitempty"`
}

type XrayVersionResponse struct {
	Version string `json:"version,omitempty"`
}

type GetXrayStateResponse struct {
	Running bool `json:"running"`
}
