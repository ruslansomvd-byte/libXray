//go:build !linux && !android

package awg

import (
	"os"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// newTunFromFD wraps the descriptor the tunnel extension handed over. MTU 0
// leaves it as the system set it (setTunnelNetworkSettings on iOS).
func newTunFromFD(fd int) (tun.Device, error) {
	file := os.NewFile(uintptr(fd), "awg-tun")
	dev, err := tun.CreateTUNFromFile(file, 0)
	if err != nil {
		_ = file.Close()
	}
	return dev, err
}
