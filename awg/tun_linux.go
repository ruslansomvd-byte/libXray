//go:build linux || android

package awg

import (
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// newTunFromFD wraps the descriptor the platform's VpnService handed over.
//
// Not CreateTUNFromFile: on Linux that always sets the interface MTU with an
// ioctl (setMTU runs even for 0), and an Android app has no NET_ADMIN, so
// the tunnel never came up -- "failed to set MTU of TUN device: permission
// denied" (Samsung SM-G960F, Android 10, 19.10). The MTU is already set by
// VpnService.Builder. This is the constructor wireguard-android uses: no MTU
// change and no netlink listener, which an app cannot open either.
// On error the descriptor is left to the os.File the library wrapped it in
// (its finalizer closes it); closing it here could close a reused number.
func newTunFromFD(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}
