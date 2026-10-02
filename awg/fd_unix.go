//go:build darwin || linux || android || ios

package awg

import "golang.org/x/sys/unix"

// dupTunFd дублирует описатель туннеля.
//
// Системный описатель принадлежит расширению туннеля (на iOS) или
// VpnService (на Android). Если отдать его движку напрямую, то при
// остановке движок закроет чужой описатель, и расширение останется с
// нерабочим туннелем — именно так выглядят «Bad file descriptor» в
// журналах. Поэтому работаем с копией.
func dupTunFd(fd int) (int, error) {
	return unix.Dup(fd)
}
