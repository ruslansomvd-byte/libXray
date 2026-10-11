package awg

import (
	"fmt"
	"net/netip"
	"sort"
)

// Маршруты для Android ниже 13: там у VpnService нет excludeRoute, и
// «весь интернет минус российские сети» задаётся дополнением — списком
// того, что ИДЁТ в туннель.
//
// Ошибка здесь опасна в одну сторону: пропущенный кусок дополнения —
// это зарубежные адреса мимо туннеля, то есть без защиты. Поэтому
// огрубление (MinPrefix) делается только в безопасную сторону: мелкие
// российские сети не вычитаются и идут в туннель, как шли до этого.

// RoutesComplementRequest — что вычесть из 0.0.0.0/0.
type RoutesComplementRequest struct {
	// Exclude — российские сети вида a.b.c.d/n.
	Exclude []string `json:"exclude"`
	// MinPrefix — сети мельче этого префикса не вычитаются (0 — все).
	// Нужен, если телефон не потянет полный список.
	MinPrefix int `json:"minPrefix"`
}

// RoutesComplementResponse — что отдать в addRoute.
type RoutesComplementResponse struct {
	Routes   []string `json:"routes"`
	Excluded int      `json:"excluded"`
}

type span struct{ lo, hi uint64 } // [lo, hi], адреса IPv4 как числа

// RoutesComplement вычитает Exclude из всего IPv4 и отдаёт минимальный
// набор сетей, покрывающий остаток.
func RoutesComplement(req RoutesComplementRequest) (RoutesComplementResponse, error) {
	var spans []span
	for _, s := range req.Exclude {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return RoutesComplementResponse{}, fmt.Errorf("не сеть: %q", s)
		}
		if !p.Addr().Is4() {
			continue
		}
		if req.MinPrefix > 0 && p.Bits() > req.MinPrefix {
			continue
		}
		p = p.Masked()
		lo := uint64(ip4(p.Addr()))
		spans = append(spans, span{lo, lo + (uint64(1) << (32 - p.Bits())) - 1})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })

	var routes []string
	next := uint64(0)
	const end = uint64(1) << 32
	for _, s := range spans {
		if s.lo > next {
			routes = append(routes, cidrsBetween(next, s.lo-1)...)
		}
		if s.hi+1 > next {
			next = s.hi + 1
		}
	}
	if next < end {
		routes = append(routes, cidrsBetween(next, end-1)...)
	}
	return RoutesComplementResponse{Routes: routes, Excluded: len(spans)}, nil
}

// cidrsBetween — минимальный набор выровненных сетей, ровно покрывающий [lo, hi].
func cidrsBetween(lo, hi uint64) []string {
	var out []string
	for lo <= hi {
		size := uint64(1)
		// Самый большой блок, выровненный по lo и не вылезающий за hi.
		for size<<1 <= hi-lo+1 && lo%(size<<1) == 0 {
			size <<= 1
		}
		bits := 32
		for s := size; s > 1; s >>= 1 {
			bits--
		}
		out = append(out, fmt.Sprintf("%s/%d", fromIP4(uint32(lo)), bits))
		lo += size
	}
	return out
}

func ip4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromIP4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
