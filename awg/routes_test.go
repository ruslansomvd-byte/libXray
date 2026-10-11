package awg

import (
	"bufio"
	"math/rand"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func inAny(a netip.Addr, nets []string) bool {
	for _, n := range nets {
		if netip.MustParsePrefix(n).Contains(a) {
			return true
		}
	}
	return false
}

func TestRoutesComplementSimple(t *testing.T) {
	r, err := RoutesComplement(RoutesComplementRequest{Exclude: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"0.0.0.0/5": true, "8.0.0.0/7": true, "11.0.0.0/8": true, "12.0.0.0/6": true,
		"16.0.0.0/4": true, "32.0.0.0/3": true, "64.0.0.0/2": true, "128.0.0.0/1": true}
	if len(r.Routes) != len(want) {
		t.Fatalf("ждал %d сетей, получил %v", len(want), r.Routes)
	}
	for _, x := range r.Routes {
		if !want[x] {
			t.Fatalf("лишняя сеть %s в %v", x, r.Routes)
		}
	}
}

func TestRoutesComplementNothingExcludedIsWholeInternet(t *testing.T) {
	r, _ := RoutesComplement(RoutesComplementRequest{})
	if len(r.Routes) != 1 || r.Routes[0] != "0.0.0.0/0" {
		t.Fatalf("без исключений должен быть весь интернет, а не %v", r.Routes)
	}
}

func TestRoutesComplementOverlapsAndEdges(t *testing.T) {
	r, _ := RoutesComplement(RoutesComplementRequest{Exclude: []string{
		"0.0.0.0/8", "255.255.255.0/24", "5.3.0.0/16", "5.3.4.0/24", "5.3.0.0/17",
	}})
	for _, a := range []string{"0.0.0.1", "255.255.255.255", "5.3.200.1", "5.3.4.4"} {
		if inAny(netip.MustParseAddr(a), r.Routes) {
			t.Fatalf("%s вычтен, но остался в туннеле", a)
		}
	}
	for _, a := range []string{"1.0.0.0", "255.255.254.255", "5.2.255.255", "5.4.0.0"} {
		if !inAny(netip.MustParseAddr(a), r.Routes) {
			t.Fatalf("%s не вычитался, а в туннель не попал", a)
		}
	}
}

// Главная проверка на настоящем списке: случайные адреса со всего IPv4
// попадают ровно в одно из двух — российские мимо туннеля, прочие в туннель.
func TestRoutesComplementRealListExact(t *testing.T) {
	f, err := os.Open("/Volumes/RU888/ANTIGRAVITY/SFERAVPN-APP/hiddify-app-test/assets/routes/ru-ipv4.txt")
	if err != nil {
		t.Skip("списка нет на этой машине")
	}
	defer f.Close()
	var ru []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			ru = append(ru, l)
		}
	}
	r, err := RoutesComplement(RoutesComplementRequest{Exclude: ru})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("российских сетей %d, маршрутов в туннель %d", len(ru), len(r.Routes))

	ruP := make([]netip.Prefix, len(ru))
	for i, s := range ru {
		ruP[i] = netip.MustParsePrefix(s)
	}
	tun := make([]netip.Prefix, len(r.Routes))
	for i, s := range r.Routes {
		tun[i] = netip.MustParsePrefix(s)
	}
	contains := func(ps []netip.Prefix, a netip.Addr) bool {
		for _, p := range ps {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	rng := rand.New(rand.NewSource(1))
	probe := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("77.88.8.8"), netip.MustParseAddr("213.59.254.7"), netip.MustParseAddr("84.252.149.206")}
	for i := 0; i < 3000; i++ {
		probe = append(probe, fromIP4(rng.Uint32()))
	}
	for _, a := range probe {
		isRU, inTun := contains(ruP, a), contains(tun, a)
		if isRU == inTun {
			t.Fatalf("%s: российский=%v, в туннеле=%v — должно быть ровно одно", a, isRU, inTun)
		}
	}

	// Огрубление только в безопасную сторону: мелкие российские сети идут в
	// туннель, но ни один зарубежный адрес мимо туннеля не уходит.
	c, _ := RoutesComplement(RoutesComplementRequest{Exclude: ru, MinPrefix: 22})
	t.Logf("с порогом /22 маршрутов %d", len(c.Routes))
	cTun := make([]netip.Prefix, len(c.Routes))
	for i, s := range c.Routes {
		cTun[i] = netip.MustParsePrefix(s)
	}
	for _, a := range probe {
		if !contains(ruP, a) && !contains(cTun, a) {
			t.Fatalf("%s не российский, а с порогом ушёл мимо туннеля", a)
		}
	}
}
