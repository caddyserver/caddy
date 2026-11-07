package reverseproxy

import (
	"strconv"
	"testing"
)

func BenchmarkHostByHashing(b *testing.B) {
	pool := make(UpstreamPool, 0, 8)
	for i := 0; i < 8; i++ {
		pool = append(pool, &Upstream{Host: new(Host), Dial: "10.0.0." + strconv.Itoa(i) + ":8080"})
	}
	const key = "192.168.1.100"
	b.ReportAllocs()
	for b.Loop() {
		_ = hostByHashing(pool, key)
	}
}
