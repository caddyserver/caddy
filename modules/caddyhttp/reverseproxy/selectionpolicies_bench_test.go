package reverseproxy

import (
	"net/http"
	"testing"
)

func BenchmarkWeightedRoundRobinSelect(b *testing.B) {
	pool := UpstreamPool{
		{Host: new(Host), Dial: "0.0.0.1"},
		{Host: new(Host), Dial: "0.0.0.2"},
		{Host: new(Host), Dial: "0.0.0.3"},
		{Host: new(Host), Dial: "0.0.0.4"},
		{Host: new(Host), Dial: "0.0.0.5"},
	}
	wrrPolicy := &WeightedRoundRobinSelection{
		Weights:     []int{5, 4, 3, 2, 1},
		totalWeight: 15,
	}
	req, _ := http.NewRequest("GET", "/", nil)
	b.ReportAllocs()
	for b.Loop() {
		_ = wrrPolicy.Select(pool, req, nil)
	}
}
