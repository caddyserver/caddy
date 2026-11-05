// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
