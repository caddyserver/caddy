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
	"net/http/httptest"
	"testing"
)

func testPool() UpstreamPool {
	return UpstreamPool{
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
	}
}

func TestRoundRobinPolicy(t *testing.T) {
	pool := testPool()
	rrPolicy := new(RoundRobinSelection)
	req, _ := http.NewRequest("GET", "/", nil)

	h := rrPolicy.Select(pool, req, nil)
	// First selected host is 1, because counter starts at 0
	// and increments before host is selected
	if h != pool[1] {
		t.Error("Expected first round robin host to be second host in the pool.")
	}
	h = rrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected second round robin host to be third host in the pool.")
	}
	h = rrPolicy.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected third round robin host to be first host in the pool.")
	}
	// mark host as down
	pool[1].SetHealthy(false)
	h = rrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected to skip down host.")
	}
	// mark host as up
	pool[1].SetHealthy(true)

	h = rrPolicy.Select(pool, req, nil)
	if h == pool[2] {
		t.Error("Expected to balance evenly among healthy hosts")
	}
	// mark host as full
	pool[1].CountRequest(1)
	pool[1].MaxRequests = 1
	h = rrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected to skip full host.")
	}
}

func TestLeastConnPolicy(t *testing.T) {
	pool := testPool()
	lcPolicy := new(LeastConnSelection)
	req, _ := http.NewRequest("GET", "/", nil)

	pool[0].CountRequest(10)
	pool[1].CountRequest(10)
	h := lcPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected least connection host to be third host.")
	}
	pool[2].CountRequest(100)
	h = lcPolicy.Select(pool, req, nil)
	if h != pool[0] && h != pool[1] {
		t.Error("Expected least connection host to be first or second host.")
	}
}

func TestIPHashPolicy(t *testing.T) {
	pool := testPool()
	ipHash := new(IPHashSelection)
	req, _ := http.NewRequest("GET", "/", nil)

	// We should be able to predict where every request is routed.
	req.RemoteAddr = "172.0.0.1:80"
	h := ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}
	req.RemoteAddr = "172.0.0.2:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}
	req.RemoteAddr = "172.0.0.3:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected ip hash policy host to be the third host.")
	}
	req.RemoteAddr = "172.0.0.4:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}

	// we should get the same results without a port
	req.RemoteAddr = "172.0.0.1"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}
	req.RemoteAddr = "172.0.0.2"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}
	req.RemoteAddr = "172.0.0.3"
	h = ipHash.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected ip hash policy host to be the third host.")
	}
	req.RemoteAddr = "172.0.0.4"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}

	// we should get a healthy host if the original host is unhealthy and a
	// healthy host is available
	req.RemoteAddr = "172.0.0.1"
	pool[1].SetHealthy(false)
	h = ipHash.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected ip hash policy host to be the third host.")
	}

	req.RemoteAddr = "172.0.0.2"
	h = ipHash.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected ip hash policy host to be the third host.")
	}
	pool[1].SetHealthy(true)

	req.RemoteAddr = "172.0.0.3"
	pool[2].SetHealthy(false)
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	req.RemoteAddr = "172.0.0.4"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}

	// We should be able to resize the host pool and still be able to predict
	// where a req will be routed with the same IP's used above
	pool = UpstreamPool{
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
	}
	req.RemoteAddr = "172.0.0.1:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	req.RemoteAddr = "172.0.0.2:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}
	req.RemoteAddr = "172.0.0.3:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	req.RemoteAddr = "172.0.0.4:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}

	// We should get nil when there are no healthy hosts
	pool[0].SetHealthy(false)
	pool[1].SetHealthy(false)
	h = ipHash.Select(pool, req, nil)
	if h != nil {
		t.Error("Expected ip hash policy host to be nil.")
	}

	// Reproduce #4135
	pool = UpstreamPool{
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
	}
	pool[0].SetHealthy(false)
	pool[1].SetHealthy(false)
	pool[2].SetHealthy(false)
	pool[3].SetHealthy(false)
	pool[4].SetHealthy(false)
	pool[5].SetHealthy(false)
	pool[6].SetHealthy(false)
	pool[7].SetHealthy(false)
	pool[8].SetHealthy(true)

	// We should get a result back when there is one healthy host left.
	h = ipHash.Select(pool, req, nil)
	if h == nil {
		// If it is nil, it means we missed a host even though one is available
		t.Error("Expected ip hash policy host to not be nil, but it is nil.")
	}
}

func TestFirstPolicy(t *testing.T) {
	pool := testPool()
	firstPolicy := new(FirstSelection)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := firstPolicy.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected first policy host to be the first host.")
	}

	pool[0].SetHealthy(false)
	h = firstPolicy.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected first policy host to be the second host.")
	}
}

func TestURIHashPolicy(t *testing.T) {
	pool := testPool()
	uriPolicy := new(URIHashSelection)

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	h := uriPolicy.Select(pool, request, nil)
	if h != pool[0] {
		t.Error("Expected uri policy host to be the first host.")
	}

	pool[0].SetHealthy(false)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected uri policy host to be the first host.")
	}

	request = httptest.NewRequest(http.MethodGet, "/test_2", nil)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected uri policy host to be the second host.")
	}

	// We should be able to resize the host pool and still be able to predict
	// where a request will be routed with the same URI's used above
	pool = UpstreamPool{
		{Host: new(upstreamHost)},
		{Host: new(upstreamHost)},
	}

	request = httptest.NewRequest(http.MethodGet, "/test", nil)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[0] {
		t.Error("Expected uri policy host to be the first host.")
	}

	pool[0].SetHealthy(false)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected uri policy host to be the first host.")
	}

	request = httptest.NewRequest(http.MethodGet, "/test_2", nil)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected uri policy host to be the second host.")
	}

	pool[0].SetHealthy(false)
	pool[1].SetHealthy(false)
	h = uriPolicy.Select(pool, request, nil)
	if h != nil {
		t.Error("Expected uri policy policy host to be nil.")
	}
}

func TestLeastRequests(t *testing.T) {
	pool := testPool()
	pool[0].Dial = "localhost:8080"
	pool[1].Dial = "localhost:8081"
	pool[2].Dial = "localhost:8082"
	pool[0].SetHealthy(true)
	pool[1].SetHealthy(true)
	pool[2].SetHealthy(true)
	pool[0].CountRequest(10)
	pool[1].CountRequest(20)
	pool[2].CountRequest(30)

	result := leastRequests(pool)

	if result == nil {
		t.Error("Least request should not return nil")
	}

	if result != pool[0] {
		t.Error("Least request should return pool[0]")
	}
}

func TestRandomChoicePolicy(t *testing.T) {
	pool := testPool()
	pool[0].Dial = "localhost:8080"
	pool[1].Dial = "localhost:8081"
	pool[2].Dial = "localhost:8082"
	pool[0].SetHealthy(false)
	pool[1].SetHealthy(true)
	pool[2].SetHealthy(true)
	pool[0].CountRequest(10)
	pool[1].CountRequest(20)
	pool[2].CountRequest(30)

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	randomChoicePolicy := new(RandomChoiceSelection)
	randomChoicePolicy.Choose = 2

	h := randomChoicePolicy.Select(pool, request, nil)

	if h == nil {
		t.Error("RandomChoicePolicy should not return nil")
	}

	if h == pool[0] {
		t.Error("RandomChoicePolicy should not choose pool[0]")
	}

}

func TestCookieHashPolicy(t *testing.T) {
	pool := testPool()
	pool[0].Dial = "localhost:8080"
	pool[1].Dial = "localhost:8081"
	pool[2].Dial = "localhost:8082"
	pool[0].SetHealthy(true)
	pool[1].SetHealthy(false)
	pool[2].SetHealthy(false)
	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	cookieHashPolicy := new(CookieHashSelection)
	h := cookieHashPolicy.Select(pool, request, w)
	cookieServer1 := w.Result().Cookies()[0]
	if cookieServer1 == nil {
		t.Fatal("cookieHashPolicy should set a cookie")
	}
	if cookieServer1.Name != "lb" {
		t.Error("cookieHashPolicy should set a cookie with name lb")
	}
	if h != pool[0] {
		t.Error("Expected cookieHashPolicy host to be the first only available host.")
	}
	pool[1].SetHealthy(true)
	pool[2].SetHealthy(true)
	request = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	request.AddCookie(cookieServer1)
	h = cookieHashPolicy.Select(pool, request, w)
	if h != pool[0] {
		t.Error("Expected cookieHashPolicy host to stick to the first host (matching cookie).")
	}
	s := w.Result().Cookies()
	if len(s) != 0 {
		t.Error("Expected cookieHashPolicy to not set a new cookie.")
	}
	pool[0].SetHealthy(false)
	request = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	request.AddCookie(cookieServer1)
	h = cookieHashPolicy.Select(pool, request, w)
	if h == pool[0] {
		t.Error("Expected cookieHashPolicy to select a new host.")
	}
	if w.Result().Cookies() == nil {
		t.Error("Expected cookieHashPolicy to set a new cookie.")
	}
}
