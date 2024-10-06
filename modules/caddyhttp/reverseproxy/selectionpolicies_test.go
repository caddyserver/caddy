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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func testPool() UpstreamPool {
	return UpstreamPool{
		{Host: new(Host), Dial: "0.0.0.1"},
		{Host: new(Host), Dial: "0.0.0.2"},
		{Host: new(Host), Dial: "0.0.0.3"},
	}
}

func TestRoundRobinPolicy(t *testing.T) {
	pool := testPool()
	rrPolicy := RoundRobinSelection{}
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
	pool[1].setHealthy(false)
	h = rrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected to skip down host.")
	}
	// mark host as up
	pool[1].setHealthy(true)

	h = rrPolicy.Select(pool, req, nil)
	if h == pool[2] {
		t.Error("Expected to balance evenly among healthy hosts")
	}
	// mark host as full
	pool[1].countRequest(1)
	pool[1].MaxRequests = 1
	h = rrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected to skip full host.")
	}
}

func TestWeightedRoundRobinPolicy(t *testing.T) {
	pool := testPool()
	wrrPolicy := WeightedRoundRobinSelection{
		Weights:     []int{3, 2, 1},
		totalWeight: 6,
	}
	req, _ := http.NewRequest("GET", "/", nil)

	h := wrrPolicy.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected first weighted round robin host to be first host in the pool.")
	}
	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected second weighted round robin host to be first host in the pool.")
	}
	// Third selected host is 1, because counter starts at 0
	// and increments before host is selected
	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected third weighted round robin host to be second host in the pool.")
	}
	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected fourth weighted round robin host to be second host in the pool.")
	}
	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected fifth weighted round robin host to be third host in the pool.")
	}
	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected sixth weighted round robin host to be first host in the pool.")
	}

	// mark host as down
	pool[0].setHealthy(false)
	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected to skip down host.")
	}
	// mark host as up
	pool[0].setHealthy(true)

	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected to select first host on availability.")
	}
	// mark host as full
	pool[1].countRequest(1)
	pool[1].MaxRequests = 1
	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected to skip full host.")
	}
}

func TestWeightedRoundRobinPolicyWithZeroWeight(t *testing.T) {
	pool := testPool()
	wrrPolicy := WeightedRoundRobinSelection{
		Weights:     []int{0, 2, 1},
		totalWeight: 3,
	}
	req, _ := http.NewRequest("GET", "/", nil)

	h := wrrPolicy.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected first weighted round robin host to be second host in the pool.")
	}

	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected second weighted round robin host to be third host in the pool.")
	}

	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected third weighted round robin host to be second host in the pool.")
	}

	// mark second host as down
	pool[1].setHealthy(false)
	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expect select next available host.")
	}

	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expect select only available host.")
	}
	// mark second host as up
	pool[1].setHealthy(true)

	h = wrrPolicy.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expect select first host on availability.")
	}

	// test next select in full cycle
	expected := []*Upstream{pool[1], pool[2], pool[1], pool[1], pool[2], pool[1]}
	for i, want := range expected {
		got := wrrPolicy.Select(pool, req, nil)
		if want != got {
			t.Errorf("Selection %d: got host[%s], want host[%s]", i+1, got, want)
		}
	}
}

func TestLeastConnPolicy(t *testing.T) {
	pool := testPool()
	lcPolicy := LeastConnSelection{}
	req, _ := http.NewRequest("GET", "/", nil)

	pool[0].countRequest(10)
	pool[1].countRequest(10)
	h := lcPolicy.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected least connection host to be third host.")
	}
	pool[2].countRequest(100)
	h = lcPolicy.Select(pool, req, nil)
	if h != pool[0] && h != pool[1] {
		t.Error("Expected least connection host to be first or second host.")
	}
}

func TestIPHashPolicy(t *testing.T) {
	pool := testPool()
	ipHash := IPHashSelection{}
	req, _ := http.NewRequest("GET", "/", nil)

	// We should be able to predict where every request is routed.
	req.RemoteAddr = "172.0.0.1:80"
	h := ipHash.Select(pool, req, nil)
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

	// we should get the same results without a port
	req.RemoteAddr = "172.0.0.1"
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	req.RemoteAddr = "172.0.0.2"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}
	req.RemoteAddr = "172.0.0.3"
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	req.RemoteAddr = "172.0.0.4"
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}

	// we should get a healthy host if the original host is unhealthy and a
	// healthy host is available
	req.RemoteAddr = "172.0.0.4"
	pool[1].setHealthy(false)
	h = ipHash.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected ip hash policy host to be the third host.")
	}

	req.RemoteAddr = "172.0.0.2"
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	pool[1].setHealthy(true)

	req.RemoteAddr = "172.0.0.3"
	pool[2].setHealthy(false)
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
		{Host: new(Host), Dial: "0.0.0.2"},
		{Host: new(Host), Dial: "0.0.0.3"},
	}
	req.RemoteAddr = "172.0.0.1:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	req.RemoteAddr = "172.0.0.2:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	req.RemoteAddr = "172.0.0.3:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	req.RemoteAddr = "172.0.0.4:80"
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}

	// We should get nil when there are no healthy hosts
	pool[0].setHealthy(false)
	pool[1].setHealthy(false)
	h = ipHash.Select(pool, req, nil)
	if h != nil {
		t.Error("Expected ip hash policy host to be nil.")
	}

	// Reproduce #4135
	pool = UpstreamPool{
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
	}
	pool[0].setHealthy(false)
	pool[1].setHealthy(false)
	pool[2].setHealthy(false)
	pool[3].setHealthy(false)
	pool[4].setHealthy(false)
	pool[5].setHealthy(false)
	pool[6].setHealthy(false)
	pool[7].setHealthy(false)
	pool[8].setHealthy(true)

	// We should get a result back when there is one healthy host left.
	h = ipHash.Select(pool, req, nil)
	if h == nil {
		// If it is nil, it means we missed a host even though one is available
		t.Error("Expected ip hash policy host to not be nil, but it is nil.")
	}
}

func TestClientIPHashPolicy(t *testing.T) {
	pool := testPool()
	ipHash := ClientIPHashSelection{}
	req, _ := http.NewRequest("GET", "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, make(map[string]any)))

	// We should be able to predict where every request is routed.
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.1:80")
	h := ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.2:80")
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.3:80")
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.4:80")
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}

	// we should get the same results without a port
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.1")
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.2")
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.3")
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.4")
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}

	// we should get a healthy host if the original host is unhealthy and a
	// healthy host is available
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.4")
	pool[1].setHealthy(false)
	h = ipHash.Select(pool, req, nil)
	if h != pool[2] {
		t.Error("Expected ip hash policy host to be the third host.")
	}

	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.2")
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	pool[1].setHealthy(true)

	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.3")
	pool[2].setHealthy(false)
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.4")
	h = ipHash.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected ip hash policy host to be the second host.")
	}

	// We should be able to resize the host pool and still be able to predict
	// where a req will be routed with the same IP's used above
	pool = UpstreamPool{
		{Host: new(Host), Dial: "0.0.0.2"},
		{Host: new(Host), Dial: "0.0.0.3"},
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.1:80")
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.2:80")
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.3:80")
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "172.0.0.4:80")
	h = ipHash.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected ip hash policy host to be the first host.")
	}

	// We should get nil when there are no healthy hosts
	pool[0].setHealthy(false)
	pool[1].setHealthy(false)
	h = ipHash.Select(pool, req, nil)
	if h != nil {
		t.Error("Expected ip hash policy host to be nil.")
	}

	// Reproduce #4135
	pool = UpstreamPool{
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
		{Host: new(Host)},
	}
	pool[0].setHealthy(false)
	pool[1].setHealthy(false)
	pool[2].setHealthy(false)
	pool[3].setHealthy(false)
	pool[4].setHealthy(false)
	pool[5].setHealthy(false)
	pool[6].setHealthy(false)
	pool[7].setHealthy(false)
	pool[8].setHealthy(true)

	// We should get a result back when there is one healthy host left.
	h = ipHash.Select(pool, req, nil)
	if h == nil {
		// If it is nil, it means we missed a host even though one is available
		t.Error("Expected ip hash policy host to not be nil, but it is nil.")
	}
}

func TestFirstPolicy(t *testing.T) {
	pool := testPool()
	firstPolicy := FirstSelection{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := firstPolicy.Select(pool, req, nil)
	if h != pool[0] {
		t.Error("Expected first policy host to be the first host.")
	}

	pool[0].setHealthy(false)
	h = firstPolicy.Select(pool, req, nil)
	if h != pool[1] {
		t.Error("Expected first policy host to be the second host.")
	}
}

func TestQueryHashPolicy(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	queryPolicy := QueryHashSelection{Key: "foo"}
	if err := queryPolicy.Provision(ctx); err != nil {
		t.Errorf("Provision error: %v", err)
		t.FailNow()
	}

	pool := testPool()

	request := httptest.NewRequest(http.MethodGet, "/?foo=1", nil)
	h := queryPolicy.Select(pool, request, nil)
	if h != pool[0] {
		t.Error("Expected query policy host to be the first host.")
	}

	request = httptest.NewRequest(http.MethodGet, "/?foo=100000", nil)
	h = queryPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected query policy host to be the second host.")
	}

	request = httptest.NewRequest(http.MethodGet, "/?foo=1", nil)
	pool[0].setHealthy(false)
	h = queryPolicy.Select(pool, request, nil)
	if h != pool[2] {
		t.Error("Expected query policy host to be the third host.")
	}

	request = httptest.NewRequest(http.MethodGet, "/?foo=100000", nil)
	h = queryPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected query policy host to be the second host.")
	}

	// We should be able to resize the host pool and still be able to predict
	// where a request will be routed with the same query used above
	pool = UpstreamPool{
		{Host: new(Host)},
		{Host: new(Host)},
	}

	request = httptest.NewRequest(http.MethodGet, "/?foo=1", nil)
	h = queryPolicy.Select(pool, request, nil)
	if h != pool[0] {
		t.Error("Expected query policy host to be the first host.")
	}

	pool[0].setHealthy(false)
	h = queryPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected query policy host to be the second host.")
	}

	request = httptest.NewRequest(http.MethodGet, "/?foo=4", nil)
	h = queryPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected query policy host to be the second host.")
	}

	pool[0].setHealthy(false)
	pool[1].setHealthy(false)
	h = queryPolicy.Select(pool, request, nil)
	if h != nil {
		t.Error("Expected query policy policy host to be nil.")
	}

	request = httptest.NewRequest(http.MethodGet, "/?foo=aa11&foo=bb22", nil)
	pool = testPool()
	h = queryPolicy.Select(pool, request, nil)
	if h != pool[0] {
		t.Error("Expected query policy host to be the first host.")
	}
}

func TestURIHashPolicy(t *testing.T) {
	pool := testPool()
	uriPolicy := URIHashSelection{}

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	h := uriPolicy.Select(pool, request, nil)
	if h != pool[2] {
		t.Error("Expected uri policy host to be the third host.")
	}

	pool[2].setHealthy(false)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[0] {
		t.Error("Expected uri policy host to be the first host.")
	}

	request = httptest.NewRequest(http.MethodGet, "/test_2", nil)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[0] {
		t.Error("Expected uri policy host to be the first host.")
	}

	// We should be able to resize the host pool and still be able to predict
	// where a request will be routed with the same URI's used above
	pool = UpstreamPool{
		{Host: new(Host)},
		{Host: new(Host)},
	}

	request = httptest.NewRequest(http.MethodGet, "/test", nil)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[0] {
		t.Error("Expected uri policy host to be the first host.")
	}

	pool[0].setHealthy(false)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected uri policy host to be the first host.")
	}

	request = httptest.NewRequest(http.MethodGet, "/test_2", nil)
	h = uriPolicy.Select(pool, request, nil)
	if h != pool[1] {
		t.Error("Expected uri policy host to be the second host.")
	}

	pool[0].setHealthy(false)
	pool[1].setHealthy(false)
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
	pool[0].setHealthy(true)
	pool[1].setHealthy(true)
	pool[2].setHealthy(true)
	pool[0].countRequest(10)
	pool[1].countRequest(20)
	pool[2].countRequest(30)

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
	pool[0].setHealthy(false)
	pool[1].setHealthy(true)
	pool[2].setHealthy(true)
	pool[0].countRequest(10)
	pool[1].countRequest(20)
	pool[2].countRequest(30)

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	randomChoicePolicy := RandomChoiceSelection{Choose: 2}

	h := randomChoicePolicy.Select(pool, request, nil)

	if h == nil {
		t.Error("RandomChoicePolicy should not return nil")
	}

	if h == pool[0] {
		t.Error("RandomChoicePolicy should not choose pool[0]")
	}
}

func TestCookieHashPolicy(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	cookieHashPolicy := CookieHashSelection{}
	if err := cookieHashPolicy.Provision(ctx); err != nil {
		t.Errorf("Provision error: %v", err)
		t.FailNow()
	}

	pool := testPool()
	pool[0].Dial = "localhost:8080"
	pool[1].Dial = "localhost:8081"
	pool[2].Dial = "localhost:8082"
	pool[0].setHealthy(true)
	pool[1].setHealthy(false)
	pool[2].setHealthy(false)
	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	h := cookieHashPolicy.Select(pool, request, w)
	cookieServer1 := w.Result().Cookies()[0]
	if cookieServer1 == nil {
		t.Fatal("cookieHashPolicy should set a cookie")
	}
	if cookieServer1.Name != "lb" {
		t.Error("cookieHashPolicy should set a cookie with name lb")
	}
	if cookieServer1.Secure {
		t.Error("cookieHashPolicy should set cookie Secure attribute to false when request is not secure")
	}
	if h != pool[0] {
		t.Error("Expected cookieHashPolicy host to be the first only available host.")
	}
	pool[1].setHealthy(true)
	pool[2].setHealthy(true)
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
	pool[0].setHealthy(false)
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

func TestCookieHashPolicyWithSecureRequest(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	cookieHashPolicy := CookieHashSelection{}
	if err := cookieHashPolicy.Provision(ctx); err != nil {
		t.Errorf("Provision error: %v", err)
		t.FailNow()
	}

	pool := testPool()
	pool[0].Dial = "localhost:8080"
	pool[1].Dial = "localhost:8081"
	pool[2].Dial = "localhost:8082"
	pool[0].setHealthy(true)
	pool[1].setHealthy(false)
	pool[2].setHealthy(false)

	// Create a test server that serves HTTPS requests
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := cookieHashPolicy.Select(pool, r, w)
		if h != pool[0] {
			t.Error("Expected cookieHashPolicy host to be the first only available host.")
		}
	}))
	defer ts.Close()

	// Make a new HTTPS request to the test server
	client := ts.Client()
	request, err := http.NewRequest(http.MethodGet, ts.URL+"/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	// Check if the cookie set is Secure and has SameSiteNone mode
	cookies := response.Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected a cookie to be set")
	}
	cookie := cookies[0]
	if !cookie.Secure {
		t.Error("Expected cookie Secure attribute to be true when request is secure")
	}
	if cookie.SameSite != http.SameSiteNoneMode {
		t.Error("Expected cookie SameSite attribute to be None when request is secure")
	}
}

func TestCookieHashPolicyWithFirstFallback(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	cookieHashPolicy := CookieHashSelection{
		FallbackRaw: caddyconfig.JSONModuleObject(FirstSelection{}, "policy", "first", nil),
	}
	if err := cookieHashPolicy.Provision(ctx); err != nil {
		t.Errorf("Provision error: %v", err)
		t.FailNow()
	}

	pool := testPool()
	pool[0].Dial = "localhost:8080"
	pool[1].Dial = "localhost:8081"
	pool[2].Dial = "localhost:8082"
	pool[0].setHealthy(true)
	pool[1].setHealthy(true)
	pool[2].setHealthy(true)
	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	h := cookieHashPolicy.Select(pool, request, w)
	cookieServer1 := w.Result().Cookies()[0]
	if cookieServer1 == nil {
		t.Fatal("cookieHashPolicy should set a cookie")
	}
	if cookieServer1.Name != "lb" {
		t.Error("cookieHashPolicy should set a cookie with name lb")
	}
	if h != pool[0] {
		t.Errorf("Expected cookieHashPolicy host to be the first only available host, got %s", h)
	}
	request = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	request.AddCookie(cookieServer1)
	h = cookieHashPolicy.Select(pool, request, w)
	if h != pool[0] {
		t.Errorf("Expected cookieHashPolicy host to stick to the first host (matching cookie), got %s", h)
	}
	s := w.Result().Cookies()
	if len(s) != 0 {
		t.Error("Expected cookieHashPolicy to not set a new cookie.")
	}
	pool[0].setHealthy(false)
	request = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	request.AddCookie(cookieServer1)
	h = cookieHashPolicy.Select(pool, request, w)
	if h != pool[1] {
		t.Errorf("Expected cookieHashPolicy to select the next first available host, got %s", h)
	}
	if w.Result().Cookies() == nil {
		t.Error("Expected cookieHashPolicy to set a new cookie.")
	}
}
