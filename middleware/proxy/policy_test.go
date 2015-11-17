package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

var workableServer *httptest.Server

func TestMain(m *testing.M) {
	workableServer = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// do nothing
		}))
	r := m.Run()
	workableServer.Close()
	os.Exit(r)
}

type customPolicy struct{}

func (r *customPolicy) Select(pool HostPool) *UpstreamHost {
	return pool[0]
}

func testPool() HostPool {
	pool := []*UpstreamHost{
		{
			Name: workableServer.URL, // this should resolve (healthcheck test)
		},
		{
			Name: "http://shouldnot.resolve", // this shouldn't
		},
		{
			Name: "http://C",
		},
	}
	return HostPool(pool)
}

func TestRoundRobinPolicy(t *testing.T) {
	pool := testPool()
	rrPolicy := &RoundRobin{}
	h := rrPolicy.Select(pool)
	// First selected host is 1, because counter starts at 0
	// and increments before host is selected
	if h != pool[1] {
		t.Error("Expected first round robin host to be second host in the pool.")
	}
	h = rrPolicy.Select(pool)
	if h != pool[2] {
		t.Error("Expected second round robin host to be third host in the pool.")
	}
	// mark host as down
	pool[0].Unhealthy = true
	h = rrPolicy.Select(pool)
	if h != pool[1] {
		t.Error("Expected third round robin host to be first host in the pool.")
	}
}

func TestLeastConnPolicy(t *testing.T) {
	pool := testPool()
	lcPolicy := &LeastConn{}
	pool[0].Conns = 10
	pool[1].Conns = 10
	h := lcPolicy.Select(pool)
	if h != pool[2] {
		t.Error("Expected least connection host to be third host.")
	}
	pool[2].Conns = 100
	h = lcPolicy.Select(pool)
	if h != pool[0] && h != pool[1] {
		t.Error("Expected least connection host to be first or second host.")
	}
}

func TestCustomPolicy(t *testing.T) {
	pool := testPool()
	customPolicy := &customPolicy{}
	h := customPolicy.Select(pool)
	if h != pool[0] {
		t.Error("Expected custom policy host to be the first host.")
	}
}
