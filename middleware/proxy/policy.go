package proxy

import (
	"math/rand"
	"sync/atomic"
)

// HostPool is a collection of UpstreamHosts.
type HostPool []*UpstreamHost

// Policy decides how a host will be selected from a pool.
type Policy interface {
	Select(pool HostPool) *UpstreamHost
}

func init() {
	RegisterPolicy("random", func() Policy { return &Random{} })
	RegisterPolicy("least_conn", func() Policy { return &LeastConn{} })
	RegisterPolicy("round_robin", func() Policy { return &RoundRobin{} })
}

// Random is a policy that selects up hosts from a pool at random.
type Random struct{}

// Select selects an up host at random from the specified pool.
func (r *Random) Select(pool HostPool) *UpstreamHost {
	// instead of just generating a random index
	// this is done to prevent selecting a down host
	var randHost *UpstreamHost
	count := 0
	for _, host := range pool {
		if host.Down() {
			continue
		}
		count++
		if count == 1 {
			randHost = host
		} else {
			r := rand.Int() % count
			if r == (count - 1) {
				randHost = host
			}
		}
	}
	return randHost
}

// LeastConn is a policy that selects the host with the least connections.
type LeastConn struct{}

// Select selects the up host with the least number of connections in the
// pool.  If more than one host has the same least number of connections,
// one of the hosts is chosen at random.
func (r *LeastConn) Select(pool HostPool) *UpstreamHost {
	var bestHost *UpstreamHost
	count := 0
	leastConn := int64(1<<63 - 1)
	for _, host := range pool {
		if host.Down() {
			continue
		}
		hostConns := host.Conns
		if hostConns < leastConn {
			bestHost = host
			leastConn = hostConns
			count = 1
		} else if hostConns == leastConn {
			// randomly select host among hosts with least connections
			count++
			if count == 1 {
				bestHost = host
			} else {
				r := rand.Int() % count
				if r == (count - 1) {
					bestHost = host
				}
			}
		}
	}
	return bestHost
}

// RoundRobin is a policy that selects hosts based on round robin ordering.
type RoundRobin struct {
	Robin uint32
}

// Select selects an up host from the pool using a round robin ordering scheme.
func (r *RoundRobin) Select(pool HostPool) *UpstreamHost {
	poolLen := uint32(len(pool))
	selection := atomic.AddUint32(&r.Robin, 1) % poolLen
	host := pool[selection]
	// if the currently selected host is down, just ffwd to up host
	for i := uint32(1); host.Down() && i < poolLen; i++ {
		host = pool[(selection+i)%poolLen]
	}
	if host.Down() {
		return nil
	}
	return host
}
