package proxy

import (
	"hash/fnv"
	"math"
	"math/rand"
	"net"
	"net/http"
	"sync"
)

// HostPool is a collection of UpstreamHosts.
type HostPool []*UpstreamHost

// Policy decides how a host will be selected from a pool.
type Policy interface {
	Select(pool HostPool, r *http.Request) *UpstreamHost
}

func init() {
	RegisterPolicy("random", func() Policy { return &Random{} })
	RegisterPolicy("least_conn", func() Policy { return &LeastConn{} })
	RegisterPolicy("round_robin", func() Policy { return &RoundRobin{} })
	RegisterPolicy("ip_hash", func() Policy { return &IPHash{} })
	RegisterPolicy("first", func() Policy { return &First{} })
}

// Random is a policy that selects up hosts from a pool at random.
type Random struct{}

// Select selects an up host at random from the specified pool.
func (r *Random) Select(pool HostPool, request *http.Request) *UpstreamHost {

	// Because the number of available hosts isn't known
	// up front, the host is selected via reservoir sampling
	// https://en.wikipedia.org/wiki/Reservoir_sampling
	var randHost *UpstreamHost
	count := 0
	for _, host := range pool {
		if !host.Available() {
			continue
		}

		// (n % 1 == 0) holds for all n, therefore randHost
		// will always get assigned a value if there is
		// at least 1 available host
		count++
		if (rand.Int() % count) == 0 {
			randHost = host
		}
	}
	return randHost
}

// LeastConn is a policy that selects the host with the least connections.
type LeastConn struct{}

// Select selects the up host with the least number of connections in the
// pool.  If more than one host has the same least number of connections,
// one of the hosts is chosen at random.
func (r *LeastConn) Select(pool HostPool, request *http.Request) *UpstreamHost {
	var bestHost *UpstreamHost
	count := 0
	leastConn := int64(math.MaxInt64)
	for _, host := range pool {
		if !host.Available() {
			continue
		}

		if host.Conns < leastConn {
			leastConn = host.Conns
			count = 0
		}

		// Among hosts with same least connections, perform a reservoir
		// sample: https://en.wikipedia.org/wiki/Reservoir_sampling
		if host.Conns == leastConn {
			count++
			if (rand.Int() % count) == 0 {
				bestHost = host
			}
		}
	}
	return bestHost
}

// RoundRobin is a policy that selects hosts based on round robin ordering.
type RoundRobin struct {
	robin uint32
	mutex sync.Mutex
}

// Select selects an up host from the pool using a round robin ordering scheme.
func (r *RoundRobin) Select(pool HostPool, request *http.Request) *UpstreamHost {
	poolLen := uint32(len(pool))
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// Return next available host
	for i := uint32(0); i < poolLen; i++ {
		r.robin++
		host := pool[r.robin%poolLen]
		if host.Available() {
			return host
		}
	}
	return nil
}

// IPHash is a policy that selects hosts based on hashing the request ip
type IPHash struct{}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// Select selects an up host from the pool using a round robin ordering scheme.
func (r *IPHash) Select(pool HostPool, request *http.Request) *UpstreamHost {
	poolLen := uint32(len(pool))
	clientIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		clientIP = request.RemoteAddr
	}
	index := hash(clientIP) % poolLen
	for i := uint32(0); i < poolLen; i++ {
		index += i
		host := pool[index%poolLen]
		if host.Available() {
			return host
		}
	}
	return nil
}

// First is a policy that selects the fist available host
type First struct{}

// Select selects the first host from the pool, that is available
func (r *First) Select(pool HostPool, request *http.Request) *UpstreamHost {
	for _, host := range pool {
		if host.Available() {
			return host
		}
	}
	return nil
}
