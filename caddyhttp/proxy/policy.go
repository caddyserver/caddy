// Copyright 2015 Light Code Labs, LLC
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

package proxy

import (
	"hash/fnv"
	"log"
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
	RegisterPolicy("random", func(arg string) Policy { return &Random{} })
	RegisterPolicy("least_conn", func(arg string) Policy { return &LeastConn{} })
	RegisterPolicy("round_robin", func(arg string) Policy { return &RoundRobin{} })
	RegisterPolicy("ip_hash", func(arg string) Policy { return &IPHash{} })
	RegisterPolicy("first", func(arg string) Policy { return &First{} })
	RegisterPolicy("uri_hash", func(arg string) Policy { return &URIHash{} })
	RegisterPolicy("header", func(arg string) Policy { return &Header{arg} })
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
// pool. If more than one host has the same least number of connections,
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

// RoundRobin is a policy that selects hosts based on round-robin ordering.
type RoundRobin struct {
	robin uint32
	mutex sync.Mutex
}

// Select selects an up host from the pool using a round-robin ordering scheme.
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

// hostByHashing returns an available host from pool based on a hashable string
func hostByHashing(pool HostPool, s string) *UpstreamHost {
	poolLen := uint32(len(pool))
	index := hash(s) % poolLen
	for i := uint32(0); i < poolLen; i++ {
		index += i
		host := pool[index%poolLen]
		if host.Available() {
			return host
		}
	}
	return nil
}

// hash calculates a hash based on string s
func hash(s string) uint32 {
	h := fnv.New32a()
	if _, err := h.Write([]byte(s)); err != nil {
		log.Println("[ERROR] failed to write bytes: ", err)
	}
	return h.Sum32()
}

// IPHash is a policy that selects hosts based on hashing the request IP
type IPHash struct{}

// Select selects an up host from the pool based on hashing the request IP
func (r *IPHash) Select(pool HostPool, request *http.Request) *UpstreamHost {
	clientIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		clientIP = request.RemoteAddr
	}
	return hostByHashing(pool, clientIP)
}

// URIHash is a policy that selects the host based on hashing the request URI
type URIHash struct{}

// Select selects the host based on hashing the URI
func (r *URIHash) Select(pool HostPool, request *http.Request) *UpstreamHost {
	return hostByHashing(pool, request.RequestURI)
}

// First is a policy that selects the first available host
type First struct{}

// Select selects the first available host from the pool
func (r *First) Select(pool HostPool, request *http.Request) *UpstreamHost {
	for _, host := range pool {
		if host.Available() {
			return host
		}
	}
	return nil
}

// Header is a policy that selects based on a hash of the given header
type Header struct {
	// The name of the request header, the value of which will determine
	// how the request is routed
	Name string
}

var roundRobinPolicier RoundRobin

// Select selects the host based on hashing the header value
func (r *Header) Select(pool HostPool, request *http.Request) *UpstreamHost {
	if r.Name == "" {
		return nil
	}
	val := request.Header.Get(r.Name)
	if val == "" {
		// fallback to RoundRobin policy in case no Header in request
		return roundRobinPolicier.Select(pool, request)
	}
	return hostByHashing(pool, val)
}
