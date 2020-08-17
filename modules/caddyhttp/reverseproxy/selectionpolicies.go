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
	"fmt"
	"hash/fnv"
	weakrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(RandomSelection{})
	caddy.RegisterModule(RandomChoiceSelection{})
	caddy.RegisterModule(LeastConnSelection{})
	caddy.RegisterModule(RoundRobinSelection{})
	caddy.RegisterModule(FirstSelection{})
	caddy.RegisterModule(IPHashSelection{})
	caddy.RegisterModule(URIHashSelection{})
	caddy.RegisterModule(HeaderHashSelection{})

	weakrand.Seed(time.Now().UTC().UnixNano())
}

// RandomSelection is a policy that selects
// an available host at random.
type RandomSelection struct{}

// CaddyModule returns the Caddy module information.
func (RandomSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.random",
		New: func() caddy.Module { return new(RandomSelection) },
	}
}

// Select returns an available host, if any.
func (r RandomSelection) Select(pool UpstreamPool, request *http.Request) *Upstream {
	// use reservoir sampling because the number of available
	// hosts isn't known: https://en.wikipedia.org/wiki/Reservoir_sampling
	var randomHost *Upstream
	var count int
	for _, upstream := range pool {
		if !upstream.Available() {
			continue
		}
		// (n % 1 == 0) holds for all n, therefore a
		// upstream will always be chosen if there is at
		// least one available
		count++
		if (weakrand.Int() % count) == 0 {
			randomHost = upstream
		}
	}
	return randomHost
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (r *RandomSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// RandomChoiceSelection is a policy that selects
// two or more available hosts at random, then
// chooses the one with the least load.
type RandomChoiceSelection struct {
	// The size of the sub-pool created from the larger upstream pool. The default value
	// is 2 and the maximum at selection time is the size of the upstream pool.
	Choose int `json:"choose,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (RandomChoiceSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.random_choose",
		New: func() caddy.Module { return new(RandomChoiceSelection) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (r *RandomChoiceSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		chooseStr := d.Val()
		choose, err := strconv.Atoi(chooseStr)
		if err != nil {
			return d.Errf("invalid choice value '%s': %v", chooseStr, err)
		}
		r.Choose = choose
	}
	return nil
}

// Provision sets up r.
func (r *RandomChoiceSelection) Provision(ctx caddy.Context) error {
	if r.Choose == 0 {
		r.Choose = 2
	}
	return nil
}

// Validate ensures that r's configuration is valid.
func (r RandomChoiceSelection) Validate() error {
	if r.Choose < 2 {
		return fmt.Errorf("choose must be at least 2")
	}
	return nil
}

// Select returns an available host, if any.
func (r RandomChoiceSelection) Select(pool UpstreamPool, _ *http.Request) *Upstream {
	k := r.Choose
	if k > len(pool) {
		k = len(pool)
	}
	choices := make([]*Upstream, k)
	for i, upstream := range pool {
		if !upstream.Available() {
			continue
		}
		j := weakrand.Intn(i + 1)
		if j < k {
			choices[j] = upstream
		}
	}
	return leastRequests(choices)
}

// LeastConnSelection is a policy that selects the
// host with the least active requests. If multiple
// hosts have the same fewest number, one is chosen
// randomly. The term "conn" or "connection" is used
// in this policy name due to its similar meaning in
// other software, but our load balancer actually
// counts active requests rather than connections,
// since these days requests are multiplexed onto
// shared connections.
type LeastConnSelection struct{}

// CaddyModule returns the Caddy module information.
func (LeastConnSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.least_conn",
		New: func() caddy.Module { return new(LeastConnSelection) },
	}
}

// Select selects the up host with the least number of connections in the
// pool. If more than one host has the same least number of connections,
// one of the hosts is chosen at random.
func (LeastConnSelection) Select(pool UpstreamPool, _ *http.Request) *Upstream {
	var bestHost *Upstream
	var count int
	leastReqs := -1

	for _, host := range pool {
		if !host.Available() {
			continue
		}
		numReqs := host.NumRequests()
		if leastReqs == -1 || numReqs < leastReqs {
			leastReqs = numReqs
			count = 0
		}

		// among hosts with same least connections, perform a reservoir
		// sample: https://en.wikipedia.org/wiki/Reservoir_sampling
		if numReqs == leastReqs {
			count++
			if (weakrand.Int() % count) == 0 {
				bestHost = host
			}
		}
	}

	return bestHost
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (r *LeastConnSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// RoundRobinSelection is a policy that selects
// a host based on round-robin ordering.
type RoundRobinSelection struct {
	robin uint32
}

// CaddyModule returns the Caddy module information.
func (RoundRobinSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.round_robin",
		New: func() caddy.Module { return new(RoundRobinSelection) },
	}
}

// Select returns an available host, if any.
func (r *RoundRobinSelection) Select(pool UpstreamPool, _ *http.Request) *Upstream {
	n := uint32(len(pool))
	if n == 0 {
		return nil
	}
	for i := uint32(0); i < n; i++ {
		atomic.AddUint32(&r.robin, 1)
		host := pool[r.robin%n]
		if host.Available() {
			return host
		}
	}
	return nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (r *RoundRobinSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// FirstSelection is a policy that selects
// the first available host.
type FirstSelection struct{}

// CaddyModule returns the Caddy module information.
func (FirstSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.first",
		New: func() caddy.Module { return new(FirstSelection) },
	}
}

// Select returns an available host, if any.
func (FirstSelection) Select(pool UpstreamPool, _ *http.Request) *Upstream {
	for _, host := range pool {
		if host.Available() {
			return host
		}
	}
	return nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (r *FirstSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// IPHashSelection is a policy that selects a host
// based on hashing the remote IP of the request.
type IPHashSelection struct{}

// CaddyModule returns the Caddy module information.
func (IPHashSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.ip_hash",
		New: func() caddy.Module { return new(IPHashSelection) },
	}
}

// Select returns an available host, if any.
func (IPHashSelection) Select(pool UpstreamPool, req *http.Request) *Upstream {
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		clientIP = req.RemoteAddr
	}
	return hostByHashing(pool, clientIP)
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (r *IPHashSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// URIHashSelection is a policy that selects a
// host by hashing the request URI.
type URIHashSelection struct{}

// CaddyModule returns the Caddy module information.
func (URIHashSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.uri_hash",
		New: func() caddy.Module { return new(URIHashSelection) },
	}
}

// Select returns an available host, if any.
func (URIHashSelection) Select(pool UpstreamPool, req *http.Request) *Upstream {
	return hostByHashing(pool, req.RequestURI)
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (r *URIHashSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// HeaderHashSelection is a policy that selects
// a host based on a given request header.
type HeaderHashSelection struct {
	// The HTTP header field whose value is to be hashed and used for upstream selection.
	Field string `json:"field,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (HeaderHashSelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.header",
		New: func() caddy.Module { return new(HeaderHashSelection) },
	}
}

// Select returns an available host, if any.
func (s HeaderHashSelection) Select(pool UpstreamPool, req *http.Request) *Upstream {
	if s.Field == "" {
		return nil
	}

	// The Host header should be obtained from the req.Host field
	// since net/http removes it from the header map.
	if s.Field == "Host" && req.Host != "" {
		return hostByHashing(pool, req.Host)
	}

	val := req.Header.Get(s.Field)
	if val == "" {
		return RandomSelection{}.Select(pool, req)
	}
	return hostByHashing(pool, val)
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (s *HeaderHashSelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		s.Field = d.Val()
	}
	return nil
}

// leastRequests returns the host with the
// least number of active requests to it.
// If more than one host has the same
// least number of active requests, then
// one of those is chosen at random.
func leastRequests(upstreams []*Upstream) *Upstream {
	if len(upstreams) == 0 {
		return nil
	}
	var best []*Upstream
	var bestReqs int
	for _, upstream := range upstreams {
		reqs := upstream.NumRequests()
		if reqs == 0 {
			return upstream
		}
		if reqs <= bestReqs {
			bestReqs = reqs
			best = append(best, upstream)
		}
	}
	if len(best) == 0 {
		return nil
	}
	return best[weakrand.Intn(len(best))]
}

// hostByHashing returns an available host
// from pool based on a hashable string s.
func hostByHashing(pool []*Upstream, s string) *Upstream {
	poolLen := uint32(len(pool))
	if poolLen == 0 {
		return nil
	}
	index := hash(s) % poolLen
	for i := uint32(0); i < poolLen; i++ {
		index += i
		upstream := pool[index%poolLen]
		if upstream.Available() {
			return upstream
		}
	}
	return nil
}

// hash calculates a fast hash based on s.
func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// Interface guards
var (
	_ Selector = (*RandomSelection)(nil)
	_ Selector = (*RandomChoiceSelection)(nil)
	_ Selector = (*LeastConnSelection)(nil)
	_ Selector = (*RoundRobinSelection)(nil)
	_ Selector = (*FirstSelection)(nil)
	_ Selector = (*IPHashSelection)(nil)
	_ Selector = (*URIHashSelection)(nil)
	_ Selector = (*HeaderHashSelection)(nil)

	_ caddy.Validator   = (*RandomChoiceSelection)(nil)
	_ caddy.Provisioner = (*RandomChoiceSelection)(nil)

	_ caddyfile.Unmarshaler = (*RandomChoiceSelection)(nil)
)
