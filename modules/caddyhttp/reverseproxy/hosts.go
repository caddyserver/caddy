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
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// UpstreamPool is a collection of upstreams.
type UpstreamPool []*Upstream

// Upstream bridges this proxy's configuration to the
// state of the backend host it is correlated with.
type Upstream struct {
	*Host `json:"-"`

	// The [network address](/docs/conventions#network-addresses)
	// to dial to connect to the upstream. Must represent precisely
	// one socket (i.e. no port ranges). A valid network address
	// either has a host and port or is a unix socket address.
	//
	// Placeholders may be used to make the upstream dynamic, but be
	// aware of the health check implications of this: a single
	// upstream that represents numerous (perhaps arbitrary) backends
	// can be considered down if one or enough of the arbitrary
	// backends is down. Also be aware of open proxy vulnerabilities.
	Dial string `json:"dial,omitempty"`

	// If DNS SRV records are used for service discovery with this
	// upstream, specify the DNS name for which to look up SRV
	// records here, instead of specifying a dial address.
	LookupSRV string `json:"lookup_srv,omitempty"`

	// The maximum number of simultaneous requests to allow to
	// this upstream. If set, overrides the global passive health
	// check UnhealthyRequestCount value.
	MaxRequests int `json:"max_requests,omitempty"`

	// TODO: This could be really useful, to bind requests
	// with certain properties to specific backends
	// HeaderAffinity string
	// IPAffinity     string

	activeHealthCheckPort int
	healthCheckPolicy     *PassiveHealthChecks
	cb                    CircuitBreaker
}

func (u Upstream) String() string {
	if u.LookupSRV != "" {
		return u.LookupSRV
	}
	return u.Dial
}

// Available returns true if the remote host
// is available to receive requests. This is
// the method that should be used by selection
// policies, etc. to determine if a backend
// should be able to be sent a request.
func (u *Upstream) Available() bool {
	return u.Healthy() && !u.Full()
}

// Healthy returns true if the remote host
// is currently known to be healthy or "up".
// It consults the circuit breaker, if any.
func (u *Upstream) Healthy() bool {
	healthy := !u.Host.Unhealthy()
	if healthy && u.healthCheckPolicy != nil {
		healthy = u.Host.Fails() < u.healthCheckPolicy.MaxFails
	}
	if healthy && u.cb != nil {
		healthy = u.cb.OK()
	}
	return healthy
}

// Full returns true if the remote host
// cannot receive more requests at this time.
func (u *Upstream) Full() bool {
	return u.MaxRequests > 0 && u.Host.NumRequests() >= u.MaxRequests
}

// fillDialInfo returns a filled DialInfo for upstream u, using the request
// context. If the upstream has a SRV lookup configured, that is done and a
// returned address is chosen; otherwise, the upstream's regular dial address
// field is used. Note that the returned value is not a pointer.
func (u *Upstream) fillDialInfo(r *http.Request) (DialInfo, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	var addr caddy.NetworkAddress

	if u.LookupSRV != "" {
		// perform DNS lookup for SRV records and choose one
		srvName := repl.ReplaceAll(u.LookupSRV, "")
		_, records, err := net.DefaultResolver.LookupSRV(r.Context(), "", "", srvName)
		if err != nil {
			return DialInfo{}, err
		}
		addr.Network = "tcp"
		addr.Host = records[0].Target
		addr.StartPort, addr.EndPort = uint(records[0].Port), uint(records[0].Port)
	} else {
		// use provided dial address
		var err error
		dial := repl.ReplaceAll(u.Dial, "")
		addr, err = caddy.ParseNetworkAddress(dial)
		if err != nil {
			return DialInfo{}, fmt.Errorf("upstream %s: invalid dial address %s: %v", u.Dial, dial, err)
		}
		if numPorts := addr.PortRangeSize(); numPorts != 1 {
			return DialInfo{}, fmt.Errorf("upstream %s: dial address must represent precisely one socket: %s represents %d",
				u.Dial, dial, numPorts)
		}
	}

	return DialInfo{
		Upstream: u,
		Network:  addr.Network,
		Address:  addr.JoinHostPort(0),
		Host:     addr.Host,
		Port:     strconv.Itoa(int(addr.StartPort)),
	}, nil
}

func (u *Upstream) fillHost() {
	host := new(Host)
	existingHost, loaded := hosts.LoadOrStore(u.String(), host)
	if loaded {
		host = existingHost.(*Host)
	}
	u.Host = host
}

// Host is the basic, in-memory representation
// of the state of a remote host.
type Host struct {
	numRequests int64 // must be 64-bit aligned on 32-bit systems (see https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	fails       int64
	unhealthy   int32
}

// NumRequests returns the number of active requests to the upstream.
func (h *Host) NumRequests() int {
	return int(atomic.LoadInt64(&h.numRequests))
}

// Fails returns the number of recent failures with the upstream.
func (h *Host) Fails() int {
	return int(atomic.LoadInt64(&h.fails))
}

// Unhealthy returns whether the upstream is healthy.
func (h *Host) Unhealthy() bool {
	return atomic.LoadInt32(&h.unhealthy) == 1
}

// CountRequest mutates the active request count by
// delta. It returns an error if the adjustment fails.
func (h *Host) CountRequest(delta int) error {
	result := atomic.AddInt64(&h.numRequests, int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// CountFail mutates the recent failures count by
// delta. It returns an error if the adjustment fails.
func (h *Host) CountFail(delta int) error {
	result := atomic.AddInt64(&h.fails, int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// SetHealthy sets the upstream has healthy or unhealthy
// and returns true if the new value is different.
func (h *Host) SetHealthy(healthy bool) (bool, error) {
	var unhealthy, compare int32 = 1, 0
	if healthy {
		unhealthy, compare = 0, 1
	}
	swapped := atomic.CompareAndSwapInt32(&h.unhealthy, compare, unhealthy)
	return swapped, nil
}

// DialInfo contains information needed to dial a
// connection to an upstream host. This information
// may be different than that which is represented
// in a URL (for example, unix sockets don't have
// a host that can be represented in a URL, but
// they certainly have a network name and address).
type DialInfo struct {
	// Upstream is the Upstream associated with
	// this DialInfo. It may be nil.
	Upstream *Upstream

	// The network to use. This should be one of
	// the values that is accepted by net.Dial:
	// https://golang.org/pkg/net/#Dial
	Network string

	// The address to dial. Follows the same
	// semantics and rules as net.Dial.
	Address string

	// Host and Port are components of Address.
	Host, Port string
}

// String returns the Caddy network address form
// by joining the network and address with a
// forward slash.
func (di DialInfo) String() string {
	return caddy.JoinNetworkAddress(di.Network, di.Host, di.Port)
}

// GetDialInfo gets the upstream dialing info out of the context,
// and returns true if there was a valid value; false otherwise.
func GetDialInfo(ctx context.Context) (DialInfo, bool) {
	dialInfo, ok := caddyhttp.GetVar(ctx, dialInfoVarKey).(DialInfo)
	return dialInfo, ok
}

// hosts is the global repository for hosts that are
// currently in use by active configuration(s). This
// allows the state of remote hosts to be preserved
// through config reloads.
var hosts = caddy.NewUsagePool()

// dialInfoVarKey is the key used for the variable that holds
// the dial info for the upstream connection.
const dialInfoVarKey = "reverse_proxy.dial_info"
