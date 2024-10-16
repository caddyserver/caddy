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
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// UpstreamPool is a collection of upstreams.
type UpstreamPool []*Upstream

// Upstream bridges this proxy's configuration to the
// state of the backend host it is correlated with.
// Upstream values must not be copied.
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

	// The maximum number of simultaneous requests to allow to
	// this upstream. If set, overrides the global passive health
	// check UnhealthyRequestCount value.
	MaxRequests int `json:"max_requests,omitempty"`

	// TODO: This could be really useful, to bind requests
	// with certain properties to specific backends
	// HeaderAffinity string
	// IPAffinity     string

	activeHealthCheckPort     int
	activeHealthCheckUpstream string
	healthCheckPolicy         *PassiveHealthChecks
	cb                        CircuitBreaker
	unhealthy                 int32 // accessed atomically; status from active health checker
}

// (pointer receiver necessary to avoid a race condition, since
// copying the Upstream reads the 'unhealthy' field which is
// accessed atomically)
func (u *Upstream) String() string { return u.Dial }

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
	healthy := u.healthy()
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
// context. Note that the returned value is not a pointer.
func (u *Upstream) fillDialInfo(r *http.Request) (DialInfo, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	var addr caddy.NetworkAddress

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

// Host is the basic, in-memory representation of the state of a remote host.
// Its fields are accessed atomically and Host values must not be copied.
type Host struct {
	numRequests  int64 // must be 64-bit aligned on 32-bit systems (see https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	fails        int64
	activePasses int64
	activeFails  int64
}

// NumRequests returns the number of active requests to the upstream.
func (h *Host) NumRequests() int {
	return int(atomic.LoadInt64(&h.numRequests))
}

// Fails returns the number of recent failures with the upstream.
func (h *Host) Fails() int {
	return int(atomic.LoadInt64(&h.fails))
}

// activeHealthPasses returns the number of consecutive active health check passes with the upstream.
func (h *Host) activeHealthPasses() int {
	return int(atomic.LoadInt64(&h.activePasses))
}

// activeHealthFails returns the number of consecutive active health check failures with the upstream.
func (h *Host) activeHealthFails() int {
	return int(atomic.LoadInt64(&h.activeFails))
}

// countRequest mutates the active request count by
// delta. It returns an error if the adjustment fails.
func (h *Host) countRequest(delta int) error {
	result := atomic.AddInt64(&h.numRequests, int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// countFail mutates the recent failures count by
// delta. It returns an error if the adjustment fails.
func (h *Host) countFail(delta int) error {
	result := atomic.AddInt64(&h.fails, int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// countHealthPass mutates the recent passes count by
// delta. It returns an error if the adjustment fails.
func (h *Host) countHealthPass(delta int) error {
	result := atomic.AddInt64(&h.activePasses, int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// countHealthFail mutates the recent failures count by
// delta. It returns an error if the adjustment fails.
func (h *Host) countHealthFail(delta int) error {
	result := atomic.AddInt64(&h.activeFails, int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

// resetHealth resets the health check counters.
func (h *Host) resetHealth() {
	atomic.StoreInt64(&h.activePasses, 0)
	atomic.StoreInt64(&h.activeFails, 0)
}

// healthy returns true if the upstream is not actively marked as unhealthy.
// (This returns the status only from the "active" health checks.)
func (u *Upstream) healthy() bool {
	return atomic.LoadInt32(&u.unhealthy) == 0
}

// SetHealthy sets the upstream has healthy or unhealthy
// and returns true if the new value is different. This
// sets the status only for the "active" health checks.
func (u *Upstream) setHealthy(healthy bool) bool {
	var unhealthy, compare int32 = 1, 0
	if healthy {
		unhealthy, compare = 0, 1
	}
	return atomic.CompareAndSwapInt32(&u.unhealthy, compare, unhealthy)
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

// proxyProtocolInfoVarKey is the key used for the variable that holds
// the proxy protocol info for the upstream connection.
const proxyProtocolInfoVarKey = "reverse_proxy.proxy_protocol_info"

// ProxyProtocolInfo contains information needed to write proxy protocol to a
// connection to an upstream host.
type ProxyProtocolInfo struct {
	AddrPort netip.AddrPort
}
