package reverseproxy

import (
	"context"
	"encoding/json"
	"fmt"
	weakrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(SRVUpstreams{})
	caddy.RegisterModule(AUpstreams{})
	caddy.RegisterModule(MultiUpstreams{})
}

// SRVUpstreams provides upstreams from SRV lookups.
// The lookup DNS name can be configured either by
// its individual parts (that is, specifying the
// service, protocol, and name separately) to form
// the standard "_service._proto.name" domain, or
// the domain can be specified directly in name by
// leaving service and proto empty. See RFC 2782.
//
// Lookups are cached and refreshed at the configured
// refresh interval.
//
// Returned upstreams are sorted by priority and weight.
type SRVUpstreams struct {
	// The service label.
	Service string `json:"service,omitempty"`

	// The protocol label; either tcp or udp.
	Proto string `json:"proto,omitempty"`

	// The name label; or, if service and proto are
	// empty, the entire domain name to look up.
	Name string `json:"name,omitempty"`

	// The interval at which to refresh the SRV lookup.
	// Results are cached between lookups. Default: 1m
	Refresh caddy.Duration `json:"refresh,omitempty"`

	// If > 0 and there is an error with the lookup,
	// continue to use the cached results for up to
	// this long before trying again, (even though they
	// are stale) instead of returning an error to the
	// client. Default: 0s.
	GracePeriod caddy.Duration `json:"grace_period,omitempty"`

	// Configures the DNS resolver used to resolve the
	// SRV address to SRV records.
	Resolver *UpstreamResolver `json:"resolver,omitempty"`

	// If Resolver is configured, how long to wait before
	// timing out trying to connect to the DNS server.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// If Resolver is configured, how long to wait before
	// spawning an RFC 6555 Fast Fallback connection.
	// A negative value disables this.
	FallbackDelay caddy.Duration `json:"dial_fallback_delay,omitempty"`

	resolver *net.Resolver

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SRVUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.upstreams.srv",
		New: func() caddy.Module { return new(SRVUpstreams) },
	}
}

func (su *SRVUpstreams) Provision(ctx caddy.Context) error {
	su.logger = ctx.Logger()
	if su.Refresh == 0 {
		su.Refresh = caddy.Duration(time.Minute)
	}

	if su.Resolver != nil {
		err := su.Resolver.ParseAddresses()
		if err != nil {
			return err
		}
		d := &net.Dialer{
			Timeout:       time.Duration(su.DialTimeout),
			FallbackDelay: time.Duration(su.FallbackDelay),
		}
		su.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				//nolint:gosec
				addr := su.Resolver.netAddrs[weakrand.Intn(len(su.Resolver.netAddrs))]
				return d.DialContext(ctx, addr.Network, addr.JoinHostPort(0))
			},
		}
	}
	if su.resolver == nil {
		su.resolver = net.DefaultResolver
	}

	return nil
}

func (su SRVUpstreams) GetUpstreams(r *http.Request) ([]*Upstream, error) {
	suAddr, service, proto, name := su.expandedAddr(r)

	// first, use a cheap read-lock to return a cached result quickly
	srvsMu.RLock()
	cached := srvs[suAddr]
	srvsMu.RUnlock()
	if cached.isFresh() {
		return allNew(cached.upstreams), nil
	}

	// otherwise, obtain a write-lock to update the cached value
	srvsMu.Lock()
	defer srvsMu.Unlock()

	// check to see if it's still stale, since we're now in a different
	// lock from when we first checked freshness; another goroutine might
	// have refreshed it in the meantime before we re-obtained our lock
	cached = srvs[suAddr]
	if cached.isFresh() {
		return allNew(cached.upstreams), nil
	}

	if c := su.logger.Check(zapcore.DebugLevel, "refreshing SRV upstreams"); c != nil {
		c.Write(
			zap.String("service", service),
			zap.String("proto", proto),
			zap.String("name", name),
		)
	}

	_, records, err := su.resolver.LookupSRV(r.Context(), service, proto, name)
	if err != nil {
		// From LookupSRV docs: "If the response contains invalid names, those records are filtered
		// out and an error will be returned alongside the remaining results, if any." Thus, we
		// only return an error if no records were also returned.
		if len(records) == 0 {
			if su.GracePeriod > 0 {
				if c := su.logger.Check(zapcore.ErrorLevel, "SRV lookup failed; using previously cached"); c != nil {
					c.Write(zap.Error(err))
				}
				cached.freshness = time.Now().Add(time.Duration(su.GracePeriod) - time.Duration(su.Refresh))
				srvs[suAddr] = cached
				return allNew(cached.upstreams), nil
			}
			return nil, err
		}
		if c := su.logger.Check(zapcore.WarnLevel, "SRV records filtered"); c != nil {
			c.Write(zap.Error(err))
		}
	}

	upstreams := make([]Upstream, len(records))
	for i, rec := range records {
		if c := su.logger.Check(zapcore.DebugLevel, "discovered SRV record"); c != nil {
			c.Write(
				zap.String("target", rec.Target),
				zap.Uint16("port", rec.Port),
				zap.Uint16("priority", rec.Priority),
				zap.Uint16("weight", rec.Weight),
			)
		}
		addr := net.JoinHostPort(rec.Target, strconv.Itoa(int(rec.Port)))
		upstreams[i] = Upstream{Dial: addr}
	}

	// before adding a new one to the cache (as opposed to replacing stale one), make room if cache is full
	if cached.freshness.IsZero() && len(srvs) >= 100 {
		for randomKey := range srvs {
			delete(srvs, randomKey)
			break
		}
	}

	srvs[suAddr] = srvLookup{
		srvUpstreams: su,
		freshness:    time.Now(),
		upstreams:    upstreams,
	}

	return allNew(upstreams), nil
}

func (su SRVUpstreams) String() string {
	if su.Service == "" && su.Proto == "" {
		return su.Name
	}
	return su.formattedAddr(su.Service, su.Proto, su.Name)
}

// expandedAddr expands placeholders in the configured SRV domain labels.
// The return values are: addr, the RFC 2782 representation of the SRV domain;
// service, the service; proto, the protocol; and name, the name.
// If su.Service and su.Proto are empty, name will be returned as addr instead.
func (su SRVUpstreams) expandedAddr(r *http.Request) (addr, service, proto, name string) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	name = repl.ReplaceAll(su.Name, "")
	if su.Service == "" && su.Proto == "" {
		addr = name
		return
	}
	service = repl.ReplaceAll(su.Service, "")
	proto = repl.ReplaceAll(su.Proto, "")
	addr = su.formattedAddr(service, proto, name)
	return
}

// formattedAddr the RFC 2782 representation of the SRV domain, in
// the form "_service._proto.name".
func (SRVUpstreams) formattedAddr(service, proto, name string) string {
	return fmt.Sprintf("_%s._%s.%s", service, proto, name)
}

type srvLookup struct {
	srvUpstreams SRVUpstreams
	freshness    time.Time
	upstreams    []Upstream
}

func (sl srvLookup) isFresh() bool {
	return time.Since(sl.freshness) < time.Duration(sl.srvUpstreams.Refresh)
}

type IPVersions struct {
	IPv4 *bool `json:"ipv4,omitempty"`
	IPv6 *bool `json:"ipv6,omitempty"`
}

func resolveIpVersion(versions *IPVersions) string {
	resolveIpv4 := versions == nil || (versions.IPv4 == nil && versions.IPv6 == nil) || (versions.IPv4 != nil && *versions.IPv4)
	resolveIpv6 := versions == nil || (versions.IPv6 == nil && versions.IPv4 == nil) || (versions.IPv6 != nil && *versions.IPv6)
	switch {
	case resolveIpv4 && !resolveIpv6:
		return "ip4"
	case !resolveIpv4 && resolveIpv6:
		return "ip6"
	default:
		return "ip"
	}
}

// AUpstreams provides upstreams from A/AAAA lookups.
// Results are cached and refreshed at the configured
// refresh interval.
type AUpstreams struct {
	// The domain name to look up.
	Name string `json:"name,omitempty"`

	// The port to use with the upstreams. Default: 80
	Port string `json:"port,omitempty"`

	// The interval at which to refresh the A lookup.
	// Results are cached between lookups. Default: 1m
	Refresh caddy.Duration `json:"refresh,omitempty"`

	// Configures the DNS resolver used to resolve the
	// domain name to A records.
	Resolver *UpstreamResolver `json:"resolver,omitempty"`

	// If Resolver is configured, how long to wait before
	// timing out trying to connect to the DNS server.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// If Resolver is configured, how long to wait before
	// spawning an RFC 6555 Fast Fallback connection.
	// A negative value disables this.
	FallbackDelay caddy.Duration `json:"dial_fallback_delay,omitempty"`

	// The IP versions to resolve for. By default, both
	// "ipv4" and "ipv6" will be enabled, which
	// correspond to A and AAAA records respectively.
	Versions *IPVersions `json:"versions,omitempty"`

	resolver *net.Resolver

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (AUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.upstreams.a",
		New: func() caddy.Module { return new(AUpstreams) },
	}
}

func (au *AUpstreams) Provision(ctx caddy.Context) error {
	au.logger = ctx.Logger()
	if au.Refresh == 0 {
		au.Refresh = caddy.Duration(time.Minute)
	}
	if au.Port == "" {
		au.Port = "80"
	}

	if au.Resolver != nil {
		err := au.Resolver.ParseAddresses()
		if err != nil {
			return err
		}
		d := &net.Dialer{
			Timeout:       time.Duration(au.DialTimeout),
			FallbackDelay: time.Duration(au.FallbackDelay),
		}
		au.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				//nolint:gosec
				addr := au.Resolver.netAddrs[weakrand.Intn(len(au.Resolver.netAddrs))]
				return d.DialContext(ctx, addr.Network, addr.JoinHostPort(0))
			},
		}
	}
	if au.resolver == nil {
		au.resolver = net.DefaultResolver
	}

	return nil
}

func (au AUpstreams) GetUpstreams(r *http.Request) ([]*Upstream, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// Map ipVersion early, so we can use it as part of the cache-key.
	// This should be fairly inexpensive and comes and the upside of
	// allowing the same dynamic upstream (name + port combination)
	// to be used multiple times with different ip versions.
	//
	// It also forced a cache-miss if a previously cached dynamic
	// upstream changes its ip version, e.g. after a config reload,
	// while keeping the cache-invalidation as simple as it currently is.
	ipVersion := resolveIpVersion(au.Versions)

	auStr := repl.ReplaceAll(au.String()+ipVersion, "")

	// first, use a cheap read-lock to return a cached result quickly
	aAaaaMu.RLock()
	cached := aAaaa[auStr]
	aAaaaMu.RUnlock()
	if cached.isFresh() {
		return allNew(cached.upstreams), nil
	}

	// otherwise, obtain a write-lock to update the cached value
	aAaaaMu.Lock()
	defer aAaaaMu.Unlock()

	// check to see if it's still stale, since we're now in a different
	// lock from when we first checked freshness; another goroutine might
	// have refreshed it in the meantime before we re-obtained our lock
	cached = aAaaa[auStr]
	if cached.isFresh() {
		return allNew(cached.upstreams), nil
	}

	name := repl.ReplaceAll(au.Name, "")
	port := repl.ReplaceAll(au.Port, "")

	if c := au.logger.Check(zapcore.DebugLevel, "refreshing A upstreams"); c != nil {
		c.Write(
			zap.String("version", ipVersion),
			zap.String("name", name),
			zap.String("port", port),
		)
	}

	ips, err := au.resolver.LookupIP(r.Context(), ipVersion, name)
	if err != nil {
		return nil, err
	}

	upstreams := make([]Upstream, len(ips))
	for i, ip := range ips {
		if c := au.logger.Check(zapcore.DebugLevel, "discovered A record"); c != nil {
			c.Write(zap.String("ip", ip.String()))
		}
		upstreams[i] = Upstream{
			Dial: net.JoinHostPort(ip.String(), port),
		}
	}

	// before adding a new one to the cache (as opposed to replacing stale one), make room if cache is full
	if cached.freshness.IsZero() && len(aAaaa) >= 100 {
		for randomKey := range aAaaa {
			delete(aAaaa, randomKey)
			break
		}
	}

	aAaaa[auStr] = aLookup{
		aUpstreams: au,
		freshness:  time.Now(),
		upstreams:  upstreams,
	}

	return allNew(upstreams), nil
}

func (au AUpstreams) String() string { return net.JoinHostPort(au.Name, au.Port) }

type aLookup struct {
	aUpstreams AUpstreams
	freshness  time.Time
	upstreams  []Upstream
}

func (al aLookup) isFresh() bool {
	return time.Since(al.freshness) < time.Duration(al.aUpstreams.Refresh)
}

// MultiUpstreams is a single dynamic upstream source that
// aggregates the results of multiple dynamic upstream sources.
// All configured sources will be queried in order, with their
// results appended to the end of the list. Errors returned
// from individual sources will be logged and the next source
// will continue to be invoked.
//
// This module makes it easy to implement redundant cluster
// failovers, especially in conjunction with the `first` load
// balancing policy: if the first source returns an error or
// no upstreams, the second source's upstreams will be used
// naturally.
type MultiUpstreams struct {
	// The list of upstream source modules to get upstreams from.
	// They will be queried in order, with their results appended
	// in the order they are returned.
	SourcesRaw []json.RawMessage `json:"sources,omitempty" caddy:"namespace=http.reverse_proxy.upstreams inline_key=source"`
	sources    []UpstreamSource

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (MultiUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.upstreams.multi",
		New: func() caddy.Module { return new(MultiUpstreams) },
	}
}

func (mu *MultiUpstreams) Provision(ctx caddy.Context) error {
	mu.logger = ctx.Logger()

	if mu.SourcesRaw != nil {
		mod, err := ctx.LoadModule(mu, "SourcesRaw")
		if err != nil {
			return fmt.Errorf("loading upstream source modules: %v", err)
		}
		for _, src := range mod.([]any) {
			mu.sources = append(mu.sources, src.(UpstreamSource))
		}
	}

	return nil
}

func (mu MultiUpstreams) GetUpstreams(r *http.Request) ([]*Upstream, error) {
	var upstreams []*Upstream

	for i, src := range mu.sources {
		select {
		case <-r.Context().Done():
			return upstreams, context.Canceled
		default:
		}

		up, err := src.GetUpstreams(r)
		if err != nil {
			if c := mu.logger.Check(zapcore.ErrorLevel, "upstream source returned error"); c != nil {
				c.Write(
					zap.Int("source_idx", i),
					zap.Error(err),
				)
			}
		} else if len(up) == 0 {
			if c := mu.logger.Check(zapcore.WarnLevel, "upstream source returned 0 upstreams"); c != nil {
				c.Write(zap.Int("source_idx", i))
			}
		} else {
			upstreams = append(upstreams, up...)
		}
	}

	return upstreams, nil
}

// UpstreamResolver holds the set of addresses of DNS resolvers of
// upstream addresses
type UpstreamResolver struct {
	// The addresses of DNS resolvers to use when looking up the addresses of proxy upstreams.
	// It accepts [network addresses](/docs/conventions#network-addresses)
	// with port range of only 1. If the host is an IP address, it will be dialed directly to resolve the upstream server.
	// If the host is not an IP address, the addresses are resolved using the [name resolution convention](https://golang.org/pkg/net/#hdr-Name_Resolution) of the Go standard library.
	// If the array contains more than 1 resolver address, one is chosen at random.
	Addresses []string `json:"addresses,omitempty"`
	netAddrs  []caddy.NetworkAddress
}

// ParseAddresses parses all the configured network addresses
// and ensures they're ready to be used.
func (u *UpstreamResolver) ParseAddresses() error {
	for _, v := range u.Addresses {
		addr, err := caddy.ParseNetworkAddressWithDefaults(v, "udp", 53)
		if err != nil {
			return err
		}
		if addr.PortRangeSize() != 1 {
			return fmt.Errorf("resolver address must have exactly one address; cannot call %v", addr)
		}
		u.netAddrs = append(u.netAddrs, addr)
	}
	return nil
}

func allNew(upstreams []Upstream) []*Upstream {
	results := make([]*Upstream, len(upstreams))
	for i := range upstreams {
		results[i] = &Upstream{Dial: upstreams[i].Dial}
	}
	return results
}

var (
	srvs   = make(map[string]srvLookup)
	srvsMu sync.RWMutex

	aAaaa   = make(map[string]aLookup)
	aAaaaMu sync.RWMutex
)

// Interface guards
var (
	_ caddy.Provisioner = (*SRVUpstreams)(nil)
	_ UpstreamSource    = (*SRVUpstreams)(nil)
	_ caddy.Provisioner = (*AUpstreams)(nil)
	_ UpstreamSource    = (*AUpstreams)(nil)
)
