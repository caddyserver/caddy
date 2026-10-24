package reverseproxy

import "testing"

func TestResolveIpVersion(t *testing.T) {
	falseBool := false
	trueBool := true
	tests := []struct {
		Versions          *IPVersions
		expectedIpVersion string
	}{
		{
			Versions:          &IPVersions{IPv4: &trueBool},
			expectedIpVersion: "ip4",
		},
		{
			Versions:          &IPVersions{IPv4: &falseBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &trueBool, IPv6: &falseBool},
			expectedIpVersion: "ip4",
		},
		{
			Versions:          &IPVersions{IPv6: &trueBool},
			expectedIpVersion: "ip6",
		},
		{
			Versions:          &IPVersions{IPv6: &falseBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv6: &trueBool, IPv4: &falseBool},
			expectedIpVersion: "ip6",
		},
		{
			Versions:          &IPVersions{},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &trueBool, IPv6: &trueBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &falseBool, IPv6: &falseBool},
			expectedIpVersion: "ip",
		},
	}
	for _, test := range tests {
		ipVersion := resolveIpVersion(test.Versions)
		if ipVersion != test.expectedIpVersion {
			t.Errorf("resolveIpVersion(): Expected %s got %s", test.expectedIpVersion, ipVersion)
		}
	}
}

func TestResolverCacheKey(t *testing.T) {
	key := func(addrs ...string) string {
		if addrs == nil {
			return resolverCacheKey(nil)
		}
		return resolverCacheKey(&UpstreamResolver{Addresses: addrs})
	}

	// The default resolver (nil or empty) yields the empty key, so default-resolver
	// sources keep sharing the cache.
	if got := key(); got != "" {
		t.Errorf("nil resolver: got %q, want \"\"", got)
	}
	if got := resolverCacheKey(&UpstreamResolver{}); got != "" {
		t.Errorf("empty resolver: got %q, want \"\"", got)
	}

	// Order does not matter: the same set maps to the same key.
	if a, b := key("1.1.1.1", "8.8.8.8"), key("8.8.8.8", "1.1.1.1"); a != b {
		t.Errorf("order should not matter: %q != %q", a, b)
	}

	// Different sets must not collide, even when an address contains the
	// delimiter that a naive join would use. {"a,b"} and {"a","b"} are distinct
	// resolver configurations and must get distinct keys.
	colliding := [][2][]string{
		{{"a,b"}, {"a", "b"}},
		{{"unix//run/x,y.sock"}, {"unix//run/x", "y.sock"}},
		{{"10:1"}, {"1", "0:1"}}, // guards the length-prefix encoding itself
	}
	for _, c := range colliding {
		if k1, k2 := key(c[0]...), key(c[1]...); k1 == k2 {
			t.Errorf("distinct address sets %q and %q share key %q", c[0], c[1], k1)
		}
	}
}
