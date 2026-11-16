package caddytls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestServerNameRegexpQuantifiers(t *testing.T) {
	t.Setenv("CADDY_TEST_SNI_SUFFIX", "example")
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	for _, tc := range []struct {
		pattern, input string
		match          bool
	}{
		{`^a{2}\.example$`, "aa.example", true},
		{`^a{2}\.example$`, "a.example", false},
		{`^a{2,}\.example$`, "aaa.example", true},
		{`^a{2,}\.example$`, "a.example", false},
		{`^a{2,3}\.example$`, "aaa.example", true},
		{`^a{2,3}\.example$`, "a.example", false},
		{`^a{2,3}\.example$`, "aaaa.example", false},
		{`^a{2}\.{env.CADDY_TEST_SNI_SUFFIX}$`, "aa.example", true},
		{`^a{unknown}\.example$`, "a.example", false},
	} {
		t.Run(tc.pattern+"/"+tc.input, func(t *testing.T) {
			matcher := &MatchServerNameRE{MatchRegexp: MatchRegexp{Pattern: tc.pattern}}
			if err := matcher.Provision(ctx); err != nil {
				t.Fatal(err)
			}
			public := &tls.Config{MinVersion: tls.VersionTLS12}
			protected := &tls.Config{
				MinVersion: tls.VersionTLS12,
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  x509.NewCertPool(),
			}
			policies := ConnectionPolicies{
				{matchers: []ConnectionMatcher{matcher}, TLSConfig: public},
				{TLSConfig: protected},
			}
			selected, err := policies.TLSConfig(ctx).GetConfigForClient(&tls.ClientHelloInfo{ServerName: tc.input})
			if err != nil {
				t.Fatal(err)
			}
			want := protected
			if tc.match {
				want = public
			}
			if selected != want {
				t.Fatalf("selected client authentication %v, want %v", selected.ClientAuth, want.ClientAuth)
			}
		})
	}
}
