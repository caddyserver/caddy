package httpcaddyfile

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(testDNSProvider{})
}

func TestAutomationPolicyIsSubset(t *testing.T) {
	for i, test := range []struct {
		a, b   []string
		expect bool
	}{
		{
			a:      []string{"example.com"},
			b:      []string{},
			expect: true,
		},
		{
			a:      []string{},
			b:      []string{"example.com"},
			expect: false,
		},
		{
			a:      []string{"foo.example.com"},
			b:      []string{"*.example.com"},
			expect: true,
		},
		{
			a:      []string{"foo.example.com"},
			b:      []string{"foo.example.com"},
			expect: true,
		},
		{
			a:      []string{"foo.example.com"},
			b:      []string{"example.com"},
			expect: false,
		},
		{
			a:      []string{"example.com", "foo.example.com"},
			b:      []string{"*.com", "*.*.com"},
			expect: true,
		},
		{
			a:      []string{"example.com", "foo.example.com"},
			b:      []string{"*.com"},
			expect: false,
		},
	} {
		apA := &caddytls.AutomationPolicy{SubjectsRaw: test.a}
		apB := &caddytls.AutomationPolicy{SubjectsRaw: test.b}
		if actual := automationPolicyIsSubset(apA, apB); actual != test.expect {
			t.Errorf("Test %d: Expected %t but got %t (A: %v  B: %v)", i, test.expect, actual, test.a, test.b)
		}
	}
}

func TestAutomationPoliciesAllowSameHostOnDifferentPorts(t *testing.T) {
	input := `https://example.com:5000 localhost:5000 {
	respond "one"
}

https://example.net localhost:8080 {
	respond "two"
}
`

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	_, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v", err)
	}
}

func TestSiteBlockECH(t *testing.T) {
	const repeatedAdaptationAttempts = 10

	input := `{
	dns test
	ech global-public.example.net
}

www.example.com, example.com {
	tls {
		ech public.example.net {
			dns test
		}
	}
	respond "protected"
}

second.example.com {
	tls {
		ech second-public.example.net
	}
	respond "also protected"
}

shared.example.com {
	tls {
		ech second-public.example.net
	}
	respond "shares an ECH config"
}

unprotected.example.com {
	respond "unprotected"
}
`

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	output, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v", err)
	}
	for range repeatedAdaptationAttempts {
		repeatedOutput, _, err := adapter.Adapt([]byte(input), nil)
		if err != nil {
			t.Fatalf("repeatedly adapting Caddyfile: %v", err)
		}
		if !reflect.DeepEqual(repeatedOutput, output) {
			t.Fatal("adapted output is not deterministic")
		}
	}

	var config struct {
		Apps struct {
			TLS *caddytls.TLS `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatalf("unmarshaling adapted config: %v", err)
	}
	if config.Apps.TLS == nil || config.Apps.TLS.EncryptedClientHello == nil {
		t.Fatal("expected ECH configuration")
	}

	ech := config.Apps.TLS.EncryptedClientHello
	expectedConfigs := []caddytls.ECHConfiguration{
		{PublicName: "global-public.example.net"},
		{PublicName: "public.example.net"},
		{PublicName: "second-public.example.net"},
	}
	if !reflect.DeepEqual(ech.Configs, expectedConfigs) {
		t.Fatalf("unexpected ECH configurations: got %v, want %v", ech.Configs, expectedConfigs)
	}
	if len(ech.Publication) != 3 {
		t.Fatalf("unexpected ECH publication count: got %d, want 3", len(ech.Publication))
	}
	if diff := compareECHPublication(
		ech.Publication[0],
		[]string{"global-public.example.net"},
		[]string{"unprotected.example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
	if diff := compareECHPublication(
		ech.Publication[1],
		[]string{"public.example.net"},
		[]string{"example.com", "www.example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
	if _, ok := ech.Publication[1].PublishersRaw["dns"]; !ok {
		t.Fatal("expected DNS publisher for example.com")
	}
	if diff := compareECHPublication(
		ech.Publication[2],
		[]string{"second-public.example.net"},
		[]string{"second.example.com", "shared.example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
	for _, publication := range ech.Publication {
		if _, ok := publication.PublishersRaw["dns"]; !ok {
			t.Fatalf("expected inherited DNS publisher for %v", publication.Domains)
		}
	}
}

func TestSiteBlockECHWithoutGlobalECH(t *testing.T) {
	input := `example.com {
	tls {
		ech public.example.net {
			dns test
		}
	}
}`

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	output, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v", err)
	}

	var config struct {
		Apps struct {
			TLS *caddytls.TLS `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatalf("unmarshaling adapted config: %v", err)
	}
	if config.Apps.TLS == nil || config.Apps.TLS.EncryptedClientHello == nil {
		t.Fatal("expected site-specific ECH configuration")
	}
}

func TestSiteBlockECHRestrictsConfiguredGlobalPublication(t *testing.T) {
	input := `{
	ech global-public.example.net {
		dns test
	}
}

site.example.com {
	tls {
		ech site-public.example.net
	}
}

global.example.com {
}`

	ech := adaptECH(t, input)
	if len(ech.Publication) != 2 {
		t.Fatalf("unexpected ECH publication count: got %d, want 2", len(ech.Publication))
	}
	if diff := compareECHPublication(
		ech.Publication[0],
		[]string{"global-public.example.net"},
		[]string{"global.example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
	if diff := compareECHPublication(
		ech.Publication[1],
		[]string{"site-public.example.net"},
		[]string{"site.example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
}

func TestSiteBlockECHOmitGlobalPublicationWithoutDomains(t *testing.T) {
	input := `{
	ech global-public.example.net {
		dns test
	}
}

site.example.com {
	tls {
		ech site-public.example.net
	}
}`

	ech := adaptECH(t, input)
	if len(ech.Publication) != 1 {
		t.Fatalf("unexpected ECH publication count: got %d, want 1", len(ech.Publication))
	}
	if diff := compareECHPublication(
		ech.Publication[0],
		[]string{"site-public.example.net"},
		[]string{"site.example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
}

func TestSiteBlockECHAcrossListenerAddresses(t *testing.T) {
	input := `{
	dns test
}

https://a.example.com, https://b.example.com:8443 {
	tls {
		ech public.example.net {
			dns test
		}
	}
}`

	ech := adaptECH(t, input)
	if len(ech.Publication) != 1 {
		t.Fatalf("unexpected ECH publication count: got %d, want 1", len(ech.Publication))
	}
	if diff := compareECHPublication(
		ech.Publication[0],
		[]string{"public.example.net"},
		[]string{"a.example.com", "b.example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
}

func TestSiteBlockECHRejectsConflictingAssignments(t *testing.T) {
	tests := map[string]string{
		"configs": `example.com {
	tls {
		ech first-public.example.net {
			dns test
		}
	}
}

example.com:8443 {
	tls {
		ech second-public.example.net {
			dns test
		}
	}
}`,
		"publishers": `example.com {
	tls {
		ech public.example.net {
			dns test
		}
	}
}

example.com:8443 {
	tls {
		ech public.example.net
	}
}`,
	}

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := adapter.Adapt([]byte(input), nil); err == nil {
				t.Fatal("expected conflicting ECH assignments for the same hostname to fail")
			} else if !strings.Contains(err.Error(), "example.com") {
				t.Fatalf("expected conflict error to identify the hostname, got: %v", err)
			}
		})
	}
}

func TestSiteBlockECHConsolidatesIdenticalHostAssignment(t *testing.T) {
	input := `example.com {
	tls {
		ech public.example.net {
			dns test
		}
	}
}

example.com:8443 {
	tls {
		ech public.example.net {
			dns test
		}
	}
}`

	ech := adaptECH(t, input)
	if len(ech.Publication) != 1 {
		t.Fatalf("unexpected ECH publication count: got %d, want 1", len(ech.Publication))
	}
	if diff := compareECHPublication(
		ech.Publication[0],
		[]string{"public.example.net"},
		[]string{"example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
}

func TestSiteBlockECHPreservesCatchAllAssignment(t *testing.T) {
	input := `:443 {
	tls {
		ech public.example.net {
			dns test
		}
	}
}

example.com:8443 {
	tls {
		ech public.example.net {
			dns test
		}
	}
}`

	ech := adaptECH(t, input)
	if len(ech.Publication) != 1 {
		t.Fatalf("unexpected ECH publication count: got %d, want 1", len(ech.Publication))
	}
	if diff := compareECHPublication(
		ech.Publication[0],
		[]string{"public.example.net"},
		nil,
	); diff != "" {
		t.Fatal(diff)
	}
}

func TestSiteBlockECHRejectsCatchAllConflict(t *testing.T) {
	tests := map[string]string{
		"catch-all first": `:443 {
	tls {
		ech catch-all-public.example.net {
			dns test
		}
	}
}

example.com:8443 {
	tls {
		ech named-public.example.net {
			dns test
		}
	}
}`,
		"catch-all last": `example.com:8443 {
	tls {
		ech named-public.example.net {
			dns test
		}
	}
}

:443 {
	tls {
		ech catch-all-public.example.net {
			dns test
		}
	}
}`,
		"two catch-alls": `:443 {
	tls {
		ech first-public.example.net {
			dns test
		}
	}
}

:8443 {
	tls {
		ech second-public.example.net {
			dns test
		}
	}
}`,
	}

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := adapter.Adapt([]byte(input), nil); err == nil {
				t.Fatal("expected catch-all ECH assignments to conflict")
			}
		})
	}
}

func TestSiteBlockECHSortsPublicationsWithIdenticalConfigsByDomain(t *testing.T) {
	input := `b.example.com {
	tls {
		ech public.example.net
	}
}

a.example.com {
	tls {
		ech public.example.net {
			dns test
		}
	}
}`

	ech := adaptECH(t, input)
	if len(ech.Publication) != 2 {
		t.Fatalf("unexpected ECH publication count: got %d, want 2", len(ech.Publication))
	}
	if diff := compareECHPublication(
		ech.Publication[0],
		[]string{"public.example.net"},
		[]string{"a.example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
	if diff := compareECHPublication(
		ech.Publication[1],
		[]string{"public.example.net"},
		[]string{"b.example.com"},
	); diff != "" {
		t.Fatal(diff)
	}
}

func TestConsolidateECHPublicationsRejectsCatchAllAfterNamedAssignment(t *testing.T) {
	publications := []*caddytls.ECHPublication{
		{
			Configs: []string{"named-public.example.net"},
			Domains: []string{"example.com"},
		},
		{
			Configs: []string{"catch-all-public.example.net"},
		},
	}

	if _, err := consolidateECHPublications(publications); err == nil {
		t.Fatal("expected a named assignment followed by a catch-all assignment to conflict")
	} else if !strings.Contains(err.Error(), "example.com") {
		t.Fatalf("expected conflict error to identify the hostname, got: %v", err)
	}
}

func TestSiteBlockECHRejectsGlobalAndSiteConflictForSameHost(t *testing.T) {
	input := `{
	dns test
	ech global-public.example.net
}

https://example.com/api {
	tls {
		ech site-public.example.net {
			dns test
		}
	}
}

https://example.com/app {
	respond "hello"
}`

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	if _, _, err := adapter.Adapt([]byte(input), nil); err == nil {
		t.Fatal("expected global and site-specific ECH assignments for the same hostname to fail")
	}
}

func TestSiteBlockECHRequiresPublicName(t *testing.T) {
	input := `example.com {
	tls {
		ech
	}
}`

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	if _, _, err := adapter.Adapt([]byte(input), nil); err == nil {
		t.Fatal("expected adapting ECH without a public name to fail")
	}
}

func compareECHPublication(publication *caddytls.ECHPublication, configs, domains []string) string {
	if !reflect.DeepEqual(publication.Configs, configs) {
		return fmt.Sprintf("unexpected publication configs: got %v, want %v", publication.Configs, configs)
	}
	if !reflect.DeepEqual(publication.Domains, domains) {
		return fmt.Sprintf("unexpected publication domains: got %v, want %v", publication.Domains, domains)
	}
	return ""
}

func adaptECH(t *testing.T, input string) *caddytls.ECH {
	t.Helper()
	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	output, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v", err)
	}
	var config struct {
		Apps struct {
			TLS *caddytls.TLS `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatalf("unmarshaling adapted config: %v", err)
	}
	if config.Apps.TLS == nil || config.Apps.TLS.EncryptedClientHello == nil {
		t.Fatal("expected ECH configuration")
	}
	return config.Apps.TLS.EncryptedClientHello
}

type testDNSProvider struct{}

func (testDNSProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.test",
		New: func() caddy.Module { return new(testDNSProvider) },
	}
}

func (*testDNSProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

func (*testDNSProvider) AppendRecords(
	context.Context,
	string,
	[]libdns.Record,
) ([]libdns.Record, error) {
	return nil, nil
}

func (*testDNSProvider) DeleteRecords(
	context.Context,
	string,
	[]libdns.Record,
) ([]libdns.Record, error) {
	return nil, nil
}

func (*testDNSProvider) GetRecords(context.Context, string) ([]libdns.Record, error) {
	return nil, nil
}

func (*testDNSProvider) SetRecords(
	context.Context,
	string,
	[]libdns.Record,
) ([]libdns.Record, error) {
	return nil, nil
}

var (
	_ caddy.Module          = (*testDNSProvider)(nil)
	_ caddyfile.Unmarshaler = (*testDNSProvider)(nil)
	_ certmagic.DNSProvider = (*testDNSProvider)(nil)
)
