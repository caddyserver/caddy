package caddyhttp

import (
	"reflect"
	"testing"
)

func TestHTTPSRRALPNsDefaultProtocols(t *testing.T) {
	srv := &Server{}

	got := httpsRRALPNs(srv)
	want := []string{"h3", "h2", "http/1.1"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ALPN values: got %v want %v", got, want)
	}
}

func TestHTTPSRRALPNsListenProtocolOverrides(t *testing.T) {
	srv := &Server{
		Protocols: []string{"h1", "h2"},
		ListenProtocols: [][]string{
			{"h1"},
			nil,
			{"h2c", "h3"},
		},
	}

	got := httpsRRALPNs(srv)
	want := []string{"h3", "h2", "http/1.1"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ALPN values: got %v want %v", got, want)
	}
}

func TestHTTPSRRALPNsIgnoresH2COnly(t *testing.T) {
	srv := &Server{
		Protocols: []string{"h2c"},
	}

	got := httpsRRALPNs(srv)
	if len(got) != 0 {
		t.Fatalf("unexpected ALPN values: got %v want none", got)
	}
}
