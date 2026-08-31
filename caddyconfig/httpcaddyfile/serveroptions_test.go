package httpcaddyfile

import (
	"testing"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestUnmarshalCaddyfileServerOptionsProtocols(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		wantProto []string
	}{
		{
			name:      "h1 only",
			input:     "servers {\n protocols h1\n}",
			wantProto: []string{"h1"},
		},
		{
			name:      "h1 h2 h3",
			input:     "servers {\n protocols h1 h2 h3\n}",
			wantProto: []string{"h1", "h2", "h3"},
		},
		{
			name:      "h2c",
			input:     "servers {\n protocols h2c\n}",
			wantProto: []string{"h2c"},
		},
		{
			name:    "unknown protocol",
			input:   "servers {\n protocols h4\n}",
			wantErr: true,
		},
		{
			name:    "duplicate protocol",
			input:   "servers {\n protocols h1 h1\n}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			result, err := unmarshalCaddyfileServerOptions(d)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			opts := result.(serverOptions)
			if len(opts.Protocols) != len(tt.wantProto) {
				t.Fatalf("Protocols = %v, want %v", opts.Protocols, tt.wantProto)
			}
			for i, p := range tt.wantProto {
				if opts.Protocols[i] != p {
					t.Errorf("Protocols[%d] = %q, want %q", i, opts.Protocols[i], p)
				}
			}
		})
	}
}

func TestUnmarshalCaddyfileServerOptionsTimeouts(t *testing.T) {
	input := `servers {
	timeouts {
		read_body 30s
		read_header 10s
		write 60s
		idle 120s
	}
}`
	d := caddyfile.NewTestDispenser(input)
	result, err := unmarshalCaddyfileServerOptions(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := result.(serverOptions)

	if time.Duration(opts.ReadTimeout) != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", time.Duration(opts.ReadTimeout))
	}
	if time.Duration(opts.ReadHeaderTimeout) != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 10s", time.Duration(opts.ReadHeaderTimeout))
	}
	if time.Duration(opts.WriteTimeout) != 60*time.Second {
		t.Errorf("WriteTimeout = %v, want 60s", time.Duration(opts.WriteTimeout))
	}
	if time.Duration(opts.IdleTimeout) != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", time.Duration(opts.IdleTimeout))
	}
}

func TestUnmarshalCaddyfileServerOptionsKeepalive(t *testing.T) {
	input := `servers {
	keepalive_interval 15s
	keepalive_idle 60s
	keepalive_count 5
}`
	d := caddyfile.NewTestDispenser(input)
	result, err := unmarshalCaddyfileServerOptions(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := result.(serverOptions)

	if time.Duration(opts.KeepAliveInterval) != 15*time.Second {
		t.Errorf("KeepAliveInterval = %v, want 15s", time.Duration(opts.KeepAliveInterval))
	}
	if time.Duration(opts.KeepAliveIdle) != 60*time.Second {
		t.Errorf("KeepAliveIdle = %v, want 60s", time.Duration(opts.KeepAliveIdle))
	}
	if opts.KeepAliveCount != 5 {
		t.Errorf("KeepAliveCount = %d, want 5", opts.KeepAliveCount)
	}
}

func TestUnmarshalCaddyfileServerOptionsBooleans(t *testing.T) {
	input := `servers {
	enable_full_duplex
	log_credentials
	trace
}`
	d := caddyfile.NewTestDispenser(input)
	result, err := unmarshalCaddyfileServerOptions(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := result.(serverOptions)

	if !opts.EnableFullDuplex {
		t.Error("EnableFullDuplex should be true")
	}
	if !opts.ShouldLogCredentials {
		t.Error("ShouldLogCredentials should be true")
	}
	if !opts.Trace {
		t.Error("Trace should be true")
	}
}

func TestUnmarshalCaddyfileServerOptionsStrictSNI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		wantBool *bool
	}{
		{
			name:     "strict_sni_host on",
			input:    "servers {\n strict_sni_host on\n}",
			wantBool: boolPtr(true),
		},
		{
			name:     "strict_sni_host insecure_off",
			input:    "servers {\n strict_sni_host insecure_off\n}",
			wantBool: boolPtr(false),
		},
		{
			name:     "strict_sni_host bare (defaults to true)",
			input:    "servers {\n strict_sni_host\n}",
			wantBool: boolPtr(true),
		},
		{
			name:    "strict_sni_host invalid",
			input:   "servers {\n strict_sni_host invalid\n}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			result, err := unmarshalCaddyfileServerOptions(d)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			opts := result.(serverOptions)
			if opts.StrictSNIHost == nil {
				t.Fatal("StrictSNIHost is nil")
			}
			if *opts.StrictSNIHost != *tt.wantBool {
				t.Errorf("StrictSNIHost = %v, want %v", *opts.StrictSNIHost, *tt.wantBool)
			}
		})
	}
}

func TestUnmarshalCaddyfileServerOptionsMaxHeaderSize(t *testing.T) {
	input := `servers {
	max_header_size 1MB
}`
	d := caddyfile.NewTestDispenser(input)
	result, err := unmarshalCaddyfileServerOptions(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := result.(serverOptions)
	if opts.MaxHeaderBytes != 1000000 {
		t.Errorf("MaxHeaderBytes = %d, want 1000000", opts.MaxHeaderBytes)
	}
}

func TestUnmarshalCaddyfileServerOptions0RTT(t *testing.T) {
	input := `servers {
	0rtt off
}`
	d := caddyfile.NewTestDispenser(input)
	result, err := unmarshalCaddyfileServerOptions(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := result.(serverOptions)
	if opts.Allow0RTT == nil {
		t.Fatal("Allow0RTT is nil")
	}
	if *opts.Allow0RTT != false {
		t.Errorf("Allow0RTT = %v, want false", *opts.Allow0RTT)
	}
}

func TestUnmarshalCaddyfileServerOptions0RTTInvalid(t *testing.T) {
	input := `servers {
	0rtt on
}`
	d := caddyfile.NewTestDispenser(input)
	_, err := unmarshalCaddyfileServerOptions(d)
	if err == nil {
		t.Error("expected error for unsupported 0rtt argument")
	}
}

func TestUnmarshalCaddyfileServerOptionsListenerAddress(t *testing.T) {
	input := `servers :443 {
	name myserver
	protocols h1 h2
}`
	d := caddyfile.NewTestDispenser(input)
	result, err := unmarshalCaddyfileServerOptions(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := result.(serverOptions)
	if opts.ListenerAddress != ":443" {
		t.Errorf("ListenerAddress = %q, want ':443'", opts.ListenerAddress)
	}
	if opts.Name != "myserver" {
		t.Errorf("Name = %q, want 'myserver'", opts.Name)
	}
}

func TestUnmarshalCaddyfileServerOptionsNameWithoutAddress(t *testing.T) {
	input := `servers {
	name myserver
}`
	d := caddyfile.NewTestDispenser(input)
	_, err := unmarshalCaddyfileServerOptions(d)
	if err == nil {
		t.Error("expected error for name without listener address")
	}
}

func TestUnmarshalCaddyfileServerOptionsUnknownOption(t *testing.T) {
	input := `servers {
	nonexistent_option
}`
	d := caddyfile.NewTestDispenser(input)
	_, err := unmarshalCaddyfileServerOptions(d)
	if err == nil {
		t.Error("expected error for unknown option")
	}
}

func TestUnmarshalCaddyfileServerOptionsInvalidTimeout(t *testing.T) {
	input := `servers {
	timeouts {
		read_body notaduration
	}
}`
	d := caddyfile.NewTestDispenser(input)
	_, err := unmarshalCaddyfileServerOptions(d)
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestUnmarshalCaddyfileServerOptionsUnrecognizedTimeout(t *testing.T) {
	input := `servers {
	timeouts {
		unknown_timeout 30s
	}
}`
	d := caddyfile.NewTestDispenser(input)
	_, err := unmarshalCaddyfileServerOptions(d)
	if err == nil {
		t.Error("expected error for unrecognized timeout option")
	}
}

func TestUnmarshalCaddyfileServerOptionsEmpty(t *testing.T) {
	input := `servers {
}`
	d := caddyfile.NewTestDispenser(input)
	result, err := unmarshalCaddyfileServerOptions(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := result.(serverOptions)
	if opts.ListenerAddress != "" {
		t.Errorf("ListenerAddress = %q, want empty", opts.ListenerAddress)
	}
	if len(opts.Protocols) != 0 {
		t.Errorf("Protocols = %v, want empty", opts.Protocols)
	}
}

func TestUnmarshalCaddyfileServerOptionsClientIPHeaders(t *testing.T) {
	input := `servers {
	client_ip_headers X-Forwarded-For X-Real-IP
}`
	d := caddyfile.NewTestDispenser(input)
	result, err := unmarshalCaddyfileServerOptions(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := result.(serverOptions)
	if len(opts.ClientIPHeaders) != 2 {
		t.Fatalf("ClientIPHeaders = %v, want 2 headers", opts.ClientIPHeaders)
	}
	if opts.ClientIPHeaders[0] != "X-Forwarded-For" {
		t.Errorf("ClientIPHeaders[0] = %q, want 'X-Forwarded-For'", opts.ClientIPHeaders[0])
	}
}

func TestUnmarshalCaddyfileServerOptionsDuplicateClientIPHeaders(t *testing.T) {
	input := `servers {
	client_ip_headers X-Forwarded-For X-Forwarded-For
}`
	d := caddyfile.NewTestDispenser(input)
	_, err := unmarshalCaddyfileServerOptions(d)
	if err == nil {
		t.Error("expected error for duplicate client IP header")
	}
}

func TestUnmarshalCaddyfileServerOptionsTrustedProxiesStrict(t *testing.T) {
	input := `servers {
	trusted_proxies_strict
}`
	d := caddyfile.NewTestDispenser(input)
	result, err := unmarshalCaddyfileServerOptions(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := result.(serverOptions)
	if opts.TrustedProxiesStrict != 1 {
		t.Errorf("TrustedProxiesStrict = %d, want 1", opts.TrustedProxiesStrict)
	}
}

func TestApplyServerOptionsDuplicateNames(t *testing.T) {
	options := map[string]any{
		"servers": []serverOptions{
			{ListenerAddress: ":80", Name: "myserver"},
			{ListenerAddress: ":443", Name: "myserver"},
		},
	}
	servers := map[string]*caddyhttp.Server{
		"srv0": {Listen: []string{":80"}},
		"srv1": {Listen: []string{":443"}},
	}
	err := applyServerOptions(servers, options, nil)
	if err == nil {
		t.Error("expected error for duplicate server names")
	}
}

func TestApplyServerOptionsNoOptions(t *testing.T) {
	servers := map[string]*caddyhttp.Server{
		"srv0": {Listen: []string{":80"}},
	}
	err := applyServerOptions(servers, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyServerOptionsRename(t *testing.T) {
	options := map[string]any{
		"servers": []serverOptions{
			{ListenerAddress: ":80", Name: "web"},
		},
	}
	servers := map[string]*caddyhttp.Server{
		"srv0": {Listen: []string{":80"}},
	}
	err := applyServerOptions(servers, options, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := servers["web"]; !ok {
		t.Error("server should have been renamed to 'web'")
	}
	if _, ok := servers["srv0"]; ok {
		t.Error("old server name 'srv0' should have been removed")
	}
}

func TestApplyServerOptionsProtocols(t *testing.T) {
	options := map[string]any{
		"servers": []serverOptions{
			{Protocols: []string{"h1", "h2"}},
		},
	}
	servers := map[string]*caddyhttp.Server{
		"srv0": {Listen: []string{":80"}},
	}
	err := applyServerOptions(servers, options, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers["srv0"].Protocols) != 2 {
		t.Errorf("Protocols = %v, want [h1 h2]", servers["srv0"].Protocols)
	}
}

func TestApplyServerOptionsTimeouts(t *testing.T) {
	readTimeout := caddy.Duration(30 * time.Second)
	writeTimeout := caddy.Duration(60 * time.Second)
	options := map[string]any{
		"servers": []serverOptions{
			{ReadTimeout: readTimeout, WriteTimeout: writeTimeout},
		},
	}
	servers := map[string]*caddyhttp.Server{
		"srv0": {Listen: []string{":80"}},
	}
	err := applyServerOptions(servers, options, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if servers["srv0"].ReadTimeout != readTimeout {
		t.Errorf("ReadTimeout = %v, want %v", servers["srv0"].ReadTimeout, readTimeout)
	}
	if servers["srv0"].WriteTimeout != writeTimeout {
		t.Errorf("WriteTimeout = %v, want %v", servers["srv0"].WriteTimeout, writeTimeout)
	}
}

func boolPtr(b bool) *bool {
	return &b
}
