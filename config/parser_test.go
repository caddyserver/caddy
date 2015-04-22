package config

import (
	"os"
	"strings"
	"testing"
)

func TestNewParser(t *testing.T) {
	filePath := "./parser_test.go"
	expected := "parser_test.go"

	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal("Could not open file")
	}
	defer file.Close()

	p, err := newParser(file)
	if err != nil {
		t.Fatal(err)
	}

	if p.filename != expected {
		t.Errorf("Expected parser to have filename '%s' but had '%s'", expected, p.filename)
	}

	if p == nil {
		t.Error("Expected parser to not be nil, but it was")
	}
}

func TestParserBasic(t *testing.T) {
	p := &parser{filename: "test"}

	input := `localhost:1234
			  root /test/www
			  tls  cert.pem key.pem`

	p.lexer.load(strings.NewReader(input))

	confs, err := p.parse()
	if err != nil {
		t.Fatalf("Expected no errors, but got '%s'", err)
	}
	conf := confs[0]

	if conf.Host != "localhost" {
		t.Errorf("Expected host to be 'localhost', got '%s'", conf.Host)
	}
	if conf.Port != "1234" {
		t.Errorf("Expected port to be '1234', got '%s'", conf.Port)
	}
	if conf.Root != "/test/www" {
		t.Errorf("Expected root to be '/test/www', got '%s'", conf.Root)
	}
	if !conf.TLS.Enabled {
		t.Error("Expected TLS to be enabled, but it wasn't")
	}
	if conf.TLS.Certificate != "cert.pem" {
		t.Errorf("Expected TLS certificate to be 'cert.pem', got '%s'", conf.TLS.Certificate)
	}
	if conf.TLS.Key != "key.pem" {
		t.Errorf("Expected TLS server key to be 'key.pem', got '%s'", conf.TLS.Key)
	}
}

func TestParserBasicWithMultipleServerBlocks(t *testing.T) {
	p := &parser{filename: "test"}

	input := `host1.com:443 {
				  root /test/www
				  tls cert.pem key.pem
			  }

			  host2:80 {
				  root "/test/my site"
			  }`

	p.lexer.load(strings.NewReader(input))

	confs, err := p.parse()
	if err != nil {
		t.Fatalf("Expected no errors, but got '%s'", err)
	}
	if len(confs) != 2 {
		t.Fatalf("Expected 2 configurations, but got %d: %#v", len(confs), confs)
	}

	// First server
	if confs[0].Host != "host1.com" {
		t.Errorf("Expected first host to be 'host1.com', got '%s'", confs[0].Host)
	}
	if confs[0].Port != "443" {
		t.Errorf("Expected first port to be '443', got '%s'", confs[0].Port)
	}
	if confs[0].Root != "/test/www" {
		t.Errorf("Expected first root to be '/test/www', got '%s'", confs[0].Root)
	}
	if !confs[0].TLS.Enabled {
		t.Error("Expected first TLS to be enabled, but it wasn't")
	}
	if confs[0].TLS.Certificate != "cert.pem" {
		t.Errorf("Expected first TLS certificate to be 'cert.pem', got '%s'", confs[0].TLS.Certificate)
	}
	if confs[0].TLS.Key != "key.pem" {
		t.Errorf("Expected first TLS server key to be 'key.pem', got '%s'", confs[0].TLS.Key)
	}

	// Second server
	if confs[1].Host != "host2" {
		t.Errorf("Expected second host to be 'host2', got '%s'", confs[1].Host)
	}
	if confs[1].Port != "80" {
		t.Errorf("Expected second port to be '80', got '%s'", confs[1].Port)
	}
	if confs[1].Root != "/test/my site" {
		t.Errorf("Expected second root to be '/test/my site', got '%s'", confs[1].Root)
	}
	if confs[1].TLS.Enabled {
		t.Error("Expected second TLS to be disabled, but it was enabled")
	}
	if confs[1].TLS.Certificate != "" {
		t.Errorf("Expected second TLS certificate to be '', got '%s'", confs[1].TLS.Certificate)
	}
	if confs[1].TLS.Key != "" {
		t.Errorf("Expected second TLS server key to be '', got '%s'", confs[1].TLS.Key)
	}
}

func TestParserBasicWithMultipleHostsPerBlock(t *testing.T) {
	// This test is table-driven; it is expected that each
	// input string produce the same set of configs.
	for _, input := range []string{
		`host1.com host2.com:1234
		 root /public_html`, // space-separated, no block

		`host1.com, host2.com:1234
		 root /public_html`, // comma-separated, no block

		`host1.com,
		 host2.com:1234
		 root /public_html`, // comma-separated, newlines, no block

		`host1.com host2.com:1234 {
			root /public_html
		 }`, // space-separated, block

		`host1.com, host2.com:1234 {
			root /public_html
		 }`, // comma-separated, block

		`host1.com,
		 host2.com:1234 {
			root /public_html
		 }`, // comma-separated, newlines, block
	} {

		p := &parser{filename: "test"}
		p.lexer.load(strings.NewReader(input))

		confs, err := p.parse()
		if err != nil {
			t.Fatalf("Expected no errors, but got '%s'", err)
		}
		if len(confs) != 2 {
			t.Fatalf("Expected 2 configurations, but got %d: %#v", len(confs), confs)
		}

		if confs[0].Host != "host1.com" {
			t.Errorf("Expected host of first conf to be 'host1.com', got '%s'", confs[0].Host)
		}
		if confs[0].Port != defaultPort {
			t.Errorf("Expected port of first conf to be '%s', got '%s'", defaultPort, confs[0].Port)
		}
		if confs[0].Root != "/public_html" {
			t.Errorf("Expected root of first conf to be '/public_html', got '%s'", confs[0].Root)
		}

		if confs[1].Host != "host2.com" {
			t.Errorf("Expected host of second conf to be 'host2.com', got '%s'", confs[1].Host)
		}
		if confs[1].Port != "1234" {
			t.Errorf("Expected port of second conf to be '1234', got '%s'", confs[1].Port)
		}
		if confs[1].Root != "/public_html" {
			t.Errorf("Expected root of second conf to be '/public_html', got '%s'", confs[1].Root)
		}

	}
}

func TestParserBasicWithAlternateAddressStyles(t *testing.T) {
	p := &parser{filename: "test"}
	input := `http://host1.com, https://host2.com,
			  host3.com:http, host4.com:1234 {
				  root /test/www
			  }`
	p.lexer.load(strings.NewReader(input))

	confs, err := p.parse()
	if err != nil {
		t.Fatalf("Expected no errors, but got '%s'", err)
	}
	if len(confs) != 4 {
		t.Fatalf("Expected 4 configurations, but got %d: %#v", len(confs), confs)
	}

	for _, conf := range confs {
		if conf.Root != "/test/www" {
			t.Fatalf("Expected root for conf of %s to be '/test/www', but got: %s", conf.Address(), conf.Root)
		}
	}

	p = &parser{filename: "test"}
	input = `host:port, http://host:port, http://host, https://host:port, host`
	p.lexer.load(strings.NewReader(input))

	confs, err = p.parse()
	if err != nil {
		t.Fatalf("Expected no errors, but got '%s'", err)
	}
	if len(confs) != 5 {
		t.Fatalf("Expected 5 configurations, but got %d: %#v", len(confs), confs)
	}

	if confs[0].Host != "host" {
		t.Errorf("Expected conf[0] Host='host', got '%#v'", confs[0])
	}
	if confs[0].Port != "port" {
		t.Errorf("Expected conf[0] Port='port', got '%#v'", confs[0])
	}

	if confs[1].Host != "host" {
		t.Errorf("Expected conf[1] Host='host', got '%#v'", confs[1])
	}
	if confs[1].Port != "port" {
		t.Errorf("Expected conf[1] Port='port', got '%#v'", confs[1])
	}

	if confs[2].Host != "host" {
		t.Errorf("Expected conf[2] Host='host', got '%#v'", confs[2])
	}
	if confs[2].Port != "http" {
		t.Errorf("Expected conf[2] Port='http', got '%#v'", confs[2])
	}

	if confs[3].Host != "host" {
		t.Errorf("Expected conf[3] Host='host', got '%#v'", confs[3])
	}
	if confs[3].Port != "port" {
		t.Errorf("Expected conf[3] Port='port', got '%#v'", confs[3])
	}

	if confs[4].Host != "host" {
		t.Errorf("Expected conf[4] Host='host', got '%#v'", confs[4])
	}
	if confs[4].Port != defaultPort {
		t.Errorf("Expected conf[4] Port='%s', got '%#v'", defaultPort, confs[4].Port)
	}
}

func TestParserImport(t *testing.T) {
	p := &parser{filename: "test"}

	input := `host:123
			  import import_test.txt`

	p.lexer.load(strings.NewReader(input))

	confs, err := p.parse()
	if err != nil {
		t.Fatalf("Expected no errors, but got '%s'", err)
	}
	conf := confs[0]

	if conf.Host != "host" {
		t.Errorf("Expected host to be 'host', got '%s'", conf.Host)
	}
	if conf.Port != "123" {
		t.Errorf("Expected port to be '123', got '%s'", conf.Port)
	}
	if conf.Root != "/test/imported/public_html" {
		t.Errorf("Expected root to be '/test/imported/public_html', got '%s'", conf.Root)
	}
	if conf.TLS.Enabled {
		t.Error("Expected TLS to be disabled, but it was enabled")
	}
	if conf.TLS.Certificate != "" {
		t.Errorf("Expected TLS certificate to be '', got '%s'", conf.TLS.Certificate)
	}
	if conf.TLS.Key != "" {
		t.Errorf("Expected TLS server key to be '', got '%s'", conf.TLS.Key)
	}
}

func TestParserLocationContext(t *testing.T) {
	p := &parser{filename: "test"}

	input := `host:123 {
				/scope {
					gzip
				}
			}`

	p.lexer.load(strings.NewReader(input))

	confs, err := p.parse()
	if err != nil {
		t.Fatalf("Expected no errors, but got '%s'", err)
	}
	if len(confs) != 1 {
		t.Fatalf("Expected 1 configuration, but got %d: %#v", len(confs), confs)
	}

	if len(p.other) != 2 {
		t.Fatalf("Expected 2 path scopes, but got %d: %#v", len(p.other), p.other)
	}

	if p.other[0].path != "/" {
		t.Fatalf("Expected first path scope to be default '/', but got %d: %#v", p.other[0].path, p.other)
	}
	if p.other[1].path != "/scope" {
		t.Fatalf("Expected first path scope to be '/scope', but got %d: %#v", p.other[0].path, p.other)
	}

	if dir, ok := p.other[1].directives["gzip"]; !ok {
		t.Fatalf("Expected scoped directive to be gzip, but got %d: %#v", dir, p.other[1].directives)
	}
}
