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
			  tls cert.pem key.pem`

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

func TestParserBasicWithMultipleHosts(t *testing.T) {
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
		t.Fatalf("Expected 2 configurations, but got '%d': %#v", len(confs), confs)
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
