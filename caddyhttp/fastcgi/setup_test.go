package fastcgi

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `fastcgi / 127.0.0.1:9000`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Handler)

	if !ok {
		t.Fatalf("Expected handler to be type , got: %#v", handler)
	}

	if myHandler.Rules[0].Path != "/" {
		t.Errorf("Expected / as the Path")
	}
	if myHandler.Rules[0].Address != "127.0.0.1:9000" {
		t.Errorf("Expected 127.0.0.1:9000 as the Address")
	}

}

func (p *persistentDialer) Equals(q *persistentDialer) bool {
	if p.size != q.size {
		return false
	}
	if p.network != q.network {
		return false
	}
	if p.address != q.address {
		return false
	}

	if len(p.pool) != len(q.pool) {
		return false
	}
	for i, client := range p.pool {
		if client != q.pool[i] {
			return false
		}
	}
	// ignore mutex state
	return true
}

func TestFastcgiParse(t *testing.T) {
	rootPath, err := os.Getwd()
	if err != nil {
		t.Errorf("Can't determine current working directory; got '%v'", err)
	}

	defaultAddress := "127.0.0.1:9001"
	network, address := parseAddress(defaultAddress)
	t.Logf("Address '%v' was parsed to network '%v' and address '%v'", defaultAddress, network, address)

	tests := []struct {
		inputFastcgiConfig    string
		shouldErr             bool
		expectedFastcgiConfig []Rule
	}{

		{`fastcgi /blog 127.0.0.1:9000 php`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/blog",
				Address:     "127.0.0.1:9000",
				Ext:         ".php",
				SplitPath:   ".php",
				dialer:      &loadBalancingDialer{dialers: []dialer{basicDialer{network: "tcp", address: "127.0.0.1:9000", timeout: 60 * time.Second}}},
				IndexFiles:  []string{"index.php"},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi /blog 127.0.0.1:9000 php {
			root /tmp
		}`,
			false, []Rule{{
				Root:        "/tmp",
				Path:        "/blog",
				Address:     "127.0.0.1:9000",
				Ext:         ".php",
				SplitPath:   ".php",
				dialer:      &loadBalancingDialer{dialers: []dialer{basicDialer{network: "tcp", address: "127.0.0.1:9000", timeout: 60 * time.Second}}},
				IndexFiles:  []string{"index.php"},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi /blog 127.0.0.1:9000 php {
			upstream 127.0.0.1:9001
		}`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/blog",
				Address:     "127.0.0.1:9000,127.0.0.1:9001",
				Ext:         ".php",
				SplitPath:   ".php",
				dialer:      &loadBalancingDialer{dialers: []dialer{basicDialer{network: "tcp", address: "127.0.0.1:9000", timeout: 60 * time.Second}, basicDialer{network: "tcp", address: "127.0.0.1:9001", timeout: 60 * time.Second}}},
				IndexFiles:  []string{"index.php"},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi /blog 127.0.0.1:9000 {
			upstream 127.0.0.1:9001 
		}`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/blog",
				Address:     "127.0.0.1:9000,127.0.0.1:9001",
				Ext:         "",
				SplitPath:   "",
				dialer:      &loadBalancingDialer{dialers: []dialer{basicDialer{network: "tcp", address: "127.0.0.1:9000", timeout: 60 * time.Second}, basicDialer{network: "tcp", address: "127.0.0.1:9001", timeout: 60 * time.Second}}},
				IndexFiles:  []string{},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi / ` + defaultAddress + ` {
	              split .html
	              }`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/",
				Address:     defaultAddress,
				Ext:         "",
				SplitPath:   ".html",
				dialer:      &loadBalancingDialer{dialers: []dialer{basicDialer{network: network, address: address, timeout: 60 * time.Second}}},
				IndexFiles:  []string{},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi / ` + defaultAddress + ` {
	              split .html
	              except /admin /user
	              }`,
			false, []Rule{{
				Root:            rootPath,
				Path:            "/",
				Address:         "127.0.0.1:9001",
				Ext:             "",
				SplitPath:       ".html",
				dialer:          &loadBalancingDialer{dialers: []dialer{basicDialer{network: network, address: address, timeout: 60 * time.Second}}},
				IndexFiles:      []string{},
				IgnoredSubPaths: []string{"/admin", "/user"},
				ReadTimeout:     60 * time.Second,
				SendTimeout:     60 * time.Second,
			}}},
		{`fastcgi / ` + defaultAddress + ` {
	              pool 0
	              }`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/",
				Address:     defaultAddress,
				Ext:         "",
				SplitPath:   "",
				dialer:      &loadBalancingDialer{dialers: []dialer{&persistentDialer{size: 0, network: network, address: address, timeout: 60 * time.Second}}},
				IndexFiles:  []string{},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi / 127.0.0.1:8080  {
			upstream 127.0.0.1:9000
	              pool 5
	              }`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/",
				Address:     "127.0.0.1:8080,127.0.0.1:9000",
				Ext:         "",
				SplitPath:   "",
				dialer:      &loadBalancingDialer{dialers: []dialer{&persistentDialer{size: 5, network: "tcp", address: "127.0.0.1:8080", timeout: 60 * time.Second}, &persistentDialer{size: 5, network: "tcp", address: "127.0.0.1:9000", timeout: 60 * time.Second}}},
				IndexFiles:  []string{},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi / ` + defaultAddress + ` {
	              split .php
	              }`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/",
				Address:     defaultAddress,
				Ext:         "",
				SplitPath:   ".php",
				dialer:      &loadBalancingDialer{dialers: []dialer{basicDialer{network: network, address: address, timeout: 60 * time.Second}}},
				IndexFiles:  []string{},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi / ` + defaultAddress + ` {
	              connect_timeout 5s
	              }`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/",
				Address:     defaultAddress,
				Ext:         "",
				SplitPath:   "",
				dialer:      &loadBalancingDialer{dialers: []dialer{basicDialer{network: network, address: address, timeout: 5 * time.Second}}},
				IndexFiles:  []string{},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{
			`fastcgi / ` + defaultAddress + ` { connect_timeout BADVALUE }`,
			true,
			[]Rule{},
		},
		{`fastcgi / ` + defaultAddress + ` {
	              read_timeout 5s
	              }`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/",
				Address:     defaultAddress,
				Ext:         "",
				SplitPath:   "",
				dialer:      &loadBalancingDialer{dialers: []dialer{basicDialer{network: network, address: address, timeout: 60 * time.Second}}},
				IndexFiles:  []string{},
				ReadTimeout: 5 * time.Second,
				SendTimeout: 60 * time.Second,
			}}},
		{
			`fastcgi / ` + defaultAddress + ` { read_timeout BADVALUE }`,
			true,
			[]Rule{},
		},
		{`fastcgi / ` + defaultAddress + ` {
	              send_timeout 5s
	              }`,
			false, []Rule{{
				Root:        rootPath,
				Path:        "/",
				Address:     defaultAddress,
				Ext:         "",
				SplitPath:   "",
				dialer:      &loadBalancingDialer{dialers: []dialer{basicDialer{network: network, address: address, timeout: 60 * time.Second}}},
				IndexFiles:  []string{},
				ReadTimeout: 60 * time.Second,
				SendTimeout: 5 * time.Second,
			}}},
		{
			`fastcgi / ` + defaultAddress + ` { send_timeout BADVALUE }`,
			true,
			[]Rule{},
		},
		{`fastcgi / {

		              }`,
			true, []Rule{},
		},
	}
	for i, test := range tests {
		actualFastcgiConfigs, err := fastcgiParse(caddy.NewTestController("http", test.inputFastcgiConfig))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}
		if len(actualFastcgiConfigs) != len(test.expectedFastcgiConfig) {
			t.Fatalf("Test %d expected %d no of FastCGI configs, but got %d ",
				i, len(test.expectedFastcgiConfig), len(actualFastcgiConfigs))
		}
		for j, actualFastcgiConfig := range actualFastcgiConfigs {

			if actualFastcgiConfig.Root != test.expectedFastcgiConfig[j].Root {
				t.Errorf("Test %d expected %dth FastCGI Root to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].Root, actualFastcgiConfig.Root)
			}

			if actualFastcgiConfig.Path != test.expectedFastcgiConfig[j].Path {
				t.Errorf("Test %d expected %dth FastCGI Path to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].Path, actualFastcgiConfig.Path)
			}

			if actualFastcgiConfig.Address != test.expectedFastcgiConfig[j].Address {
				t.Errorf("Test %d expected %dth FastCGI Address to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].Address, actualFastcgiConfig.Address)
			}

			if actualFastcgiConfig.Ext != test.expectedFastcgiConfig[j].Ext {
				t.Errorf("Test %d expected %dth FastCGI Ext to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].Ext, actualFastcgiConfig.Ext)
			}

			if actualFastcgiConfig.SplitPath != test.expectedFastcgiConfig[j].SplitPath {
				t.Errorf("Test %d expected %dth FastCGI SplitPath to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].SplitPath, actualFastcgiConfig.SplitPath)
			}

			if reflect.TypeOf(actualFastcgiConfig.dialer) != reflect.TypeOf(test.expectedFastcgiConfig[j].dialer) {
				t.Errorf("Test %d expected %dth FastCGI dialer to be of type %T, but got %T",
					i, j, test.expectedFastcgiConfig[j].dialer, actualFastcgiConfig.dialer)
			} else {
				if !areDialersEqual(actualFastcgiConfig.dialer, test.expectedFastcgiConfig[j].dialer, t) {
					t.Errorf("Test %d expected %dth FastCGI dialer to be %v, but got %v",
						i, j, test.expectedFastcgiConfig[j].dialer, actualFastcgiConfig.dialer)
				}
			}

			if fmt.Sprint(actualFastcgiConfig.IndexFiles) != fmt.Sprint(test.expectedFastcgiConfig[j].IndexFiles) {
				t.Errorf("Test %d expected %dth FastCGI IndexFiles to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].IndexFiles, actualFastcgiConfig.IndexFiles)
			}

			if fmt.Sprint(actualFastcgiConfig.IgnoredSubPaths) != fmt.Sprint(test.expectedFastcgiConfig[j].IgnoredSubPaths) {
				t.Errorf("Test %d expected %dth FastCGI IgnoredSubPaths to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].IgnoredSubPaths, actualFastcgiConfig.IgnoredSubPaths)
			}

			if fmt.Sprint(actualFastcgiConfig.ReadTimeout) != fmt.Sprint(test.expectedFastcgiConfig[j].ReadTimeout) {
				t.Errorf("Test %d expected %dth FastCGI ReadTimeout to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].ReadTimeout, actualFastcgiConfig.ReadTimeout)
			}

			if fmt.Sprint(actualFastcgiConfig.SendTimeout) != fmt.Sprint(test.expectedFastcgiConfig[j].SendTimeout) {
				t.Errorf("Test %d expected %dth FastCGI SendTimeout to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].SendTimeout, actualFastcgiConfig.SendTimeout)
			}
		}
	}
}

func areDialersEqual(current, expected dialer, t *testing.T) bool {

	switch actual := current.(type) {
	case *loadBalancingDialer:
		if expected, ok := expected.(*loadBalancingDialer); ok {
			for i := 0; i < len(actual.dialers); i++ {
				if !areDialersEqual(actual.dialers[i], expected.dialers[i], t) {
					return false
				}
			}

			return true
		}
	case basicDialer:
		return current == expected
	case *persistentDialer:
		if expected, ok := expected.(*persistentDialer); ok {
			return actual.Equals(expected)
		}

	default:
		t.Errorf("Unknown dialer type %T", current)
	}

	return false
}
