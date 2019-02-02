// Copyright 2015 Light Code Labs, LLC
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

package fastcgi

import (
	"context"
	"fmt"
	"net"
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
	addr, err := myHandler.Rules[0].Address()
	if err != nil {
		t.Errorf("Unexpected error in trying to retrieve address: %s", err.Error())
	}

	if addr != "127.0.0.1:9000" {
		t.Errorf("Expected 127.0.0.1:9000 as the Address")
	}

	if myHandler.Rules[0].ConnectTimeout != 60*time.Second {
		t.Errorf("Expected default value of 60 seconds")
	}

	if myHandler.Rules[0].ReadTimeout != 60*time.Second {
		t.Errorf("Expected default value of 60 seconds")
	}

	if myHandler.Rules[0].SendTimeout != 60*time.Second {
		t.Errorf("Expected default value of 60 seconds")
	}
}

func TestFastcgiParse(t *testing.T) {
	tests := []struct {
		inputFastcgiConfig    string
		shouldErr             bool
		expectedFastcgiConfig []Rule
	}{

		{`fastcgi /blog 127.0.0.1:9000 php`,
			false, []Rule{{
				Path:        "/blog",
				balancer:    &roundRobin{addresses: []string{"127.0.0.1:9000"}},
				Ext:         ".php",
				SplitPath:   ".php",
				IndexFiles:  []string{"index.php"},
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi / 127.0.0.1:9001 {
	              split .html
	              }`,
			false, []Rule{{
				Path:        "/",
				balancer:    &roundRobin{addresses: []string{"127.0.0.1:9001"}},
				Ext:         "",
				SplitPath:   ".html",
				IndexFiles:  []string{},
				SendTimeout: 60 * time.Second,
			}}},
		{`fastcgi / 127.0.0.1:9001 {
	              split .html
	              except /admin /user
	              }`,
			false, []Rule{{
				Path:            "/",
				balancer:        &roundRobin{addresses: []string{"127.0.0.1:9001"}},
				Ext:             "",
				SplitPath:       ".html",
				IndexFiles:      []string{},
				IgnoredSubPaths: []string{"/admin", "/user"},
				SendTimeout:     60 * time.Second,
			}}},
		{`fastcgi / 127.0.0.1:9001 {
					send_timeout 30s
				}`,
			false, []Rule{{
				Path:        "/",
				balancer:    &roundRobin{addresses: []string{"127.0.0.1:9001"}},
				Ext:         "",
				IndexFiles:  []string{},
				SendTimeout: 30 * time.Second,
			}}},
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

			if actualFastcgiConfig.Path != test.expectedFastcgiConfig[j].Path {
				t.Errorf("Test %d expected %dth FastCGI Path to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].Path, actualFastcgiConfig.Path)
			}

			actualAddr, err := actualFastcgiConfig.Address()
			if err != nil {
				t.Errorf("Test %d unexpected error in trying to retrieve %dth actual address: %s", i, j, err.Error())
			}

			expectedAddr, err := test.expectedFastcgiConfig[j].Address()
			if err != nil {
				t.Errorf("Test %d unexpected error in trying to retrieve %dth expected address: %s", i, j, err.Error())
			}

			if actualAddr != expectedAddr {
				t.Errorf("Test %d expected %dth FastCGI Address to be  %s  , but got %s",
					i, j, expectedAddr, actualAddr)
			}

			if actualFastcgiConfig.Ext != test.expectedFastcgiConfig[j].Ext {
				t.Errorf("Test %d expected %dth FastCGI Ext to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].Ext, actualFastcgiConfig.Ext)
			}

			if actualFastcgiConfig.SplitPath != test.expectedFastcgiConfig[j].SplitPath {
				t.Errorf("Test %d expected %dth FastCGI SplitPath to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].SplitPath, actualFastcgiConfig.SplitPath)
			}

			if fmt.Sprint(actualFastcgiConfig.IndexFiles) != fmt.Sprint(test.expectedFastcgiConfig[j].IndexFiles) {
				t.Errorf("Test %d expected %dth FastCGI IndexFiles to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].IndexFiles, actualFastcgiConfig.IndexFiles)
			}

			if fmt.Sprint(actualFastcgiConfig.IgnoredSubPaths) != fmt.Sprint(test.expectedFastcgiConfig[j].IgnoredSubPaths) {
				t.Errorf("Test %d expected %dth FastCGI IgnoredSubPaths to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].IgnoredSubPaths, actualFastcgiConfig.IgnoredSubPaths)
			}

			if actualFastcgiConfig.SendTimeout != test.expectedFastcgiConfig[j].SendTimeout {
				t.Errorf("Test %d expected %dth FastCGI SendTimeout to be %s   , but got %s",
					i, j, test.expectedFastcgiConfig[j].SendTimeout, actualFastcgiConfig.SendTimeout)
			}
		}
	}

}

func TestFastCGIResolveSRV(t *testing.T) {
	tests := []struct {
		inputFastcgiConfig string
		locator            string
		target             string
		port               uint16
		shouldErr          bool
	}{
		{
			`fastcgi / srv://fpm.tcp.service.consul {
				upstream yolo
			}`,
			"fpm.tcp.service.consul",
			"127.0.0.1",
			9000,
			true,
		},
		{
			`fastcgi / srv://fpm.tcp.service.consul`,
			"fpm.tcp.service.consul",
			"127.0.0.1",
			9000,
			false,
		},
	}

	for i, test := range tests {
		actualFastcgiConfigs, err := fastcgiParse(caddy.NewTestController("http", test.inputFastcgiConfig))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}

		for _, actualFastcgiConfig := range actualFastcgiConfigs {
			resolver, ok := (actualFastcgiConfig.balancer).(*srv)
			if !ok {
				t.Errorf("Test %d upstream balancer is not srv", i)
			}
			resolver.resolver = buildTestResolver(test.target, test.port)

			addr, err := actualFastcgiConfig.Address()
			if err != nil {
				t.Errorf("Test %d failed to retrieve upstream address. %s", i, err.Error())
			}

			expectedAddr := fmt.Sprintf("%s:%d", test.target, test.port)
			if addr != expectedAddr {
				t.Errorf("Test %d expected upstream address to be %s, got %s", i, expectedAddr, addr)
			}
		}
	}
}

func buildTestResolver(target string, port uint16) srvResolver {
	return &testSRVResolver{target, port}
}

type testSRVResolver struct {
	target string
	port   uint16
}

func (r *testSRVResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	return "", []*net.SRV{
		{Target: r.target,
			Port:     r.port,
			Priority: 1,
			Weight:   1}}, nil
}
