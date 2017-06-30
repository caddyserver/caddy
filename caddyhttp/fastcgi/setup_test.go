package fastcgi

import (
	"fmt"
	"testing"

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
	if myHandler.Rules[0].Address() != "127.0.0.1:9000" {
		t.Errorf("Expected 127.0.0.1:9000 as the Address")
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
				Path:       "/blog",
				balancer:   &roundRobin{addresses: []string{"127.0.0.1:9000"}},
				Ext:        ".php",
				SplitPath:  ".php",
				IndexFiles: []string{"index.php"},
			}}},
		{`fastcgi / 127.0.0.1:9001 {
	              split .html
	              }`,
			false, []Rule{{
				Path:       "/",
				balancer:   &roundRobin{addresses: []string{"127.0.0.1:9001"}},
				Ext:        "",
				SplitPath:  ".html",
				IndexFiles: []string{},
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

			if actualFastcgiConfig.Address() != test.expectedFastcgiConfig[j].Address() {
				t.Errorf("Test %d expected %dth FastCGI Address to be  %s  , but got %s",
					i, j, test.expectedFastcgiConfig[j].Address(), actualFastcgiConfig.Address())
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
		}
	}

}
