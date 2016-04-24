package setup

import (
	"fmt"
	"testing"

	"github.com/mholt/caddy/middleware/scgi"
)

func TestSCGI(t *testing.T) {

	c := NewTestController(`scgi / 127.0.0.1:4000`)

	mid, err := SCGI(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(scgi.Handler)

	if !ok {
		t.Fatalf("Expected handler to be type , got: %#v", handler)
	}

	if myHandler.Rules[0].Path != "/" {
		t.Errorf("Expected / as the Path")
	}
	if myHandler.Rules[0].Address != "127.0.0.1:4000" {
		t.Errorf("Expected 127.0.0.1:4000 as the Address")
	}

}

func TestScgiParse(t *testing.T) {
	tests := []struct {
		inputScgiConfig    string
		shouldErr             bool
		expectedScgiConfig []scgi.Rule
	}{

		{`scgi /blog 127.0.0.1:4000`,
			false, []scgi.Rule{{
				Path:       "/blog",
				Address:    "127.0.0.1:4000",
			}}},
		{`scgi / 127.0.0.1:4001 {
	              except /admin /user
	              }`,
			false, []scgi.Rule{{
				Path:            "/",
				Address:         "127.0.0.1:4001",
				IgnoredSubPaths: []string{"/admin", "/user"},
			}}},
	}
	for i, test := range tests {
		c := NewTestController(test.inputScgiConfig)
		actualScgiConfigs, err := scgiParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}
		if len(actualScgiConfigs) != len(test.expectedScgiConfig) {
			t.Fatalf("Test %d expected %d no of SCGI configs, but got %d ",
				i, len(test.expectedScgiConfig), len(actualScgiConfigs))
		}
		for j, actualScgiConfig := range actualScgiConfigs {

			if actualScgiConfig.Path != test.expectedScgiConfig[j].Path {
				t.Errorf("Test %d expected %dth SCGI Path to be  %s  , but got %s",
					i, j, test.expectedScgiConfig[j].Path, actualScgiConfig.Path)
			}

			if actualScgiConfig.Address != test.expectedScgiConfig[j].Address {
				t.Errorf("Test %d expected %dth SCGI Address to be  %s  , but got %s",
					i, j, test.expectedScgiConfig[j].Address, actualScgiConfig.Address)
			}

			if fmt.Sprint(actualScgiConfig.IgnoredSubPaths) != fmt.Sprint(test.expectedScgiConfig[j].IgnoredSubPaths) {
				t.Errorf("Test %d expected %dth SCGI IgnoredSubPaths to be  %s  , but got %s",
					i, j, test.expectedScgiConfig[j].IgnoredSubPaths, actualScgiConfig.IgnoredSubPaths)
			}
		}
	}

}
