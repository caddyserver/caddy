package proxy

import (
	"reflect"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	for i, test := range []struct {
		input         string
		shouldErr     bool
		expectedHosts map[string]struct{}
	}{
		// test #0 test usual to destination still works normally
		{
			"proxy / localhost:80",
			false,
			map[string]struct{}{
				"http://localhost:80": {},
			},
		},

		// test #1 test usual to destination with port range
		{
			"proxy / localhost:8080-8082",
			false,
			map[string]struct{}{
				"http://localhost:8080": {},
				"http://localhost:8081": {},
				"http://localhost:8082": {},
			},
		},

		// test #2 test upstream directive
		{
			"proxy / {\n upstream localhost:8080\n}",
			false,
			map[string]struct{}{
				"http://localhost:8080": {},
			},
		},

		// test #3 test upstream directive with port range
		{
			"proxy / {\n upstream localhost:8080-8081\n}",
			false,
			map[string]struct{}{
				"http://localhost:8080": {},
				"http://localhost:8081": {},
			},
		},

		// test #4 test to destination with upstream directive
		{
			"proxy / localhost:8080 {\n upstream localhost:8081-8082\n}",
			false,
			map[string]struct{}{
				"http://localhost:8080": {},
				"http://localhost:8081": {},
				"http://localhost:8082": {},
			},
		},

		// test #5 test with unix sockets
		{
			"proxy / localhost:8080 {\n upstream unix:/var/foo\n}",
			false,
			map[string]struct{}{
				"http://localhost:8080": {},
				"unix:/var/foo":         {},
			},
		},

		// test #6 test fail on malformed port range
		{
			"proxy / localhost:8090-8080",
			true,
			nil,
		},

		// test #7 test fail on malformed port range 2
		{
			"proxy / {\n upstream localhost:80-A\n}",
			true,
			nil,
		},

		// test #8 test upstreams without ports work correctly
		{
			"proxy / http://localhost {\n upstream testendpoint\n}",
			false,
			map[string]struct{}{
				"http://localhost":    {},
				"http://testendpoint": {},
			},
		},

		// test #9 test several upstream directives
		{
			"proxy / localhost:8080 {\n upstream localhost:8081-8082\n upstream localhost:8083-8085\n}",
			false,
			map[string]struct{}{
				"http://localhost:8080": {},
				"http://localhost:8081": {},
				"http://localhost:8082": {},
				"http://localhost:8083": {},
				"http://localhost:8084": {},
				"http://localhost:8085": {},
			},
		},
		// test #10 test hyphen without port range
		{
			"proxy / http://localhost:8001/a--b",
			false,
			map[string]struct{}{
				"http://localhost:8001/a--b": {},
			},
		},
		// test #11 test hyphen with port range
		{
			"proxy / http://localhost:8001-8005/a--b",
			false,
			map[string]struct{}{
				"http://localhost:8001/a--b": {},
				"http://localhost:8002/a--b": {},
				"http://localhost:8003/a--b": {},
				"http://localhost:8004/a--b": {},
				"http://localhost:8005/a--b": {},
			},
		},
		// test #12 test value is optional when remove upstream header
		{
			"proxy / localhost:1984 {\n header_upstream -server \n}",
			false,
			map[string]struct{}{
				"http://localhost:1984": {},
			},
		},
		// test #13 test value is optional when remove downstream header
		{
			"proxy / localhost:1984 {\n header_downstream -server \n}",
			false,
			map[string]struct{}{
				"http://localhost:1984": {},
			},
		},
	} {
		c := caddy.NewTestController("http", test.input)
		err := setup(c)
		if err != nil && !test.shouldErr {
			t.Errorf("Test case #%d received an error of %v", i, err)
		} else if test.shouldErr {
			continue
		}

		mids := httpserver.GetConfig(c).Middleware()
		mid := mids[len(mids)-1]

		upstreams := mid(nil).(Proxy).Upstreams
		for _, upstream := range upstreams {
			val := reflect.ValueOf(upstream).Elem()
			hosts := val.FieldByName("Hosts").Interface().(HostPool)
			if len(hosts) != len(test.expectedHosts) {
				t.Errorf("Test case #%d expected %d hosts but received %d", i, len(test.expectedHosts), len(hosts))
			} else {
				for _, host := range hosts {
					if _, found := test.expectedHosts[host.Name]; !found {
						t.Errorf("Test case #%d has an unexpected host %s", i, host.Name)
					}
				}
			}
		}
	}
}
