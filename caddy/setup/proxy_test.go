package setup

import (
	"reflect"
	"testing"

	"github.com/mholt/caddy/middleware/proxy"
)

func TestUpstream(t *testing.T) {
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
				"http://localhost:80": struct{}{},
			},
		},

		// test #1 test usual to destination with port range
		{
			"proxy / localhost:8080-8082",
			false,
			map[string]struct{}{
				"http://localhost:8080": struct{}{},
				"http://localhost:8081": struct{}{},
				"http://localhost:8082": struct{}{},
			},
		},

		// test #2 test upstream directive
		{
			"proxy / {\n upstream localhost:8080\n}",
			false,
			map[string]struct{}{
				"http://localhost:8080": struct{}{},
			},
		},

		// test #3 test upstream directive with port range
		{
			"proxy / {\n upstream localhost:8080-8081\n}",
			false,
			map[string]struct{}{
				"http://localhost:8080": struct{}{},
				"http://localhost:8081": struct{}{},
			},
		},

		// test #4 test to destination with upstream directive
		{
			"proxy / localhost:8080 {\n upstream localhost:8081-8082\n}",
			false,
			map[string]struct{}{
				"http://localhost:8080": struct{}{},
				"http://localhost:8081": struct{}{},
				"http://localhost:8082": struct{}{},
			},
		},

		// test #5 test with unix sockets
		{
			"proxy / localhost:8080 {\n upstream unix:/var/foo\n}",
			false,
			map[string]struct{}{
				"http://localhost:8080": struct{}{},
				"unix:/var/foo":         struct{}{},
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
				"http://localhost":    struct{}{},
				"http://testendpoint": struct{}{},
			},
		},
	} {
		receivedFunc, err := Proxy(NewTestController(test.input))
		if err != nil && !test.shouldErr {
			t.Errorf("Test case #%d received an error of %v", i, err)
		} else if test.shouldErr {
			continue
		}

		upstreams := receivedFunc(nil).(proxy.Proxy).Upstreams
		for _, upstream := range upstreams {
			val := reflect.ValueOf(upstream).Elem()
			hosts := val.FieldByName("Hosts").Interface().(proxy.HostPool)
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
