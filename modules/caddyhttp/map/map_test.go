package maphandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestHandler(t *testing.T) {
	for i, tc := range []struct {
		handler Handler
		reqPath string
		expect  map[string]interface{}
	}{
		{
			reqPath: "/foo",
			handler: Handler{
				Source:       "{http.request.uri.path}",
				Destinations: []string{"{output}"},
				Mappings: []Mapping{
					{
						Input:   "/foo",
						Outputs: []interface{}{"FOO"},
					},
				},
			},
			expect: map[string]interface{}{
				"output": "FOO",
			},
		},
		{
			reqPath: "/abcdef",
			handler: Handler{
				Source:       "{http.request.uri.path}",
				Destinations: []string{"{output}"},
				Mappings: []Mapping{
					{
						InputRegexp: "(/abc)",
						Outputs:     []interface{}{"ABC"},
					},
				},
			},
			expect: map[string]interface{}{
				"output": "ABC",
			},
		},
		{
			reqPath: "/ABCxyzDEF",
			handler: Handler{
				Source:       "{http.request.uri.path}",
				Destinations: []string{"{output}"},
				Mappings: []Mapping{
					{
						InputRegexp: "(xyz)",
						Outputs:     []interface{}{"...${1}..."},
					},
				},
			},
			expect: map[string]interface{}{
				"output": "...xyz...",
			},
		},
	} {
		if err := tc.handler.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Test %d: Provisioning handler: %v", i, err)
		}

		req, err := http.NewRequest(http.MethodGet, tc.reqPath, nil)
		if err != nil {
			t.Fatalf("Test %d: Creating request: %v", i, err)
		}
		repl := caddyhttp.NewTestReplacer(req)
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		noop := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error { return nil })

		if err := tc.handler.ServeHTTP(rr, req, noop); err != nil {
			t.Errorf("Test %d: Handler returned error: %v", i, err)
			continue
		}

		for key, expected := range tc.expect {
			actual, _ := repl.Get(key)
			if !reflect.DeepEqual(actual, expected) {
				t.Errorf("Test %d: Expected %#v but got %#v for {%s}", i, expected, actual, key)
			}
		}
	}
}
