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
		reqURI  string
		expect  map[string]any
	}{
		{
			reqURI: "/foo",
			handler: Handler{
				Source:       "{http.request.uri.path}",
				Destinations: []string{"{output}"},
				Mappings: []Mapping{
					{
						Input:   "/foo",
						Outputs: []any{"FOO"},
					},
				},
			},
			expect: map[string]any{
				"output": "FOO",
			},
		},
		{
			reqURI: "/abcdef",
			handler: Handler{
				Source:       "{http.request.uri.path}",
				Destinations: []string{"{output}"},
				Mappings: []Mapping{
					{
						InputRegexp: "(/abc)",
						Outputs:     []any{"ABC"},
					},
				},
			},
			expect: map[string]any{
				"output": "ABC",
			},
		},
		{
			reqURI: "/ABCxyzDEF",
			handler: Handler{
				Source:       "{http.request.uri.path}",
				Destinations: []string{"{output}"},
				Mappings: []Mapping{
					{
						InputRegexp: "(xyz)",
						Outputs:     []any{"...${1}..."},
					},
				},
			},
			expect: map[string]any{
				"output": "...xyz...",
			},
		},
		{
			// Test case from https://caddy.community/t/map-directive-and-regular-expressions/13866/14?u=matt
			reqURI: "/?s=0%27+AND+%28SELECT+0+FROM+%28SELECT+count%28%2A%29%2C+CONCAT%28%28SELECT+%40%40version%29%2C+0x23%2C+FLOOR%28RAND%280%29%2A2%29%29+AS+x+FROM+information_schema.columns+GROUP+BY+x%29+y%29+-+-+%27",
			handler: Handler{
				Source:       "{http.request.uri}",
				Destinations: []string{"{output}"},
				Mappings: []Mapping{
					{
						InputRegexp: "(?i)(\\^|`|<|>|%|\\\\|\\{|\\}|\\|)",
						Outputs:     []any{"3"},
					},
				},
			},
			expect: map[string]any{
				"output": "3",
			},
		},
		{
			reqURI: "/foo",
			handler: Handler{
				Source:       "{http.request.uri.path}",
				Destinations: []string{"{output}"},
				Mappings: []Mapping{
					{
						Input:   "/foo",
						Outputs: []any{"{testvar}"},
					},
				},
			},
			expect: map[string]any{
				"output": "testing",
			},
		},
		{
			reqURI: "/foo",
			handler: Handler{
				Source:       "{http.request.uri.path}",
				Destinations: []string{"{output}"},
				Defaults:     []string{"default"},
			},
			expect: map[string]any{
				"output": "default",
			},
		},
		{
			reqURI: "/foo",
			handler: Handler{
				Source:       "{http.request.uri.path}",
				Destinations: []string{"{output}"},
				Defaults:     []string{"{testvar}"},
			},
			expect: map[string]any{
				"output": "testing",
			},
		},
	} {
		if err := tc.handler.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Test %d: Provisioning handler: %v", i, err)
		}

		req, err := http.NewRequest(http.MethodGet, tc.reqURI, nil)
		if err != nil {
			t.Fatalf("Test %d: Creating request: %v", i, err)
		}
		repl := caddyhttp.NewTestReplacer(req)
		repl.Set("testvar", "testing")
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
