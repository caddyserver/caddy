package httpcaddyfile_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
)

func TestNamedRouteGroupsAreDistinct(t *testing.T) {
	for _, tc := range []struct {
		name, named, site string
	}{
		{
			name: "handle",
			named: `&(guard) {
	handle /api/admin {
		respond "denied" 403
	}
	handle {
		respond "public"
	}
}`,
			site: `handle /api/* {
	invoke guard
	respond "allowed"
}`,
		},
		{
			name: "handle_path",
			named: `&(guard) {
	handle /admin {
		respond "denied" 403
	}
	handle {
		respond "public"
	}
}`,
			site: `handle_path /api/* {
	invoke guard
	respond "allowed"
}`,
		},
		{
			name: "nested invoke",
			named: `&(inner) {
	handle /api/admin {
		respond "denied" 403
	}
	handle {
		respond "public"
	}
}
&(guard) {
	handle /api/* {
		invoke inner
	}
	handle {
		respond "outer"
	}
}`,
			site: `handle /api/* {
	invoke guard
	respond "allowed"
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, handler := adaptedRouteHandler(t, "{\nadmin off\nauto_https off\n}\n"+tc.named+"\n:9080 {\n"+tc.site+`
	handle {
		respond "fallback" 404
	}
}`)
			for _, request := range []struct {
				path string
				code int
				body string
			}{
				{"/api/admin", http.StatusForbidden, "denied"},
				{"/api/public", http.StatusOK, "public"},
				{"/other", http.StatusNotFound, "fallback"},
			} {
				req := httptest.NewRequest(http.MethodGet, request.path, nil)
				req = caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, server)
				rec := httptest.NewRecorder()
				if err := handler.ServeHTTP(rec, req); err != nil {
					t.Fatal(err)
				}
				if rec.Code != request.code || rec.Body.String() != request.body {
					t.Errorf("%s: got %d %q, want %d %q", request.path, rec.Code, rec.Body.String(), request.code, request.body)
				}
			}
		})
	}
}
