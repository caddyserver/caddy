package httpcaddyfile_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

func adaptedRouteHandler(t *testing.T, input string) (*caddyhttp.Server, caddyhttp.Handler) {
	t.Helper()
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
	data, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Apps struct {
			HTTP struct {
				Servers map[string]*caddyhttp.Server `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Apps.HTTP.Servers) != 1 {
		t.Fatalf("expected one server, got %s", data)
	}
	for _, server := range config.Apps.HTTP.Servers {
		ctx, cancel := caddy.NewContext(caddy.Context{
			Context: context.WithValue(context.Background(), caddyhttp.ServerCtxKey, server),
		})
		t.Cleanup(cancel)
		for _, route := range server.NamedRoutes {
			if err := route.Provision(ctx, nil); err != nil {
				t.Fatal(err)
			}
		}
		if err := server.Routes.Provision(ctx); err != nil {
			t.Fatal(err)
		}
		return server, server.Routes.Compile(caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			_, err := w.Write([]byte("next"))
			return err
		}))
	}
	t.Fatal("no server")
	return nil, nil
}

func TestNamedRoutePreservesHandlers(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("synthetic"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	server, handler := adaptedRouteHandler(t, fmt.Sprintf(`{
	admin off
	auto_https off
}
&(protected) {
	header X-Test retained
	basic_auth {
		alice %s
	}
}
:9080 {
	invoke protected
	respond "protected"
}`, hash))
	if got := len(server.NamedRoutes["protected"].Handlers); got != 2 {
		t.Fatalf("named route has %d handlers, want header and authentication", got)
	}
	for _, authenticated := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if authenticated {
			req.SetBasicAuth("alice", "synthetic")
		}
		req = caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, server)
		rec := httptest.NewRecorder()
		err := handler.ServeHTTP(rec, req)
		if authenticated {
			if err != nil || rec.Body.String() != "protected" {
				t.Fatalf("authenticated request: body=%q error=%v", rec.Body.String(), err)
			}
		} else if herr, ok := err.(caddyhttp.HandlerError); !ok || herr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated request was not rejected: %v", err)
		}
		if rec.Header().Get("X-Test") != "retained" {
			t.Fatal("header handler did not run")
		}
	}
}
