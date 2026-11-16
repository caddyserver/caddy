package caddyhttp

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestServerRequestTargetForms(t *testing.T) {
	for _, tc := range []struct {
		method, target string
		code           int
		routed         bool
	}{
		{http.MethodGet, "/public", http.StatusOK, true},
		{http.MethodGet, "/admin/secret", http.StatusUnauthorized, true},
		{http.MethodGet, "http://public.example/public", http.StatusOK, true},
		{http.MethodGet, "http://public.example/admin/secret", http.StatusUnauthorized, true},
		{http.MethodConnect, "public.example:443", http.StatusOK, true},
		{http.MethodOptions, "*", http.StatusOK, true},
		{http.MethodGet, "http:http://upstream.example/admin/secret", http.StatusBadRequest, false},
		{http.MethodGet, "http:http://private.example/secret", http.StatusBadRequest, false},
		{http.MethodGet, "http:secret", http.StatusBadRequest, false},
	} {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			raw := tc.method + " " + tc.target + " HTTP/1.1\r\nHost: public.example\r\n\r\n"
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
			if err != nil {
				t.Fatal(err)
			}
			defer req.Body.Close()
			routed := false
			server := &Server{
				logger: zap.NewNop(), errorLogger: zap.NewNop(), accessLogger: zap.NewNop(),
				Errors: &HTTPErrorConfig{Routes: RouteList{{}}},
				errorHandlerChain: HandlerFunc(func(http.ResponseWriter, *http.Request) error {
					t.Fatal("opaque target reached error routes")
					return nil
				}),
				primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, req *http.Request) error {
					routed = true
					if (MatchPath{"/admin/*"}).Match(req) {
						w.WriteHeader(http.StatusUnauthorized)
					} else {
						w.WriteHeader(http.StatusOK)
					}
					return nil
				}),
			}
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			if rec.Code != tc.code || routed != tc.routed {
				t.Fatalf("got status=%d routed=%v, want status=%d routed=%v", rec.Code, routed, tc.code, tc.routed)
			}
		})
	}
}
