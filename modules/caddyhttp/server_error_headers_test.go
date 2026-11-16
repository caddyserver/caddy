package caddyhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestServerErrorRoutesReceiveSanitizedHeaders(t *testing.T) {
	for _, invalid := range []string{"method", "missing host", "invalid host"} {
		t.Run(invalid, func(t *testing.T) {
			reachedErrorRoute := false
			server := &Server{
				logger: zap.NewNop(), errorLogger: zap.NewNop(), accessLogger: zap.NewNop(),
				Errors: &HTTPErrorConfig{Routes: RouteList{{}}},
				primaryHandlerChain: HandlerFunc(func(http.ResponseWriter, *http.Request) error {
					t.Fatal("invalid request reached primary routes")
					return nil
				}),
				errorHandlerChain: HandlerFunc(func(w http.ResponseWriter, req *http.Request) error {
					reachedErrorRoute = true
					if req.Header.Get("Authorization") != "synthetic" {
						t.Fatal("normal authorization header was removed")
					}
					// Stand in for a trusted authentication response copied into the request.
					req.Header.Set("Remote-User", "alice")
					var users []string
					for name, values := range req.Header {
						if strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToUpper(name)) == "REMOTE_USER" {
							users = append(users, values...)
						}
					}
					if len(users) != 1 || users[0] != "alice" {
						t.Fatalf("backend identity collision: %v", users)
					}
					w.WriteHeader(http.StatusForbidden)
					return nil
				}),
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "synthetic")
			req.Header.Set("Remote_user", "admin")
			req.Header.Set("Remote.user", "admin")
			req.Header.Set("Remote_.user", "admin")
			switch invalid {
			case "method":
				req.Method = strings.Repeat("A", 33)
			case "missing host":
				req.Host = ""
			case "invalid host":
				req.Host = "..."
			}
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			if !reachedErrorRoute || rec.Code != http.StatusForbidden {
				t.Fatalf("error route not reached: status %d", rec.Code)
			}
		})
	}
}
