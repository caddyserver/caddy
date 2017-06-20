package requestid

import (
	"context"
	"net/http"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestRequestID(t *testing.T) {
	request, err := http.NewRequest("GET", "http://localhost/", nil)
	if err != nil {
		t.Fatal("Could not create HTTP request:", err)
	}

	reqid := UUID()

	c := context.WithValue(request.Context(), httpserver.RequestIDCtxKey, reqid)

	request = request.WithContext(c)

	// See caddyhttp/replacer.go
	value, _ := request.Context().Value(httpserver.RequestIDCtxKey).(string)

	if value == "" {
		t.Fatal("Request ID should not be empty")
	}

	if value != reqid {
		t.Fatal("Request ID does not match")
	}
}
