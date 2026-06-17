package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestClientDisconnectRecordsStatus verifies that when the downstream client
// disconnects (its request context is canceled) before the upstream sends any
// response headers, the recorded status is 499 ("client closed request")
// rather than 0.
func TestClientDisconnectRecordsStatus(t *testing.T) {
	// backend that blocks until the client goes away, so it never gets
	// the chance to send response headers
	gotRequest := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(gotRequest)
		<-r.Context().Done()
	}))
	defer backend.Close()

	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backend.Listener.Addr().String(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).WithContext(ctx)
	req = prepareTestRequest(req)

	rec := caddyhttp.NewResponseRecorder(httptest.NewRecorder(), nil, nil)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			return nil
		}))
	}()

	<-gotRequest
	cancel()
	wg.Wait()

	if got := rec.Status(); got != 499 {
		t.Errorf("expected status 499 after client disconnect, got %d", got)
	}
}
