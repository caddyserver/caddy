package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestUpstreamClientSpans(t *testing.T) {
	var gotTraceparent []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = append(gotTraceparent, r.Header.Get("Traceparent"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	t.Run("traced request", func(t *testing.T) {
		gotTraceparent = nil
		recorder := tracetest.NewSpanRecorder()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
		t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

		// round robin selects index 1 first, which refuses connections, so
		// the retry produces a second client span under the same server span
		h := minimalHandler(1,
			&Upstream{Host: new(Host), Dial: upstream.Listener.Addr().String()},
			&Upstream{Host: new(Host), Dial: deadUpstreamAddr(t)},
		)
		h.tracedTransport = newTracedTransport(h.Transport)

		ctx, serverSpan := tp.Tracer("test").Start(context.Background(), "server",
			trace.WithSpanKind(trace.SpanKindServer))
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).WithContext(ctx)
		req = prepareTestRequest(req)
		rec := httptest.NewRecorder()
		if err := h.ServeHTTP(rec, req, nil); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		serverSpan.End()

		var clientSpans []sdktrace.ReadOnlySpan
		for _, s := range recorder.Ended() {
			if s.SpanKind() == trace.SpanKindClient {
				clientSpans = append(clientSpans, s)
			}
		}
		if len(clientSpans) != 2 {
			t.Fatalf("expected 2 client spans, got %d", len(clientSpans))
		}
		for i, s := range clientSpans {
			if s.Parent().SpanID() != serverSpan.SpanContext().SpanID() {
				t.Errorf("client span %d: parent is not the server span", i)
			}
		}
		if clientSpans[0].Status().Code != codes.Error {
			t.Errorf("expected failed attempt to have error status, got %v", clientSpans[0].Status().Code)
		}

		if len(gotTraceparent) != 1 {
			t.Fatalf("expected 1 upstream request, got %d", len(gotTraceparent))
		}
		want := clientSpans[1].SpanContext().SpanID().String()
		if !strings.Contains(gotTraceparent[0], want) {
			t.Errorf("upstream traceparent %q does not reference client span %s", gotTraceparent[0], want)
		}
	})

	t.Run("untraced request", func(t *testing.T) {
		gotTraceparent = nil
		h := minimalHandler(0, &Upstream{Host: new(Host), Dial: upstream.Listener.Addr().String()})
		h.tracedTransport = newTracedTransport(h.Transport)

		req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
		if err := h.ServeHTTP(httptest.NewRecorder(), req, nil); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if len(gotTraceparent) != 1 || gotTraceparent[0] != "" {
			t.Errorf("expected no traceparent upstream, got %q", gotTraceparent)
		}
	})
}
