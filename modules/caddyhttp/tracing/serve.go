package tracing

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.opentelemetry.io/otel/propagation"
)

// nextCall store the next handler, and the error value return on calling it (if any)
type nextCall struct {
	next caddyhttp.Handler
	err  error
}

const nextCallCtxKey caddy.CtxKey = "nextCall"

func (ot *openTelemetryWrapper) serveHTTP(w http.ResponseWriter, r *http.Request) {
	ot.propagators.Inject(r.Context(), propagation.HeaderCarrier(r.Header))
	next := r.Context().Value(nextCallCtxKey).(*nextCall)
	next.err = next.next.ServeHTTP(w, r)
}
