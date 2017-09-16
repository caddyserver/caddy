package requestid

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Handler is a middleware handler
type Handler struct {
	Next httpserver.Handler
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	reqid := uuid.New().String()
	c := context.WithValue(r.Context(), httpserver.RequestIDCtxKey, reqid)
	r = r.WithContext(c)

	return h.Next.ServeHTTP(w, r)
}
