package requestid

import (
	"context"
	"log"
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	uuid "github.com/nu7hatch/gouuid"
)

// Handler is a middleware handler
type Handler struct {
	Next httpserver.Handler
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	reqid := UUID()
	c := context.WithValue(r.Context(), httpserver.RequestIDCtxKey, reqid)
	r = r.WithContext(c)

	return h.Next.ServeHTTP(w, r)
}

// UUID returns U4 UUID
func UUID() string {
	u4, err := uuid.NewV4()
	if err != nil {
		log.Printf("[ERROR] generating request ID: %v", err)
		return ""
	}

	return u4.String()
}
