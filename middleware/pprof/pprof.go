package pprof

import (
	"net/http"
	pp "net/http/pprof"

	"github.com/mholt/caddy/middleware"
)

//Handler is a simple struct whose ServeHTTP will delegate relevant pprof endpoints to net/http/pprof
type handler struct {
	mux *http.ServeMux
}

//New creates a new pprof middleware
func New(next middleware.Handler) middleware.Handler {
	//pretty much copying what pprof does on init: https://golang.org/src/net/http/pprof/pprof.go#L67
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pp.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pp.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pp.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pp.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pp.Trace)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
	return &handler{mux}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	rec := middleware.NewResponseRecorder(w)
	h.mux.ServeHTTP(rec, r)
	return rec.Status(), nil
}
